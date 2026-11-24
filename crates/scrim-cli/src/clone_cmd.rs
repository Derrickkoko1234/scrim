//! `scrim clone`: clones a Scrim repository as a partial clone whose sparse
//! checkout excludes the paths the server withholds from the caller, and
//! enables the private-file filter before the first checkout.
//!
//! The bearer token reaches `git` only through `GIT_CONFIG_*` environment
//! variables scoped to the Scrim server URL, never through argv, the remote
//! URL or `.git/config`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use secrecy::SecretString;
use zeroize::Zeroizing;

use crate::cli::CloneArgs;
use crate::client::{MyWithheldPathsResponse, ScrimClient};
use crate::config::{ScrimConfig, load_config, normalize_server_url};
use crate::git::{
    git_cat_file_blob, git_configure_scrim_filter, git_extra_header_env, git_head_commit_exists,
    git_local_config_set, git_sparse_checkout_set, run_git_checked_with_env, validate_remote_name,
    validate_sparse_checkout_patterns,
};
use crate::private_cmd::FilterEnv;
use crate::{CliEnv, write_line};

/// Partial-clone filter used when the server withholds paths from the caller.
///
/// No real blob reaches 2 GiB, so the server still sends every blob the
/// caller may see in the initial pack (checkout needs no lazy fetches), while
/// Git records the remote as a promisor and tolerates the withheld blobs that
/// are missing from the pack.
pub(crate) const WITHHOLD_PARTIAL_CLONE_FILTER: &str = "blob:limit=2147483647";

/// A clone source split into the Scrim server and the repository on it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CloneSource {
    /// Normalized HTTP(S) Scrim API server base URL without a trailing slash.
    pub(crate) server_base_url: String,
    /// Repository key on the server (for example `team/app.git`).
    pub(crate) repo_key: String,
    /// Normalized SSH base URL (for example `ssh://git@git.example.com:2222`)
    /// when cloning over SSH, or `None` for HTTP(S) clones.
    pub(crate) ssh_base_url: Option<String>,
}

impl CloneSource {
    /// Returns whether Git transport uses SSH instead of HTTP(S).
    pub(crate) fn is_ssh(&self) -> bool {
        self.ssh_base_url.is_some()
    }

    /// Returns the Git remote URL for the repository.
    pub(crate) fn remote_url(&self) -> String {
        match &self.ssh_base_url {
            Some(ssh_base) => format!("{ssh_base}/{}", self.repo_key),
            None => format!("{}/{}", self.server_base_url, self.repo_key),
        }
    }
}

/// Validates a repository key the way `scrim-server` does: `/`-separated,
/// non-empty segments of ASCII letters, digits, `.`, `_` or `-`, none starting
/// with `.` (which also rules out `.` and `..`).
pub(crate) fn validate_repo_key(repo_key: &str) -> anyhow::Result<()> {
    if repo_key.is_empty() {
        bail!("repository key cannot be empty");
    }
    for segment in repo_key.split('/') {
        let is_valid_segment = !segment.is_empty()
            && !segment.starts_with('.')
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
        if !is_valid_segment {
            bail!(
                "invalid repository key '{repo_key}': use '/'-separated segments of ASCII letters, digits, '.', '_' or '-', none empty or starting with '.'"
            );
        }
    }
    Ok(())
}

/// Rejects whitespace, control characters, backslashes, percent-encoding, and
/// `.` or `..` path segments in raw URL text before `reqwest::Url::parse`
/// normalizes them away.
fn validate_raw_url_chars(raw: &str, scheme_end: usize, label: &str) -> anyhow::Result<()> {
    if raw
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("{label} must not contain whitespace or control characters");
    }
    if raw.contains(['\\', '%']) {
        bail!("{label} must not contain backslashes or percent-encoding");
    }
    if raw[scheme_end..]
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        bail!("{label} must not contain '.' or '..' path segments");
    }
    Ok(())
}

/// Parses and validates an `ssh://[user@]host[:port][/path]` URL, returning
/// `(normalized_ssh_base_url, path_without_leading_slash)`.
fn parse_ssh_url(
    raw: &str,
    require_empty_path: bool,
    label: &str,
) -> anyhow::Result<(String, String)> {
    let raw = raw.trim();
    let Some(rest) = raw.strip_prefix("ssh://") else {
        bail!("{label} must start with 'ssh://'");
    };
    if let Err(err) = validate_raw_url_chars(raw, "ssh://".len(), label) {
        return Err(err);
    }

    let authority = match rest.split('/').next() {
        Some(authority) => authority,
        None => rest,
    };
    if let Some((userinfo, _host)) = authority.split_once('@')
        && (userinfo.is_empty() || userinfo.contains(':'))
    {
        bail!("{label} must not contain an empty username or embedded password");
    }

    let parsed = match reqwest::Url::parse(raw) {
        Ok(url) => url,
        Err(err) => return Err(anyhow!("invalid {label}: {err}")),
    };
    let host = match parsed.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => bail!("{label} must include a host"),
    };
    if parsed.password().is_some() {
        bail!("{label} must not contain embedded credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("{label} must not contain a query string or fragment");
    }

    let user_prefix = if parsed.username().is_empty() {
        String::new()
    } else {
        format!("{}@", parsed.username())
    };
    let port_suffix = match parsed.port() {
        Some(port) => format!(":{port}"),
        None => String::new(),
    };
    let host_lower = host.to_ascii_lowercase();
    let ssh_base_url = format!("ssh://{user_prefix}{host_lower}{port_suffix}");

    let path = match parsed.path().strip_prefix('/') {
        Some(stripped) => stripped,
        None => parsed.path(),
    };
    if require_empty_path && !path.is_empty() {
        bail!("{label} must not include a repository path");
    }
    Ok((ssh_base_url, path.to_owned()))
}

/// Splits `source` into an HTTP(S) Scrim server base URL, repository key, and
/// optional SSH base URL.
///
/// A full `http(s)://` URL is split at `configured_server` when the URL lies
/// under it (keeping any base-path prefix), and otherwise at its origin. A full
/// `ssh://` URL uses `configured_server` for the HTTP admin API and keeps the
/// SSH base URL for Git transport. Any other `source` is a repository key on
/// `configured_server` (using `ssh_base` for Git transport when `--ssh` is
/// given).
///
/// # Errors
///
/// Fails for URLs with embedded passwords, a query, a fragment,
/// percent-encoding, backslashes or dot segments, for unsafe repository keys,
/// when `--ssh` is combined with a full URL, and when no HTTP server URL is
/// configured for a bare repository key or `ssh://` URL.
pub(crate) fn parse_clone_source(
    source: &str,
    configured_server: Option<&str>,
    ssh_base: Option<&str>,
) -> anyhow::Result<CloneSource> {
    let source = source.trim();
    if source.starts_with("ssh://") {
        if ssh_base.is_some() {
            bail!("--ssh cannot be used when SOURCE is already a full URL");
        }
        let (ssh_base_url, repo_key) = match parse_ssh_url(source, false, "repository URL") {
            Ok(parts) => parts,
            Err(err) => return Err(err),
        };
        if let Err(err) = validate_repo_key(&repo_key) {
            return Err(err);
        }
        let Some(server) = configured_server else {
            bail!(
                "no HTTP server URL configured for SSH clone '{source}'; pass --server <URL> or run 'scrim login --server <URL>' to query withholding rules"
            );
        };
        return Ok(CloneSource {
            server_base_url: server.to_owned(),
            repo_key,
            ssh_base_url: Some(ssh_base_url),
        });
    }

    let Some(scheme_end) = source
        .strip_prefix("https://")
        .or_else(|| source.strip_prefix("http://"))
        .map(|rest| source.len() - rest.len())
    else {
        if let Err(err) = validate_repo_key(source) {
            return Err(err);
        }
        let Some(server) = configured_server else {
            bail!(
                "no server URL configured for repository key '{source}'; pass a full repository URL, --server, or run 'scrim login --server <URL>'"
            );
        };
        let ssh_base_url = match ssh_base {
            Some(raw_ssh) => match parse_ssh_url(raw_ssh, true, "SSH URL") {
                Ok((base, _)) => Some(base),
                Err(err) => return Err(err),
            },
            None => None,
        };
        return Ok(CloneSource {
            server_base_url: server.to_owned(),
            repo_key: source.to_owned(),
            ssh_base_url,
        });
    };

    if ssh_base.is_some() {
        bail!("--ssh cannot be used when SOURCE is already a full URL");
    }

    // The URL parser silently resolves dot segments, percent-encoded dots and
    // backslashes, so reject them in the raw text before parsing.
    if let Err(err) = validate_raw_url_chars(source, scheme_end, "repository URL") {
        return Err(err);
    }

    let parsed = match reqwest::Url::parse(source) {
        Ok(url) => url,
        Err(err) => return Err(anyhow!("invalid repository URL: {err}")),
    };
    if !parsed.has_host() {
        bail!("repository URL must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("repository URL must not contain embedded credentials");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        bail!("repository URL must not contain a query string or fragment");
    }

    let path = parsed.path();
    let under_configured = configured_server.and_then(|server| {
        let server_url = match reqwest::Url::parse(server) {
            Ok(url) => url,
            Err(_) => return None,
        };
        if server_url.origin() != parsed.origin() {
            return None;
        }
        let prefix = format!("{}/", server_url.path().trim_end_matches('/'));
        path.strip_prefix(prefix.as_str())
            .map(|repo_key| (server.to_owned(), repo_key.to_owned()))
    });
    let (server_base_url, repo_key) = match under_configured {
        Some(split) => split,
        None => {
            let repo_key = match path.strip_prefix('/') {
                Some(rest) => rest.to_owned(),
                None => path.to_owned(),
            };
            (parsed.origin().ascii_serialization(), repo_key)
        }
    };
    if let Err(err) = validate_repo_key(&repo_key) {
        return Err(err);
    }
    Ok(CloneSource {
        server_base_url,
        repo_key,
        ssh_base_url: None,
    })
}

/// Returns the Git HTTP auth environment variables for `source`, or an empty
/// list when `source` clones over SSH (never leak HTTP bearer tokens to SSH).
fn auth_env_for_source(
    source: &CloneSource,
    parent_env: &BTreeMap<String, String>,
    client: &ScrimClient,
) -> anyhow::Result<Vec<(String, Zeroizing<String>)>> {
    if source.is_ssh() {
        return Ok(Vec::new());
    }
    git_extra_header_env(
        parent_env,
        client.base_url(),
        &client.authorization_header(),
    )
}

/// Derives the default clone directory like `git clone`: the repository key's
/// last segment without a trailing `.git`.
pub(crate) fn default_clone_directory(repo_key: &str) -> anyhow::Result<PathBuf> {
    let last_segment = match repo_key.rsplit('/').next() {
        Some(segment) => segment,
        None => repo_key,
    };
    let name = match last_segment.strip_suffix(".git") {
        Some(stripped) => stripped,
        None => last_segment,
    };
    if name.is_empty() || name == "." || name == ".." {
        bail!(
            "cannot derive a directory name from repository '{repo_key}'; pass <DIRECTORY> explicitly"
        );
    }
    Ok(PathBuf::from(name))
}

/// Rejects branch names that are empty, could be parsed as options, or
/// contain whitespace or control characters.
fn validate_branch_arg(branch: &str) -> anyhow::Result<()> {
    if branch.is_empty() {
        bail!("branch name cannot be empty");
    }
    if branch.starts_with('-') {
        bail!("branch name '{branch}' must not start with '-'");
    }
    if branch
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("branch name '{branch}' must not contain whitespace or control characters");
    }
    Ok(())
}

/// Checks a `GET /api/v1/path-rules/me` response before it reaches Git: the
/// canonical repository key and every sparse-checkout pattern must be safe,
/// and withheld paths must come with patterns that exclude them (otherwise
/// checkout would try to fetch blobs the server refuses to send).
pub(crate) fn validate_withheld_response(response: &MyWithheldPathsResponse) -> anyhow::Result<()> {
    if let Err(err) = validate_repo_key(&response.repository) {
        return Err(err).context("server returned an invalid repository key");
    }
    if let Err(err) = validate_sparse_checkout_patterns(&response.sparse_checkout_patterns) {
        return Err(err);
    }
    if !response.withheld_patterns.is_empty() && response.sparse_checkout_patterns.is_empty() {
        bail!("server withholds paths but returned no sparse-checkout patterns to exclude them");
    }
    Ok(())
}

/// Executes `scrim clone`.
pub(crate) fn handle_clone(
    args: CloneArgs,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let loaded: Option<ScrimConfig> = match config_path {
        Some(path) => match load_config(path) {
            Ok(config) => config,
            Err(err) => return Err(err),
        },
        None => None,
    };
    let (config_server, config_token) = match loaded {
        Some(config) => (config.server, config.token),
        None => (None, None),
    };
    let explicit_server = match server_flag {
        Some(raw) => match normalize_server_url(&raw) {
            Ok(url) => Some(url),
            Err(err) => return Err(err),
        },
        None => None,
    };

    let source = match parse_clone_source(
        &args.source,
        explicit_server.as_deref().or(config_server.as_deref()),
        args.ssh.as_deref(),
    ) {
        Ok(source) => source,
        Err(err) => return Err(err),
    };
    if let Some(server) = &explicit_server
        && *server != source.server_base_url
    {
        bail!(
            "repository URL '{}' is not on the server given by --server/SCRIM_SERVER ({server})",
            args.source.trim()
        );
    }

    // A saved token belongs to the saved server; never send it to a different
    // host just because the user pasted that host's URL.
    let token = match (token_override, config_token) {
        (Some(token), _) => token,
        (None, Some(token)) => {
            if let Some(saved_server) = &config_server
                && *saved_server != source.server_base_url
            {
                bail!(
                    "the saved token is for {saved_server}; pass --token or SCRIM_TOKEN to authenticate to {}",
                    source.server_base_url
                );
            }
            token
        }
        (None, None) => bail!("not logged in; run 'scrim login --server <URL>' or pass --token"),
    };

    if let Err(err) = validate_remote_name(&args.remote) {
        return Err(err);
    }
    if let Some(branch) = &args.branch
        && let Err(err) = validate_branch_arg(branch)
    {
        return Err(err);
    }
    let directory = match args.directory {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        Some(_) => bail!("destination directory cannot be empty"),
        None => match default_clone_directory(&source.repo_key) {
            Ok(directory) => directory,
            Err(err) => return Err(err),
        },
    };
    let target_dir = env.cwd.join(directory);

    let client = match ScrimClient::new(&source.server_base_url, token) {
        Ok(client) => client,
        Err(err) => return Err(err),
    };
    // Also verifies the token before Git runs, so authentication problems
    // surface as a clear API error instead of a Git HTTP failure.
    let withheld = match client.get_my_withheld_paths(&source.repo_key) {
        Ok(response) => response,
        Err(err) => return Err(err),
    };
    if let Err(err) = validate_withheld_response(&withheld) {
        return Err(err);
    }

    let auth_env = match auth_env_for_source(&source, &env.env_vars, &client) {
        Ok(vars) => vars,
        Err(err) => return Err(err),
    };
    let auth_pairs: Vec<(&str, &str)> = auth_env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();

    let remote_url = source.remote_url();
    let filter_arg = format!("--filter={WITHHOLD_PARTIAL_CLONE_FILTER}");
    let mut clone_args: Vec<&std::ffi::OsStr> = vec!["clone".as_ref(), "--no-checkout".as_ref()];
    if !withheld.withheld_patterns.is_empty() {
        clone_args.push(filter_arg.as_ref());
    }
    clone_args.push("--origin".as_ref());
    clone_args.push(args.remote.as_ref());
    if let Some(branch) = &args.branch {
        clone_args.push("--branch".as_ref());
        clone_args.push(branch.as_ref());
    }
    clone_args.push("--".as_ref());
    clone_args.push(remote_url.as_ref());
    clone_args.push(target_dir.as_os_str());
    if let Err(err) = run_git_checked_with_env(&env.cwd, &clone_args, &auth_pairs) {
        return Err(err);
    }

    if let Err(err) = git_local_config_set(&target_dir, "scrim.repo", &withheld.repository) {
        return Err(err);
    }
    if let Err(err) = git_local_config_set(&target_dir, "scrim.server", client.base_url()) {
        return Err(err);
    }
    let sparse_configured = !withheld.sparse_checkout_patterns.is_empty();
    if sparse_configured
        && let Err(err) =
            git_sparse_checkout_set(&target_dir, &withheld.sparse_checkout_patterns, &auth_pairs)
    {
        return Err(err);
    }
    // Configure the filter before the first checkout so encrypted private
    // files are decrypted (or replaced by placeholders) as they are written.
    let filter_enabled = match git_cat_file_blob(&target_dir, "HEAD:.scrim/paths.toml") {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => return Err(err),
    };
    if filter_enabled && let Err(err) = git_configure_scrim_filter(&target_dir) {
        return Err(err);
    }

    let checkout_line = if args.no_checkout {
        "Checkout: skipped (--no-checkout)"
    } else {
        match git_head_commit_exists(&target_dir) {
            Ok(true) => {
                let filter_env = FilterEnv::new(env, cli_key_file, config_path);
                let mut checkout_env = filter_env.pairs();
                checkout_env.extend_from_slice(&auth_pairs);
                if let Err(err) =
                    run_git_checked_with_env(&target_dir, &["checkout"], &checkout_env)
                {
                    return Err(err);
                }
                "Checkout: done"
            }
            Ok(false) => "Checkout: skipped (empty repository)",
            Err(err) => return Err(err),
        }
    };

    let partial_line = if withheld.withheld_patterns.is_empty() {
        "Partial clone: not needed (no paths withheld from you)".to_owned()
    } else {
        format!(
            "Partial clone: enabled ({} withheld pattern(s)); sparse checkout excludes withheld paths",
            withheld.withheld_patterns.len()
        )
    };
    let filter_line = if filter_enabled {
        "Private-file filter: enabled"
    } else {
        "Private-file filter: not needed (no .scrim/paths.toml)"
    };
    for line in [
        format!(
            "Cloned {} into {}",
            withheld.repository,
            target_dir.display()
        ),
        format!("Remote ({}): {remote_url}", args.remote),
        partial_line,
        filter_line.to_owned(),
        checkout_line.to_owned(),
    ] {
        if let Err(err) = write_line(env.stdout, &line) {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(source: &str, configured: Option<&str>) -> CloneSource {
        parse_ssh_ok(source, configured, None)
    }

    fn parse_ssh_ok(source: &str, configured: Option<&str>, ssh_base: Option<&str>) -> CloneSource {
        match parse_clone_source(source, configured, ssh_base) {
            Ok(parsed) => parsed,
            Err(err) => panic!("expected {source:?} (ssh={ssh_base:?}) to parse: {err:#}"),
        }
    }

    fn parse_err(source: &str, configured: Option<&str>) -> String {
        parse_ssh_err(source, configured, None)
    }

    fn parse_ssh_err(source: &str, configured: Option<&str>, ssh_base: Option<&str>) -> String {
        match parse_clone_source(source, configured, ssh_base) {
            Ok(parsed) => {
                panic!("expected {source:?} (ssh={ssh_base:?}) to be rejected, got {parsed:?}")
            }
            Err(err) => format!("{err:#}"),
        }
    }

    #[test]
    fn parses_full_urls_at_their_origin() {
        let parsed = parse_ok("https://Git.Example.com/team/app.git", None);
        assert_eq!(parsed.server_base_url, "https://git.example.com");
        assert_eq!(parsed.repo_key, "team/app.git");
        assert_eq!(parsed.remote_url(), "https://git.example.com/team/app.git");

        let with_port = parse_ok("http://127.0.0.1:8080/team/app.git", None);
        assert_eq!(with_port.server_base_url, "http://127.0.0.1:8080");
        assert_eq!(with_port.repo_key, "team/app.git");

        let default_port = parse_ok("https://git.example.com:443/app.git", None);
        assert_eq!(default_port.server_base_url, "https://git.example.com");

        // A configured server on another host does not affect the split.
        let other = parse_ok(
            "https://git.example.com/team/app.git",
            Some("https://other.example.com/scrim"),
        );
        assert_eq!(other.server_base_url, "https://git.example.com");
        assert_eq!(other.repo_key, "team/app.git");
    }

    #[test]
    fn strips_configured_server_base_path() {
        let parsed = parse_ok(
            "https://git.example.com/scrim/team/app.git",
            Some("https://git.example.com/scrim"),
        );
        assert_eq!(parsed.server_base_url, "https://git.example.com/scrim");
        assert_eq!(parsed.repo_key, "team/app.git");
        assert_eq!(
            parsed.remote_url(),
            "https://git.example.com/scrim/team/app.git"
        );

        // A prefix must match whole segments.
        let partial = parse_ok(
            "https://git.example.com/scrimmage/app.git",
            Some("https://git.example.com/scrim"),
        );
        assert_eq!(partial.server_base_url, "https://git.example.com");
        assert_eq!(partial.repo_key, "scrimmage/app.git");
    }

    #[test]
    fn resolves_bare_repo_keys_against_configured_server() {
        let parsed = parse_ok("team/app.git", Some("http://127.0.0.1:8080"));
        assert_eq!(parsed.server_base_url, "http://127.0.0.1:8080");
        assert_eq!(parsed.repo_key, "team/app.git");
        assert!(parse_err("team/app.git", None).contains("no server URL configured"));
    }

    #[test]
    fn rejects_unsafe_sources() {
        for (source, expected) in [
            ("https://alice:pw@git.example.com/app.git", "credentials"),
            ("https://alice@git.example.com/app.git", "credentials"),
            ("https://git.example.com/app.git?x=1", "query"),
            ("https://git.example.com/app.git#frag", "query"),
            ("https://git.example.com/team/../app.git", "'..'"),
            ("https://git.example.com/./app.git", "'..'"),
            ("https://git.example.com/%2e%2e/app.git", "percent"),
            ("https://git.example.com\\team\\app.git", "backslash"),
            ("https://git.example.com/", "repository key cannot be empty"),
            ("https://git.example.com", "repository key cannot be empty"),
            ("https://git.example.com//app.git", "invalid repository key"),
            (
                "https://git.example.com/team/app.git/",
                "invalid repository key",
            ),
            (
                "https://git.example.com/.hidden/app.git",
                "invalid repository key",
            ),
            ("https://git.example.com/a b.git", "whitespace"),
        ] {
            let message = parse_err(source, None);
            assert!(
                message.contains(expected),
                "{source:?}: expected {expected:?} in {message:?}"
            );
        }
        for key in [
            "../app.git",
            "team/../app.git",
            "/app.git",
            "app.git/",
            "a\\b",
        ] {
            let message = parse_err(key, Some("http://127.0.0.1:8080"));
            assert!(
                message.contains("repository key") || message.contains("invalid"),
                "{key:?}: {message:?}"
            );
        }
    }

    #[test]
    fn derives_default_directory_like_git_clone() {
        let derive = |key: &str| match default_clone_directory(key) {
            Ok(dir) => dir,
            Err(err) => panic!("{key}: {err:#}"),
        };
        assert_eq!(derive("team/app.git"), PathBuf::from("app"));
        assert_eq!(derive("app"), PathBuf::from("app"));
        assert_eq!(derive("a/b/tool.js.git"), PathBuf::from("tool.js"));
        for key in ["team/.git", "..git", "...git", "team/"] {
            assert!(default_clone_directory(key).is_err(), "{key:?}");
        }
    }

    #[test]
    fn validates_withheld_responses() {
        let response = |withheld: &[&str], sparse: &[&str]| MyWithheldPathsResponse {
            repository: "team/app.git".to_owned(),
            withheld_patterns: withheld.iter().map(|p| (*p).to_owned()).collect(),
            sparse_checkout_patterns: sparse.iter().map(|p| (*p).to_owned()).collect(),
        };
        assert!(validate_withheld_response(&response(&[], &[])).is_ok());
        assert!(
            validate_withheld_response(&response(&["secret/**"], &["/*", "!/secret/**"])).is_ok()
        );
        assert!(validate_withheld_response(&response(&["secret/**"], &[])).is_err());
        assert!(validate_withheld_response(&response(&["x"], &["/*", "-x"])).is_err());
        assert!(validate_withheld_response(&response(&["x"], &["/*", ""])).is_err());
        assert!(validate_withheld_response(&response(&["x"], &["/*", "!/x\n/y"])).is_err());
        let mut bad_repo = response(&[], &[]);
        bad_repo.repository = "../etc".to_owned();
        assert!(validate_withheld_response(&bad_repo).is_err());
    }

    #[test]
    fn validates_branch_args() {
        assert!(validate_branch_arg("main").is_ok());
        assert!(validate_branch_arg("feature/x").is_ok());
        for branch in ["", "-b", "a b", "a\nb"] {
            assert!(validate_branch_arg(branch).is_err(), "{branch:?}");
        }
    }

    #[test]
    fn parses_ssh_urls_and_ssh_flag() {
        let with_user_port = parse_ok(
            "ssh://git@Git.Example.com:2222/team/app.git",
            Some("https://api.example.com"),
        );
        assert!(with_user_port.is_ssh());
        assert_eq!(with_user_port.server_base_url, "https://api.example.com");
        assert_eq!(with_user_port.repo_key, "team/app.git");
        assert_eq!(
            with_user_port.ssh_base_url.as_deref(),
            Some("ssh://git@git.example.com:2222")
        );
        assert_eq!(
            with_user_port.remote_url(),
            "ssh://git@git.example.com:2222/team/app.git"
        );

        let without_user_port = parse_ok(
            "ssh://git.example.com/team/app.git",
            Some("http://127.0.0.1:8080"),
        );
        assert!(without_user_port.is_ssh());
        assert_eq!(without_user_port.server_base_url, "http://127.0.0.1:8080");
        assert_eq!(without_user_port.repo_key, "team/app.git");
        assert_eq!(
            without_user_port.remote_url(),
            "ssh://git.example.com/team/app.git"
        );

        let via_flag = parse_ssh_ok(
            "team/app.git",
            Some("http://127.0.0.1:8080"),
            Some("ssh://git@git.example.com:2222/"),
        );
        assert!(via_flag.is_ssh());
        assert_eq!(via_flag.server_base_url, "http://127.0.0.1:8080");
        assert_eq!(via_flag.repo_key, "team/app.git");
        assert_eq!(
            via_flag.remote_url(),
            "ssh://git@git.example.com:2222/team/app.git"
        );
    }

    #[test]
    fn rejects_invalid_ssh_sources_and_flag_combinations() {
        let server = Some("https://api.example.com");
        assert!(
            parse_err("ssh://git@git.example.com/team/app.git", None)
                .contains("--server <URL> or run 'scrim login")
        );
        for (source, expected) in [
            ("ssh://alice:pw@git.example.com/app.git", "password"),
            ("ssh://:pw@git.example.com/app.git", "password"),
            ("ssh://@git.example.com/app.git", "empty username"),
            ("ssh://git@git.example.com/app.git?x=1", "query"),
            ("ssh://git@git.example.com/app.git#frag", "query"),
            ("ssh://git@git.example.com/team/../app.git", "'..'"),
            ("ssh://git@git.example.com/./app.git", "'..'"),
            ("ssh://git@git.example.com/%2e%2e/app.git", "percent"),
            ("ssh://git@git.example.com\\team\\app.git", "backslash"),
            ("ssh://git@git.example.com/a b.git", "whitespace"),
            (
                "ssh://git@git.example.com/",
                "repository key cannot be empty",
            ),
        ] {
            let message = parse_err(source, server);
            assert!(
                message.contains(expected),
                "{source:?}: expected {expected:?} in {message:?}"
            );
        }

        assert!(
            parse_ssh_err(
                "https://git.example.com/team/app.git",
                server,
                Some("ssh://git@git.example.com:2222")
            )
            .contains("--ssh cannot be used")
        );
        assert!(
            parse_ssh_err(
                "ssh://git@git.example.com/team/app.git",
                server,
                Some("ssh://git@git.example.com:2222")
            )
            .contains("--ssh cannot be used")
        );
        for bad_ssh in [
            "https://git.example.com",
            "ssh://git@git.example.com/team/app.git",
            "ssh://alice:pw@git.example.com:2222",
            "ssh://git@git.example.com:2222?x=1",
            "ssh://git@git.example.com:2222#frag",
            "ssh://git@git.example.com:2222/..",
            "ssh://git@git.example.com:2222/%2e",
            "ssh://git@git.example.com:2222\\x",
            "ssh://git@git.example.com:22 22",
        ] {
            let trimmed = bad_ssh.trim();
            if trimmed.is_empty() {
                continue;
            }
            assert!(
                parse_ssh_err("team/app.git", server, Some(bad_ssh)).contains("SSH URL"),
                "expected SSH URL error for {bad_ssh:?}"
            );
        }
        assert!(
            parse_ssh_err(
                "team/app.git",
                server,
                Some("ssh://git@git.example.com:22\n22")
            )
            .contains("whitespace or control")
        );
    }

    #[test]
    fn ssh_clone_never_attaches_http_auth_env() {
        let client = match ScrimClient::new(
            "https://api.example.com",
            SecretString::from("scrim-secret-token"),
        ) {
            Ok(client) => client,
            Err(err) => panic!("client should build: {err:#}"),
        };
        let parent_env = BTreeMap::new();

        let ssh_source = parse_ok(
            "ssh://git@git.example.com:2222/team/app.git",
            Some("https://api.example.com"),
        );
        let ssh_env = match auth_env_for_source(&ssh_source, &parent_env, &client) {
            Ok(env) => env,
            Err(err) => panic!("ssh auth env failed: {err:#}"),
        };
        assert!(
            ssh_env.is_empty(),
            "SSH clone must not attach HTTP auth env"
        );

        let http_source = parse_ok("https://api.example.com/team/app.git", None);
        let http_env = match auth_env_for_source(&http_source, &parent_env, &client) {
            Ok(env) => env,
            Err(err) => panic!("http auth env failed: {err:#}"),
        };
        assert!(
            !http_env.is_empty(),
            "HTTP clone should attach GIT_CONFIG_* auth env"
        );
    }
}
