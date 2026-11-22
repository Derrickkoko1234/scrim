//! `scrim clone`: clones a Scrim repository as a partial clone whose sparse
//! checkout excludes the paths the server withholds from the caller, and
//! enables the private-file filter before the first checkout.
//!
//! The bearer token reaches `git` only through `GIT_CONFIG_*` environment
//! variables scoped to the Scrim server URL, never through argv, the remote
//! URL or `.git/config`.

use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use secrecy::SecretString;

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
    /// Normalized server base URL without a trailing slash.
    pub(crate) server_base_url: String,
    /// Repository key on the server (for example `team/app.git`).
    pub(crate) repo_key: String,
}

impl CloneSource {
    /// Returns the Git remote URL for the repository.
    pub(crate) fn remote_url(&self) -> String {
        format!("{}/{}", self.server_base_url, self.repo_key)
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

/// Splits `source` into a server base URL and repository key.
///
/// A full `http(s)://` URL is split at `configured_server` when the URL lies
/// under it (keeping any base-path prefix), and otherwise at its origin. Any
/// other `source` is a repository key on `configured_server`.
///
/// # Errors
///
/// Fails for URLs with credentials, a query, a fragment, percent-encoding,
/// backslashes or dot segments, for unsafe repository keys, and for a bare
/// repository key when no server is configured.
pub(crate) fn parse_clone_source(
    source: &str,
    configured_server: Option<&str>,
) -> anyhow::Result<CloneSource> {
    let source = source.trim();
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
        return Ok(CloneSource {
            server_base_url: server.to_owned(),
            repo_key: source.to_owned(),
        });
    };

    // The URL parser silently resolves dot segments, percent-encoded dots and
    // backslashes, so reject them in the raw text before parsing.
    if source
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("repository URL must not contain whitespace or control characters");
    }
    if source.contains(['\\', '%']) {
        bail!("repository URL must not contain backslashes or percent-encoding");
    }
    if source[scheme_end..]
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        bail!("repository URL must not contain '.' or '..' path segments");
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
    })
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

    let auth_env = match git_extra_header_env(
        &env.env_vars,
        client.base_url(),
        &client.authorization_header(),
    ) {
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
        match parse_clone_source(source, configured) {
            Ok(parsed) => parsed,
            Err(err) => panic!("expected {source:?} to parse: {err:#}"),
        }
    }

    fn parse_err(source: &str, configured: Option<&str>) -> String {
        match parse_clone_source(source, configured) {
            Ok(parsed) => panic!("expected {source:?} to be rejected, got {parsed:?}"),
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
}
