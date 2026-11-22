//! Thin helpers around the local `git` CLI.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};
use zeroize::Zeroizing;

/// Returns the repository top-level directory when `cwd` is inside a Git
/// working tree, or `Ok(None)` when outside one.
pub fn git_toplevel(cwd: &Path) -> anyhow::Result<Option<PathBuf>> {
    let output = match Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--show-toplevel"])
        .output()
    {
        Ok(out) => out,
        Err(err) => {
            return Err(anyhow!(err)).context("failed to execute git rev-parse --show-toplevel");
        }
    };

    if !output.status.success() {
        return Ok(None);
    }

    let text = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(err) => {
            return Err(anyhow!(err)).context("git rev-parse output was not valid UTF-8");
        }
    };
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(trimmed)))
}

/// Validates that a Git remote name cannot be mistaken for a CLI option or
/// contain whitespace or control characters.
pub fn validate_remote_name(remote: &str) -> anyhow::Result<()> {
    if remote.is_empty() {
        bail!("git remote name cannot be empty");
    }
    if remote.starts_with('-') {
        bail!("git remote name '{remote}' must not start with '-'");
    }
    if remote
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("git remote name '{remote}' must not contain whitespace or control characters");
    }
    Ok(())
}

/// Reads a single local Git config value (`git config --local --get -- <key>`),
/// returning `Ok(None)` when not inside a Git repo or when the key is unset.
pub fn git_local_config_get(cwd: &Path, key: &str) -> anyhow::Result<Option<String>> {
    let output = match Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["config", "--local", "--get", "--", key])
        .output()
    {
        Ok(out) => out,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to execute git config --local --get {key}"));
        }
    };

    if !output.status.success() {
        return Ok(None);
    }

    let text = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("git config value for {key} was not valid UTF-8"));
        }
    };
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_owned()))
}

/// Sets a local Git config key (`git config --local -- <key> <value>`).
pub fn git_local_config_set(cwd: &Path, key: &str, value: &str) -> anyhow::Result<()> {
    run_git_checked(cwd, &["config", "--local", "--", key, value])
}

/// Returns the URL configured for `remote` (`git remote get-url -- <remote>`), or
/// `Ok(None)` if that remote does not exist.
pub fn git_remote_get_url(cwd: &Path, remote: &str) -> anyhow::Result<Option<String>> {
    if let Err(err) = validate_remote_name(remote) {
        return Err(err);
    }
    let output = match Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["remote", "get-url", "--", remote])
        .output()
    {
        Ok(out) => out,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to execute git remote get-url {remote}"));
        }
    };

    if !output.status.success() {
        return Ok(None);
    }

    let text = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("git remote URL for {remote} was not valid UTF-8"));
        }
    };
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_owned()))
}

/// Adds a new Git remote (`git remote add -- <remote> <url>`).
pub fn git_remote_add(cwd: &Path, remote: &str, url: &str) -> anyhow::Result<()> {
    if let Err(err) = validate_remote_name(remote) {
        return Err(err);
    }
    run_git_checked(cwd, &["remote", "add", "--", remote, url])
}

/// Updates an existing Git remote's URL (`git remote set-url -- <remote> <url>`).
pub fn git_remote_set_url(cwd: &Path, remote: &str, url: &str) -> anyhow::Result<()> {
    if let Err(err) = validate_remote_name(remote) {
        return Err(err);
    }
    run_git_checked(cwd, &["remote", "set-url", "--", remote, url])
}

fn run_git_checked(cwd: &Path, args: &[&str]) -> anyhow::Result<()> {
    run_git_checked_with_env(cwd, args, &[])
}

/// Runs `git -C <cwd> <args>` with `extra_env` set, failing with Git's stderr
/// when it exits unsuccessfully.
pub fn run_git_checked_with_env<S: AsRef<OsStr>>(
    cwd: &Path,
    args: &[S],
    extra_env: &[(&str, &str)],
) -> anyhow::Result<()> {
    let display = args
        .iter()
        .map(|arg| arg.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let mut command = Command::new("git");
    command.arg("-C").arg(cwd).args(args);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let output = match command.output() {
        Ok(out) => out,
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| format!("failed to execute git {display}"));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            bail!("git {display} exited with status {}", output.status);
        }
        bail!("git {display} failed: {detail}");
    }

    Ok(())
}

/// Builds environment variables that make spawned `git` processes send
/// `header` (for example `Authorization: Bearer ...`) only to URLs under
/// `server_base_url`, via `http.<server_base_url>/.extraHeader`.
///
/// The header travels in `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_<n>`/
/// `GIT_CONFIG_VALUE_<n>` so it never appears in argv or `.git/config`.
/// Entries already present in `parent_env` are copied and the header is
/// appended after them. `GIT_TERMINAL_PROMPT=0` stops Git from prompting
/// for credentials when the server rejects the header. Values are zeroized
/// on drop.
///
/// # Errors
///
/// Fails when `parent_env` holds a malformed `GIT_CONFIG_COUNT` or lacks a
/// key/value it announces.
pub fn git_extra_header_env(
    parent_env: &BTreeMap<String, String>,
    server_base_url: &str,
    header: &str,
) -> anyhow::Result<Vec<(String, Zeroizing<String>)>> {
    let existing_count = match parent_env.get("GIT_CONFIG_COUNT") {
        Some(raw) if !raw.trim().is_empty() => match raw.trim().parse::<usize>() {
            Ok(count) => count,
            Err(_) => bail!("GIT_CONFIG_COUNT must be a non-negative integer, got {raw:?}"),
        },
        _ => 0,
    };
    let mut vars = Vec::with_capacity(existing_count * 2 + 4);
    for index in 0..existing_count {
        for prefix in ["GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"] {
            let name = format!("{prefix}{index}");
            match parent_env.get(&name) {
                Some(value) => vars.push((name, Zeroizing::new(value.clone()))),
                None => bail!("GIT_CONFIG_COUNT is {existing_count} but {name} is not set"),
            }
        }
    }
    vars.push((
        format!("GIT_CONFIG_KEY_{existing_count}"),
        Zeroizing::new(format!("http.{server_base_url}/.extraHeader")),
    ));
    vars.push((
        format!("GIT_CONFIG_VALUE_{existing_count}"),
        Zeroizing::new(header.to_owned()),
    ));
    vars.push((
        "GIT_CONFIG_COUNT".to_owned(),
        Zeroizing::new((existing_count + 1).to_string()),
    ));
    vars.push((
        "GIT_TERMINAL_PROMPT".to_owned(),
        Zeroizing::new("0".to_owned()),
    ));
    Ok(vars)
}

/// Returns whether `HEAD` resolves to a commit (false for an unborn `HEAD`,
/// such as in a freshly cloned empty repository).
pub fn git_head_commit_exists(repo_root: &Path) -> anyhow::Result<bool> {
    match Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
        .output()
    {
        Ok(out) => Ok(out.status.success()),
        Err(err) => Err(anyhow!(err)).context("failed to execute git rev-parse --verify HEAD"),
    }
}

/// Rejects sparse-checkout patterns that could be misparsed on Git's command
/// line or in `.git/info/sparse-checkout`: empty patterns, patterns starting
/// with `-`, and patterns containing NUL, CR or LF.
pub fn validate_sparse_checkout_patterns(patterns: &[String]) -> anyhow::Result<()> {
    for pattern in patterns {
        if pattern.is_empty() {
            bail!("server returned an empty sparse-checkout pattern");
        }
        if pattern.starts_with('-') {
            bail!("server returned sparse-checkout pattern {pattern:?} starting with '-'");
        }
        if pattern.contains(['\0', '\r', '\n']) {
            bail!("server returned sparse-checkout pattern {pattern:?} containing NUL, CR or LF");
        }
    }
    Ok(())
}

/// Lists the repository's configured Git remote names (`git remote`).
pub fn git_list_remotes(repo_root: &Path) -> anyhow::Result<Vec<String>> {
    let output = match Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .arg("remote")
        .output()
    {
        Ok(out) => out,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git remote"),
    };
    if !output.status.success() {
        bail!(
            "git remote failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let text = match String::from_utf8(output.stdout) {
        Ok(text) => text,
        Err(err) => return Err(anyhow!(err)).context("git remote output was not valid UTF-8"),
    };
    Ok(text
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Returns the promisor remotes (`remote.<name>.promisor = true`) whose URL
/// lies under `server_base_url`.
pub fn git_promisor_remotes_for_server(
    repo_root: &Path,
    server_base_url: &str,
) -> anyhow::Result<Vec<String>> {
    let remotes = match git_list_remotes(repo_root) {
        Ok(remotes) => remotes,
        Err(err) => return Err(err),
    };
    let server_prefix = format!("{}/", server_base_url.trim_end_matches('/'));
    let mut promisor_remotes = Vec::new();
    for remote in remotes {
        if validate_remote_name(&remote).is_err() {
            continue;
        }
        let promisor_key = format!("remote.{remote}.promisor");
        let is_promisor = match git_local_config_get(repo_root, &promisor_key) {
            Ok(Some(value)) => value.eq_ignore_ascii_case("true"),
            Ok(None) => false,
            Err(err) => return Err(err),
        };
        if !is_promisor {
            continue;
        }
        let remote_url = match git_remote_get_url(repo_root, &remote) {
            Ok(Some(url)) => url,
            Ok(None) => continue,
            Err(err) => return Err(err),
        };
        if remote_url.starts_with(&server_prefix) {
            promisor_remotes.push(remote);
        }
    }
    Ok(promisor_remotes)
}

/// Refetches visible blobs from partial-clone `remote` at commit level
/// (`git fetch --quiet --refetch --filter=<filter> -- <remote>`) so widening
/// or disabling sparse checkout never falls back to a per-blob promisor fetch
/// (which `scrim-server` refuses by design).
pub fn git_refetch_partial_remote(
    repo_root: &Path,
    remote: &str,
    filter: &str,
    extra_env: &[(&str, &str)],
) -> anyhow::Result<()> {
    if let Err(err) = validate_remote_name(remote) {
        return Err(err);
    }
    let filter_arg = format!("--filter={filter}");
    run_git_checked_with_env(
        repo_root,
        &["fetch", "--quiet", "--refetch", &filter_arg, "--", remote],
        extra_env,
    )
}

/// Enables non-cone sparse checkout limited to `patterns`
/// (`git sparse-checkout init --no-cone` then
/// `git sparse-checkout set --no-cone -- <patterns>`). `extra_env` is set on
/// both commands, which may run smudge filters or lazily fetch blobs.
pub fn git_sparse_checkout_set(
    repo_root: &Path,
    patterns: &[String],
    extra_env: &[(&str, &str)],
) -> anyhow::Result<()> {
    if let Err(err) = validate_sparse_checkout_patterns(patterns) {
        return Err(err);
    }
    if let Err(err) = run_git_checked_with_env(
        repo_root,
        &["sparse-checkout", "init", "--no-cone"],
        extra_env,
    ) {
        return Err(err);
    }
    let mut args = vec!["sparse-checkout", "set", "--no-cone", "--"];
    args.extend(patterns.iter().map(String::as_str));
    run_git_checked_with_env(repo_root, &args, extra_env)
}

/// Disables sparse checkout (`git sparse-checkout disable`) when
/// `core.sparseCheckout` is enabled, returning whether it was.
pub fn git_sparse_checkout_disable_if_active(
    repo_root: &Path,
    extra_env: &[(&str, &str)],
) -> anyhow::Result<bool> {
    // Effective lookup: `sparse-checkout init` stores the setting in the
    // per-worktree config, which `git config --local` does not read.
    match git_config_get_effective(repo_root, "core.sparseCheckout") {
        Ok(Some(value)) if value.eq_ignore_ascii_case("true") => {}
        Ok(_) => return Ok(false),
        Err(err) => return Err(err),
    }
    match run_git_checked_with_env(repo_root, &["sparse-checkout", "disable"], extra_env) {
        Ok(()) => Ok(true),
        Err(err) => Err(err),
    }
}

/// Number of paths passed to a single `git` invocation, keeping command lines
/// well under OS argument limits.
const GIT_PATH_CHUNK: usize = 100;

/// Lists tracked files (`git ls-files -z`) as repo-relative UTF-8 paths.
///
/// # Errors
///
/// Fails when `git` cannot run, exits unsuccessfully, or reports a path that
/// is not valid UTF-8.
pub fn git_ls_files(repo_root: &Path) -> anyhow::Result<Vec<String>> {
    let output = match Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["ls-files", "-z"])
        .output()
    {
        Ok(out) => out,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git ls-files"),
    };
    if !output.status.success() {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let mut paths = Vec::new();
    for raw in output.stdout.split(|&byte| byte == 0) {
        if raw.is_empty() {
            continue;
        }
        match std::str::from_utf8(raw) {
            Ok(path) => paths.push(path.to_owned()),
            Err(_) => bail!(
                "git ls-files reported a non-UTF-8 path: {}",
                String::from_utf8_lossy(raw)
            ),
        }
    }
    Ok(paths)
}

/// Reads the blob named by `rev_and_path` (for example `HEAD:.scrim/paths.toml`)
/// with `git cat-file blob`, returning `Ok(None)` when no such blob exists.
///
/// # Errors
///
/// Fails when `rev_and_path` starts with `-` (so it can never be parsed as an
/// option) or `git` cannot be executed.
pub fn git_cat_file_blob(repo_root: &Path, rev_and_path: &str) -> anyhow::Result<Option<Vec<u8>>> {
    if rev_and_path.is_empty() || rev_and_path.starts_with('-') {
        bail!("invalid git object name {rev_and_path:?}");
    }
    let output = match Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["cat-file", "blob", rev_and_path])
        .output()
    {
        Ok(out) => out,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git cat-file"),
    };
    if !output.status.success() {
        return Ok(None);
    }
    Ok(Some(output.stdout))
}

/// Re-applies clean filters to `paths` and stages the result
/// (`git add --renormalize -- <paths>`), in chunks.
///
/// `extra_env` is set on each `git` process so the `scrim filter-process` it
/// spawns resolves the same config and identity as the calling command.
pub fn git_add_renormalize(
    repo_root: &Path,
    paths: &[String],
    extra_env: &[(&str, &str)],
) -> anyhow::Result<()> {
    run_git_on_path_chunks(repo_root, &["add", "--renormalize"], paths, extra_env)
}

/// Rewrites `paths` in the working tree from the index through smudge filters
/// and refreshes their index stat data (`git checkout-index --force --index --
/// <paths>`), in chunks. See [`git_add_renormalize`] for `extra_env`.
pub fn git_checkout_index_force(
    repo_root: &Path,
    paths: &[String],
    extra_env: &[(&str, &str)],
) -> anyhow::Result<()> {
    run_git_on_path_chunks(
        repo_root,
        &["checkout-index", "--force", "--index"],
        paths,
        extra_env,
    )
}

/// Configures the local repository to run `scrim filter-process` for
/// `filter=scrim` paths and to fail rather than skip the filter when it is
/// unavailable.
pub fn git_configure_scrim_filter(repo_root: &Path) -> anyhow::Result<()> {
    if let Err(err) =
        git_local_config_set(repo_root, "filter.scrim.process", "scrim filter-process")
    {
        return Err(err);
    }
    git_local_config_set(repo_root, "filter.scrim.required", "true")
}

/// Returns the effective (`git config --get`, so local, global and system)
/// values of `filter.scrim.process` and `filter.scrim.required`.
pub fn git_is_scrim_filter_configured(
    repo_root: &Path,
) -> anyhow::Result<(Option<String>, Option<String>)> {
    let process = match git_config_get_effective(repo_root, "filter.scrim.process") {
        Ok(value) => value,
        Err(err) => return Err(err),
    };
    let required = match git_config_get_effective(repo_root, "filter.scrim.required") {
        Ok(value) => value,
        Err(err) => return Err(err),
    };
    Ok((process, required))
}

fn git_config_get_effective(cwd: &Path, key: &str) -> anyhow::Result<Option<String>> {
    let output = match Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["config", "--get", "--", key])
        .output()
    {
        Ok(out) => out,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to execute git config --get {key}"));
        }
    };
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Ok(None);
    }
    Ok(Some(trimmed.to_owned()))
}

fn run_git_on_path_chunks(
    repo_root: &Path,
    args: &[&str],
    paths: &[String],
    extra_env: &[(&str, &str)],
) -> anyhow::Result<()> {
    for chunk in paths.chunks(GIT_PATH_CHUNK) {
        let mut command = Command::new("git");
        command
            .arg("-C")
            .arg(repo_root)
            .args(args)
            .arg("--")
            .args(chunk);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let output = match command.output() {
            Ok(out) => out,
            Err(err) => {
                return Err(anyhow!(err))
                    .with_context(|| format!("failed to execute git {}", args.join(" ")));
            }
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("git {} failed: {}", args.join(" "), stderr.trim());
        }
    }
    Ok(())
}
