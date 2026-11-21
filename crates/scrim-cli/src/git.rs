//! Thin helpers around the local `git` CLI.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, anyhow, bail};

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
    let output = match Command::new("git").arg("-C").arg(cwd).args(args).output() {
        Ok(out) => out,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to execute git {}", args.join(" ")));
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            bail!(
                "git {} exited with status {}",
                args.join(" "),
                output.status
            );
        }
        bail!("git {} failed: {detail}", args.join(" "));
    }

    Ok(())
}
