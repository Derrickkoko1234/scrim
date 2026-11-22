//! `scrim ssh-key`: manages SSH public keys for Git-over-SSH authentication.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use secrecy::SecretString;

use crate::cli::SshKeyCommand;
use crate::{CliEnv, build_authenticated_client, escape_control_chars, write_line};

/// Maximum `.pub` file size read when resolving an SSH public key from disk.
const MAX_SSH_KEY_FILE_BYTES: u64 = 8 * 1024;

/// Handles `scrim ssh-key` subcommands (`add`, `list`, `rm`).
pub(crate) fn handle_ssh_key(
    command: SshKeyCommand,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    match command {
        SshKeyCommand::Add { key, label, member } => {
            if let Err(err) = validate_member_flag(member.as_deref()) {
                return Err(err);
            }
            if label.chars().any(char::is_control) {
                bail!("--label cannot contain control characters");
            }
            let public_key = match resolve_ssh_public_key(&key, &env.cwd) {
                Ok(resolved) => resolved,
                Err(err) => return Err(err),
            };
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            let res = match client.add_ssh_key(member.as_deref(), &public_key, &label) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            let member_name = escape_control_chars(&res.member);
            let fingerprint = escape_control_chars(&res.key.fingerprint);
            let saved_label = escape_control_chars(&res.key.label);
            let line = if saved_label.is_empty() {
                format!(
                    "Added SSH key #{} for {member_name} ({fingerprint})",
                    res.key.id
                )
            } else {
                format!(
                    "Added SSH key #{} for {member_name} ({fingerprint}, label: {saved_label})",
                    res.key.id
                )
            };
            write_line(env.stdout, &line)
        }
        SshKeyCommand::List { member } => {
            if let Err(err) = validate_member_flag(member.as_deref()) {
                return Err(err);
            }
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            let res = match client.list_ssh_keys(member.as_deref()) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            let member_name = escape_control_chars(&res.member);
            if let Err(err) = write_line(env.stdout, &format!("SSH keys for {member_name}:")) {
                return Err(err);
            }
            if res.keys.is_empty() {
                return write_line(env.stdout, "  (none)");
            }
            for key in &res.keys {
                let fingerprint = escape_control_chars(&key.fingerprint);
                let label = escape_control_chars(&key.label);
                let line = if label.is_empty() {
                    format!("  #{}  {fingerprint}", key.id)
                } else {
                    format!("  #{}  {fingerprint}  {label}", key.id)
                };
                if let Err(err) = write_line(env.stdout, &line) {
                    return Err(err);
                }
            }
            Ok(())
        }
        SshKeyCommand::Rm { id, member } => {
            if id <= 0 {
                bail!("SSH key ID must be a positive integer, got {id}");
            }
            if let Err(err) = validate_member_flag(member.as_deref()) {
                return Err(err);
            }
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            let res = match client.revoke_ssh_key(member.as_deref(), id) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            let member_name = escape_control_chars(&res.member);
            if res.revoked {
                write_line(
                    env.stdout,
                    &format!("Revoked SSH key #{} for {member_name}.", res.id),
                )
            } else {
                write_line(
                    env.stdout,
                    &format!("SSH key #{} for {member_name} was not active.", res.id),
                )
            }
        }
    }
}

fn validate_member_flag(member: Option<&str>) -> anyhow::Result<()> {
    if let Some(name) = member
        && name.trim().is_empty()
    {
        bail!("--member cannot be empty");
    }
    Ok(())
}

/// Resolves an SSH public key argument from either an existing regular `.pub`
/// file on disk (relative to `cwd`, at most 8 KiB) or an inline key string,
/// trimming trailing `\r\n` and rejecting empty, multi-line, or control-char
/// inputs.
fn resolve_ssh_public_key(raw_key: &str, cwd: &Path) -> anyhow::Result<String> {
    let trimmed_input = match normalize_single_line_key(raw_key) {
        Ok(value) => value,
        Err(err) => return Err(err),
    };

    let candidate = cwd.join(&trimmed_input);
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) => read_ssh_key_file(&candidate, &metadata),
        Err(err) if is_inline_key_fallback_error(&err) => Ok(trimmed_input),
        Err(err) => Err(anyhow!(err)).with_context(|| {
            format!(
                "failed to inspect SSH public key path '{}'",
                candidate.display()
            )
        }),
    }
}

fn is_inline_key_fallback_error(err: &std::io::Error) -> bool {
    matches!(err.kind(), ErrorKind::NotFound | ErrorKind::InvalidFilename)
}

fn read_ssh_key_file(path: &Path, metadata: &fs::Metadata) -> anyhow::Result<String> {
    if metadata.file_type().is_symlink() {
        bail!(
            "SSH public key file '{}' must not be a symlink",
            path.display()
        );
    }
    if metadata.is_dir() {
        bail!("SSH public key path '{}' is a directory", path.display());
    }
    if !metadata.is_file() {
        bail!(
            "SSH public key path '{}' is not a regular file",
            path.display()
        );
    }
    if metadata.len() > MAX_SSH_KEY_FILE_BYTES {
        bail!(
            "SSH public key file '{}' exceeds maximum size of {MAX_SSH_KEY_FILE_BYTES} bytes",
            path.display()
        );
    }

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| {
                format!("failed to open SSH public key file '{}'", path.display())
            });
        }
    };
    let mut bytes = Vec::new();
    let mut limited = file.take(MAX_SSH_KEY_FILE_BYTES + 1);
    if let Err(err) = limited.read_to_end(&mut bytes) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to read SSH public key file '{}'", path.display()));
    }
    if bytes.len() as u64 > MAX_SSH_KEY_FILE_BYTES {
        bail!(
            "SSH public key file '{}' exceeds maximum size of {MAX_SSH_KEY_FILE_BYTES} bytes",
            path.display()
        );
    }

    let content = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => bail!(
            "SSH public key file '{}' is not valid UTF-8",
            path.display()
        ),
    };
    normalize_single_line_key(&content)
}

fn normalize_single_line_key(raw: &str) -> anyhow::Result<String> {
    let stripped = raw.trim_end_matches(['\r', '\n']);
    if stripped.trim().is_empty() {
        bail!("SSH public key cannot be empty");
    }
    if stripped.contains(['\r', '\n']) {
        bail!("SSH public key must be a single line");
    }
    if stripped.chars().any(char::is_control) {
        bail!("SSH public key cannot contain control characters");
    }
    Ok(stripped.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl alice@laptop";

    #[test]
    fn resolves_inline_key_and_trims_trailing_crlf() {
        let tmp = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let resolved = match resolve_ssh_public_key(&format!("{TEST_KEY}\r\n"), tmp.path()) {
            Ok(key) => key,
            Err(err) => panic!("expected inline key to resolve: {err}"),
        };
        assert_eq!(resolved, TEST_KEY);
    }

    #[test]
    fn resolves_key_from_relative_pub_file() {
        let tmp = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let key_path = tmp.path().join("id_ed25519.pub");
        if let Err(err) = fs::write(&key_path, format!("{TEST_KEY}\r\n")) {
            panic!("failed to write key file: {err}");
        }
        let resolved = match resolve_ssh_public_key("id_ed25519.pub", tmp.path()) {
            Ok(key) => key,
            Err(err) => panic!("expected file key to resolve: {err}"),
        };
        assert_eq!(resolved, TEST_KEY);
    }

    #[test]
    fn rejects_empty_multiline_and_control_char_keys() {
        let tmp = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        assert!(resolve_ssh_public_key("", tmp.path()).is_err());
        assert!(resolve_ssh_public_key("   \r\n", tmp.path()).is_err());
        assert!(resolve_ssh_public_key(&format!("{TEST_KEY}\n{TEST_KEY}"), tmp.path()).is_err());
        assert!(resolve_ssh_public_key("ssh-ed25519\tAAAA", tmp.path()).is_err());
        assert!(resolve_ssh_public_key("ssh-ed25519 AAAA\x1b[2J", tmp.path()).is_err());
    }

    #[test]
    fn rejects_oversized_directory_non_utf8_multiline_and_empty_files() {
        let tmp = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };

        // Directory
        let dir_path = tmp.path().join("keys.pub");
        if let Err(err) = fs::create_dir(&dir_path) {
            panic!("failed to create dir: {err}");
        }
        assert!(resolve_ssh_public_key("keys.pub", tmp.path()).is_err());

        // Oversized (> 8 KiB)
        let big_path = tmp.path().join("big.pub");
        let big_data = vec![b'A'; (MAX_SSH_KEY_FILE_BYTES as usize) + 1];
        if let Err(err) = fs::write(&big_path, big_data) {
            panic!("failed to write big file: {err}");
        }
        assert!(resolve_ssh_public_key("big.pub", tmp.path()).is_err());

        // Non-UTF-8
        let non_utf8 = tmp.path().join("bad.pub");
        if let Err(err) = fs::write(&non_utf8, [0xff, 0xfe, 0xfd]) {
            panic!("failed to write non-utf8 file: {err}");
        }
        assert!(resolve_ssh_public_key("bad.pub", tmp.path()).is_err());

        // Empty file
        let empty = tmp.path().join("empty.pub");
        if let Err(err) = fs::write(&empty, "\n") {
            panic!("failed to write empty file: {err}");
        }
        assert!(resolve_ssh_public_key("empty.pub", tmp.path()).is_err());

        // Multi-line file
        let multi = tmp.path().join("multi.pub");
        if let Err(err) = fs::write(&multi, format!("{TEST_KEY}\n{TEST_KEY}\n")) {
            panic!("failed to write multi-line file: {err}");
        }
        assert!(resolve_ssh_public_key("multi.pub", tmp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_pub_file() {
        let tmp = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let target = tmp.path().join("real.pub");
        if let Err(err) = fs::write(&target, TEST_KEY) {
            panic!("failed to write target key: {err}");
        }
        let link = tmp.path().join("link.pub");
        if let Err(err) = std::os::unix::fs::symlink(&target, &link) {
            panic!("failed to create symlink: {err}");
        }
        assert!(resolve_ssh_public_key("link.pub", tmp.path()).is_err());
    }
}
