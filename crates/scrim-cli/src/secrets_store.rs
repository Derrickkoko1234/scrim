//! Repo-versioned secret and scope-key storage under `.scrim/`.
//!
//! Files live inside the Git repository root:
//! - `.scrim/keys/<scope>.toml` ([`ScopeKeysFile`])
//! - `.scrim/secrets/<scope>.enc` ([`EncryptedSecretsFile`])

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, anyhow, bail};
use scrim_crypto::{
    EncryptedSecretsFile, MemberIdentity, ScopeDataKey, ScopeKeysFile, SecretBundle,
    validate_scope_name,
};

use crate::git::git_toplevel;

static STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Resolves the Git repository top-level directory from `cwd`, failing clearly
/// when not inside a Git working tree.
pub fn require_repo_root(cwd: &Path) -> anyhow::Result<PathBuf> {
    match git_toplevel(cwd) {
        Ok(Some(root)) => Ok(root),
        Ok(None) => bail!("not inside a git repository"),
        Err(err) => Err(err),
    }
}

/// Returns `<repo_root>/.scrim/keys/<scope>.toml` after validating `scope`.
pub fn scope_keys_path(repo_root: &Path, scope: &str) -> anyhow::Result<PathBuf> {
    if let Err(err) = validate_scope_name(scope) {
        return Err(anyhow!(err));
    }
    Ok(repo_root
        .join(".scrim")
        .join("keys")
        .join(format!("{scope}.toml")))
}

/// Returns `<repo_root>/.scrim/secrets/<scope>.enc` after validating `scope`.
pub fn scope_secrets_path(repo_root: &Path, scope: &str) -> anyhow::Result<PathBuf> {
    if let Err(err) = validate_scope_name(scope) {
        return Err(anyhow!(err));
    }
    Ok(repo_root
        .join(".scrim")
        .join("secrets")
        .join(format!("{scope}.enc")))
}

/// Reads and validates `.scrim/keys/<scope>.toml`, returning `Ok(None)` if the
/// file does not exist.
pub fn read_scope_keys(repo_root: &Path, scope: &str) -> anyhow::Result<Option<ScopeKeysFile>> {
    let path = match scope_keys_path(repo_root, scope) {
        Ok(p) => p,
        Err(err) => return Err(err),
    };
    let text = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read scope keys file {}", path.display()));
        }
    };
    match ScopeKeysFile::from_toml_str(&text) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(err) => {
            Err(anyhow!(err)).with_context(|| format!("invalid scope keys file {}", path.display()))
        }
    }
}

/// Reads and validates `.scrim/secrets/<scope>.enc`, returning `Ok(None)` if
/// the file does not exist.
pub fn read_scope_secrets(
    repo_root: &Path,
    scope: &str,
) -> anyhow::Result<Option<EncryptedSecretsFile>> {
    let path = match scope_secrets_path(repo_root, scope) {
        Ok(p) => p,
        Err(err) => return Err(err),
    };
    let text = match fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read secrets file {}", path.display()));
        }
    };
    match EncryptedSecretsFile::from_toml_str(&text) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(err) => {
            Err(anyhow!(err)).with_context(|| format!("invalid secrets file {}", path.display()))
        }
    }
}

/// Atomically writes `keys_file` to `<repo_root>/.scrim/keys/<scope>.toml`.
pub fn write_scope_keys(
    repo_root: &Path,
    scope: &str,
    keys_file: &ScopeKeysFile,
) -> anyhow::Result<()> {
    let path = match scope_keys_path(repo_root, scope) {
        Ok(p) => p,
        Err(err) => return Err(err),
    };
    let text = match keys_file.to_toml_string() {
        Ok(s) => s,
        Err(err) => return Err(anyhow!(err)).context("failed to serialize scope keys file"),
    };
    write_repo_file_atomic(&path, text.as_bytes())
}

/// Atomically writes `secrets_file` to `<repo_root>/.scrim/secrets/<scope>.enc`.
pub fn write_scope_secrets(
    repo_root: &Path,
    scope: &str,
    secrets_file: &EncryptedSecretsFile,
) -> anyhow::Result<()> {
    let path = match scope_secrets_path(repo_root, scope) {
        Ok(p) => p,
        Err(err) => return Err(err),
    };
    let text = match secrets_file.to_toml_string() {
        Ok(s) => s,
        Err(err) => return Err(anyhow!(err)).context("failed to serialize encrypted secrets file"),
    };
    write_repo_file_atomic(&path, text.as_bytes())
}

/// Lists all local scope names present in `<repo_root>/.scrim/keys/*.toml`,
/// sorted ascending and ignoring non-`.toml` entries.
pub fn list_local_scopes(repo_root: &Path) -> anyhow::Result<Vec<String>> {
    let keys_dir = repo_root.join(".scrim").join("keys");
    let entries = match fs::read_dir(&keys_dir) {
        Ok(iter) => iter,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| {
                format!("failed to read scope keys directory {}", keys_dir.display())
            });
        }
    };

    let mut scopes = Vec::new();
    for entry_res in entries {
        let entry = match entry_res {
            Ok(e) => e,
            Err(err) => {
                return Err(anyhow!(err))
                    .with_context(|| format!("failed to read entry in {}", keys_dir.display()));
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        if validate_scope_name(stem).is_ok() {
            scopes.push(stem.to_owned());
        }
    }
    scopes.sort();
    Ok(scopes)
}

/// Decrypts `scope` offline using `identity`.
///
/// Fails if `.scrim/keys/<scope>.toml` does not exist or `identity` is not an
/// authorized recipient. If `.scrim/secrets/<scope>.enc` is absent, returns an
/// empty [`SecretBundle`].
pub fn load_and_decrypt_scope(
    repo_root: &Path,
    scope: &str,
    identity: &MemberIdentity,
) -> anyhow::Result<(ScopeKeysFile, ScopeDataKey, SecretBundle)> {
    let keys_file = match read_scope_keys(repo_root, scope) {
        Ok(Some(file)) => file,
        Ok(None) => bail!("secret scope '{scope}' does not exist locally"),
        Err(err) => return Err(err),
    };

    let data_key = match keys_file.unwrap_key(scope, identity) {
        Ok(key) => key,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to unwrap key for scope '{scope}'"));
        }
    };

    let bundle = match read_scope_secrets(repo_root, scope) {
        Ok(Some(secrets_file)) => {
            match secrets_file.decrypt(scope, keys_file.generation, &data_key) {
                Ok(decrypted) => decrypted,
                Err(err) => {
                    return Err(anyhow!(err))
                        .with_context(|| format!("failed to decrypt secrets for scope '{scope}'"));
                }
            }
        }
        Ok(None) => SecretBundle::new(),
        Err(err) => return Err(err),
    };

    Ok((keys_file, data_key, bundle))
}

/// Writes `contents` to a temporary sibling file, syncs it, and renames it over
/// `dest_path`, creating parent directories as needed.
pub(crate) fn write_repo_file_atomic(dest_path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = match dest_path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if let Err(err) = fs::create_dir_all(parent) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to create directory {}", parent.display()));
    }

    let pid = std::process::id();
    let mut last_err = None;

    for _ in 0..16 {
        let seq = STORE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!(".scrim.tmp.{pid}.{seq}");
        let tmp_path = parent.join(tmp_name);

        let file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                last_err = Some(err);
                continue;
            }
            Err(err) => {
                return Err(anyhow!(err)).with_context(|| {
                    format!("failed to create temporary file {}", tmp_path.display())
                });
            }
        };

        let result = write_sync_rename(file, &tmp_path, dest_path, contents);
        if result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        return result;
    }

    match last_err {
        Some(err) => Err(anyhow!(err)).context("failed to allocate temporary file"),
        None => Err(anyhow!("failed to allocate temporary file")),
    }
}

fn write_sync_rename(
    mut file: fs::File,
    tmp_path: &Path,
    dest_path: &Path,
    contents: &[u8],
) -> anyhow::Result<()> {
    if let Err(err) = file.write_all(contents) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to write {}", tmp_path.display()));
    }
    if let Err(err) = file.flush() {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to flush {}", tmp_path.display()));
    }
    if let Err(err) = file.sync_all() {
        return Err(anyhow!(err)).with_context(|| format!("failed to sync {}", tmp_path.display()));
    }
    drop(file);

    if let Err(err) = fs::rename(tmp_path, dest_path) {
        return Err(anyhow!(err))
            .with_context(|| format!("failed to replace {}", dest_path.display()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use scrim_crypto::{ExposeSecret, SecretString};

    use super::*;

    #[test]
    fn scope_files_round_trip_list_and_decrypt() {
        let dir = match tempfile::tempdir() {
            Ok(d) => d,
            Err(err) => panic!("tempdir failed: {err}"),
        };
        let repo_root = dir.path();

        let alice = MemberIdentity::generate();
        let data_key = match ScopeDataKey::generate() {
            Ok(k) => k,
            Err(err) => panic!("ScopeDataKey::generate failed: {err}"),
        };
        let mut recipients = BTreeMap::new();
        recipients.insert("alice".to_owned(), alice.public_key());

        let keys_file = match ScopeKeysFile::wrap_for_recipients("prod", 1, &data_key, &recipients)
        {
            Ok(f) => f,
            Err(err) => panic!("wrap_for_recipients failed: {err}"),
        };
        if let Err(err) = write_scope_keys(repo_root, "prod", &keys_file) {
            panic!("write_scope_keys failed: {err}");
        }

        // Before secrets file exists, decrypt yields an empty bundle.
        let (_, _, empty_bundle) = match load_and_decrypt_scope(repo_root, "prod", &alice) {
            Ok(res) => res,
            Err(err) => panic!("load_and_decrypt_scope (empty) failed: {err}"),
        };
        assert!(empty_bundle.is_empty());

        let mut bundle = SecretBundle::new();
        if let Err(err) = bundle.set("DB_URL", SecretString::from("postgres://localhost/db")) {
            panic!("bundle.set failed: {err}");
        }
        let secrets_file = match EncryptedSecretsFile::encrypt("prod", 1, &data_key, &bundle) {
            Ok(f) => f,
            Err(err) => panic!("encrypt failed: {err}"),
        };
        if let Err(err) = write_scope_secrets(repo_root, "prod", &secrets_file) {
            panic!("write_scope_secrets failed: {err}");
        }

        // Write another keys file and a stray non-toml file to verify list_local_scopes.
        let dev_keys = match ScopeKeysFile::wrap_for_recipients("dev", 1, &data_key, &recipients) {
            Ok(f) => f,
            Err(err) => panic!("wrap_for_recipients dev failed: {err}"),
        };
        if let Err(err) = write_scope_keys(repo_root, "dev", &dev_keys) {
            panic!("write_scope_keys dev failed: {err}");
        }
        if let Err(err) = fs::write(
            repo_root.join(".scrim").join("keys").join("README.md"),
            "hi",
        ) {
            panic!("write stray file failed: {err}");
        }

        let scopes = match list_local_scopes(repo_root) {
            Ok(s) => s,
            Err(err) => panic!("list_local_scopes failed: {err}"),
        };
        assert_eq!(scopes, vec!["dev".to_owned(), "prod".to_owned()]);

        let (_, _, decrypted) = match load_and_decrypt_scope(repo_root, "prod", &alice) {
            Ok(res) => res,
            Err(err) => panic!("load_and_decrypt_scope failed: {err}"),
        };
        let db_url = match decrypted.get("DB_URL") {
            Some(v) => v,
            None => panic!("expected DB_URL"),
        };
        assert_eq!(db_url.expose_secret(), "postgres://localhost/db");

        assert!(scope_keys_path(repo_root, "../escape").is_err());
        assert!(scope_secrets_path(repo_root, "../escape").is_err());
    }
}
