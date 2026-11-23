//! Optional OS keychain storage of the member's private key.
//!
//! By default the age identity lives in `identity.age` next to `config.toml`.
//! `scrim keygen --keychain` and `scrim keychain enable` put it in the macOS
//! Keychain or Windows Credential Manager instead and record the keychain
//! account in `config.toml`; `scrim keychain disable` moves it back. Every move
//! writes the destination, reads it back and compares before removing the
//! source, so a failed or partial write never loses the key. Other platforms
//! are refused: Linux kernel keyrings are not persistent and Secret Service
//! needs D-Bus, so neither is a safe home for the only copy of a key.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use scrim_crypto::MemberIdentity;
use secrecy::{ExposeSecret, SecretString};

use crate::cli::KeychainCommand;
use crate::config::{
    load_config, read_member_identity_file, resolve_identity_path, save_keychain_account,
    save_member_identity,
};
use crate::{CliEnv, build_authenticated_client, write_line};

/// Keychain service name under which Scrim stores member identities.
pub const KEYCHAIN_SERVICE: &str = "scrim-for-git";

/// A store of secrets keyed by account name within [`KEYCHAIN_SERVICE`].
///
/// The CLI uses [`OsKeychain`]; tests substitute an in-memory store.
pub trait SecretStore {
    /// Returns the secret stored for `account`, or `None` when there is none.
    fn read(&self, account: &str) -> anyhow::Result<Option<SecretString>>;
    /// Stores `secret` for `account`, replacing any existing secret.
    fn write(&self, account: &str, secret: &SecretString) -> anyhow::Result<()>;
    /// Removes the secret stored for `account`.
    fn delete(&self, account: &str) -> anyhow::Result<()>;
}

/// The platform keychain: the macOS Keychain or the Windows Credential
/// Manager. On every other platform each operation fails.
pub struct OsKeychain;

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl OsKeychain {
    fn entry(account: &str) -> anyhow::Result<keyring::Entry> {
        match keyring::Entry::new(KEYCHAIN_SERVICE, account) {
            Ok(entry) => Ok(entry),
            Err(err) => Err(anyhow!(err)).context("failed to open OS keychain entry"),
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl SecretStore for OsKeychain {
    fn read(&self, account: &str) -> anyhow::Result<Option<SecretString>> {
        let entry = match Self::entry(account) {
            Ok(entry) => entry,
            Err(err) => return Err(err),
        };
        match entry.get_password() {
            // Moved straight into a zeroize-on-drop SecretString.
            Ok(password) => Ok(Some(SecretString::from(password))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(anyhow!(err)).context("failed to read from the OS keychain"),
        }
    }

    fn write(&self, account: &str, secret: &SecretString) -> anyhow::Result<()> {
        let entry = match Self::entry(account) {
            Ok(entry) => entry,
            Err(err) => return Err(err),
        };
        match entry.set_password(secret.expose_secret()) {
            Ok(()) => Ok(()),
            Err(err) => Err(anyhow!(err)).context("failed to write to the OS keychain"),
        }
    }

    fn delete(&self, account: &str) -> anyhow::Result<()> {
        let entry = match Self::entry(account) {
            Ok(entry) => entry,
            Err(err) => return Err(err),
        };
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(anyhow!(err)).context("failed to delete from the OS keychain"),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const UNSUPPORTED: &str = "OS keychain storage is not supported on this platform (only macOS and Windows); keep the key in identity.age or set SCRIM_KEY";

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
impl SecretStore for OsKeychain {
    fn read(&self, _account: &str) -> anyhow::Result<Option<SecretString>> {
        Err(anyhow!(UNSUPPORTED))
    }

    fn write(&self, _account: &str, _secret: &SecretString) -> anyhow::Result<()> {
        Err(anyhow!(UNSUPPORTED))
    }

    fn delete(&self, _account: &str) -> anyhow::Result<()> {
        Err(anyhow!(UNSUPPORTED))
    }
}

/// The keychain account for `member` on the server at `server_url`, such as
/// `alice@https://scrim.example.com`. It is recorded in `config.toml` when the
/// key is stored, so later renames or server moves never orphan the entry.
pub fn keychain_account(member: &str, server_url: &str) -> String {
    format!("{member}@{server_url}")
}

/// Describes an entry for messages, without any secret material.
fn describe_entry(account: &str) -> String {
    format!("OS keychain entry (service \"{KEYCHAIN_SERVICE}\", account \"{account}\")")
}

/// Loads the identity stored in `store` for `account`.
///
/// # Errors
///
/// Fails when the keychain cannot be read, has no entry for `account`, or
/// holds something that is not an age identity. Never falls back to a file.
pub(crate) fn load_identity_from_keychain(
    store: &dyn SecretStore,
    account: &str,
) -> anyhow::Result<MemberIdentity> {
    let entry = describe_entry(account);
    let secret = match store.read(account) {
        Ok(Some(secret)) => secret,
        Ok(None) => bail!(
            "config.toml stores the identity in the {entry}, but that entry does not exist; restore it, set SCRIM_KEY, or replace the key with 'scrim keygen --keychain --force'"
        ),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "failed to read the identity from the {entry}; unlock the keychain and retry, or set SCRIM_KEY (identity.age is ignored while keychain storage is enabled)"
                )
            });
        }
    };
    match MemberIdentity::parse(secret.expose_secret()) {
        Ok(identity) => Ok(identity),
        Err(err) => {
            Err(anyhow!(err)).with_context(|| format!("invalid age identity in the {entry}"))
        }
    }
}

/// Writes `secret` for `account`, then reads it back and fails unless the
/// stored value is identical.
fn write_verified(
    store: &dyn SecretStore,
    account: &str,
    secret: &SecretString,
) -> anyhow::Result<()> {
    if let Err(err) = store.write(account, secret) {
        return Err(err);
    }
    match store.read(account) {
        Ok(Some(stored)) if stored.expose_secret() == secret.expose_secret() => Ok(()),
        Ok(_) => bail!(
            "the {} did not return the identity just written to it",
            describe_entry(account)
        ),
        Err(err) => Err(err).context("failed to read back the identity just written"),
    }
}

/// Stores a newly generated `identity` in the keychain under `account`,
/// verifying the write.
pub(crate) fn store_new_identity(
    store: &dyn SecretStore,
    account: &str,
    identity: &MemberIdentity,
) -> anyhow::Result<()> {
    write_verified(store, account, &identity.to_secret_string())
}

fn identities_match(left: &MemberIdentity, right: &MemberIdentity) -> bool {
    left.to_secret_string().expose_secret() == right.to_secret_string().expose_secret()
}

/// Moves the identity in `identity_path` into the keychain under `account`:
/// write and verify the entry, record `account` in `config_path`, then delete
/// the file. Re-running after an interruption is safe.
///
/// # Errors
///
/// Fails, leaving the file in place, when it cannot be read, the keychain
/// already holds a different key for `account`, the write does not verify, or
/// the config cannot be updated.
pub(crate) fn move_file_to_keychain(
    store: &dyn SecretStore,
    account: &str,
    identity_path: &Path,
    config_path: &Path,
) -> anyhow::Result<()> {
    let identity = match read_member_identity_file(identity_path) {
        Ok(identity) => identity,
        Err(err) => return Err(err),
    };
    let entry = describe_entry(account);
    let existing = match store.read(account) {
        Ok(existing) => existing,
        Err(err) => return Err(err),
    };
    match existing {
        None => {
            if let Err(err) = store_new_identity(store, account, &identity) {
                return Err(err)
                    .with_context(|| format!("{} was left in place", identity_path.display()));
            }
        }
        Some(stored) => {
            // An identical key means an earlier run stopped after writing.
            let matches = match MemberIdentity::parse(stored.expose_secret()) {
                Ok(stored_identity) => identities_match(&stored_identity, &identity),
                Err(_) => false,
            };
            if !matches {
                bail!(
                    "the {entry} already holds a different value; refusing to overwrite it ({} was left in place)",
                    identity_path.display()
                );
            }
        }
    }

    if let Err(err) = save_keychain_account(config_path, Some(account)) {
        return Err(err).with_context(|| {
            format!(
                "the identity was copied to the {entry}, but recording that in {} failed; {} was left in place and is still used",
                config_path.display(),
                identity_path.display()
            )
        });
    }
    match fs::remove_file(identity_path) {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(err)).with_context(|| {
            format!(
                "the identity is now in the {entry}, but deleting {} failed; delete it yourself",
                identity_path.display()
            )
        }),
    }
}

/// Moves the identity stored under `account` back into `identity_path`:
/// write the file atomically with `0600` permissions and verify it, clear the
/// keychain account in `config_path`, then delete the keychain entry.
/// Re-running after an interruption is safe.
///
/// # Errors
///
/// Fails, leaving the keychain entry in place, when it cannot be read, a
/// different identity file already exists, the written file does not verify,
/// or the config cannot be updated.
pub(crate) fn move_keychain_to_file(
    store: &dyn SecretStore,
    account: &str,
    identity_path: &Path,
    config_path: &Path,
) -> anyhow::Result<()> {
    let identity = match load_identity_from_keychain(store, account) {
        Ok(identity) => identity,
        Err(err) => return Err(err),
    };
    let entry = describe_entry(account);

    match fs::symlink_metadata(identity_path) {
        Ok(_) => {
            // An identical file means an earlier run stopped after writing.
            let matches = match read_member_identity_file(identity_path) {
                Ok(existing) => identities_match(&existing, &identity),
                Err(_) => false,
            };
            if !matches {
                bail!(
                    "{} already exists and does not hold the key in the {entry}; refusing to overwrite it",
                    identity_path.display()
                );
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if let Err(err) = save_member_identity(identity_path, &identity) {
                return Err(err);
            }
            let written = match read_member_identity_file(identity_path) {
                Ok(written) => written,
                Err(err) => {
                    return Err(err).context("failed to read back the identity file just written");
                }
            };
            if !identities_match(&written, &identity) {
                bail!(
                    "{} does not hold the identity just written to it; the {entry} was left in place",
                    identity_path.display()
                );
            }
        }
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to inspect {}", identity_path.display()));
        }
    }

    if let Err(err) = save_keychain_account(config_path, None) {
        return Err(err).with_context(|| {
            format!(
                "the identity was copied to {}, but recording that in {} failed; the {entry} was left in place and is still used",
                identity_path.display(),
                config_path.display()
            )
        });
    }
    match store.delete(account) {
        Ok(()) => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "the identity is now in {}, but deleting the {entry} failed; delete it yourself",
                identity_path.display()
            )
        }),
    }
}

/// Fails when `--key-file` or `SCRIM_KEY_FILE` names an identity file, since
/// keychain storage replaces the default `identity.age` and those would
/// otherwise take precedence over it.
pub(crate) fn reject_explicit_key_file(
    cli_key_file: Option<&Path>,
    env: &CliEnv<'_>,
) -> anyhow::Result<()> {
    let has_flag = cli_key_file.is_some_and(|path| !path.as_os_str().is_empty());
    if has_flag || env.non_empty_env("SCRIM_KEY_FILE").is_some() {
        bail!(
            "keychain storage replaces the default identity.age; drop --key-file and unset SCRIM_KEY_FILE"
        );
    }
    Ok(())
}

/// Handles `scrim keychain enable` and `scrim keychain disable`.
pub(crate) fn handle_keychain(
    command: KeychainCommand,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path_result: anyhow::Result<PathBuf>,
    env: &mut CliEnv<'_>,
    store: &dyn SecretStore,
) -> anyhow::Result<()> {
    if let Err(err) = reject_explicit_key_file(cli_key_file, env) {
        return Err(err);
    }
    let config_path = match config_path_result {
        Ok(path) => path,
        Err(err) => return Err(err),
    };
    let recorded_account = match load_config(&config_path) {
        Ok(Some(cfg)) => cfg.keychain_account,
        Ok(None) => None,
        Err(err) => return Err(err),
    };
    let identity_path = resolve_identity_path(None, &|key| env.env_var(key), &config_path);

    match command {
        KeychainCommand::Enable => {
            if let Some(account) = recorded_account {
                bail!(
                    "the identity is already stored in the {}",
                    describe_entry(&account)
                );
            }
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                Some(&config_path),
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            let member = match client.whoami() {
                Ok(info) => info.name,
                Err(err) => return Err(err),
            };
            let account = keychain_account(&member, client.base_url());
            if let Err(err) = move_file_to_keychain(store, &account, &identity_path, &config_path) {
                return Err(err);
            }
            write_line(
                env.stdout,
                &format!(
                    "Moved identity from {} to the {}",
                    identity_path.display(),
                    describe_entry(&account)
                ),
            )
        }
        KeychainCommand::Disable => {
            let Some(account) = recorded_account else {
                bail!(
                    "the identity is not stored in the OS keychain ({} is used)",
                    identity_path.display()
                );
            };
            if let Err(err) = move_keychain_to_file(store, &account, &identity_path, &config_path) {
                return Err(err);
            }
            write_line(
                env.stdout,
                &format!(
                    "Moved identity from the {} to {}",
                    describe_entry(&account),
                    identity_path.display()
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use super::*;
    use crate::config::{load_member_identity_with_store, save_config};

    /// In-memory [`SecretStore`] with fault injection; never touches the OS.
    #[derive(Default)]
    struct MemoryStore {
        entries: RefCell<BTreeMap<String, String>>,
        corrupt_writes: Cell<bool>,
        fail_reads: Cell<bool>,
        fail_deletes: Cell<bool>,
    }

    impl SecretStore for MemoryStore {
        fn read(&self, account: &str) -> anyhow::Result<Option<SecretString>> {
            if self.fail_reads.get() {
                bail!("keychain is locked");
            }
            Ok(self
                .entries
                .borrow()
                .get(account)
                .map(|value| SecretString::from(value.as_str())))
        }

        fn write(&self, account: &str, secret: &SecretString) -> anyhow::Result<()> {
            let value = if self.corrupt_writes.get() {
                "garbage".to_owned()
            } else {
                secret.expose_secret().to_owned()
            };
            self.entries.borrow_mut().insert(account.to_owned(), value);
            Ok(())
        }

        fn delete(&self, account: &str) -> anyhow::Result<()> {
            if self.fail_deletes.get() {
                bail!("delete refused");
            }
            self.entries.borrow_mut().remove(account);
            Ok(())
        }
    }

    const ACCOUNT: &str = "alice@https://scrim.example.com";

    struct Fixture {
        _dir: tempfile::TempDir,
        config_path: PathBuf,
        identity_path: PathBuf,
        identity: MemberIdentity,
    }

    fn fixture() -> Fixture {
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("failed to create tempdir: {err}"),
        };
        let config_path = dir.path().join("config.toml");
        let identity_path = dir.path().join("identity.age");
        let token = SecretString::from("scrim_test_token");
        if let Err(err) = save_config(&config_path, "https://scrim.example.com", &token) {
            panic!("save_config failed: {err:#}");
        }
        let identity = MemberIdentity::generate();
        if let Err(err) = save_member_identity(&identity_path, &identity) {
            panic!("save_member_identity failed: {err:#}");
        }
        Fixture {
            _dir: dir,
            config_path,
            identity_path,
            identity,
        }
    }

    fn no_env(_key: &str) -> Option<String> {
        None
    }

    fn recorded_account(config_path: &Path) -> Option<String> {
        match load_config(config_path) {
            Ok(Some(cfg)) => cfg.keychain_account,
            Ok(None) => None,
            Err(err) => panic!("load_config failed: {err:#}"),
        }
    }

    fn load(fx: &Fixture, store: &MemoryStore) -> anyhow::Result<MemberIdentity> {
        load_member_identity_with_store(None, &no_env, Some(&fx.config_path), store)
    }

    fn error_text<T>(result: anyhow::Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(err) => format!("{err:#}"),
        }
    }

    #[test]
    fn enable_then_disable_round_trips_the_identity() {
        let fx = fixture();
        let store = MemoryStore::default();

        if let Err(err) = move_file_to_keychain(&store, ACCOUNT, &fx.identity_path, &fx.config_path)
        {
            panic!("enable failed: {err:#}");
        }
        assert!(!fx.identity_path.exists(), "identity.age must be removed");
        assert_eq!(recorded_account(&fx.config_path).as_deref(), Some(ACCOUNT));
        let loaded = match load(&fx, &store) {
            Ok(identity) => identity,
            Err(err) => panic!("load from keychain failed: {err:#}"),
        };
        assert!(identities_match(&loaded, &fx.identity));

        // `scrim login` rewrites config.toml and must keep keychain mode.
        let token = SecretString::from("scrim_new_token");
        if let Err(err) = save_config(&fx.config_path, "https://scrim.example.com", &token) {
            panic!("save_config failed: {err:#}");
        }
        assert_eq!(recorded_account(&fx.config_path).as_deref(), Some(ACCOUNT));

        if let Err(err) = move_keychain_to_file(&store, ACCOUNT, &fx.identity_path, &fx.config_path)
        {
            panic!("disable failed: {err:#}");
        }
        assert!(store.entries.borrow().is_empty(), "entry must be deleted");
        assert_eq!(recorded_account(&fx.config_path), None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = match fs::metadata(&fx.identity_path) {
                Ok(meta) => meta.permissions().mode() & 0o777,
                Err(err) => panic!("metadata failed: {err}"),
            };
            assert_eq!(mode, 0o600);
        }
        let loaded = match load(&fx, &store) {
            Ok(identity) => identity,
            Err(err) => panic!("load from file failed: {err:#}"),
        };
        assert!(identities_match(&loaded, &fx.identity));
    }

    #[test]
    fn enable_keeps_the_file_when_the_keychain_write_does_not_verify() {
        let fx = fixture();
        let store = MemoryStore::default();
        store.corrupt_writes.set(true);

        let message = error_text(move_file_to_keychain(
            &store,
            ACCOUNT,
            &fx.identity_path,
            &fx.config_path,
        ));
        assert!(message.contains("did not return the identity"), "{message}");
        assert!(fx.identity_path.exists());
        assert_eq!(recorded_account(&fx.config_path), None);
    }

    #[test]
    fn enable_refuses_to_overwrite_a_different_keychain_entry() {
        let fx = fixture();
        let store = MemoryStore::default();
        let other = MemberIdentity::generate();
        store.entries.borrow_mut().insert(
            ACCOUNT.to_owned(),
            other.to_secret_string().expose_secret().to_owned(),
        );

        let message = error_text(move_file_to_keychain(
            &store,
            ACCOUNT,
            &fx.identity_path,
            &fx.config_path,
        ));
        assert!(message.contains("refusing to overwrite"), "{message}");
        assert!(fx.identity_path.exists());
        assert_eq!(
            store.entries.borrow().get(ACCOUNT).map(String::as_str),
            Some(other.to_secret_string().expose_secret())
        );
    }

    #[test]
    fn enable_resumes_after_an_interrupted_run() {
        let fx = fixture();
        let store = MemoryStore::default();
        store.entries.borrow_mut().insert(
            ACCOUNT.to_owned(),
            fx.identity.to_secret_string().expose_secret().to_owned(),
        );
        if let Err(err) = move_file_to_keychain(&store, ACCOUNT, &fx.identity_path, &fx.config_path)
        {
            panic!("resumed enable failed: {err:#}");
        }
        assert!(!fx.identity_path.exists());
    }

    #[test]
    fn disable_refuses_to_overwrite_a_different_identity_file() {
        let fx = fixture();
        let store = MemoryStore::default();
        let keychain_identity = MemberIdentity::generate();
        if let Err(err) = store_new_identity(&store, ACCOUNT, &keychain_identity) {
            panic!("store failed: {err:#}");
        }
        if let Err(err) = save_keychain_account(&fx.config_path, Some(ACCOUNT)) {
            panic!("save_keychain_account failed: {err:#}");
        }

        let message = error_text(move_keychain_to_file(
            &store,
            ACCOUNT,
            &fx.identity_path,
            &fx.config_path,
        ));
        assert!(message.contains("refusing to overwrite"), "{message}");
        assert!(store.entries.borrow().contains_key(ACCOUNT));
        assert_eq!(recorded_account(&fx.config_path).as_deref(), Some(ACCOUNT));
        match read_member_identity_file(&fx.identity_path) {
            Ok(file_identity) => assert!(identities_match(&file_identity, &fx.identity)),
            Err(err) => panic!("identity file damaged: {err:#}"),
        }
    }

    #[test]
    fn disable_reports_a_failed_delete_after_the_file_is_safe() {
        let fx = fixture();
        let store = MemoryStore::default();
        if let Err(err) = move_file_to_keychain(&store, ACCOUNT, &fx.identity_path, &fx.config_path)
        {
            panic!("enable failed: {err:#}");
        }
        store.fail_deletes.set(true);

        let message = error_text(move_keychain_to_file(
            &store,
            ACCOUNT,
            &fx.identity_path,
            &fx.config_path,
        ));
        assert!(message.contains("delete it yourself"), "{message}");
        assert_eq!(recorded_account(&fx.config_path), None);
        match read_member_identity_file(&fx.identity_path) {
            Ok(file_identity) => assert!(identities_match(&file_identity, &fx.identity)),
            Err(err) => panic!("identity file missing: {err:#}"),
        }
    }

    #[test]
    fn keychain_mode_never_falls_back_to_a_plaintext_file() {
        let fx = fixture();
        let store = MemoryStore::default();
        // identity.age still exists, but config.toml says keychain.
        if let Err(err) = save_keychain_account(&fx.config_path, Some(ACCOUNT)) {
            panic!("save_keychain_account failed: {err:#}");
        }

        let missing = error_text(load(&fx, &store));
        assert!(missing.contains("does not exist"), "{missing}");

        store.fail_reads.set(true);
        let locked = error_text(load(&fx, &store));
        assert!(locked.contains("unlock the keychain"), "{locked}");
        assert!(locked.contains("SCRIM_KEY"), "{locked}");

        // SCRIM_KEY still takes precedence over keychain mode.
        let env_identity = MemberIdentity::generate();
        let env_secret = env_identity.to_secret_string();
        let env_lookup = |key: &str| {
            if key == "SCRIM_KEY" {
                Some(env_secret.expose_secret().to_owned())
            } else {
                None
            }
        };
        match load_member_identity_with_store(None, &env_lookup, Some(&fx.config_path), &store) {
            Ok(identity) => assert!(identities_match(&identity, &env_identity)),
            Err(err) => panic!("SCRIM_KEY load failed: {err:#}"),
        }
    }

    #[test]
    fn keychain_account_combines_member_and_server() {
        assert_eq!(
            keychain_account("alice", "https://scrim.example.com"),
            "alice@https://scrim.example.com"
        );
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn os_keychain_is_refused_on_unsupported_platforms() {
        let message = error_text(OsKeychain.read(ACCOUNT));
        assert!(
            message.contains("not supported on this platform"),
            "{message}"
        );
    }
}
