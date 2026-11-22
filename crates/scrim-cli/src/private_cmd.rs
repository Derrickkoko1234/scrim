//! `scrim private ...` commands, the hidden `scrim filter-process` entry
//! point, and group-key rotation after `scrim access revoke`.

use std::collections::BTreeMap;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::Path;

use anyhow::{Context, anyhow, bail};
use scrim_crypto::{
    GroupDataKey, GroupKeysFile, MemberIdentity, MemberPublicKey, extract_placeholder,
    is_encrypted_file, is_placeholder, rotate_group_key,
};
use scrim_policy::{PathPolicy, PathRule, validate_group_name, validate_path_glob};
use secrecy::SecretString;
use zeroize::{Zeroize, Zeroizing};

use crate::cli::PrivateCommand;
use crate::client::ScrimClient;
use crate::clone_cmd::{WITHHOLD_PARTIAL_CLONE_FILTER, validate_withheld_response};
use crate::config::load_member_identity;
use crate::filter::{FilterContext, serve};
use crate::git::{
    git_add_renormalize, git_cat_file_blob, git_checkout_index_force, git_configure_scrim_filter,
    git_extra_header_env, git_is_scrim_filter_configured, git_ls_files,
    git_promisor_remotes_for_server, git_refetch_partial_remote,
    git_sparse_checkout_disable_if_active, git_sparse_checkout_set, git_toplevel,
};
use crate::private_store::{
    list_local_groups, read_group_keys, read_path_policy, sync_gitattributes, write_group_keys,
    write_path_policy,
};
use crate::secrets_store::require_repo_root;
use crate::{
    CliEnv, build_authenticated_client, format_list_or_none, recipients_from_server,
    resolve_repo_arg, write_line,
};

/// Environment variables forwarded to `git` processes that may start
/// `scrim filter-process`, so the filter resolves the same config and
/// identity as the command that spawned it (including embedded `run_from`
/// callers whose variables live only in [`CliEnv::env_vars`]).
const FORWARDED_ENV: [&str; 7] = [
    "SCRIM_CONFIG",
    "SCRIM_CONFIG_DIR",
    "SCRIM_KEY",
    "SCRIM_KEY_FILE",
    "XDG_CONFIG_HOME",
    "HOME",
    "PATH",
];

/// Environment overrides for filter-invoking `git` commands. Values (which
/// may include `SCRIM_KEY`) are zeroized on drop.
pub(crate) struct FilterEnv(Vec<(String, String)>);

impl FilterEnv {
    pub(crate) fn new(
        env: &CliEnv<'_>,
        cli_key_file: Option<&Path>,
        config_path: Option<&Path>,
    ) -> Self {
        let key_file_flag = cli_key_file
            .filter(|path| !path.as_os_str().is_empty())
            .and_then(Path::to_str);
        let config_flag = config_path.and_then(Path::to_str);
        let mut vars = Vec::new();
        for key in FORWARDED_ENV {
            let value = match (key, key_file_flag, config_flag) {
                // `--key-file` outranks SCRIM_KEY, so blank SCRIM_KEY and pass
                // the flag on as SCRIM_KEY_FILE.
                ("SCRIM_KEY", Some(_), _) => Some(String::new()),
                ("SCRIM_KEY_FILE", Some(path), _) => Some(path.to_owned()),
                ("SCRIM_CONFIG", _, Some(path)) => Some(path.to_owned()),
                // Blank (which Scrim treats as unset) rather than omit absent
                // identity variables, so an embedding process's own
                // environment never leaks into the filter.
                ("SCRIM_KEY" | "SCRIM_KEY_FILE", _, _) => match env.env_vars.get(key) {
                    Some(value) => Some(value.clone()),
                    None => Some(String::new()),
                },
                _ => env.env_vars.get(key).cloned(),
            };
            if let Some(value) = value {
                vars.push((key.to_owned(), value));
            }
        }
        Self(vars)
    }

    pub(crate) fn pairs(&self) -> Vec<(&str, &str)> {
        self.0
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }
}

impl Drop for FilterEnv {
    fn drop(&mut self) {
        for (_, value) in &mut self.0 {
            value.zeroize();
        }
    }
}

/// What the working tree currently holds for a tracked private file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileState {
    /// Absent or not a regular file.
    Missing,
    /// Decrypted (or never encrypted) contents.
    Plaintext,
    /// An intact placeholder.
    Placeholder,
    /// A placeholder that no longer extracts cleanly.
    EditedPlaceholder,
    /// A raw `SCRIMFILE\0` blob (checked out without the filter).
    Encrypted,
}

impl FileState {
    fn describe(self) -> &'static str {
        match self {
            Self::Missing => "missing from the working tree",
            Self::Plaintext => "decrypted",
            Self::Placeholder => "placeholder (no access)",
            Self::EditedPlaceholder => {
                "edited placeholder (restore it with 'git checkout -- <path>')"
            }
            Self::Encrypted => "encrypted blob (run 'scrim private setup')",
        }
    }
}

fn file_state(repo_root: &Path, path: &str) -> anyhow::Result<FileState> {
    let full_path = repo_root.join(path);
    match fs::symlink_metadata(&full_path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Ok(FileState::Missing),
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(FileState::Missing),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to inspect {}", full_path.display()));
        }
    }
    let contents = match fs::read(&full_path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read {}", full_path.display()));
        }
    };
    if is_encrypted_file(&contents) {
        Ok(FileState::Encrypted)
    } else if is_placeholder(&contents) {
        match extract_placeholder(&contents) {
            Ok(_) => Ok(FileState::Placeholder),
            Err(_) => Ok(FileState::EditedPlaceholder),
        }
    } else {
        Ok(FileState::Plaintext)
    }
}

/// Reports whether the working-tree copy of `path` (a raw blob or an intact
/// placeholder) holds exactly the blob staged in the index.
fn holds_staged_blob(repo_root: &Path, path: &str) -> anyhow::Result<bool> {
    let full_path = repo_root.join(path);
    let contents = match fs::read(&full_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read {}", full_path.display()));
        }
    };
    let stored = if is_encrypted_file(&contents) {
        contents
    } else {
        match extract_placeholder(&contents) {
            Ok(extracted) => extracted.blob,
            Err(_) => return Ok(false),
        }
    };
    match git_cat_file_blob(repo_root, &format!(":{path}")) {
        Ok(Some(staged)) => Ok(staged == stored),
        Ok(None) => Ok(false),
        Err(err) => Err(err),
    }
}

/// Groups every tracked file protected by `policy` by its group.
///
/// # Errors
///
/// Fails when any tracked file matches rules of more than one group.
fn private_files_by_group(
    repo_root: &Path,
    policy: &PathPolicy,
) -> anyhow::Result<BTreeMap<String, Vec<String>>> {
    let mut by_group: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if policy.is_empty() {
        return Ok(by_group);
    }
    let tracked = match git_ls_files(repo_root) {
        Ok(files) => files,
        Err(err) => return Err(err),
    };
    for path in tracked {
        match policy.group_for_path(&path) {
            Ok(Some(group)) => by_group.entry(group.to_owned()).or_default().push(path),
            Ok(None) => {}
            Err(err) => return Err(anyhow!(err)),
        }
    }
    Ok(by_group)
}

/// Paths re-cleaned by [`renormalize_plaintext_files`], and the skipped ones
/// with their working-tree state.
type Renormalized = (Vec<String>, Vec<(String, FileState)>);

/// Re-cleans the files in `paths` whose working-tree copy is plaintext and
/// stages the result.
fn renormalize_plaintext_files(
    repo_root: &Path,
    paths: &[String],
    filter_env: &FilterEnv,
) -> anyhow::Result<Renormalized> {
    let mut plaintext = Vec::new();
    let mut skipped = Vec::new();
    for path in paths {
        match file_state(repo_root, path) {
            Ok(FileState::Plaintext) => plaintext.push(path.clone()),
            Ok(state) => skipped.push((path.clone(), state)),
            Err(err) => return Err(err),
        }
    }
    if !plaintext.is_empty()
        && let Err(err) = git_add_renormalize(repo_root, &plaintext, &filter_env.pairs())
    {
        return Err(err);
    }
    Ok((plaintext, skipped))
}

fn warn_skipped(stderr: &mut dyn Write, skipped: &[(String, FileState)]) {
    for (path, state) in skipped {
        let _ = writeln!(
            stderr,
            "warning: '{path}' was not re-encrypted: its working-tree copy is {}",
            state.describe()
        );
    }
}

/// Configures the local `filter.scrim.*` settings unless an effective
/// configuration (local or global) already requires the filter.
fn ensure_filter_configured(repo_root: &Path) -> anyhow::Result<()> {
    match git_is_scrim_filter_configured(repo_root) {
        Ok((Some(_), Some(required))) if required == "true" => Ok(()),
        Ok(_) => git_configure_scrim_filter(repo_root),
        Err(err) => Err(err),
    }
}

fn print_paths(stdout: &mut dyn Write, heading: &str, paths: &[String]) -> anyhow::Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    if let Err(err) = write_line(stdout, heading) {
        return Err(err);
    }
    for path in paths {
        if let Err(err) = write_line(stdout, &format!("  {path}")) {
            return Err(err);
        }
    }
    Ok(())
}

fn warn_group_members_without_key(stderr: &mut dyn Write, group: &str, members: &[String]) {
    for member in members {
        let _ = writeln!(
            stderr,
            "warning: member '{member}' has no public key registered and cannot decrypt group '{group}'"
        );
    }
}

/// Result of rotating a group key and re-encrypting its files.
struct GroupRotation {
    keys_file: GroupKeysFile,
    reencrypted: Vec<String>,
    skipped: Vec<(String, FileState)>,
}

/// Rotates `group` to a new key for `new_recipients`, writes the key file and
/// re-encrypts the group's tracked plaintext files under it.
fn rotate_group_files(
    repo_root: &Path,
    group: &str,
    keys_file: &GroupKeysFile,
    identity: &MemberIdentity,
    new_recipients: &BTreeMap<String, MemberPublicKey>,
    filter_env: &FilterEnv,
) -> anyhow::Result<GroupRotation> {
    let policy = match read_path_policy(repo_root) {
        Ok(policy) => policy,
        Err(err) => return Err(err),
    };
    let files: Vec<String> = match private_files_by_group(repo_root, &policy) {
        Ok(mut by_group) => by_group.remove(group).into_iter().flatten().collect(),
        Err(err) => return Err(err),
    };
    let rotated = match rotate_group_key(group, keys_file, identity, new_recipients) {
        Ok(rotated) => rotated,
        Err(err) => return Err(anyhow!(err)).context("failed to rotate group key"),
    };
    if let Err(err) = write_group_keys(repo_root, group, &rotated.keys_file) {
        return Err(err);
    }
    if let Err(err) = ensure_filter_configured(repo_root) {
        return Err(err);
    }
    let (reencrypted, skipped) = match renormalize_plaintext_files(repo_root, &files, filter_env) {
        Ok(result) => result,
        Err(err) => return Err(err),
    };
    Ok(GroupRotation {
        keys_file: rotated.keys_file,
        reencrypted,
        skipped,
    })
}

/// Executes a `scrim private` subcommand.
pub(crate) fn handle_private(
    command: PrivateCommand,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    match command {
        PrivateCommand::Add {
            glob,
            groups,
            withhold: true,
            repo,
            ..
        } => handle_withhold_add(
            glob,
            groups,
            repo,
            server_flag,
            token_override,
            config_path,
            env,
        ),
        PrivateCommand::Add {
            glob,
            groups,
            offline,
            withhold: false,
            ..
        } => {
            // Encrypted files are protected by exactly one group's key.
            let group = match groups.as_slice() {
                [group] => group.clone(),
                _ => bail!(
                    "encrypted private files use a single group key, so pass exactly one --group; pass --withhold to restrict paths on the server to several groups"
                ),
            };
            let rule = match PathRule::new(&glob, &group) {
                Ok(rule) => rule,
                Err(err) => return Err(anyhow!(err)),
            };
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let current = match read_path_policy(&repo_root) {
                Ok(policy) => policy,
                Err(err) => return Err(err),
            };
            let mut rules = current.rules().to_vec();
            match rules.iter().find(|existing| existing.pattern == glob) {
                Some(existing) if existing.group != group => bail!(
                    "'{glob}' is already protected by group '{}'; run 'scrim private rm {glob}' first",
                    existing.group
                ),
                Some(_) => {}
                None => rules.push(rule.clone()),
            }
            let policy = match PathPolicy::compile(rules) {
                Ok(policy) => policy,
                Err(err) => return Err(anyhow!(err)),
            };
            // Resolving every tracked file first rejects overlapping rules of
            // different groups before anything is written.
            let by_group = match private_files_by_group(&repo_root, &policy) {
                Ok(by_group) => by_group,
                Err(err) => return Err(err),
            };
            let new_rule_policy = match PathPolicy::compile([rule]) {
                Ok(policy) => policy,
                Err(err) => return Err(anyhow!(err)),
            };
            let newly_matched: Vec<String> = match by_group.get(&group) {
                Some(files) => files
                    .iter()
                    .filter(|path| matches!(new_rule_policy.group_for_path(path), Ok(Some(_))))
                    .cloned()
                    .collect(),
                None => Vec::new(),
            };

            let identity =
                match load_member_identity(cli_key_file, &|key| env.env_var(key), config_path) {
                    Ok(identity) => identity,
                    Err(err) => return Err(err),
                };
            let created_keys = match read_group_keys(&repo_root, &group) {
                Ok(Some(keys_file)) => {
                    if let Err(err) = keys_file.unwrap_key(&group, &identity) {
                        return Err(anyhow!(err)).with_context(|| {
                            format!("cannot encrypt files for group '{group}' with your identity")
                        });
                    }
                    None
                }
                Ok(None) => {
                    let recipients = if offline {
                        let mut map = BTreeMap::new();
                        map.insert("self".to_owned(), identity.public_key());
                        map
                    } else {
                        let client = match build_authenticated_client(
                            server_flag,
                            token_override,
                            config_path,
                            &env.cwd,
                        ) {
                            Ok(client) => client,
                            Err(err) => return Err(err),
                        };
                        let response = match client.get_group_recipients(&group) {
                            Ok(response) => response,
                            Err(err) => return Err(err),
                        };
                        warn_group_members_without_key(
                            env.stderr,
                            &group,
                            &response.members_without_key,
                        );
                        let map = match recipients_from_server(&response.recipients) {
                            Ok(map) => map,
                            Err(err) => return Err(err),
                        };
                        let own_key = identity.public_key();
                        if !map.values().any(|key| *key == own_key) {
                            bail!(
                                "your public key ({own_key}) is not a registered recipient of group '{group}'; run 'scrim keygen' or ask an admin to add you to the group"
                            );
                        }
                        map
                    };
                    let data_key = match GroupDataKey::generate() {
                        Ok(key) => key,
                        Err(err) => {
                            return Err(anyhow!(err)).context("failed to generate group key");
                        }
                    };
                    match GroupKeysFile::wrap_for_recipients(&group, 1, &data_key, &recipients) {
                        Ok(keys_file) => Some(keys_file),
                        Err(err) => return Err(anyhow!(err)).context("failed to wrap group key"),
                    }
                }
                Err(err) => return Err(err),
            };

            if let Some(keys_file) = &created_keys
                && let Err(err) = write_group_keys(&repo_root, &group, keys_file)
            {
                return Err(err);
            }
            if let Err(err) = write_path_policy(&repo_root, &policy) {
                return Err(err);
            }
            if let Err(err) = sync_gitattributes(&repo_root, &policy) {
                return Err(err);
            }
            if let Err(err) = ensure_filter_configured(&repo_root) {
                return Err(err);
            }
            let filter_env = FilterEnv::new(env, cli_key_file, config_path);
            let (encrypted, skipped) =
                match renormalize_plaintext_files(&repo_root, &newly_matched, &filter_env) {
                    Ok(result) => result,
                    Err(err) => return Err(err),
                };

            if let Err(err) = write_line(
                env.stdout,
                &format!("Protected '{glob}' with group '{group}'"),
            ) {
                return Err(err);
            }
            if let Some(keys_file) = &created_keys
                && let Err(err) = write_line(
                    env.stdout,
                    &format!(
                        "Created group key '{group}' (generation 1, {} recipient(s))",
                        keys_file.recipients.len()
                    ),
                )
            {
                return Err(err);
            }
            if let Err(err) = print_paths(env.stdout, "Encrypted tracked file(s):", &encrypted) {
                return Err(err);
            }
            if !encrypted.is_empty() {
                let _ = writeln!(
                    env.stderr,
                    "warning: earlier commits still contain these files in plaintext; rotate any credentials they hold"
                );
            }
            warn_skipped(env.stderr, &skipped);
            write_line(
                env.stdout,
                "Remember to commit .gitattributes and the .scrim/ files.",
            )
        }
        PrivateCommand::Rm {
            glob,
            withhold: true,
            repo,
        } => handle_withhold_rm(glob, repo, server_flag, token_override, config_path, env),
        PrivateCommand::Rm {
            glob,
            withhold: false,
            ..
        } => {
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let current = match read_path_policy(&repo_root) {
                Ok(policy) => policy,
                Err(err) => return Err(err),
            };
            let Some(removed) = current.rules().iter().find(|rule| rule.pattern == glob) else {
                bail!("no private path rule for '{glob}'");
            };
            let removed_group = removed.group.clone();
            let remaining: Vec<PathRule> = current
                .rules()
                .iter()
                .filter(|rule| rule.pattern != glob)
                .cloned()
                .collect();
            let policy = match PathPolicy::compile(remaining) {
                Ok(policy) => policy,
                Err(err) => return Err(anyhow!(err)),
            };
            let before = match private_files_by_group(&repo_root, &current) {
                Ok(by_group) => by_group,
                Err(err) => return Err(err),
            };
            let mut unprotected = Vec::new();
            for path in before.into_values().flatten() {
                match policy.group_for_path(&path) {
                    Ok(None) => unprotected.push(path),
                    Ok(Some(_)) => {}
                    Err(err) => return Err(anyhow!(err)),
                }
            }
            // Storing a placeholder or raw blob as "plaintext" would lose the
            // file, so every affected copy must already be decrypted.
            for path in &unprotected {
                match file_state(&repo_root, path) {
                    Ok(FileState::Plaintext | FileState::Missing) => {}
                    Ok(state) => bail!(
                        "cannot unprotect '{path}': its working-tree copy is {} (decrypting it requires access to group '{removed_group}')",
                        state.describe()
                    ),
                    Err(err) => return Err(err),
                }
            }

            if let Err(err) = write_path_policy(&repo_root, &policy) {
                return Err(err);
            }
            if let Err(err) = sync_gitattributes(&repo_root, &policy) {
                return Err(err);
            }
            let filter_env = FilterEnv::new(env, cli_key_file, config_path);
            let (stored, _) =
                match renormalize_plaintext_files(&repo_root, &unprotected, &filter_env) {
                    Ok(result) => result,
                    Err(err) => return Err(err),
                };

            if let Err(err) = write_line(
                env.stdout,
                &format!("Unprotected '{glob}' (group '{removed_group}')"),
            ) {
                return Err(err);
            }
            if let Err(err) = print_paths(env.stdout, "Stored as plaintext again:", &stored) {
                return Err(err);
            }
            write_line(
                env.stdout,
                "Remember to commit .gitattributes and the .scrim/ files.",
            )
        }
        PrivateCommand::Status {
            withhold: true,
            repo,
        } => handle_withhold_status(repo, server_flag, token_override, config_path, env),
        PrivateCommand::Status {
            withhold: false, ..
        } => handle_status(cli_key_file, config_path, env),
        PrivateCommand::Setup { withhold, repo } => {
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            if let Err(err) = git_configure_scrim_filter(&repo_root) {
                return Err(err);
            }
            let filter_env = FilterEnv::new(env, cli_key_file, config_path);
            // Updating sparse checkout first lets the refresh below see every
            // private file that is now part of the working tree.
            let sparse_line = if withhold {
                match apply_withheld_sparse_checkout(
                    &repo_root,
                    repo,
                    server_flag,
                    token_override,
                    config_path,
                    &filter_env,
                    env,
                ) {
                    Ok(line) => Some(line),
                    Err(err) => return Err(err),
                }
            } else {
                None
            };
            let policy = match read_path_policy(&repo_root) {
                Ok(policy) => policy,
                Err(err) => return Err(err),
            };
            let by_group = match private_files_by_group(&repo_root, &policy) {
                Ok(by_group) => by_group,
                Err(err) => return Err(err),
            };
            // Only raw blobs and intact placeholders that hold exactly the
            // staged blob are rewritten, so no uncommitted edit is clobbered.
            // They are removed first because `git checkout-index --force`
            // skips files whose cleaned content already matches the index.
            let mut refresh = Vec::new();
            for path in by_group.into_values().flatten() {
                match file_state(&repo_root, &path) {
                    Ok(FileState::Encrypted | FileState::Placeholder) => {
                        match holds_staged_blob(&repo_root, &path) {
                            Ok(true) => {}
                            Ok(false) => {
                                let _ = writeln!(
                                    env.stderr,
                                    "warning: '{path}' differs from the staged version and was left untouched"
                                );
                                continue;
                            }
                            Err(err) => return Err(err),
                        }
                        let full_path = repo_root.join(&path);
                        if let Err(err) = fs::remove_file(&full_path) {
                            return Err(anyhow!(err)).with_context(|| {
                                format!("failed to remove {}", full_path.display())
                            });
                        }
                        refresh.push(path);
                    }
                    Ok(FileState::EditedPlaceholder) => {
                        let _ = writeln!(
                            env.stderr,
                            "warning: '{path}' is an edited placeholder; restore it with 'git checkout -- {path}'"
                        );
                    }
                    Ok(_) => {}
                    Err(err) => return Err(err),
                }
            }
            if !refresh.is_empty()
                && let Err(err) =
                    git_checkout_index_force(&repo_root, &refresh, &filter_env.pairs())
            {
                return Err(err);
            }
            if let Err(err) = write_line(
                env.stdout,
                "Configured Git filter 'scrim' for this repository",
            ) {
                return Err(err);
            }
            if let Some(line) = sparse_line
                && let Err(err) = write_line(env.stdout, &line)
            {
                return Err(err);
            }
            write_line(
                env.stdout,
                &format!("Refreshed {} private file(s)", refresh.len()),
            )
        }
        PrivateCommand::Sync { group } => {
            if let Err(err) = validate_group_name(&group) {
                return Err(anyhow!(err));
            }
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let keys_file = match read_group_keys(&repo_root, &group) {
                Ok(Some(file)) => file,
                Ok(None) => bail!("group key file .scrim/group-keys/{group}.toml does not exist"),
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
            let identity =
                match load_member_identity(cli_key_file, &|key| env.env_var(key), config_path) {
                    Ok(identity) => identity,
                    Err(err) => return Err(err),
                };
            let response = match client.get_group_recipients(&group) {
                Ok(response) => response,
                Err(err) => return Err(err),
            };
            warn_group_members_without_key(env.stderr, &group, &response.members_without_key);
            let new_recipients = match recipients_from_server(&response.recipients) {
                Ok(map) => map,
                Err(err) => return Err(err),
            };
            let removed: Vec<String> = keys_file
                .recipients
                .iter()
                .filter(|recipient| !new_recipients.contains_key(&recipient.member))
                .map(|recipient| recipient.member.clone())
                .collect();
            let filter_env = FilterEnv::new(env, cli_key_file, config_path);
            let rotation = match rotate_group_files(
                &repo_root,
                &group,
                &keys_file,
                &identity,
                &new_recipients,
                &filter_env,
            ) {
                Ok(rotation) => rotation,
                Err(err) => return Err(err),
            };

            if let Err(err) = write_line(
                env.stdout,
                &format!(
                    "Synced group '{group}' to generation {} ({} recipient(s))",
                    rotation.keys_file.generation,
                    rotation.keys_file.recipients.len()
                ),
            ) {
                return Err(err);
            }
            if !removed.is_empty()
                && let Err(err) = write_line(
                    env.stdout,
                    &format!("Removed recipient(s): {}", removed.join(", ")),
                )
            {
                return Err(err);
            }
            if let Err(err) = print_paths(
                env.stdout,
                "Private files re-encrypted (review/rotate any embedded credentials):",
                &rotation.reencrypted,
            ) {
                return Err(err);
            }
            warn_skipped(env.stderr, &rotation.skipped);
            write_line(
                env.stdout,
                "Remember to commit and push the updated .scrim/ files.",
            )
        }
    }
}

/// `scrim private add --withhold`: creates or replaces a server-side rule
/// that withholds paths matching `glob` from everyone outside `groups`.
fn handle_withhold_add(
    glob: String,
    groups: Vec<String>,
    repo: Option<String>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    if let Err(err) = validate_path_glob(&glob) {
        return Err(anyhow!(err));
    }
    for group in &groups {
        if let Err(err) = validate_group_name(group) {
            return Err(anyhow!(err));
        }
    }
    let client =
        match build_authenticated_client(server_flag, token_override, config_path, &env.cwd) {
            Ok(client) => client,
            Err(err) => return Err(err),
        };
    let repo_key = match resolve_repo_arg(repo, &env.cwd) {
        Ok(repo_key) => repo_key,
        Err(err) => return Err(err),
    };
    let response = match client.put_path_rule(&repo_key, &glob, &groups) {
        Ok(response) => response,
        Err(err) => return Err(err),
    };
    write_line(
        env.stdout,
        &format!(
            "Withholding '{}' in {} from everyone except groups: {}",
            response.pattern,
            response.repository,
            format_list_or_none(&response.groups, "(none)")
        ),
    )
}

/// `scrim private rm --withhold`: removes a server-side withholding rule.
fn handle_withhold_rm(
    glob: String,
    repo: Option<String>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    if let Err(err) = validate_path_glob(&glob) {
        return Err(anyhow!(err));
    }
    let client =
        match build_authenticated_client(server_flag, token_override, config_path, &env.cwd) {
            Ok(client) => client,
            Err(err) => return Err(err),
        };
    let repo_key = match resolve_repo_arg(repo, &env.cwd) {
        Ok(repo_key) => repo_key,
        Err(err) => return Err(err),
    };
    let response = match client.delete_path_rule(&repo_key, &glob) {
        Ok(response) => response,
        Err(err) => return Err(err),
    };
    let line = if response.removed {
        format!(
            "Removed withholding rule '{}' from {}",
            response.pattern, response.repository
        )
    } else {
        format!(
            "No withholding rule '{}' found in {}",
            response.pattern, response.repository
        )
    };
    write_line(env.stdout, &line)
}

/// `scrim private status --withhold`: lists server-side withholding rules.
fn handle_withhold_status(
    repo: Option<String>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let client =
        match build_authenticated_client(server_flag, token_override, config_path, &env.cwd) {
            Ok(client) => client,
            Err(err) => return Err(err),
        };
    let repo_key = match resolve_repo_arg(repo, &env.cwd) {
        Ok(repo_key) => repo_key,
        Err(err) => return Err(err),
    };
    let response = match client.list_path_rules(&repo_key) {
        Ok(response) => response,
        Err(err) => return Err(err),
    };
    if let Err(err) = write_line(
        env.stdout,
        &format!("Withholding rules for {}:", response.repository),
    ) {
        return Err(err);
    }
    if response.rules.is_empty() {
        return write_line(env.stdout, "  (none)");
    }
    for rule in &response.rules {
        if let Err(err) = write_line(
            env.stdout,
            &format!(
                "  {} -> {}",
                rule.pattern,
                format_list_or_none(&rule.groups, "(none)")
            ),
        ) {
            return Err(err);
        }
    }
    Ok(())
}

/// Fetches the paths withheld from the caller and makes the local sparse
/// checkout exclude exactly those, returning a summary line. The Scrim
/// bearer token is passed to Git (scoped to the server URL) because widening
/// the checkout may lazily fetch newly visible blobs from a partial clone.
fn apply_withheld_sparse_checkout(
    repo_root: &Path,
    repo: Option<String>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    filter_env: &FilterEnv,
    env: &CliEnv<'_>,
) -> anyhow::Result<String> {
    let client =
        match build_authenticated_client(server_flag, token_override, config_path, &env.cwd) {
            Ok(client) => client,
            Err(err) => return Err(err),
        };
    let repo_key = match resolve_repo_arg(repo, &env.cwd) {
        Ok(repo_key) => repo_key,
        Err(err) => return Err(err),
    };
    let response = match client.get_my_withheld_paths(&repo_key) {
        Ok(response) => response,
        Err(err) => return Err(err),
    };
    if let Err(err) = validate_withheld_response(&response) {
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
    let mut git_env = filter_env.pairs();
    git_env.extend(
        auth_env
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    );

    // On a partial clone, refetch visible blobs at commit level before
    // widening or disabling sparse checkout: `scrim-server` refuses bare
    // blob-OID promisor lazy fetches by design, so newly visible files must
    // arrive via a commit-level refetch pack first.
    let promisor_remotes = match git_promisor_remotes_for_server(repo_root, client.base_url()) {
        Ok(remotes) => remotes,
        Err(err) => return Err(err),
    };
    for promisor_remote in promisor_remotes {
        if let Err(err) = git_refetch_partial_remote(
            repo_root,
            &promisor_remote,
            WITHHOLD_PARTIAL_CLONE_FILTER,
            &git_env,
        ) {
            return Err(err);
        }
    }

    if response.withheld_patterns.is_empty() {
        return match git_sparse_checkout_disable_if_active(repo_root, &git_env) {
            Ok(true) => Ok("Sparse checkout: disabled (no paths withheld from you)".to_owned()),
            Ok(false) => Ok("Sparse checkout: not needed (no paths withheld from you)".to_owned()),
            Err(err) => Err(err),
        };
    }
    if let Err(err) =
        git_sparse_checkout_set(repo_root, &response.sparse_checkout_patterns, &git_env)
    {
        return Err(err);
    }
    Ok(format!(
        "Sparse checkout: excluding {} withheld pattern(s)",
        response.withheld_patterns.len()
    ))
}

fn handle_status(
    cli_key_file: Option<&Path>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let repo_root = match require_repo_root(&env.cwd) {
        Ok(root) => root,
        Err(err) => return Err(err),
    };
    let filter_line = match git_is_scrim_filter_configured(&repo_root) {
        Ok((Some(_), Some(required))) if required == "true" => "Filter: configured",
        Ok(_) => "Filter: not configured (run 'scrim private setup')",
        Err(err) => return Err(err),
    };
    if let Err(err) = write_line(env.stdout, filter_line) {
        return Err(err);
    }
    let policy = match read_path_policy(&repo_root) {
        Ok(policy) => policy,
        Err(err) => return Err(err),
    };
    if policy.is_empty() {
        return write_line(env.stdout, "No private path rules.");
    }

    if let Err(err) = write_line(env.stdout, "Rules:") {
        return Err(err);
    }
    for rule in policy.rules() {
        if let Err(err) = write_line(env.stdout, &format!("  {} -> {}", rule.pattern, rule.group)) {
            return Err(err);
        }
    }

    let identity = load_member_identity(cli_key_file, &|key| env.env_var(key), config_path).ok();
    if let Err(err) = write_line(env.stdout, "Groups:") {
        return Err(err);
    }
    for group in policy.groups() {
        let line = match read_group_keys(&repo_root, group) {
            Ok(Some(keys_file)) => {
                let access = match &identity {
                    Some(identity) => match keys_file.unwrap_key(group, identity) {
                        Ok(_) => "yes",
                        Err(_) => "no",
                    },
                    None => "unknown (no identity)",
                };
                format!(
                    "  {group}: generation {}, {} recipient(s), access: {access}",
                    keys_file.generation,
                    keys_file.recipients.len()
                )
            }
            Ok(None) => format!("  {group}: missing .scrim/group-keys/{group}.toml"),
            Err(err) => format!("  {group}: invalid key file ({err:#})"),
        };
        if let Err(err) = write_line(env.stdout, &line) {
            return Err(err);
        }
    }

    let by_group = match private_files_by_group(&repo_root, &policy) {
        Ok(by_group) => by_group,
        Err(err) => return Err(err),
    };
    if let Err(err) = write_line(env.stdout, "Files:") {
        return Err(err);
    }
    if by_group.is_empty() {
        return write_line(env.stdout, "  (no tracked private files)");
    }
    for (group, paths) in &by_group {
        for path in paths {
            let state = match file_state(&repo_root, path) {
                Ok(state) => state,
                Err(err) => return Err(err),
            };
            if let Err(err) = write_line(
                env.stdout,
                &format!("  {path} [{group}]: {}", state.describe()),
            ) {
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Runs the Git long-running filter process on the CLI's standard streams.
pub(crate) fn handle_filter_process(
    cli_key_file: Option<&Path>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let repo_root = match git_toplevel(&env.cwd) {
        Ok(Some(root)) => root,
        Ok(None) => env.cwd.clone(),
        Err(err) => return Err(err),
    };
    let (identity, identity_problem) =
        match load_member_identity(cli_key_file, &|key| env.env_var(key), config_path) {
            Ok(identity) => (Some(identity), String::new()),
            Err(err) => (None, format!("{err:#}")),
        };
    let mut context = FilterContext::new(repo_root, identity, identity_problem);
    serve(&mut context, env.stdin, env.stdout, env.stderr)
}

/// Rotates every local group key that lists the revoked `member` and
/// re-encrypts the affected private files. Problems are reported as warnings
/// because the server-side revocation has already succeeded. Returns whether
/// any group was rotated.
pub(crate) fn rotate_groups_after_revocation(
    member: &str,
    client: &ScrimClient,
    cli_key_file: Option<&Path>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> bool {
    let repo_root = match git_toplevel(&env.cwd) {
        Ok(Some(root)) => root,
        Ok(None) => return false,
        Err(err) => {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but local git repository discovery failed ({err}); run 'scrim private sync --group <group>' if needed"
            );
            return false;
        }
    };
    let groups = match list_local_groups(&repo_root) {
        Ok(groups) => groups,
        Err(err) => {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but local group keys could not be listed ({err:#}); run 'scrim private sync --group <group>' if needed"
            );
            return false;
        }
    };
    let mut affected = Vec::new();
    for group in groups {
        match read_group_keys(&repo_root, &group) {
            Ok(Some(keys_file)) => {
                if keys_file.recipients.iter().any(|r| r.member == member) {
                    affected.push((group, keys_file));
                }
            }
            Ok(None) => {}
            Err(err) => {
                let _ = writeln!(
                    env.stderr,
                    "warning: member '{member}' was revoked on the server, but group key '{group}' could not be read ({err:#}); run 'scrim private sync --group {group}'"
                );
            }
        }
    }
    if affected.is_empty() {
        return false;
    }

    let identity = match load_member_identity(cli_key_file, &|key| env.env_var(key), config_path) {
        Ok(identity) => identity,
        Err(err) => {
            for (group, _) in &affected {
                let _ = writeln!(
                    env.stderr,
                    "warning: member '{member}' was revoked on the server, but group key '{group}' still needs rotation ({err:#}); run 'scrim private sync --group {group}'"
                );
            }
            return false;
        }
    };
    let filter_env = FilterEnv::new(env, cli_key_file, config_path);

    let mut rotated_any = false;
    for (group, keys_file) in affected {
        let server_recipients = match client.get_group_recipients(&group) {
            Ok(response) => {
                warn_group_members_without_key(env.stderr, &group, &response.members_without_key);
                match recipients_from_server(&response.recipients) {
                    Ok(map) => Some(map),
                    Err(err) => {
                        let _ = writeln!(
                            env.stderr,
                            "warning: invalid recipient list from server for group '{group}' ({err:#}); falling back to the local key file"
                        );
                        None
                    }
                }
            }
            Err(_) => None,
        };
        let mut new_recipients = match server_recipients {
            Some(map) => map,
            None => match keys_file.recipient_public_keys() {
                Ok(map) => map,
                Err(err) => {
                    let _ = writeln!(
                        env.stderr,
                        "warning: group key '{group}' could not be rotated ({err}); run 'scrim private sync --group {group}'"
                    );
                    continue;
                }
            },
        };
        new_recipients.remove(member);
        if new_recipients.is_empty() {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but group '{group}' has no remaining recipients; run 'scrim private sync --group {group}' once another member has a key"
            );
            continue;
        }

        let rotation = match rotate_group_files(
            &repo_root,
            &group,
            &keys_file,
            &identity,
            &new_recipients,
            &filter_env,
        ) {
            Ok(rotation) => rotation,
            Err(err) => {
                let _ = writeln!(
                    env.stderr,
                    "warning: member '{member}' was revoked on the server, but group key '{group}' could not be rotated and re-encrypted ({err:#}); run 'scrim private sync --group {group}'"
                );
                continue;
            }
        };
        rotated_any = true;
        let _ = write_line(
            env.stdout,
            &format!(
                "Rotated group key '{group}' to generation {}",
                rotation.keys_file.generation
            ),
        );
        let _ = print_paths(
            env.stdout,
            "Private files re-encrypted (review/rotate any embedded credentials):",
            &rotation.reencrypted,
        );
        warn_skipped(env.stderr, &rotation.skipped);
    }
    rotated_any
}
