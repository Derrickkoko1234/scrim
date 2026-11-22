//! Repo-versioned private-file configuration under `.scrim/` plus the managed
//! `.gitattributes` block that routes private paths through `filter=scrim`.
//!
//! Files live inside the Git repository root:
//! - `.scrim/paths.toml`: path glob → group rules ([`PathPolicy`])
//! - `.scrim/group-keys/<group>.toml`: wrapped group data keys ([`GroupKeysFile`])
//! - `.gitattributes`: one `<pattern> filter=scrim` line per rule inside a
//!   marked block; every line outside the block belongs to the user and is
//!   preserved verbatim.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, anyhow, bail};
use scrim_crypto::{FILE_FORMAT_VERSION, GroupKeysFile};
use scrim_policy::{PathPolicy, PathRule, validate_group_name};
use serde::{Deserialize, Serialize};

use crate::secrets_store::write_repo_file_atomic;

/// First line of the Scrim-managed block in `.gitattributes`.
pub const GITATTRIBUTES_BEGIN: &str =
    "# BEGIN SCRIM PRIVATE PATHS (managed by scrim; do not edit manually)";
/// Last line of the Scrim-managed block in `.gitattributes`.
pub const GITATTRIBUTES_END: &str = "# END SCRIM PRIVATE PATHS";

/// On-disk shape of `.scrim/paths.toml`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathsFile {
    version: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules: Vec<PathsFileRule>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PathsFileRule {
    pattern: String,
    group: String,
}

/// Returns `<repo_root>/.scrim/paths.toml`.
pub fn paths_file_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".scrim").join("paths.toml")
}

/// Returns a policy with no rules.
pub fn empty_path_policy() -> anyhow::Result<PathPolicy> {
    match PathPolicy::compile(Vec::<PathRule>::new()) {
        Ok(policy) => Ok(policy),
        Err(err) => Err(anyhow!(err)).context("failed to compile empty path policy"),
    }
}

/// Parses and validates the contents of a `.scrim/paths.toml` file.
///
/// # Errors
///
/// Fails on malformed TOML, unknown fields, a version other than
/// [`FILE_FORMAT_VERSION`], or any rule rejected by [`PathPolicy::compile`].
pub fn parse_path_policy(text: &str) -> anyhow::Result<PathPolicy> {
    let parsed: PathsFile = match toml::from_str(text) {
        Ok(file) => file,
        Err(err) => return Err(anyhow!(err)).context("invalid .scrim/paths.toml"),
    };
    if parsed.version != FILE_FORMAT_VERSION {
        bail!(
            "unsupported .scrim/paths.toml version {} (expected {FILE_FORMAT_VERSION})",
            parsed.version
        );
    }
    let rules = parsed.rules.into_iter().map(|rule| PathRule {
        pattern: rule.pattern,
        group: rule.group,
    });
    match PathPolicy::compile(rules) {
        Ok(policy) => Ok(policy),
        Err(err) => Err(anyhow!(err)).context("invalid rule in .scrim/paths.toml"),
    }
}

/// Serializes `policy` as `.scrim/paths.toml` text, rules sorted by pattern.
pub fn format_path_policy(policy: &PathPolicy) -> anyhow::Result<String> {
    let file = PathsFile {
        version: FILE_FORMAT_VERSION,
        rules: policy
            .rules()
            .iter()
            .map(|rule| PathsFileRule {
                pattern: rule.pattern.clone(),
                group: rule.group.clone(),
            })
            .collect(),
    };
    match toml::to_string(&file) {
        Ok(text) => Ok(text),
        Err(err) => Err(anyhow!(err)).context("failed to serialize .scrim/paths.toml"),
    }
}

/// Reads `.scrim/paths.toml`, returning `Ok(None)` when it does not exist.
pub(crate) fn read_path_policy_file(repo_root: &Path) -> anyhow::Result<Option<PathPolicy>> {
    let path = paths_file_path(repo_root);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    match parse_path_policy(&text) {
        Ok(policy) => Ok(Some(policy)),
        Err(err) => Err(err),
    }
}

/// Reads `.scrim/paths.toml`, returning an empty policy when it does not
/// exist.
pub fn read_path_policy(repo_root: &Path) -> anyhow::Result<PathPolicy> {
    match read_path_policy_file(repo_root) {
        Ok(Some(policy)) => Ok(policy),
        Ok(None) => empty_path_policy(),
        Err(err) => Err(err),
    }
}

/// Atomically writes `policy` to `.scrim/paths.toml`.
pub fn write_path_policy(repo_root: &Path, policy: &PathPolicy) -> anyhow::Result<()> {
    let text = match format_path_policy(policy) {
        Ok(text) => text,
        Err(err) => return Err(err),
    };
    write_repo_file_atomic(&paths_file_path(repo_root), text.as_bytes())
}

/// Returns `<repo_root>/.scrim/group-keys/<group>.toml` after validating
/// `group`.
pub fn group_keys_path(repo_root: &Path, group: &str) -> anyhow::Result<PathBuf> {
    if let Err(err) = validate_group_name(group) {
        return Err(anyhow!(err));
    }
    Ok(repo_root
        .join(".scrim")
        .join("group-keys")
        .join(format!("{group}.toml")))
}

/// Reads and validates `.scrim/group-keys/<group>.toml`, returning `Ok(None)`
/// if it does not exist.
///
/// # Errors
///
/// Fails on an invalid group name, an unreadable or malformed file, or a file
/// whose recorded group differs from `group`.
pub fn read_group_keys(repo_root: &Path, group: &str) -> anyhow::Result<Option<GroupKeysFile>> {
    let path = match group_keys_path(repo_root, group) {
        Ok(path) => path,
        Err(err) => return Err(err),
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read group keys file {}", path.display()));
        }
    };
    let file = match GroupKeysFile::from_toml_str(&text) {
        Ok(file) => file,
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("invalid group keys file {}", path.display()));
        }
    };
    if file.group != group {
        bail!(
            "group keys file {} is for group '{}', expected '{group}'",
            path.display(),
            file.group
        );
    }
    Ok(Some(file))
}

/// Atomically writes `keys_file` to `.scrim/group-keys/<group>.toml`.
pub fn write_group_keys(
    repo_root: &Path,
    group: &str,
    keys_file: &GroupKeysFile,
) -> anyhow::Result<()> {
    if keys_file.group != group {
        bail!(
            "refusing to write keys for group '{}' to the file for group '{group}'",
            keys_file.group
        );
    }
    let path = match group_keys_path(repo_root, group) {
        Ok(path) => path,
        Err(err) => return Err(err),
    };
    let text = match keys_file.to_toml_string() {
        Ok(text) => text,
        Err(err) => return Err(anyhow!(err)).context("failed to serialize group keys file"),
    };
    write_repo_file_atomic(&path, text.as_bytes())
}

/// Lists group names with a `.scrim/group-keys/<group>.toml` file, sorted and
/// ignoring non-`.toml` entries and invalid names.
pub fn list_local_groups(repo_root: &Path) -> anyhow::Result<Vec<String>> {
    let dir = repo_root.join(".scrim").join("group-keys");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to read group keys directory {}", dir.display()));
        }
    };
    let mut groups = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                return Err(anyhow!(err))
                    .with_context(|| format!("failed to read entry in {}", dir.display()));
            }
        };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") || !path.is_file() {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if validate_group_name(stem).is_ok() {
            groups.push(stem.to_owned());
        }
    }
    groups.sort();
    Ok(groups)
}

/// Rewrites `.gitattributes` so its Scrim-managed block lists exactly one
/// `<pattern> filter=scrim` line per rule in `policy`.
///
/// Lines outside the block are preserved verbatim. An empty policy removes
/// the block, and the file itself is deleted when nothing else remains in
/// it. The file is never touched when its contents would not change.
///
/// # Errors
///
/// Fails when the existing file contains a malformed block (a begin marker
/// without an end marker, markers out of order, or repeated markers) rather
/// than guessing which user lines belong to it, or on I/O errors.
pub fn sync_gitattributes(repo_root: &Path, policy: &PathPolicy) -> anyhow::Result<()> {
    let path = repo_root.join(".gitattributes");
    let existing = match fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| format!("failed to read {}", path.display()));
        }
    };
    let current = match &existing {
        Some(text) => text.as_str(),
        None => "",
    };
    let rendered = match render_gitattributes(current, policy) {
        Ok(text) => text,
        Err(err) => return Err(err),
    };
    if existing.as_deref() == Some(rendered.as_str()) {
        return Ok(());
    }
    if rendered.is_empty() {
        if existing.is_some()
            && let Err(err) = fs::remove_file(&path)
        {
            return Err(anyhow!(err))
                .with_context(|| format!("failed to remove {}", path.display()));
        }
        return Ok(());
    }
    write_repo_file_atomic(&path, rendered.as_bytes())
}

/// Returns `existing` with its managed block replaced by one generated from
/// `policy` (see [`sync_gitattributes`]).
fn render_gitattributes(existing: &str, policy: &PathPolicy) -> anyhow::Result<String> {
    let lines: Vec<&str> = existing.split_inclusive('\n').collect();
    let marker_positions = |marker: &str| -> Vec<usize> {
        lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.trim_end_matches(['\n', '\r']) == marker)
            .map(|(index, _)| index)
            .collect()
    };
    let begins = marker_positions(GITATTRIBUTES_BEGIN);
    let ends = marker_positions(GITATTRIBUTES_END);
    let block_range = match (begins.as_slice(), ends.as_slice()) {
        ([], []) => None,
        ([begin], [end]) if begin < end => Some((*begin, *end)),
        _ => bail!(
            ".gitattributes contains a malformed Scrim block (expected one '{GITATTRIBUTES_BEGIN}' line followed by one '{GITATTRIBUTES_END}' line); fix it manually and retry"
        ),
    };

    let mut block = String::new();
    if !policy.is_empty() {
        block.push_str(GITATTRIBUTES_BEGIN);
        block.push('\n');
        for rule in policy.rules() {
            block.push_str(&rule.pattern);
            block.push_str(" filter=scrim\n");
        }
        block.push_str(GITATTRIBUTES_END);
        block.push('\n');
    }

    let is_blank = |line: &&str| line.trim().is_empty();
    let mut output = String::with_capacity(existing.len() + block.len() + 1);
    match block_range {
        Some((begin, end)) => {
            let before = match lines.get(..begin) {
                Some(before) => before,
                None => &[][..],
            };
            let after = match lines.get(end + 1..) {
                Some(after) => after,
                None => &[][..],
            };
            // When the block goes away at the end of the file, also drop the
            // blank separator line scrim inserted before it when appending.
            let keep_before =
                if block.is_empty() && after.is_empty() && before.last().is_some_and(is_blank) {
                    before.len() - 1
                } else {
                    before.len()
                };
            for line in before.iter().take(keep_before) {
                output.push_str(line);
            }
            if !block.is_empty() && !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(&block);
            for line in after {
                output.push_str(line);
            }
        }
        None => {
            output.push_str(existing);
            if !block.is_empty() && !existing.is_empty() {
                if !existing.ends_with('\n') {
                    output.push('\n');
                }
                if !lines.last().is_some_and(is_blank) {
                    output.push('\n');
                }
            }
            output.push_str(&block);
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use scrim_crypto::{GroupDataKey, MemberIdentity};

    use super::*;

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(err) => panic!("tempdir failed: {err}"),
        }
    }

    fn policy(rules: &[(&str, &str)]) -> PathPolicy {
        let rules = rules.iter().map(|(pattern, group)| PathRule {
            pattern: (*pattern).to_owned(),
            group: (*group).to_owned(),
        });
        match PathPolicy::compile(rules) {
            Ok(policy) => policy,
            Err(err) => panic!("policy should compile: {err}"),
        }
    }

    fn read(path: &Path) -> String {
        match fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => panic!("read {} failed: {err}", path.display()),
        }
    }

    fn sync(root: &Path, policy: &PathPolicy) {
        if let Err(err) = sync_gitattributes(root, policy) {
            panic!("sync_gitattributes failed: {err:#}");
        }
    }

    #[test]
    fn paths_toml_round_trips_sorted_and_rejects_bad_input() {
        let dir = tempdir();
        let root = dir.path();

        let empty = match read_path_policy(root) {
            Ok(policy) => policy,
            Err(err) => panic!("read missing paths.toml failed: {err:#}"),
        };
        assert!(empty.is_empty());

        let written = policy(&[("z/**", "ops"), ("config/billing/**", "finance")]);
        if let Err(err) = write_path_policy(root, &written) {
            panic!("write_path_policy failed: {err:#}");
        }
        let text = read(&paths_file_path(root));
        assert_eq!(
            text,
            "version = 1\n\n[[rules]]\npattern = \"config/billing/**\"\ngroup = \"finance\"\n\n[[rules]]\npattern = \"z/**\"\ngroup = \"ops\"\n"
        );
        let reread = match read_path_policy(root) {
            Ok(policy) => policy,
            Err(err) => panic!("read_path_policy failed: {err:#}"),
        };
        assert_eq!(reread.rules(), written.rules());

        assert!(parse_path_policy("version = 2\n").is_err());
        assert!(parse_path_policy("version = 1\nextra = true\n").is_err());
        assert!(
            parse_path_policy("version = 1\n[[rules]]\npattern = \".scrim/**\"\ngroup = \"a\"\n")
                .is_err()
        );
        assert!(
            parse_path_policy(
                "version = 1\n[[rules]]\npattern = \"a/**\"\ngroup = \"a\"\nother = 1\n"
            )
            .is_err()
        );
        match parse_path_policy("version = 1\n") {
            Ok(parsed) => assert!(parsed.is_empty()),
            Err(err) => panic!("empty paths.toml should parse: {err:#}"),
        }
    }

    #[test]
    fn group_keys_round_trip_and_listing() {
        let dir = tempdir();
        let root = dir.path();
        let alice = MemberIdentity::generate();
        let key = match GroupDataKey::generate() {
            Ok(key) => key,
            Err(err) => panic!("GroupDataKey::generate failed: {err}"),
        };
        let mut recipients = BTreeMap::new();
        recipients.insert("alice".to_owned(), alice.public_key());
        let keys_file = match GroupKeysFile::wrap_for_recipients("finance", 1, &key, &recipients) {
            Ok(file) => file,
            Err(err) => panic!("wrap_for_recipients failed: {err}"),
        };

        match read_group_keys(root, "finance") {
            Ok(None) => {}
            other => panic!("expected Ok(None) for missing group keys, got {other:?}"),
        }
        if let Err(err) = write_group_keys(root, "finance", &keys_file) {
            panic!("write_group_keys failed: {err:#}");
        }
        assert!(write_group_keys(root, "ops", &keys_file).is_err());
        match read_group_keys(root, "finance") {
            Ok(Some(file)) => assert_eq!(file, keys_file),
            other => panic!("expected group keys, got {other:?}"),
        }

        // A file whose contents name another group is rejected.
        let ops_path = match group_keys_path(root, "ops") {
            Ok(path) => path,
            Err(err) => panic!("group_keys_path failed: {err:#}"),
        };
        let text = match keys_file.to_toml_string() {
            Ok(text) => text,
            Err(err) => panic!("to_toml_string failed: {err}"),
        };
        if let Err(err) = fs::write(&ops_path, text) {
            panic!("write ops keys failed: {err}");
        }
        assert!(read_group_keys(root, "ops").is_err());

        if let Err(err) = fs::write(root.join(".scrim/group-keys/notes.txt"), "x") {
            panic!("write stray file failed: {err}");
        }
        match list_local_groups(root) {
            Ok(groups) => assert_eq!(groups, vec!["finance".to_owned(), "ops".to_owned()]),
            Err(err) => panic!("list_local_groups failed: {err:#}"),
        }
        assert!(group_keys_path(root, "../escape").is_err());
    }

    #[test]
    fn gitattributes_block_created_updated_and_removed_when_file_was_managed_only() {
        let dir = tempdir();
        let root = dir.path();
        let path = root.join(".gitattributes");

        sync(root, &policy(&[("b/**", "ops"), ("a.secret", "ops")]));
        assert_eq!(
            read(&path),
            format!(
                "{GITATTRIBUTES_BEGIN}\na.secret filter=scrim\nb/** filter=scrim\n{GITATTRIBUTES_END}\n"
            )
        );

        sync(root, &policy(&[("b/**", "ops")]));
        assert_eq!(
            read(&path),
            format!("{GITATTRIBUTES_BEGIN}\nb/** filter=scrim\n{GITATTRIBUTES_END}\n")
        );

        // Removing every rule deletes a file that only held the managed block.
        sync(root, &policy(&[]));
        assert!(!path.exists());
        // And an empty policy never creates the file.
        sync(root, &policy(&[]));
        assert!(!path.exists());
    }

    #[test]
    fn gitattributes_preserves_user_lines_and_keeps_file_with_user_content() {
        let dir = tempdir();
        let root = dir.path();
        let path = root.join(".gitattributes");
        let user = "*.png binary\r\n# keep me\n*.sh text eol=lf";
        if let Err(err) = fs::write(&path, user) {
            panic!("write .gitattributes failed: {err}");
        }

        sync(root, &policy(&[("config/**", "ops")]));
        let block = format!("{GITATTRIBUTES_BEGIN}\nconfig/** filter=scrim\n{GITATTRIBUTES_END}\n");
        assert_eq!(read(&path), format!("{user}\n\n{block}"));

        // User lines added after the block survive a block update in place.
        let with_trailer = format!("{user}\n\n{block}*.md text\n");
        if let Err(err) = fs::write(&path, &with_trailer) {
            panic!("write .gitattributes failed: {err}");
        }
        sync(root, &policy(&[("config/**", "ops"), ("x.key", "ops")]));
        assert_eq!(
            read(&path),
            format!(
                "{user}\n\n{GITATTRIBUTES_BEGIN}\nconfig/** filter=scrim\nx.key filter=scrim\n{GITATTRIBUTES_END}\n*.md text\n"
            )
        );

        // Removing the block keeps every user line.
        sync(root, &policy(&[]));
        assert_eq!(read(&path), format!("{user}\n\n*.md text\n"));

        // With the block last, removal also drops the separator scrim added.
        if let Err(err) = fs::write(&path, format!("{user}\n\n{block}")) {
            panic!("write .gitattributes failed: {err}");
        }
        sync(root, &policy(&[]));
        assert_eq!(read(&path), format!("{user}\n"));
    }

    #[test]
    fn gitattributes_rejects_malformed_blocks_without_touching_the_file() {
        let dir = tempdir();
        let root = dir.path();
        let path = root.join(".gitattributes");
        let malformed = [
            format!("*.png binary\n{GITATTRIBUTES_BEGIN}\nconfig/** filter=scrim\n*.md text\n"),
            format!("{GITATTRIBUTES_END}\n*.png binary\n{GITATTRIBUTES_BEGIN}\n"),
            format!(
                "{GITATTRIBUTES_BEGIN}\n{GITATTRIBUTES_END}\n{GITATTRIBUTES_BEGIN}\n{GITATTRIBUTES_END}\n"
            ),
            format!("*.png binary\n{GITATTRIBUTES_END}\n"),
        ];
        for contents in malformed {
            if let Err(err) = fs::write(&path, &contents) {
                panic!("write .gitattributes failed: {err}");
            }
            assert!(sync_gitattributes(root, &policy(&[("config/**", "ops")])).is_err());
            assert!(sync_gitattributes(root, &policy(&[])).is_err());
            assert_eq!(read(&path), contents);
        }
    }
}
