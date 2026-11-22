//! `scrim mirror`: pushes the branches and tags everyone may see to an
//! external Git remote such as GitHub.
//!
//! The command fails closed. Ref visibility comes from the server's branch
//! rules, judged for a member with no groups. Before anything is pushed,
//! every tree reachable from those refs is checked: each file covered by the
//! server's withholding rules, by that commit's own `.scrim/paths.toml`, or by
//! the current `.scrim/paths.toml` must be a client-side encrypted
//! `SCRIMFILE` blob. Only explicit `<ref>:<ref>` refspecs are pushed, so a
//! private ref can never match a wildcard, and the Scrim bearer token is never
//! handed to Git.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};

use anyhow::{Context, anyhow, bail};
use scrim_crypto::{ENCRYPTED_FILE_MAGIC, is_encrypted_file};
use scrim_policy::{BranchPolicy, BranchRule, PathPolicy, WithholdPolicy, WithholdRule};
use secrecy::SecretString;

use crate::cli::MirrorArgs;
use crate::git::run_git_checked_with_env;
use crate::private_store::{parse_path_policy, read_path_policy_file};
use crate::secrets_store::require_repo_root;
use crate::{
    CliEnv, build_authenticated_client, escape_control_chars, resolve_repo_arg, write_line,
};

/// Repo-relative path of the per-commit private path rules.
const PATHS_FILE: &str = ".scrim/paths.toml";

/// Tree entry mode of a submodule commit (gitlink); it has no blob content.
const GITLINK_MODE: &str = "160000";

/// Most unencrypted files listed in a refusal before the rest are summarized.
const MAX_REPORTED_LEAKS: usize = 20;

/// A local branch or tag from `git for-each-ref`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalRef {
    name: String,
    /// Target ref name when this ref is symbolic.
    symref_target: Option<String>,
    /// Object the ref (or its symbolic target) points at.
    object_id: String,
}

/// Local refs split by whether they may be mirrored.
#[derive(Debug, Default)]
struct RefPlan {
    public: Vec<LocalRef>,
    private: Vec<String>,
    symbolic: Vec<String>,
}

/// Rules that apply to every commit, independent of its own `.scrim/paths.toml`.
struct GlobalProtection {
    withhold: WithholdPolicy,
    /// Current `.scrim/paths.toml` versions (working tree, `HEAD`) with a label.
    local_path_policies: Vec<(&'static str, PathPolicy)>,
}

impl GlobalProtection {
    fn is_empty(&self) -> bool {
        self.withhold.is_empty()
            && self
                .local_path_policies
                .iter()
                .all(|(_, policy)| policy.is_empty())
    }
}

/// First place a protected blob was found, for the refusal message.
#[derive(Debug)]
struct ProtectedBlob {
    commit: String,
    path: String,
    reason: String,
}

/// Handles `scrim mirror <TARGET>`.
pub(crate) fn handle_mirror(
    args: MirrorArgs,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let repo_root = match require_repo_root(&env.cwd) {
        Ok(root) => root,
        Err(err) => return Err(err),
    };
    if let Err(err) = validate_mirror_target(&args.target) {
        return Err(err);
    }
    let repo_key = match resolve_repo_arg(args.repo, &env.cwd) {
        Ok(repo_key) => repo_key,
        Err(err) => return Err(err),
    };
    let client =
        match build_authenticated_client(server_flag, token_override, config_path, &env.cwd) {
            Ok(client) => client,
            Err(err) => return Err(err),
        };

    let branch_rules = match client.list_branch_rules(&repo_key) {
        Ok(response) => response.rules,
        Err(err) => return Err(err),
    };
    let mut compiled_branch_rules = Vec::with_capacity(branch_rules.len());
    for rule in branch_rules {
        match BranchRule::new(rule.pattern, rule.groups) {
            Ok(rule) => compiled_branch_rules.push(rule),
            Err(err) => return Err(anyhow!(err)).context("server returned an invalid branch rule"),
        }
    }
    let branch_policy = match BranchPolicy::compile(compiled_branch_rules) {
        Ok(policy) => policy,
        Err(err) => return Err(anyhow!(err)).context("failed to compile server branch rules"),
    };

    let path_rules = match client.list_path_rules(&repo_key) {
        Ok(response) => response.rules,
        Err(err) => return Err(err),
    };
    let mut withhold_rules = Vec::with_capacity(path_rules.len());
    for rule in path_rules {
        match WithholdRule::new(rule.pattern, rule.groups) {
            Ok(rule) => withhold_rules.push(rule),
            Err(err) => return Err(anyhow!(err)).context("server returned an invalid path rule"),
        }
    }
    let withhold = match WithholdPolicy::compile(withhold_rules) {
        Ok(policy) => policy,
        Err(err) => return Err(anyhow!(err)).context("failed to compile server path rules"),
    };

    let local_path_policies = match read_local_path_policies(&repo_root) {
        Ok(policies) => policies,
        Err(err) => return Err(err),
    };
    let protection = GlobalProtection {
        withhold,
        local_path_policies,
    };

    let refs = match list_local_refs(&repo_root, !args.no_tags) {
        Ok(refs) => refs,
        Err(err) => return Err(err),
    };
    let plan = partition_refs(&refs, &branch_policy);

    let display_target = redact_target(&args.target);
    if plan.public.is_empty() {
        if let Err(err) = write_line(
            env.stdout,
            &format!("No public refs to mirror to {display_target}."),
        ) {
            return Err(err);
        }
        return print_skipped(env.stdout, &plan);
    }

    if let Err(err) = verify_history_is_safe(&repo_root, &plan.public, &protection) {
        return Err(err).with_context(|| {
            format!("refusing to mirror to {display_target}; nothing was pushed")
        });
    }

    if args.dry_run {
        if let Err(err) = print_ref_list(
            env.stdout,
            &format!(
                "Dry run — would mirror {} public ref(s) to {display_target}:",
                plan.public.len()
            ),
            plan.public.iter().map(|local_ref| local_ref.name.as_str()),
        ) {
            return Err(err);
        }
        if let Err(err) = print_skipped(env.stdout, &plan) {
            return Err(err);
        }
        return write_line(env.stdout, SAFETY_PASSED);
    }

    if let Err(err) = write_line(env.stdout, SAFETY_PASSED) {
        return Err(err);
    }
    // `--no-follow-tags` and `--recurse-submodules=no` override user config
    // that could otherwise push private tags or other repositories.
    let mut push_args = vec![
        "push".to_owned(),
        "--no-follow-tags".to_owned(),
        "--recurse-submodules=no".to_owned(),
        "--".to_owned(),
        args.target.clone(),
    ];
    for local_ref in &plan.public {
        push_args.push(format!("{0}:{0}", local_ref.name));
    }
    // No lazy fetch: a partial clone must never contact the Scrim server
    // (its promisor remote) while pushing to an external mirror.
    if let Err(err) =
        run_git_checked_with_env(&repo_root, &push_args, &[("GIT_NO_LAZY_FETCH", "1")])
    {
        return Err(err).with_context(|| format!("failed to push to {display_target}"));
    }
    if let Err(err) = print_ref_list(
        env.stdout,
        &format!(
            "Mirrored {} public ref(s) to {display_target}:",
            plan.public.len()
        ),
        plan.public.iter().map(|local_ref| local_ref.name.as_str()),
    ) {
        return Err(err);
    }
    print_skipped(env.stdout, &plan)
}

const SAFETY_PASSED: &str =
    "Safety check: passed (all private paths encrypted, no unencrypted withheld paths).";

fn print_ref_list<'a>(
    out: &mut dyn Write,
    heading: &str,
    names: impl Iterator<Item = &'a str>,
) -> anyhow::Result<()> {
    if let Err(err) = write_line(out, heading) {
        return Err(err);
    }
    for name in names {
        if let Err(err) = write_line(out, &format!("  {name}")) {
            return Err(err);
        }
    }
    Ok(())
}

fn print_skipped(out: &mut dyn Write, plan: &RefPlan) -> anyhow::Result<()> {
    if !plan.private.is_empty()
        && let Err(err) = print_ref_list(
            out,
            &format!("Skipped {} private ref(s):", plan.private.len()),
            plan.private.iter().map(String::as_str),
        )
    {
        return Err(err);
    }
    if !plan.symbolic.is_empty()
        && let Err(err) = print_ref_list(
            out,
            &format!(
                "Skipped {} symbolic ref(s) (their targets are evaluated directly):",
                plan.symbolic.len()
            ),
            plan.symbolic.iter().map(String::as_str),
        )
    {
        return Err(err);
    }
    Ok(())
}

/// Rejects mirror targets Git could parse as an option or that contain
/// whitespace or control characters.
fn validate_mirror_target(target: &str) -> anyhow::Result<()> {
    if target.is_empty() {
        bail!("mirror target cannot be empty");
    }
    if target.starts_with('-') {
        bail!("mirror target must not start with '-'");
    }
    if target
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        bail!("mirror target must not contain whitespace or control characters");
    }
    Ok(())
}

/// Hides the user-info part of a `scheme://user:password@host/...` target so
/// credentials embedded in a URL are not echoed.
fn redact_target(target: &str) -> String {
    if let Some((scheme, rest)) = target.split_once("://") {
        let authority_end = match rest.find('/') {
            Some(index) => index,
            None => rest.len(),
        };
        let authority = &rest[..authority_end];
        if let Some(at_index) = authority.rfind('@') {
            return format!("{scheme}://***@{}", &rest[at_index + 1..]);
        }
    }
    target.to_owned()
}

/// Reads the working-tree and `HEAD` versions of `.scrim/paths.toml`, failing
/// closed when either exists but cannot be parsed.
fn read_local_path_policies(repo_root: &Path) -> anyhow::Result<Vec<(&'static str, PathPolicy)>> {
    let mut policies = Vec::new();
    match read_path_policy_file(repo_root) {
        Ok(Some(policy)) => policies.push(("the current .scrim/paths.toml", policy)),
        Ok(None) => {}
        Err(err) => return Err(err),
    }
    let head_text = match read_object(repo_root, &format!("HEAD:{PATHS_FILE}")) {
        Ok(text) => text,
        Err(err) => return Err(err),
    };
    if let Some(bytes) = head_text {
        let policy = match parse_paths_file_bytes(&bytes) {
            Ok(policy) => policy,
            Err(err) => return Err(err).context("HEAD:.scrim/paths.toml is invalid"),
        };
        policies.push(("HEAD:.scrim/paths.toml", policy));
    }
    Ok(policies)
}

fn parse_paths_file_bytes(bytes: &[u8]) -> anyhow::Result<PathPolicy> {
    match std::str::from_utf8(bytes) {
        Ok(text) => parse_path_policy(text),
        Err(_) => bail!("{PATHS_FILE} is not valid UTF-8"),
    }
}

/// Builds a `git -C <repo_root>` command for read-only inspection. Lazy
/// fetching is disabled so a partial clone never contacts its promisor remote
/// (the Scrim server) while being checked; missing objects fail closed instead.
fn git_inspect_command(repo_root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo_root)
        .env("GIT_NO_LAZY_FETCH", "1");
    command
}

/// Reads object `name` (an object ID or `<rev>:<path>`) with
/// `git cat-file blob`, returning `Ok(None)` when it does not exist.
fn read_object(repo_root: &Path, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let mut command = git_inspect_command(repo_root);
    command.args(["cat-file", "-e", name]);
    let exists = match command.output() {
        Ok(output) => output.status.success(),
        Err(err) => return Err(anyhow!(err)).context("failed to execute git cat-file -e"),
    };
    if !exists {
        return Ok(None);
    }
    let mut command = git_inspect_command(repo_root);
    command.args(["cat-file", "blob", name]);
    let output = match command.output() {
        Ok(output) => output,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git cat-file blob"),
    };
    if !output.status.success() {
        bail!(
            "git cat-file blob {name} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(Some(output.stdout))
}

/// Lists local branches (and tags when `include_tags`) with their symbolic
/// targets and object IDs.
fn list_local_refs(repo_root: &Path, include_tags: bool) -> anyhow::Result<Vec<LocalRef>> {
    let mut command = git_inspect_command(repo_root);
    command.args([
        "for-each-ref",
        "--format=%(refname)%00%(symref)%00%(objectname)",
        "refs/heads",
    ]);
    if include_tags {
        command.arg("refs/tags");
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git for-each-ref"),
    };
    if !output.status.success() {
        bail!(
            "git for-each-ref failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_ref_listing(&output.stdout)
}

fn parse_ref_listing(stdout: &[u8]) -> anyhow::Result<Vec<LocalRef>> {
    let text = match std::str::from_utf8(stdout) {
        Ok(text) => text,
        Err(_) => bail!("git for-each-ref reported a non-UTF-8 ref name"),
    };
    let mut refs = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split('\0').collect();
        let [name, symref, object_id] = fields.as_slice() else {
            bail!(
                "unexpected git for-each-ref output: {}",
                escape_control_chars(line)
            );
        };
        if let Err(err) = validate_refspec_ref(name) {
            return Err(err);
        }
        refs.push(LocalRef {
            name: (*name).to_owned(),
            symref_target: if symref.is_empty() {
                None
            } else {
                Some((*symref).to_owned())
            },
            object_id: (*object_id).to_owned(),
        });
    }
    Ok(refs)
}

/// Rejects ref names that could change the meaning of a `<ref>:<ref>`
/// refspec (wildcards, `:`, a leading `+`, revision syntax) or of the
/// command line. Git already forbids these in ref names; this fails closed if
/// one ever appears.
fn validate_refspec_ref(name: &str) -> anyhow::Result<()> {
    let is_unsafe_char = |character: char| {
        character.is_control()
            || character.is_whitespace()
            || matches!(character, '*' | ':' | '?' | '[' | '\\' | '^' | '~')
    };
    if !name.starts_with("refs/")
        || name.contains("..")
        || name.contains("@{")
        || name.chars().any(is_unsafe_char)
    {
        bail!(
            "refusing to mirror unusual ref name {:?}",
            escape_control_chars(name)
        );
    }
    Ok(())
}

/// Splits refs into those visible to a member with no groups (public),
/// restricted ones, and symbolic refs (never pushed themselves).
fn partition_refs(refs: &[LocalRef], policy: &BranchPolicy) -> RefPlan {
    let public_groups: BTreeSet<String> = BTreeSet::new();
    let mut symrefs: BTreeMap<&str, &str> = BTreeMap::new();
    for local_ref in refs {
        if let Some(target) = &local_ref.symref_target {
            symrefs.insert(local_ref.name.as_str(), target.as_str());
        }
    }
    let mut plan = RefPlan::default();
    for local_ref in refs {
        if local_ref.symref_target.is_some() {
            plan.symbolic.push(local_ref.name.clone());
            continue;
        }
        let is_public = policy.is_ref_chain_visible(&local_ref.name, &symrefs, &public_groups)
            && policy.is_ref_visible_case_insensitive(&local_ref.name, &public_groups);
        if is_public {
            plan.public.push(local_ref.clone());
        } else {
            plan.private.push(local_ref.name.clone());
        }
    }
    plan
}

/// Fails unless every file covered by a private-path or withholding rule in
/// every tree reachable from `public_refs` is an encrypted `SCRIMFILE` blob.
fn verify_history_is_safe(
    repo_root: &Path,
    public_refs: &[LocalRef],
    protection: &GlobalProtection,
) -> anyhow::Result<()> {
    let peeled = match peel_refs(repo_root, public_refs) {
        Ok(peeled) => peeled,
        Err(err) => return Err(err),
    };
    let mut commit_ids = Vec::new();
    let mut non_commit_refs = Vec::new();
    for (local_ref, (object_id, object_type)) in public_refs.iter().zip(peeled) {
        if object_type == "commit" {
            commit_ids.push(object_id);
        } else {
            non_commit_refs.push(format!("{} ({object_type})", local_ref.name));
        }
    }

    let commits_and_trees = match list_commit_trees(repo_root, &commit_ids) {
        Ok(pairs) => pairs,
        Err(err) => return Err(err),
    };

    let mut scanned_trees: HashSet<String> = HashSet::new();
    let mut commit_policies: HashMap<String, PathPolicy> = HashMap::new();
    let mut protected: BTreeMap<String, ProtectedBlob> = BTreeMap::new();
    let mut saw_commit_path_rules = false;
    for (commit, tree) in &commits_and_trees {
        if !scanned_trees.insert(tree.clone()) {
            continue;
        }
        let entries = match list_tree(repo_root, tree) {
            Ok(entries) => entries,
            Err(err) => return Err(err),
        };
        let commit_policy =
            match load_commit_policy(repo_root, commit, &entries, &mut commit_policies) {
                Ok(policy) => policy,
                Err(err) => return Err(err),
            };
        if let Some(policy) = commit_policy
            && !policy.is_empty()
        {
            saw_commit_path_rules = true;
        }
        if let Err(err) =
            collect_protected_blobs(commit, &entries, commit_policy, protection, &mut protected)
        {
            return Err(err);
        }
    }

    // A ref pointing straight at a blob or tree carries no repo-relative
    // paths, so its contents cannot be checked against path rules.
    if !non_commit_refs.is_empty() && (!protection.is_empty() || saw_commit_path_rules) {
        bail!(
            "public ref(s) {} point at non-commit objects, which cannot be checked against private path rules",
            non_commit_refs.join(", ")
        );
    }

    let blob_ids: Vec<String> = protected.keys().cloned().collect();
    let prefixes = match read_blob_prefixes(repo_root, &blob_ids) {
        Ok(prefixes) => prefixes,
        Err(err) => return Err(err),
    };
    let mut leaks: Vec<String> = Vec::new();
    for (blob_id, found) in &protected {
        let problem = match prefixes.get(blob_id) {
            Some(Some(prefix)) if is_encrypted_file(prefix) => continue,
            Some(Some(_)) => "stored as plaintext",
            Some(None) | None => "blob is not available locally, so it cannot be verified",
        };
        leaks.push(format!(
            "commit {} path '{}': {} ({problem})",
            found.commit,
            escape_control_chars(&found.path),
            found.reason
        ));
    }
    if leaks.is_empty() {
        return Ok(());
    }
    leaks.sort();
    let total = leaks.len();
    let mut message =
        format!("{total} private file(s) reachable from the refs to mirror are not encrypted:");
    for leak in leaks.iter().take(MAX_REPORTED_LEAKS) {
        message.push_str("\n  ");
        message.push_str(leak);
    }
    if total > MAX_REPORTED_LEAKS {
        message.push_str(&format!("\n  ... and {} more", total - MAX_REPORTED_LEAKS));
    }
    message.push_str(
        "\nExternal mirrors only receive private paths that are encrypted client-side: protect them with \
         'scrim private add <glob> --group <group>' and rewrite the affected history before mirroring.",
    );
    bail!("{message}")
}

/// Parses (and caches by blob ID) the `.scrim/paths.toml` stored in a tree,
/// failing closed when it exists but is invalid.
fn load_commit_policy<'cache>(
    repo_root: &Path,
    commit: &str,
    entries: &[TreeEntry],
    cache: &'cache mut HashMap<String, PathPolicy>,
) -> anyhow::Result<Option<&'cache PathPolicy>> {
    let Some(paths_entry) = entries
        .iter()
        .find(|entry| entry.path == PATHS_FILE.as_bytes())
    else {
        return Ok(None);
    };
    if !cache.contains_key(&paths_entry.object_id) {
        let bytes = match read_object(repo_root, &paths_entry.object_id) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => bail!(
                "commit {commit}: {PATHS_FILE} blob {} is not available locally",
                paths_entry.object_id
            ),
            Err(err) => return Err(err),
        };
        let policy = match parse_paths_file_bytes(&bytes) {
            Ok(policy) => policy,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("commit {commit} has an invalid {PATHS_FILE}"));
            }
        };
        cache.insert(paths_entry.object_id.clone(), policy);
    }
    Ok(cache.get(&paths_entry.object_id))
}

/// Records every blob in `entries` that some rule protects, keeping the first
/// commit and path it was seen at.
fn collect_protected_blobs(
    commit: &str,
    entries: &[TreeEntry],
    commit_policy: Option<&PathPolicy>,
    protection: &GlobalProtection,
    protected: &mut BTreeMap<String, ProtectedBlob>,
) -> anyhow::Result<()> {
    let commit_has_rules = match commit_policy {
        Some(policy) => !policy.is_empty(),
        None => false,
    };
    if protection.is_empty() && !commit_has_rules {
        return Ok(());
    }
    for entry in entries {
        if entry.mode == GITLINK_MODE || entry.object_type != "blob" {
            continue;
        }
        let path = match std::str::from_utf8(&entry.path) {
            Ok(path) => path,
            Err(_) => bail!(
                "commit {commit} contains a non-UTF-8 path ({}) that cannot be checked against private path rules",
                escape_control_chars(&String::from_utf8_lossy(&entry.path))
            ),
        };
        let reason = match protection_reason(path, commit_policy, protection) {
            Ok(reason) => reason,
            Err(err) => return Err(err).with_context(|| format!("commit {commit}")),
        };
        if let Some(reason) = reason {
            protected
                .entry(entry.object_id.clone())
                .or_insert_with(|| ProtectedBlob {
                    commit: commit.to_owned(),
                    path: path.to_owned(),
                    reason,
                });
        }
    }
    Ok(())
}

/// Returns why `path` must be encrypted, or `None` when no rule covers it.
/// Overlapping `.scrim/paths.toml` rules for different groups fail closed.
fn protection_reason(
    path: &str,
    commit_policy: Option<&PathPolicy>,
    protection: &GlobalProtection,
) -> anyhow::Result<Option<String>> {
    if let Some(policy) = commit_policy {
        match policy.is_path_private(path) {
            Ok(true) => return Ok(Some(format!("covered by that commit's {PATHS_FILE}"))),
            Ok(false) => {}
            Err(err) => return Err(anyhow!(err)),
        }
    }
    for (label, policy) in &protection.local_path_policies {
        match policy.is_path_private(path) {
            Ok(true) => return Ok(Some(format!("covered by {label}"))),
            Ok(false) => {}
            Err(err) => return Err(anyhow!(err)).with_context(|| (*label).to_owned()),
        }
    }
    let public_groups: BTreeSet<String> = BTreeSet::new();
    if protection.withhold.is_path_withheld(path, &public_groups)
        || protection
            .withhold
            .is_path_withheld_case_insensitive(path, &public_groups)
    {
        return Ok(Some("withheld by the server's path rules".to_owned()));
    }
    Ok(None)
}

/// Fully peels each ref's object (through annotated tags), returning
/// `(object_id, object_type)` in input order.
fn peel_refs(repo_root: &Path, refs: &[LocalRef]) -> anyhow::Result<Vec<(String, String)>> {
    let mut input = Vec::new();
    for local_ref in refs {
        input.extend_from_slice(local_ref.object_id.as_bytes());
        input.extend_from_slice(b"^{}\n");
    }
    let mut command = git_inspect_command(repo_root);
    command.args(["cat-file", "--batch-check=%(objectname) %(objecttype)"]);
    let stdout = match run_with_input(command, input, "git cat-file --batch-check") {
        Ok(stdout) => stdout,
        Err(err) => return Err(err),
    };
    let text = match String::from_utf8(stdout) {
        Ok(text) => text,
        Err(_) => bail!("git cat-file --batch-check output was not valid UTF-8"),
    };
    let mut peeled = Vec::with_capacity(refs.len());
    for (local_ref, line) in refs.iter().zip(text.lines()) {
        match line.split_once(' ') {
            Some((object_id, object_type)) if object_type != "missing" => {
                peeled.push((object_id.to_owned(), object_type.to_owned()));
            }
            _ => bail!("cannot resolve {} ({line})", local_ref.name),
        }
    }
    if peeled.len() != refs.len() {
        bail!("git cat-file --batch-check returned too few lines");
    }
    Ok(peeled)
}

/// Lists every commit reachable from `commit_ids` with its root tree.
fn list_commit_trees(
    repo_root: &Path,
    commit_ids: &[String],
) -> anyhow::Result<Vec<(String, String)>> {
    if commit_ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::new();
    for commit_id in commit_ids {
        input.extend_from_slice(commit_id.as_bytes());
        input.push(b'\n');
    }
    let mut command = git_inspect_command(repo_root);
    command.args(["rev-list", "--stdin", "--format=%T"]);
    let stdout = match run_with_input(command, input, "git rev-list") {
        Ok(stdout) => stdout,
        Err(err) => return Err(err),
    };
    parse_commit_trees(&stdout)
}

/// Parses `git rev-list --format=%T` output: a `commit <id>` line followed by
/// that commit's tree ID.
fn parse_commit_trees(stdout: &[u8]) -> anyhow::Result<Vec<(String, String)>> {
    let text = match std::str::from_utf8(stdout) {
        Ok(text) => text,
        Err(_) => bail!("git rev-list output was not valid UTF-8"),
    };
    let mut pairs = Vec::new();
    let mut current_commit: Option<&str> = None;
    for line in text.lines() {
        if let Some(commit) = line.strip_prefix("commit ") {
            current_commit = Some(commit);
            continue;
        }
        match current_commit.take() {
            Some(commit) if !line.is_empty() => pairs.push((commit.to_owned(), line.to_owned())),
            _ => bail!("unexpected git rev-list output line {line:?}"),
        }
    }
    if current_commit.is_some() {
        bail!("git rev-list output ended without a tree ID");
    }
    Ok(pairs)
}

/// One `git ls-tree -r` entry.
#[derive(Debug, PartialEq, Eq)]
struct TreeEntry {
    mode: String,
    object_type: String,
    object_id: String,
    /// Raw repo-relative path; Git paths need not be UTF-8.
    path: Vec<u8>,
}

fn list_tree(repo_root: &Path, tree: &str) -> anyhow::Result<Vec<TreeEntry>> {
    let mut command = git_inspect_command(repo_root);
    command.args(["ls-tree", "-r", "-z", tree]);
    let output = match command.output() {
        Ok(output) => output,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git ls-tree"),
    };
    if !output.status.success() {
        bail!(
            "git ls-tree {tree} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    parse_tree_listing(&output.stdout)
}

/// Parses NUL-terminated `<mode> SP <type> SP <id> TAB <path>` records.
fn parse_tree_listing(stdout: &[u8]) -> anyhow::Result<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    for record in stdout.split(|&byte| byte == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(tab_index) = record.iter().position(|&byte| byte == b'\t') else {
            bail!("unexpected git ls-tree record without a path");
        };
        let header = match std::str::from_utf8(&record[..tab_index]) {
            Ok(header) => header,
            Err(_) => bail!("unexpected non-UTF-8 git ls-tree header"),
        };
        let fields: Vec<&str> = header.split(' ').collect();
        let [mode, object_type, object_id] = fields.as_slice() else {
            bail!("unexpected git ls-tree header {header:?}");
        };
        entries.push(TreeEntry {
            mode: (*mode).to_owned(),
            object_type: (*object_type).to_owned(),
            object_id: (*object_id).to_owned(),
            path: record[tab_index + 1..].to_vec(),
        });
    }
    Ok(entries)
}

/// Reads the first [`ENCRYPTED_FILE_MAGIC`]-length bytes of each blob with one
/// streaming `git cat-file --batch`, so large blobs are never buffered whole.
/// A `None` value means the blob is missing locally.
fn read_blob_prefixes(
    repo_root: &Path,
    blob_ids: &[String],
) -> anyhow::Result<HashMap<String, Option<Vec<u8>>>> {
    if blob_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut input = Vec::new();
    for blob_id in blob_ids {
        input.extend_from_slice(blob_id.as_bytes());
        input.push(b'\n');
    }
    let mut command = git_inspect_command(repo_root);
    command
        .args(["cat-file", "--batch"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => return Err(anyhow!(err)).context("failed to execute git cat-file --batch"),
    };
    let writer = match spawn_stdin_writer(&mut child, input) {
        Ok(writer) => writer,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    let read_result = match child.stdout.take() {
        Some(stdout) => read_batch_prefixes(&mut BufReader::new(stdout), blob_ids),
        None => Err(anyhow!("git cat-file --batch stdout was not captured")),
    };
    if read_result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait();
    let writer_result = join_stdin_writer(writer, "git cat-file --batch");
    let prefixes = match read_result {
        Ok(prefixes) => prefixes,
        Err(err) => return Err(err),
    };
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => bail!("git cat-file --batch exited with status {status}"),
        Err(err) => return Err(anyhow!(err)).context("failed to wait for git cat-file --batch"),
    }
    match writer_result {
        Ok(()) => Ok(prefixes),
        Err(err) => Err(err),
    }
}

/// Reads one `git cat-file --batch` response per ID in `blob_ids`, keeping
/// only each blob's leading magic-length bytes.
fn read_batch_prefixes<R: BufRead>(
    reader: &mut R,
    blob_ids: &[String],
) -> anyhow::Result<HashMap<String, Option<Vec<u8>>>> {
    let mut prefixes = HashMap::with_capacity(blob_ids.len());
    for blob_id in blob_ids {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) => bail!("git cat-file --batch ended before reporting {blob_id}"),
            Ok(_) => {}
            Err(err) => {
                return Err(anyhow!(err)).context("failed to read git cat-file --batch output");
            }
        }
        let fields: Vec<&str> = header.trim_end_matches('\n').split(' ').collect();
        match fields.as_slice() {
            [name, "missing"] if *name == blob_id.as_str() => {
                prefixes.insert(blob_id.clone(), None);
            }
            [name, "blob", size] if *name == blob_id.as_str() => {
                let size = match size.parse::<u64>() {
                    Ok(size) => size,
                    Err(_) => bail!("invalid blob size in git cat-file output {header:?}"),
                };
                let prefix_length = size.min(ENCRYPTED_FILE_MAGIC.len() as u64);
                let mut prefix = vec![0_u8; prefix_length as usize];
                if let Err(err) = reader.read_exact(&mut prefix) {
                    return Err(anyhow!(err)).context("failed to read blob from git cat-file");
                }
                // The rest of the blob plus the record's trailing newline.
                let remaining = size - prefix_length + 1;
                match io::copy(&mut reader.by_ref().take(remaining), &mut io::sink()) {
                    Ok(copied) if copied == remaining => {}
                    Ok(_) => bail!("git cat-file --batch output ended inside blob {blob_id}"),
                    Err(err) => {
                        return Err(anyhow!(err)).context("failed to read blob from git cat-file");
                    }
                }
                prefixes.insert(blob_id.clone(), Some(prefix));
            }
            _ => bail!(
                "unexpected git cat-file --batch output {:?} for {blob_id}",
                header.trim_end()
            ),
        }
    }
    Ok(prefixes)
}

/// Runs `command` with `input` on stdin (written from a separate thread so a
/// full stdout pipe cannot deadlock) and returns its stdout.
fn run_with_input(
    mut command: Command,
    input: Vec<u8>,
    description: &str,
) -> anyhow::Result<Vec<u8>> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| format!("failed to execute {description}"));
        }
    };
    let writer = match spawn_stdin_writer(&mut child, input) {
        Ok(writer) => writer,
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err);
        }
    };
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| format!("failed to wait for {description}"));
        }
    };
    let writer_result = join_stdin_writer(writer, description);
    if !output.status.success() {
        bail!(
            "{description} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    match writer_result {
        Ok(()) => Ok(output.stdout),
        Err(err) => Err(err),
    }
}

fn spawn_stdin_writer(
    child: &mut Child,
    input: Vec<u8>,
) -> anyhow::Result<JoinHandle<io::Result<()>>> {
    let Some(mut stdin) = child.stdin.take() else {
        bail!("child process stdin was not captured");
    };
    // Dropping `stdin` when the closure returns closes the pipe.
    Ok(thread::spawn(move || stdin.write_all(&input)))
}

fn join_stdin_writer(writer: JoinHandle<io::Result<()>>, description: &str) -> anyhow::Result<()> {
    match writer.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => {
            Err(anyhow!(err)).with_context(|| format!("failed to write to {description}"))
        }
        Err(_) => bail!("stdin writer for {description} panicked"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn branch_policy(rules: &[(&str, &[&str])]) -> BranchPolicy {
        let mut compiled = Vec::new();
        for (pattern, groups) in rules {
            match BranchRule::new(*pattern, groups.iter().map(|group| (*group).to_owned())) {
                Ok(rule) => compiled.push(rule),
                Err(err) => panic!("invalid test rule {pattern}: {err}"),
            }
        }
        match BranchPolicy::compile(compiled) {
            Ok(policy) => policy,
            Err(err) => panic!("compile test policy: {err}"),
        }
    }

    fn local_ref(name: &str, symref_target: Option<&str>) -> LocalRef {
        LocalRef {
            name: name.to_owned(),
            symref_target: symref_target.map(str::to_owned),
            object_id: "a".repeat(40),
        }
    }

    #[test]
    fn validates_mirror_targets() {
        for target in [
            "github",
            "https://github.com/org/repo.git",
            "git@github.com:org/repo.git",
            "/tmp/mirror.git",
        ] {
            assert!(validate_mirror_target(target).is_ok(), "{target}");
        }
        for target in ["", "-u", "--mirror", "has space", "tab\there", "nl\nx"] {
            assert!(validate_mirror_target(target).is_err(), "{target:?}");
        }
    }

    #[test]
    fn redacts_url_credentials_only() {
        assert_eq!(
            redact_target("https://user:tok@github.com/org/repo.git"),
            "https://***@github.com/org/repo.git"
        );
        assert_eq!(
            redact_target("https://github.com/org/a@b.git"),
            "https://github.com/org/a@b.git"
        );
        assert_eq!(
            redact_target("git@github.com:org/repo.git"),
            "git@github.com:org/repo.git"
        );
    }

    #[test]
    fn parses_ref_listing_and_rejects_unsafe_names() {
        let listing = b"refs/heads/main\0\0aaaa\nrefs/heads/alias\0refs/heads/private/x\0bbbb\n";
        let refs = match parse_ref_listing(listing) {
            Ok(refs) => refs,
            Err(err) => panic!("parse: {err}"),
        };
        assert_eq!(
            refs,
            vec![
                LocalRef {
                    name: "refs/heads/main".to_owned(),
                    symref_target: None,
                    object_id: "aaaa".to_owned(),
                },
                LocalRef {
                    name: "refs/heads/alias".to_owned(),
                    symref_target: Some("refs/heads/private/x".to_owned()),
                    object_id: "bbbb".to_owned(),
                },
            ]
        );
        for bad in [
            &b"refs/heads/a*b\0\0aaaa\n"[..],
            b"refs/heads/a:b\0\0aaaa\n",
            b"HEAD\0\0aaaa\n",
            b"refs/heads/main\0aaaa\n",
        ] {
            assert!(parse_ref_listing(bad).is_err());
        }
    }

    #[test]
    fn partitions_public_private_and_symbolic_refs() {
        let policy = branch_policy(&[
            ("refs/heads/private/*", &["core"]),
            ("refs/tags/private-*", &["core"]),
        ]);
        let refs = vec![
            local_ref("refs/heads/main", None),
            local_ref("refs/heads/private/secret", None),
            // Case variants collide on case-insensitive file systems.
            local_ref("refs/heads/Private/secret", None),
            local_ref("refs/heads/alias", Some("refs/heads/private/secret")),
            local_ref("refs/tags/v1.0", None),
            local_ref("refs/tags/private-v1", None),
        ];
        let plan = partition_refs(&refs, &policy);
        let public: Vec<&str> = plan.public.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(public, vec!["refs/heads/main", "refs/tags/v1.0"]);
        assert_eq!(
            plan.private,
            vec![
                "refs/heads/private/secret",
                "refs/heads/Private/secret",
                "refs/tags/private-v1"
            ]
        );
        assert_eq!(plan.symbolic, vec!["refs/heads/alias"]);
    }

    #[test]
    fn parses_rev_list_and_ls_tree_output() {
        let pairs = match parse_commit_trees(b"commit c1\nt1\ncommit c2\nt2\n") {
            Ok(pairs) => pairs,
            Err(err) => panic!("parse rev-list: {err}"),
        };
        assert_eq!(
            pairs,
            vec![
                ("c1".to_owned(), "t1".to_owned()),
                ("c2".to_owned(), "t2".to_owned())
            ]
        );
        assert!(parse_commit_trees(b"commit c1\n").is_err());
        assert!(parse_commit_trees(b"t1\n").is_err());

        let entries = match parse_tree_listing(
            b"100644 blob b1\tdocs/a b.txt\x00160000 commit c9\tvendor/sub\0",
        ) {
            Ok(entries) => entries,
            Err(err) => panic!("parse ls-tree: {err}"),
        };
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, b"docs/a b.txt");
        assert_eq!(entries[1].mode, GITLINK_MODE);
        assert!(parse_tree_listing(b"100644 blob b1 no-tab\0").is_err());
    }

    #[test]
    fn reads_batch_prefixes_and_skips_blob_bodies() {
        let mut output = Vec::new();
        output.extend_from_slice(b"b1 blob 14\nSCRIMFILE\0rest\n");
        output.extend_from_slice(b"b2 missing\n");
        output.extend_from_slice(b"b3 blob 3\nabc\n");
        let ids = vec!["b1".to_owned(), "b2".to_owned(), "b3".to_owned()];
        let prefixes = match read_batch_prefixes(&mut Cursor::new(output), &ids) {
            Ok(prefixes) => prefixes,
            Err(err) => panic!("read batch: {err}"),
        };
        assert_eq!(prefixes.get("b1"), Some(&Some(b"SCRIMFILE\0".to_vec())));
        assert_eq!(prefixes.get("b2"), Some(&None));
        assert_eq!(prefixes.get("b3"), Some(&Some(b"abc".to_vec())));

        let truncated = b"b1 blob 14\nSCRIMFILE\0".to_vec();
        assert!(read_batch_prefixes(&mut Cursor::new(truncated), &ids[..1]).is_err());
        let mismatched = b"zz blob 1\na\n".to_vec();
        assert!(read_batch_prefixes(&mut Cursor::new(mismatched), &ids[..1]).is_err());
    }

    #[test]
    fn reports_protection_reasons_and_fails_closed_on_ambiguity() {
        let withhold = match WithholdRule::new("config/billing/**", vec!["finance".to_owned()]) {
            Ok(rule) => match WithholdPolicy::compile(vec![rule]) {
                Ok(policy) => policy,
                Err(err) => panic!("compile withhold: {err}"),
            },
            Err(err) => panic!("withhold rule: {err}"),
        };
        let protection = GlobalProtection {
            withhold,
            local_path_policies: Vec::new(),
        };
        let commit_policy = match parse_path_policy(
            "version = 1\n[[rules]]\npattern = \"docs/**\"\ngroup = \"a\"\n[[rules]]\npattern = \"docs/x/**\"\ngroup = \"b\"\n",
        ) {
            Ok(policy) => policy,
            Err(err) => panic!("parse paths.toml: {err}"),
        };

        let reason = |path: &str| protection_reason(path, Some(&commit_policy), &protection);
        assert!(matches!(reason("README.md"), Ok(None)));
        assert!(matches!(reason("docs/a.md"), Ok(Some(text)) if text.contains("that commit")));
        assert!(matches!(reason("CONFIG/billing/a"), Ok(Some(text)) if text.contains("withheld")));
        assert!(reason("docs/x/y.md").is_err());
        assert!(matches!(reason(".scrim/paths.toml"), Ok(None)));
    }
}
