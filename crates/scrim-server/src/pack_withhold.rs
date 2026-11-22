//! Per-member blob withholding for fetches and clones.
//!
//! When a repository has path withholding rules the member does not satisfy
//! (see [`scrim_policy::WithholdPolicy`]), `git upload-pack` runs with
//! `uploadpack.packObjectsHook` pointing at the `pack-objects` link in the
//! server's [`HookDir`], so every pack it would send is built by this module
//! instead of by a plain `git pack-objects --revs`.
//!
//! Started by git with [`PACK_OBJECTS_HOOK_MODE_ENV`] set to
//! [`PACK_OBJECTS_HOOK_MODE`], the scrim-server binary runs
//! [`run_pack_objects_hook_process`]: it fetches the member's policy from the
//! callback listener the server opened for that request
//! ([`start_pack_withhold_session`]), walks the object graph itself with
//! [`compute_allowed_pack_objects`], and feeds the resulting explicit object
//! list to an isolated `git pack-objects --stdout` whose output goes straight
//! back to `git upload-pack`.
//!
//! # What is sent
//!
//! Every commit, annotated tag and tree the client asked for (so history and
//! sparse checkouts work), plus every blob reached at a path that is not
//! withheld from the member. A blob reached only at withheld paths is never
//! listed, and `--thin` is never passed, so `pack-objects` cannot even use it
//! as a delta base. Wants that name a tree or blob directly (or a tag peeling
//! to one) are refused: without a commit there is no path to judge them by.
//!
//! # Callback transport
//!
//! Same as the `pre-receive` hook (see [`crate::pre_receive`]): a per-request
//! Unix socket inside the `0700` [`HookDir`] (an ephemeral loopback port
//! elsewhere), and proofs of a random token in both directions
//! (`hex(sha256("scrim-pack-hook-request:" || token))` and
//! `hex(sha256("scrim-pack-hook-response:" || token))`), compared in constant
//! time. The answer carries only the member's groups, the withholding rules
//! and the tag refs the member may see, so it stays small whatever the
//! repository size.
//!
//! Every failure (bad arguments, an unreachable or unauthenticated server, an
//! unreadable object, a failing `pack-objects`) exits non-zero before any pack
//! byte is written, so `git upload-pack` aborts the fetch.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use gix::{
    ObjectId,
    objs::{Kind, tree::EntryKind},
};
use scrim_policy::{WithholdPolicy, WithholdRule};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tokio::io::AsyncWriteExt;
use tokio_util::task::AbortOnDropHandle;
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use crate::pre_receive::CallbackSocketFile;
use crate::{
    git_service::list_repo_refs,
    policy_store::MemberRepoPolicy,
    pre_receive::{
        CallbackConnection, CallbackListener, CallbackRequest, HookDir, PRE_RECEIVE_HOOK_MODE_ENV,
        TOKEN_BYTES, accept_authenticated_callback, bind_callback_listener, derive_proof,
        generate_random_hex, invalid_input, send_callback_request,
    },
};

/// Environment variable that switches the scrim-server binary into a hook
/// mode; shared with the `pre-receive` hook.
pub const PACK_OBJECTS_HOOK_MODE_ENV: &str = PRE_RECEIVE_HOOK_MODE_ENV;

/// Value of [`PACK_OBJECTS_HOOK_MODE_ENV`] that runs the `pack-objects` hook.
pub const PACK_OBJECTS_HOOK_MODE: &str = "pack-objects";

/// Address of the request's callback listener: the socket path on Unix, a
/// loopback `127.0.0.1:<port>` elsewhere.
const PACK_HOOK_ADDR_ENV: &str = "SCRIM_PACK_HOOK_ADDR";

/// Per-request token both sides derive their proofs from.
const PACK_HOOK_TOKEN_ENV: &str = "SCRIM_PACK_HOOK_TOKEN";

/// Domain prefix of the proof the hook sends with its request.
const REQUEST_PROOF_DOMAIN: &str = "scrim-pack-hook-request:";

/// Domain prefix of the proof the server sends with its answer.
const RESPONSE_PROOF_DOMAIN: &str = "scrim-pack-hook-response:";

/// Most bytes of `git upload-pack`'s object list the hook reads.
const MAX_PACK_HOOK_STDIN_BYTES: usize = 16 * 1024 * 1024;

/// Most bytes of a shallow file the hook reads.
const MAX_SHALLOW_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Largest callback request the server accepts (it only carries a proof).
const MAX_PACK_HOOK_REQUEST_BYTES: usize = 4 * 1024;

/// Largest callback answer the hook accepts: rules and visible tag names.
const MAX_PACK_HOOK_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Most annotated tags followed when peeling one object.
const MAX_TAG_DEPTH: usize = 32;

/// Deepest tree nesting walked before failing closed.
const MAX_TREE_DEPTH: usize = 256;

/// `git pack-objects` flags passed through unchanged; none of them changes
/// which objects are packed.
const FORWARDED_FLAGS: [&str; 5] = [
    "--delta-base-offset",
    "--progress",
    "--non-empty",
    "--quiet",
    "-q",
];

/// Printed when a fetch without a partial-clone filter misses withheld blobs:
/// the client's connectivity check is about to fail.
const WITHHELD_NOTICE: &str =
    "scrim: withheld protected file(s); use 'scrim clone' for a partial sparse checkout\n";

/// What the hook sends to the callback listener.
#[derive(Serialize, Deserialize)]
struct PackHookRequest {
    /// `hex(sha256(REQUEST_PROOF_DOMAIN || token))`; the token itself is
    /// never sent.
    request_proof: String,
}

impl CallbackRequest for PackHookRequest {
    const MAX_BYTES: usize = MAX_PACK_HOOK_REQUEST_BYTES;

    fn request_proof_mut(&mut self) -> &mut String {
        &mut self.request_proof
    }
}

/// One withholding rule as sent to the hook.
#[derive(Serialize, Deserialize)]
struct WithholdRuleRecord {
    pattern: String,
    allowed_groups: Vec<String>,
}

/// The server's answer: everything the hook needs to select objects.
#[derive(Serialize, Deserialize)]
struct PackHookResponse {
    /// `hex(sha256(RESPONSE_PROOF_DOMAIN || token))`. A missing or wrong
    /// proof makes the hook refuse the fetch.
    #[serde(default)]
    response_proof: String,
    /// Canonical directory of the bare repository.
    repo_dir: String,
    /// The member's groups.
    member_groups: Vec<String>,
    /// The repository's withholding rules.
    withhold_rules: Vec<WithholdRuleRecord>,
    /// `refs/tags/*` refs the member may see; only these feed
    /// `--include-tag`. Sent as names because branch rules are only
    /// available compiled on the server.
    visible_tag_refs: Vec<String>,
}

/// Runs the `pack-objects` hook and returns the process exit code: the exit
/// code of the filtered `git pack-objects`, or `1` (with a short reason on
/// stderr, which git relays to the client) if anything failed before it ran.
///
/// Uses only blocking `std` I/O, so no async runtime is started in the hook
/// process.
pub fn run_pack_objects_hook_process() -> i32 {
    match run_pack_objects_hook() {
        Ok(exit_code) => exit_code,
        Err(error) => {
            // Nothing useful can be done if stderr is gone; the exit code
            // still aborts the fetch.
            let _ = writeln!(
                io::stderr(),
                "scrim: fetch refused: the server could not prepare the pack ({error})"
            );
            1
        }
    }
}

fn run_pack_objects_hook() -> io::Result<i32> {
    let callback_address = match std::env::var_os(PACK_HOOK_ADDR_ENV) {
        Some(address) if !address.is_empty() => address,
        _ => return Err(invalid_input(format!("{PACK_HOOK_ADDR_ENV} is not set"))),
    };
    let token = match std::env::var(PACK_HOOK_TOKEN_ENV) {
        Ok(token) => Zeroizing::new(token),
        Err(_) => return Err(invalid_input(format!("{PACK_HOOK_TOKEN_ENV} is not set"))),
    };
    let mut pack_args = Vec::new();
    for argument in std::env::args_os().skip(1) {
        match argument.into_string() {
            Ok(argument) => pack_args.push(argument),
            Err(_) => return Err(invalid_input("non-UTF-8 argument".to_owned())),
        }
    }
    let mut stdin_bytes = Vec::new();
    let mut limited_stdin = io::stdin()
        .lock()
        .take(MAX_PACK_HOOK_STDIN_BYTES as u64 + 1);
    if let Err(error) = limited_stdin.read_to_end(&mut stdin_bytes) {
        return Err(error);
    }
    if stdin_bytes.len() > MAX_PACK_HOOK_STDIN_BYTES {
        return Err(invalid_input("too many objects requested".to_owned()));
    }

    let response = match fetch_pack_policy(&callback_address, &token) {
        Ok(response) => response,
        Err(error) => return Err(error),
    };
    let mut rules = Vec::with_capacity(response.withhold_rules.len());
    for record in response.withhold_rules {
        match WithholdRule::new(record.pattern, record.allowed_groups) {
            Ok(rule) => rules.push(rule),
            Err(_) => return Err(invalid_input("invalid withholding rule".to_owned())),
        }
    }
    let withhold_policy = match WithholdPolicy::compile(rules) {
        Ok(withhold_policy) => withhold_policy,
        Err(_) => return Err(invalid_input("invalid withholding rules".to_owned())),
    };
    let member_groups: BTreeSet<String> = response.member_groups.into_iter().collect();
    let repo_dir = PathBuf::from(response.repo_dir);

    let selection = match compute_allowed_pack_objects(
        &repo_dir,
        &pack_args,
        &stdin_bytes,
        &withhold_policy,
        &member_groups,
        &response.visible_tag_refs,
    ) {
        Ok(selection) => selection,
        Err(error) => return Err(error),
    };
    if selection.filter == ClientObjectFilter::None && selection.withheld_any_blob {
        let _ = io::stderr().write_all(WITHHELD_NOTICE.as_bytes());
    }
    run_filtered_pack_objects(&repo_dir, &selection)
}

/// Asks the callback listener at `callback_address` for the member's policy
/// and checks its response proof in constant time.
fn fetch_pack_policy(callback_address: &OsStr, token: &str) -> io::Result<PackHookResponse> {
    let request_proof = derive_proof(REQUEST_PROOF_DOMAIN, token);
    let expected_response_proof = derive_proof(RESPONSE_PROOF_DOMAIN, token);
    let mut request = PackHookRequest {
        request_proof: request_proof.as_str().to_owned(),
    };
    let serialized = serde_json::to_vec(&request);
    request.request_proof.zeroize();
    let request_bytes = match serialized {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) => return Err(io::Error::other(error)),
    };
    let response_bytes = match send_callback_request(
        callback_address,
        &request_bytes,
        MAX_PACK_HOOK_RESPONSE_BYTES,
    ) {
        Ok(response_bytes) => response_bytes,
        Err(error) => return Err(error),
    };
    let mut response = match serde_json::from_slice::<PackHookResponse>(&response_bytes) {
        Ok(response) => response,
        Err(_) => {
            return Err(invalid_input(
                "unreadable response from the server".to_owned(),
            ));
        }
    };
    let is_authentic = bool::from(
        response
            .response_proof
            .as_bytes()
            .ct_eq(expected_response_proof.as_bytes()),
    );
    response.response_proof.zeroize();
    if is_authentic {
        Ok(response)
    } else {
        Err(invalid_input(
            "the server's answer could not be authenticated".to_owned(),
        ))
    }
}

/// Runs `git pack-objects --stdout <forwarded flags>` on `repo_dir` with the
/// same isolated environment as every other git invocation, writes the
/// selected objects to its stdin and lets it write the pack straight to the
/// hook's stdout. Returns its exit code.
fn run_filtered_pack_objects(repo_dir: &Path, selection: &PackSelection) -> io::Result<i32> {
    let mut command = std::process::Command::new("git");
    command
        .arg("--git-dir")
        .arg(repo_dir)
        .args(["pack-objects", "--stdout"])
        .args(&selection.forwarded_flags);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Err(error),
    };
    let write_result = match child.stdin.take() {
        Some(mut stdin) => stdin.write_all(&selection.object_list()),
        None => Err(io::Error::other("git stdin was not piped")),
    };
    if let Err(error) = write_result {
        // pack-objects must not finish a pack from a truncated list.
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    match child.wait() {
        Ok(status) => match status.code() {
            Some(code) => Ok(code),
            None => Ok(1),
        },
        Err(error) => Err(error),
    }
}

/// Everything the server needs to answer one fetch's `pack-objects` hook.
pub(crate) struct PackWithholdContext {
    /// Canonical directory of the bare repository.
    pub repo_dir: PathBuf,
    /// The member's groups and the repository's branch and withholding rules.
    pub policy: MemberRepoPolicy,
}

/// The hook environment for one `git upload-pack`, plus what must outlive
/// it: the hook directory and the callback listener task.
///
/// Dropping the session aborts the listener (and on Unix removes its socket
/// file), so it lives as long as the git process (it is kept in the response
/// stream).
pub(crate) struct PackWithholdSession {
    // Declared first so they are dropped before `hook_dir`, which may be the
    // last reference to the directory holding the socket.
    _callback_task: AbortOnDropHandle<()>,
    #[cfg(unix)]
    _callback_socket: CallbackSocketFile,
    hook_dir: Arc<HookDir>,
    callback_address: OsString,
    token: Zeroizing<String>,
}

impl PackWithholdSession {
    /// See [`HookDir::verify_installed`].
    pub(crate) fn verify_hook_installed(&self) -> io::Result<()> {
        self.hook_dir.verify_installed()
    }

    /// The `pack-objects` hook path, quoted for the shell git runs
    /// `uploadpack.packObjectsHook` with.
    pub(crate) fn hook_command(&self) -> io::Result<String> {
        match self
            .hook_dir
            .pack_objects_hook_path()
            .into_os_string()
            .into_string()
        {
            Ok(path) => shell_quote(&path),
            Err(_) => Err(invalid_input("non-UTF-8 hook path".to_owned())),
        }
    }

    /// The `(name, value)` environment variables `git upload-pack` passes on
    /// to the hook.
    pub(crate) fn hook_env(&self) -> [(&'static str, OsString); 3] {
        [
            (
                PACK_OBJECTS_HOOK_MODE_ENV,
                OsString::from(PACK_OBJECTS_HOOK_MODE),
            ),
            (PACK_HOOK_ADDR_ENV, self.callback_address.clone()),
            (PACK_HOOK_TOKEN_ENV, OsString::from(self.token.as_str())),
        ]
    }
}

/// Quotes `text` as one POSIX shell word: wrapped in `'`, with each `'`
/// written as `'\''`. Rejects NUL, CR and LF, which git config values and the
/// shell cannot carry safely.
fn shell_quote(text: &str) -> io::Result<String> {
    if text.contains(['\0', '\r', '\n']) {
        return Err(invalid_input("unquotable hook path".to_owned()));
    }
    Ok(format!("'{}'", text.replace('\'', "'\\''")))
}

/// Opens the callback listener for one `POST git-upload-pack` whose member
/// has withheld paths. It answers exactly one connection, the first to
/// present the session's request proof, with the member's policy.
pub(crate) async fn start_pack_withhold_session(
    hook_dir: Arc<HookDir>,
    context: PackWithholdContext,
) -> io::Result<PackWithholdSession> {
    let token = match generate_random_hex(TOKEN_BYTES) {
        Ok(token) => token,
        Err(error) => return Err(error),
    };
    let bound = match bind_callback_listener(&hook_dir).await {
        Ok(bound) => bound,
        Err(error) => return Err(error),
    };
    let callback_task = AbortOnDropHandle::new(tokio::spawn(answer_pack_hook_callback(
        bound.listener,
        derive_proof(REQUEST_PROOF_DOMAIN, &token),
        derive_proof(RESPONSE_PROOF_DOMAIN, &token),
        context,
    )));
    Ok(PackWithholdSession {
        _callback_task: callback_task,
        #[cfg(unix)]
        _callback_socket: bound.socket_file,
        hook_dir,
        callback_address: bound.address,
        token,
    })
}

/// Waits for the hook's authenticated request on `listener` and answers it
/// with the member's policy. On any failure the hook gets no answer and
/// refuses the fetch.
async fn answer_pack_hook_callback(
    listener: CallbackListener,
    expected_request_proof: Zeroizing<String>,
    response_proof: Zeroizing<String>,
    context: PackWithholdContext,
) {
    let Some((mut stream, _request)) =
        accept_authenticated_callback::<PackHookRequest>(listener, &expected_request_proof).await
    else {
        return;
    };
    let mut response = match build_pack_hook_response(&context).await {
        Ok(response) => response,
        Err(error) => {
            tracing::error!(%error, "cannot answer the pack-objects hook");
            return;
        }
    };
    response.response_proof = response_proof.as_str().to_owned();
    let serialized = serde_json::to_vec(&response);
    response.response_proof.zeroize();
    let response_bytes = match serialized {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) => {
            tracing::error!(%error, "cannot serialize the pack-objects hook answer");
            return;
        }
    };
    send_pack_hook_response(&mut stream, &response_bytes).await;
}

async fn send_pack_hook_response(stream: &mut CallbackConnection, response_bytes: &[u8]) {
    if let Err(error) = stream.write_all(response_bytes).await {
        tracing::warn!(%error, "failed to answer the pack-objects hook");
        return;
    }
    if let Err(error) = stream.shutdown().await {
        tracing::debug!(%error, "failed to close the pack-objects hook callback");
    }
}

/// Builds the hook's answer, listing the repository's tag refs now (while
/// the fetch runs) to find those the member may see.
async fn build_pack_hook_response(context: &PackWithholdContext) -> io::Result<PackHookResponse> {
    let policy = &context.policy;
    let repo_dir = match context.repo_dir.to_str() {
        Some(repo_dir) => repo_dir.to_owned(),
        None => return Err(invalid_input("non-UTF-8 repository path".to_owned())),
    };
    let repo_refs = match list_repo_refs(&context.repo_dir).await {
        Ok(repo_refs) => repo_refs,
        Err(error) => return Err(error),
    };
    let symrefs: BTreeMap<&str, &str> = repo_refs
        .iter()
        .filter_map(|entry| {
            entry
                .symref_target
                .as_deref()
                .map(|target| (entry.name.as_str(), target))
        })
        .collect();
    let visible_tag_refs = repo_refs
        .iter()
        .filter(|entry| {
            entry.name.starts_with("refs/tags/")
                && policy.branch_policy.is_ref_chain_visible(
                    &entry.name,
                    &symrefs,
                    &policy.member_groups,
                )
        })
        .map(|entry| entry.name.clone())
        .collect();
    Ok(PackHookResponse {
        response_proof: String::new(),
        repo_dir,
        member_groups: policy.member_groups.iter().cloned().collect(),
        withhold_rules: policy
            .withhold_policy
            .rules()
            .iter()
            .map(|rule| WithholdRuleRecord {
                pattern: rule.pattern.clone(),
                allowed_groups: rule.allowed_groups.iter().cloned().collect(),
            })
            .collect(),
        visible_tag_refs,
    })
}

/// The partial-clone filter the client asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientObjectFilter {
    /// No filter: the client expects every object.
    None,
    /// `blob:none`: no blobs at all.
    BlobNone,
    /// `blob:limit=<n>`: only blobs smaller than `n` bytes.
    BlobLimit(u64),
}

/// The parts of the hook's arguments that matter.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PackObjectsArgs {
    /// `--shallow-file <path>` before `pack-objects`, when non-empty.
    shallow_file: Option<String>,
    /// `--include-tag`.
    include_tag: bool,
    filter: ClientObjectFilter,
    /// Flags from [`FORWARDED_FLAGS`] and `--compression=<level>`.
    forwarded_flags: Vec<String>,
}

/// `git upload-pack`'s object list (`--revs` format).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PackObjectsInput {
    wants: Vec<ObjectId>,
    haves: Vec<ObjectId>,
    shallow_commits: HashSet<ObjectId>,
}

/// The outcome of [`compute_allowed_pack_objects`].
#[derive(Debug)]
pub(crate) struct PackSelection {
    /// Objects to pack, each with an optional path hint for delta selection.
    pub objects: Vec<(ObjectId, Option<String>)>,
    /// Whether some blob was left out because its path is withheld.
    pub withheld_any_blob: bool,
    pub filter: ClientObjectFilter,
    /// Flags passed on to `git pack-objects`.
    pub forwarded_flags: Vec<String>,
}

impl PackSelection {
    /// The `git pack-objects` stdin: `<oid>` or `<oid> <path>` per line.
    fn object_list(&self) -> Vec<u8> {
        let mut list = Vec::with_capacity(self.objects.len() * 64);
        for (object_id, path_hint) in &self.objects {
            list.extend_from_slice(object_id.to_string().as_bytes());
            if let Some(path_hint) = path_hint {
                list.push(b' ');
                list.extend_from_slice(path_hint.as_bytes());
            }
            list.push(b'\n');
        }
        list
    }
}

/// Selects the objects a member of `member_groups` may receive for one
/// `pack-objects` run.
///
/// `pack_args` are the hook's arguments after its own name (`git
/// [--shallow-file <path>] pack-objects --revs ...`) and `stdin` is git's
/// object list. The repository at `repo_dir` is read with gix in isolated
/// mode (no global or system config, no replace refs, no grafts).
///
/// # Errors
///
/// Fails closed (`InvalidInput` / `InvalidData` with a message safe to show
/// the client, or an I/O error) on unknown arguments or filters, malformed
/// input, a want that is a tree or blob (or a tag peeling to one), tag chains
/// deeper than 32 or cyclic, trees nested deeper than 256, and any object
/// that cannot be read or has an unexpected type.
pub(crate) fn compute_allowed_pack_objects(
    repo_dir: &Path,
    pack_args: &[String],
    stdin: &[u8],
    withhold_policy: &WithholdPolicy,
    member_groups: &BTreeSet<String>,
    visible_tag_refs: &[String],
) -> io::Result<PackSelection> {
    let args = match parse_pack_args(pack_args) {
        Ok(args) => args,
        Err(error) => return Err(error),
    };
    let mut input = match parse_pack_stdin(stdin) {
        Ok(input) => input,
        Err(error) => return Err(error),
    };
    if let Some(shallow_file) = &args.shallow_file {
        match read_shallow_file(Path::new(shallow_file)) {
            Ok(shallow_commits) => input.shallow_commits.extend(shallow_commits),
            Err(error) => return Err(error),
        }
    }
    let mut graph = match ObjectGraph::open(repo_dir, withhold_policy, member_groups) {
        Ok(graph) => graph,
        Err(error) => return Err(error),
    };
    select_objects(&mut graph, args, &input, visible_tag_refs)
}

/// Parses the hook's arguments (see [`compute_allowed_pack_objects`]).
pub(crate) fn parse_pack_args(pack_args: &[String]) -> io::Result<PackObjectsArgs> {
    let mut shallow_file = None;
    let mut index = 0;
    let mut has_subcommand = false;
    while let Some(argument) = pack_args.get(index) {
        index += 1;
        match argument.as_str() {
            "git" if index == 1 => {}
            "--shallow-file" if shallow_file.is_none() => {
                let Some(path) = pack_args.get(index) else {
                    return Err(invalid_input("--shallow-file without a path".to_owned()));
                };
                index += 1;
                shallow_file = Some(path.clone());
            }
            "pack-objects" => {
                has_subcommand = true;
                break;
            }
            _ => return Err(invalid_input("unexpected pack-objects argument".to_owned())),
        }
    }
    if !has_subcommand {
        return Err(invalid_input("missing pack-objects subcommand".to_owned()));
    }

    let mut has_revs = false;
    let mut include_tag = false;
    let mut filter = None;
    let mut forwarded_flags: Vec<String> = Vec::new();
    for argument in &pack_args[index..] {
        let argument = argument.as_str();
        match argument {
            "--revs" => has_revs = true,
            // Never passed on: `--thin` would let pack-objects delta against
            // objects outside the list, `--shallow` only matters with
            // `--revs`, and `--stdout` is always passed.
            "--thin" | "--shallow" | "--stdout" => {}
            "--include-tag" => include_tag = true,
            _ if FORWARDED_FLAGS.contains(&argument) => {
                if !forwarded_flags.iter().any(|flag| flag == argument) {
                    forwarded_flags.push(argument.to_owned());
                }
            }
            _ => {
                if let Some(spec) = argument.strip_prefix("--filter=") {
                    if filter.is_some() {
                        return Err(invalid_input("more than one filter".to_owned()));
                    }
                    match parse_filter_spec(spec) {
                        Ok(parsed) => filter = Some(parsed),
                        Err(error) => return Err(error),
                    }
                } else if let Some(level) = argument.strip_prefix("--compression=")
                    && !level.is_empty()
                    && level.len() <= 2
                    && level.bytes().all(|byte| byte.is_ascii_digit())
                {
                    forwarded_flags.push(argument.to_owned());
                } else {
                    return Err(invalid_input("unexpected pack-objects argument".to_owned()));
                }
            }
        }
    }
    if !has_revs {
        return Err(invalid_input("pack-objects without --revs".to_owned()));
    }
    let shallow_file = shallow_file.filter(|path| !path.is_empty());
    let filter = match filter {
        Some(filter) => filter,
        None => ClientObjectFilter::None,
    };
    Ok(PackObjectsArgs {
        shallow_file,
        include_tag,
        filter,
        forwarded_flags,
    })
}

/// Parses a `--filter=` spec: `blob:none` or `blob:limit=<n>[kmg]`
/// (case-insensitive binary units). Every other filter is refused.
fn parse_filter_spec(spec: &str) -> io::Result<ClientObjectFilter> {
    if spec == "blob:none" {
        return Ok(ClientObjectFilter::BlobNone);
    }
    let Some(limit) = spec.strip_prefix("blob:limit=") else {
        return Err(invalid_input("unsupported object filter".to_owned()));
    };
    let (digits, multiplier) = match limit.as_bytes().last() {
        Some(b'k' | b'K') => (&limit[..limit.len() - 1], 1024_u64),
        Some(b'm' | b'M') => (&limit[..limit.len() - 1], 1024 * 1024),
        Some(b'g' | b'G') => (&limit[..limit.len() - 1], 1024 * 1024 * 1024),
        _ => (limit, 1),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_input("invalid blob size limit".to_owned()));
    }
    let size = match digits.parse::<u64>() {
        Ok(size) => size,
        Err(_) => return Err(invalid_input("invalid blob size limit".to_owned())),
    };
    match size.checked_mul(multiplier) {
        Some(bytes) => Ok(ClientObjectFilter::BlobLimit(bytes)),
        None => Err(invalid_input("invalid blob size limit".to_owned())),
    }
}

/// Parses `git upload-pack`'s `--revs` object list: wants, `--not`, haves
/// (also as `^<oid>`) and `--shallow <oid>` lines. Anything else (revision
/// expressions, unknown directives) is refused.
pub(crate) fn parse_pack_stdin(stdin: &[u8]) -> io::Result<PackObjectsInput> {
    let Ok(text) = std::str::from_utf8(stdin) else {
        return Err(invalid_data("non-UTF-8 object list"));
    };
    let mut input = PackObjectsInput::default();
    // Like `git pack-objects`, each `--not` flips between wants and haves.
    let mut in_not = false;
    for line in text.split('\n') {
        if line.is_empty() {
            continue;
        }
        if line == "--not" {
            in_not = !in_not;
            continue;
        }
        if let Some(object_id) = line.strip_prefix("--shallow ") {
            match parse_object_id(object_id) {
                Some(object_id) => input.shallow_commits.insert(object_id),
                None => return Err(invalid_data("malformed object list")),
            };
            continue;
        }
        let (is_have, object_id) = match line.strip_prefix('^') {
            Some(object_id) => (true, object_id),
            None => (in_not, line),
        };
        let Some(object_id) = parse_object_id(object_id) else {
            return Err(invalid_data("malformed object list"));
        };
        if is_have {
            input.haves.push(object_id);
        } else {
            input.wants.push(object_id);
        }
    }
    Ok(input)
}

/// Reads the commit IDs of a shallow file (one per line).
fn read_shallow_file(path: &Path) -> io::Result<HashSet<ObjectId>> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return Err(error),
    };
    let mut contents = Vec::new();
    if let Err(error) = file
        .take(MAX_SHALLOW_FILE_BYTES + 1)
        .read_to_end(&mut contents)
    {
        return Err(error);
    }
    if contents.len() as u64 > MAX_SHALLOW_FILE_BYTES {
        return Err(invalid_data("oversized shallow file"));
    }
    let Ok(text) = std::str::from_utf8(&contents) else {
        return Err(invalid_data("malformed shallow file"));
    };
    let mut commits = HashSet::new();
    for line in text.split('\n').filter(|line| !line.is_empty()) {
        match parse_object_id(line) {
            Some(commit) => {
                commits.insert(commit);
            }
            None => return Err(invalid_data("malformed shallow file")),
        }
    }
    Ok(commits)
}

/// Parses a full object ID of 40 (or 64) lowercase hex digits.
fn parse_object_id(text: &str) -> Option<ObjectId> {
    let is_valid = matches!(text.len(), 40 | 64)
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !is_valid {
        return None;
    }
    ObjectId::from_hex(text.as_bytes()).ok()
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// A commit's tree and parents.
#[derive(Clone)]
struct CommitInfo {
    tree: ObjectId,
    parents: Vec<ObjectId>,
}

/// An object reached by peeling annotated tags.
struct PeeledObject {
    /// The tags passed through, outermost first.
    tags: Vec<ObjectId>,
    target: ObjectId,
    kind: Kind,
}

/// One entry of a tree.
struct TreeEntry {
    name: Vec<u8>,
    kind: EntryKind,
    object_id: ObjectId,
}

/// Read access to a repository's objects plus the member's withholding view.
struct ObjectGraph<'policy> {
    repo: gix::Repository,
    hash_kind: gix::hash::Kind,
    withhold_policy: &'policy WithholdPolicy,
    member_groups: &'policy BTreeSet<String>,
    commits: HashMap<ObjectId, CommitInfo>,
}

impl<'policy> ObjectGraph<'policy> {
    /// Opens `repo_dir` exactly as given, in gix's isolated mode (repository
    /// config only, no environment) with replace refs disabled.
    fn open(
        repo_dir: &Path,
        withhold_policy: &'policy WithholdPolicy,
        member_groups: &'policy BTreeSet<String>,
    ) -> io::Result<Self> {
        let options = gix::open::Options::isolated()
            .open_path_as_is(true)
            .cli_overrides(["core.useReplaceRefs=false"]);
        let repo = match gix::open_opts(repo_dir, options) {
            Ok(repo) => repo,
            Err(_) => return Err(io::Error::other("cannot open the repository")),
        };
        let hash_kind = repo.object_hash();
        Ok(Self {
            repo,
            hash_kind,
            withhold_policy,
            member_groups,
            commits: HashMap::new(),
        })
    }

    /// Reads one object's kind and data.
    fn read(&self, object_id: ObjectId) -> io::Result<(Kind, Vec<u8>)> {
        match self.repo.find_object(object_id) {
            Ok(object) => {
                let object = object.detach();
                Ok((object.kind, object.data))
            }
            Err(_) => Err(io::Error::other("cannot read a repository object")),
        }
    }

    /// Reads one object's kind and size without decompressing it.
    fn header(&self, object_id: ObjectId) -> io::Result<(Kind, u64)> {
        match self.repo.find_header(object_id) {
            Ok(header) => Ok((header.kind(), header.size())),
            Err(_) => Err(io::Error::other("cannot read a repository object")),
        }
    }

    /// The tree and parents of `commit`, memoized.
    fn commit(&mut self, commit: ObjectId) -> io::Result<CommitInfo> {
        if let Some(info) = self.commits.get(&commit) {
            return Ok(info.clone());
        }
        let (kind, data) = match self.read(commit) {
            Ok(object) => object,
            Err(error) => return Err(error),
        };
        if kind != Kind::Commit {
            return Err(invalid_data("expected a commit"));
        }
        let info = match gix::objs::CommitRef::from_bytes(&data, self.hash_kind) {
            Ok(parsed) => CommitInfo {
                tree: parsed.tree(),
                parents: parsed.parents().collect(),
            },
            Err(_) => return Err(invalid_data("malformed commit")),
        };
        self.commits.insert(commit, info.clone());
        Ok(info)
    }

    /// Follows annotated tags from `object_id` to the first other object, at
    /// most [`MAX_TAG_DEPTH`] deep and without cycles. Uses each object's
    /// stored type, never the type a tag claims.
    fn peel_tags(&self, object_id: ObjectId) -> io::Result<PeeledObject> {
        let mut tags = Vec::new();
        let mut current = object_id;
        loop {
            let (kind, data) = match self.read(current) {
                Ok(object) => object,
                Err(error) => return Err(error),
            };
            if kind != Kind::Tag {
                return Ok(PeeledObject {
                    tags,
                    target: current,
                    kind,
                });
            }
            if tags.len() == MAX_TAG_DEPTH || tags.contains(&current) {
                return Err(invalid_data("tag chain too deep"));
            }
            tags.push(current);
            current = match gix::objs::TagRef::from_bytes(&data, self.hash_kind) {
                Ok(tag) => tag.target(),
                Err(_) => return Err(invalid_data("malformed tag")),
            };
        }
    }

    /// The entries of the tree `tree`, which must be stored as a tree.
    fn tree_entries(&self, tree: ObjectId) -> io::Result<Vec<TreeEntry>> {
        let (kind, data) = match self.read(tree) {
            Ok(object) => object,
            Err(error) => return Err(error),
        };
        if kind != Kind::Tree {
            return Err(invalid_data("expected a tree"));
        }
        let mut entries = Vec::new();
        for entry in gix::objs::TreeRefIter::from_bytes(&data, self.hash_kind) {
            match entry {
                Ok(entry) => entries.push(TreeEntry {
                    name: entry.filename.to_vec(),
                    kind: entry.mode.kind(),
                    object_id: entry.oid.to_owned(),
                }),
                Err(_) => return Err(invalid_data("malformed tree")),
            }
        }
        Ok(entries)
    }

    /// Whether a blob at `path` (`None` for a non-UTF-8 path, or one below a
    /// non-UTF-8 directory) is withheld from the member.
    fn is_withheld(&self, path: Option<&str>) -> bool {
        match path {
            Some(path) => self
                .withhold_policy
                .is_path_withheld(path, self.member_groups),
            None => true,
        }
    }

    /// The object a ref resolves to (following symbolic refs, not tags), or
    /// `None` if the ref no longer exists.
    fn resolve_ref(&self, ref_name: &str) -> io::Result<Option<ObjectId>> {
        let reference = match self.repo.try_find_reference(ref_name) {
            Ok(reference) => reference,
            Err(_) => return Err(io::Error::other("cannot read a ref")),
        };
        let Some(mut reference) = reference else {
            return Ok(None);
        };
        match reference.follow_to_object() {
            Ok(id) => Ok(Some(id.detach())),
            Err(_) => Err(io::Error::other("cannot resolve a ref")),
        }
    }
}

/// Lists the commits reachable from `starts` (in walk order) without
/// passing `stop` commits and without following the parents of `shallow`
/// commits.
fn collect_commits(
    graph: &mut ObjectGraph<'_>,
    starts: &[ObjectId],
    stop: &HashSet<ObjectId>,
    shallow: &HashSet<ObjectId>,
) -> io::Result<(Vec<ObjectId>, HashSet<ObjectId>)> {
    let mut order = Vec::new();
    let mut visited = HashSet::new();
    let mut pending: Vec<ObjectId> = starts.iter().rev().copied().collect();
    while let Some(commit) = pending.pop() {
        if stop.contains(&commit) || !visited.insert(commit) {
            continue;
        }
        order.push(commit);
        if shallow.contains(&commit) {
            continue;
        }
        let info = match graph.commit(commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        pending.extend(info.parents.iter().rev().copied());
    }
    Ok((order, visited))
}

/// Joins a tree path and an entry name; `None` if either is not UTF-8.
fn child_path(prefix: Option<&str>, name: &[u8]) -> Option<String> {
    let (Some(prefix), Ok(name)) = (prefix, std::str::from_utf8(name)) else {
        return None;
    };
    if prefix.is_empty() {
        Some(name.to_owned())
    } else {
        Some(format!("{prefix}/{name}"))
    }
}

/// Memo key of one walked subtree: the tree, its path (`None` below a
/// non-UTF-8 name, where everything is withheld), so a tree reused at a
/// withheld and a visible path is judged at each.
type SubtreeKey = (ObjectId, Option<String>);

/// What the client already has, from the trees of the commits on the
/// boundary between what it has and what it wants.
#[derive(Default)]
struct ClientObjects {
    walked: HashSet<SubtreeKey>,
    trees: HashSet<ObjectId>,
    /// Blobs reached at a visible path only: a blob reached only at a
    /// withheld path was never sent, so moving it to a visible path later
    /// must send it.
    visible_blobs: HashSet<ObjectId>,
}

impl ClientObjects {
    fn walk(
        &mut self,
        graph: &ObjectGraph<'_>,
        tree: ObjectId,
        path: Option<String>,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(invalid_data("trees nested too deeply"));
        }
        if !self.walked.insert((tree, path.clone())) {
            return Ok(());
        }
        self.trees.insert(tree);
        let entries = match graph.tree_entries(tree) {
            Ok(entries) => entries,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry_path = child_path(path.as_deref(), &entry.name);
            match entry.kind {
                EntryKind::Tree => {
                    if let Err(error) = self.walk(graph, entry.object_id, entry_path, depth + 1) {
                        return Err(error);
                    }
                }
                EntryKind::Commit => {}
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    if !graph.is_withheld(entry_path.as_deref()) {
                        self.visible_blobs.insert(entry.object_id);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Collects the trees and allowed blobs of the commits being sent.
struct PackObjectCollector<'walk> {
    client: &'walk ClientObjects,
    filter: ClientObjectFilter,
    walked: HashSet<SubtreeKey>,
    emitted: HashSet<ObjectId>,
    objects: Vec<(ObjectId, Option<String>)>,
    withheld_any_blob: bool,
}

impl PackObjectCollector<'_> {
    /// Adds `object_id` unless it was added already.
    fn emit(&mut self, object_id: ObjectId, path_hint: Option<&str>) {
        if self.emitted.insert(object_id) {
            // A path hint containing a line break would split the line.
            let path_hint = path_hint
                .filter(|path| !path.is_empty() && !path.contains(['\r', '\n']))
                .map(str::to_owned);
            self.objects.push((object_id, path_hint));
        }
    }

    fn walk(
        &mut self,
        graph: &ObjectGraph<'_>,
        tree: ObjectId,
        path: Option<String>,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(invalid_data("trees nested too deeply"));
        }
        let key = (tree, path.clone());
        // A subtree the client has at this very path holds nothing new: its
        // visible blobs are had and its withheld blobs stay withheld.
        if self.client.walked.contains(&key) || !self.walked.insert(key) {
            return Ok(());
        }
        if !self.client.trees.contains(&tree) {
            self.emit(tree, path.as_deref());
        }
        let entries = match graph.tree_entries(tree) {
            Ok(entries) => entries,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry_path = child_path(path.as_deref(), &entry.name);
            match entry.kind {
                EntryKind::Tree => {
                    if let Err(error) = self.walk(graph, entry.object_id, entry_path, depth + 1) {
                        return Err(error);
                    }
                }
                // A submodule commit lives in another repository.
                EntryKind::Commit => {}
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    if graph.is_withheld(entry_path.as_deref()) {
                        self.withheld_any_blob = true;
                        continue;
                    }
                    if self.client.visible_blobs.contains(&entry.object_id)
                        || self.emitted.contains(&entry.object_id)
                    {
                        continue;
                    }
                    // The stored type is checked so a crafted entry cannot
                    // smuggle a commit or tag out under a blob mode.
                    let (kind, size) = match graph.header(entry.object_id) {
                        Ok(header) => header,
                        Err(error) => return Err(error),
                    };
                    if kind != Kind::Blob {
                        return Err(invalid_data("expected a blob"));
                    }
                    let is_filtered = match self.filter {
                        ClientObjectFilter::None => false,
                        ClientObjectFilter::BlobNone => true,
                        ClientObjectFilter::BlobLimit(limit) => size >= limit,
                    };
                    if !is_filtered {
                        self.emit(entry.object_id, entry_path.as_deref());
                    }
                }
            }
        }
        Ok(())
    }
}

/// The object walk behind [`compute_allowed_pack_objects`].
fn select_objects(
    graph: &mut ObjectGraph<'_>,
    args: PackObjectsArgs,
    input: &PackObjectsInput,
    visible_tag_refs: &[String],
) -> io::Result<PackSelection> {
    // Wants must be commits, or tags peeling to commits: a tree or blob has
    // no repository path to judge it by.
    let mut want_tags = Vec::new();
    let mut want_commits = Vec::new();
    for want in &input.wants {
        let peeled = match graph.peel_tags(*want) {
            Ok(peeled) => peeled,
            Err(error) => return Err(error),
        };
        if peeled.kind != Kind::Commit {
            return Err(invalid_input(
                "only commits and tags of commits may be fetched".to_owned(),
            ));
        }
        want_tags.extend(peeled.tags);
        want_commits.push(peeled.target);
    }
    // Haves only ever reduce what is sent, so other kinds are ignored.
    let mut have_commits = Vec::new();
    for have in &input.haves {
        let peeled = match graph.peel_tags(*have) {
            Ok(peeled) => peeled,
            Err(error) => return Err(error),
        };
        if peeled.kind == Kind::Commit {
            have_commits.push(peeled.target);
        }
    }

    let (_, have_commit_set) = match collect_commits(
        graph,
        &have_commits,
        &HashSet::new(),
        &input.shallow_commits,
    ) {
        Ok(walk) => walk,
        Err(error) => return Err(error),
    };
    let (send_commits, send_commit_set) = match collect_commits(
        graph,
        &want_commits,
        &have_commit_set,
        &input.shallow_commits,
    ) {
        Ok(walk) => walk,
        Err(error) => return Err(error),
    };

    // Like `git pack-objects --revs` without `--thin`, only the trees of the
    // boundary commits count as had. Missing some had objects only sends
    // more, never anything withheld.
    let mut client = ClientObjects::default();
    let mut boundary_commits = BTreeSet::new();
    for commit in &send_commits {
        if input.shallow_commits.contains(commit) {
            continue;
        }
        let info = match graph.commit(*commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        boundary_commits.extend(
            info.parents
                .into_iter()
                .filter(|parent| have_commit_set.contains(parent)),
        );
    }
    for commit in boundary_commits {
        let info = match graph.commit(commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        if let Err(error) = client.walk(graph, info.tree, Some(String::new()), 0) {
            return Err(error);
        }
    }

    let mut collector = PackObjectCollector {
        client: &client,
        filter: args.filter,
        walked: HashSet::new(),
        emitted: HashSet::new(),
        objects: Vec::new(),
        withheld_any_blob: false,
    };
    for tag in want_tags {
        collector.emit(tag, None);
    }
    if args.include_tag {
        for ref_name in visible_tag_refs {
            if !ref_name.starts_with("refs/tags/") {
                continue;
            }
            let target = match graph.resolve_ref(ref_name) {
                Ok(Some(target)) => target,
                Ok(None) => continue,
                Err(error) => return Err(error),
            };
            let peeled = match graph.peel_tags(target) {
                Ok(peeled) => peeled,
                Err(error) => return Err(error),
            };
            if peeled.kind == Kind::Commit && send_commit_set.contains(&peeled.target) {
                for tag in peeled.tags {
                    collector.emit(tag, None);
                }
            }
        }
    }
    for commit in &send_commits {
        collector.emit(*commit, None);
    }
    for commit in &send_commits {
        let info = match graph.commit(*commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        if let Err(error) = collector.walk(graph, info.tree, Some(String::new()), 0) {
            return Err(error);
        }
    }

    Ok(PackSelection {
        objects: collector.objects,
        withheld_any_blob: collector.withheld_any_blob,
        filter: args.filter,
        forwarded_flags: args.forwarded_flags,
    })
}

/// For the `pre-receive` guard: returns the blobs of `candidates` that exist
/// in the repository at `repo_dir` and are reachable from the commits of
/// `visible_refs` only at paths withheld from `member_groups`, never at a
/// visible path.
///
/// Refs that do not resolve to a commit (directly or through tags) are
/// skipped: their contents have no repository path and are never served.
/// The walk ends early once every candidate was seen at a visible path.
pub(crate) fn find_withheld_only_blobs(
    repo_dir: &Path,
    visible_refs: &[String],
    candidates: &HashSet<ObjectId>,
    withhold_policy: &WithholdPolicy,
    member_groups: &BTreeSet<String>,
) -> io::Result<HashSet<ObjectId>> {
    let mut graph = match ObjectGraph::open(repo_dir, withhold_policy, member_groups) {
        Ok(graph) => graph,
        Err(error) => return Err(error),
    };
    // Only existing blobs can be withheld content. Dropping trees and commits
    // (thin-pack delta bases are often old trees) also lets the walk below
    // end early once every remaining candidate was seen at a visible path.
    let mut existing_blobs = HashSet::new();
    for candidate in candidates {
        if !graph.repo.has_object(candidate) {
            continue;
        }
        match graph.header(*candidate) {
            Ok((Kind::Blob, _)) => {
                existing_blobs.insert(*candidate);
            }
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
    let candidates = existing_blobs;
    if candidates.is_empty() {
        return Ok(HashSet::new());
    }

    let mut tips = Vec::new();
    for ref_name in visible_refs {
        let target = match graph.resolve_ref(ref_name) {
            Ok(Some(target)) => target,
            Ok(None) => continue,
            Err(error) => return Err(error),
        };
        let peeled = match graph.peel_tags(target) {
            Ok(peeled) => peeled,
            Err(error) => return Err(error),
        };
        if peeled.kind == Kind::Commit {
            tips.push(peeled.target);
        }
    }
    let mut classifier = BlobClassifier {
        candidates: &candidates,
        walked: HashSet::new(),
        at_withheld_path: HashSet::new(),
        at_visible_path: HashSet::new(),
    };
    // History is walked lazily, newest first, so the common case (every
    // candidate visible near the tips) never parses old commits.
    let mut visited = HashSet::new();
    let mut pending: Vec<ObjectId> = tips.into_iter().rev().collect();
    while let Some(commit) = pending.pop() {
        if classifier.at_visible_path.len() == candidates.len() {
            break;
        }
        if !visited.insert(commit) {
            continue;
        }
        let info = match graph.commit(commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        if let Err(error) = classifier.walk(&graph, info.tree, Some(String::new()), 0) {
            return Err(error);
        }
        pending.extend(info.parents.iter().rev().copied());
    }
    Ok(classifier
        .at_withheld_path
        .difference(&classifier.at_visible_path)
        .copied()
        .collect())
}

/// Records at which kind of path each candidate blob appears.
struct BlobClassifier<'walk> {
    candidates: &'walk HashSet<ObjectId>,
    walked: HashSet<SubtreeKey>,
    at_withheld_path: HashSet<ObjectId>,
    at_visible_path: HashSet<ObjectId>,
}

impl BlobClassifier<'_> {
    fn walk(
        &mut self,
        graph: &ObjectGraph<'_>,
        tree: ObjectId,
        path: Option<String>,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(invalid_data("trees nested too deeply"));
        }
        if !self.walked.insert((tree, path.clone())) {
            return Ok(());
        }
        let entries = match graph.tree_entries(tree) {
            Ok(entries) => entries,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry_path = child_path(path.as_deref(), &entry.name);
            match entry.kind {
                EntryKind::Tree => {
                    if let Err(error) = self.walk(graph, entry.object_id, entry_path, depth + 1) {
                        return Err(error);
                    }
                }
                EntryKind::Commit => {}
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    if !self.candidates.contains(&entry.object_id) {
                        continue;
                    }
                    if graph.is_withheld(entry_path.as_deref()) {
                        self.at_withheld_path.insert(entry.object_id);
                    } else {
                        self.at_visible_path.insert(entry.object_id);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeSet, HashSet},
        path::PathBuf,
        process::{Command, Stdio},
    };

    use gix::ObjectId;
    use scrim_policy::{WithholdPolicy, WithholdRule};
    use tempfile::TempDir;

    use super::{
        ClientObjectFilter, PackObjectsArgs, PackSelection, compute_allowed_pack_objects,
        find_withheld_only_blobs, parse_filter_spec, parse_pack_args, parse_pack_stdin,
        shell_quote,
    };

    const COMMIT_A: &str = "1111111111111111111111111111111111111111";
    const COMMIT_B: &str = "2222222222222222222222222222222222222222";
    const COMMIT_C: &str = "3333333333333333333333333333333333333333";

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn object_id(hex: &str) -> ObjectId {
        match ObjectId::from_hex(hex.as_bytes()) {
            Ok(object_id) => object_id,
            Err(error) => panic!("bad object ID {hex}: {error}"),
        }
    }

    fn parse_args_ok(values: &[&str]) -> PackObjectsArgs {
        match parse_pack_args(&strings(values)) {
            Ok(args) => args,
            Err(error) => panic!("{values:?} should parse: {error}"),
        }
    }

    #[test]
    fn parses_upload_pack_arguments() {
        let args = parse_args_ok(&[
            "git",
            "pack-objects",
            "--revs",
            "--thin",
            "--stdout",
            "--progress",
            "--delta-base-offset",
            "--include-tag",
            "--progress",
        ]);
        assert_eq!(
            args,
            PackObjectsArgs {
                shallow_file: None,
                include_tag: true,
                filter: ClientObjectFilter::None,
                forwarded_flags: strings(&["--progress", "--delta-base-offset"]),
            }
        );

        let args = parse_args_ok(&[
            "git",
            "--shallow-file",
            "shallow_abc",
            "pack-objects",
            "--revs",
            "--stdout",
            "--shallow",
            "--filter=blob:none",
            "--compression=9",
            "-q",
        ]);
        assert_eq!(args.shallow_file.as_deref(), Some("shallow_abc"));
        assert_eq!(args.filter, ClientObjectFilter::BlobNone);
        assert!(!args.include_tag);
        assert_eq!(args.forwarded_flags, strings(&["--compression=9", "-q"]));

        let args = parse_args_ok(&["git", "--shallow-file", "", "pack-objects", "--revs"]);
        assert_eq!(args.shallow_file, None);
    }

    #[test]
    fn rejects_unexpected_arguments() {
        for values in [
            &["git"][..],
            &["git", "pack-objects"],
            &["git", "pack-objects", "--revs", "--all"],
            &["git", "pack-objects", "--revs", "--keep-true-parents"],
            &["git", "pack-objects", "--revs", "--uri-protocol=https"],
            &["git", "pack-objects", "--revs", "--compression="],
            &["git", "pack-objects", "--revs", "--compression=x"],
            &["git", "--exec-path=/tmp", "pack-objects", "--revs"],
            &["git", "--shallow-file"],
            &[
                "git",
                "--shallow-file",
                "a",
                "--shallow-file",
                "b",
                "pack-objects",
                "--revs",
            ],
            &["git", "git", "pack-objects", "--revs"],
            &[
                "git",
                "pack-objects",
                "--revs",
                "--filter=blob:none",
                "--filter=blob:none",
            ],
        ] {
            assert!(
                parse_pack_args(&strings(values)).is_err(),
                "{values:?} should be rejected"
            );
        }
    }

    #[test]
    fn parses_only_blob_filters() {
        let parse = |spec: &str| match parse_filter_spec(spec) {
            Ok(filter) => filter,
            Err(error) => panic!("{spec} should parse: {error}"),
        };
        assert_eq!(parse("blob:none"), ClientObjectFilter::BlobNone);
        assert_eq!(parse("blob:limit=0"), ClientObjectFilter::BlobLimit(0));
        assert_eq!(parse("blob:limit=123"), ClientObjectFilter::BlobLimit(123));
        assert_eq!(parse("blob:limit=1k"), ClientObjectFilter::BlobLimit(1024));
        assert_eq!(
            parse("blob:limit=2M"),
            ClientObjectFilter::BlobLimit(2 * 1024 * 1024)
        );
        assert_eq!(
            parse("blob:limit=2g"),
            ClientObjectFilter::BlobLimit(2 * 1024 * 1024 * 1024)
        );
        for spec in [
            "sparse:oid=1111111111111111111111111111111111111111",
            "tree:0",
            "combine:blob:none+tree:0",
            "object:type=blob",
            "blob:limit=",
            "blob:limit=k",
            "blob:limit=-1",
            "blob:limit=1t",
            "blob:limit=18446744073709551615k",
            "BLOB:NONE",
        ] {
            assert!(parse_filter_spec(spec).is_err(), "{spec} should be refused");
        }
    }

    #[test]
    fn parses_object_lists() {
        let stdin =
            format!("{COMMIT_A}\n\n--not\n{COMMIT_B}\n^{COMMIT_C}\n--shallow {COMMIT_C}\n\n");
        let input = match parse_pack_stdin(stdin.as_bytes()) {
            Ok(input) => input,
            Err(error) => panic!("object list should parse: {error}"),
        };
        assert_eq!(input.wants, vec![object_id(COMMIT_A)]);
        assert_eq!(input.haves, vec![object_id(COMMIT_B), object_id(COMMIT_C)]);
        assert_eq!(input.shallow_commits, HashSet::from([object_id(COMMIT_C)]));

        let caret_only = format!("{COMMIT_A}\n^{COMMIT_B}\n{COMMIT_C}\n");
        match parse_pack_stdin(caret_only.as_bytes()) {
            Ok(input) => {
                assert_eq!(input.wants, vec![object_id(COMMIT_A), object_id(COMMIT_C)]);
                assert_eq!(input.haves, vec![object_id(COMMIT_B)]);
            }
            Err(error) => panic!("object list should parse: {error}"),
        }
    }

    #[test]
    fn rejects_malformed_object_lists() {
        let upper = COMMIT_A.replace('1', "A");
        for stdin in [
            "HEAD\n".to_owned(),
            "refs/heads/main\n".to_owned(),
            "--all\n".to_owned(),
            "--exclude-promisor-objects\n".to_owned(),
            format!("{COMMIT_A}\r\n"),
            format!("{}\n", &COMMIT_A[..39]),
            format!("{upper}\n"),
            format!("--shallow {}\n", &COMMIT_A[..10]),
            format!("{COMMIT_A} extra\n"),
        ] {
            assert!(
                parse_pack_stdin(stdin.as_bytes()).is_err(),
                "{stdin:?} should be rejected"
            );
        }
        assert!(parse_pack_stdin(&[0xff, b'\n']).is_err());
    }

    #[test]
    fn quotes_hook_paths_for_the_shell() {
        assert!(
            matches!(shell_quote("/tmp/scrim-x/pack-objects"), Ok(quoted) if quoted == "'/tmp/scrim-x/pack-objects'")
        );
        assert!(
            matches!(shell_quote("/tmp/it's here"), Ok(quoted) if quoted == "'/tmp/it'\\''s here'")
        );
        for path in ["/tmp/a\nb", "/tmp/a\rb", "/tmp/a\0b"] {
            assert!(shell_quote(path).is_err());
        }
    }

    /// A non-bare repository built with real `git` in a temporary directory.
    struct TestRepo {
        _root: TempDir,
        work: PathBuf,
    }

    impl TestRepo {
        fn new() -> Self {
            let root = match TempDir::new() {
                Ok(root) => root,
                Err(error) => panic!("failed to create temp dir: {error}"),
            };
            let work = root.path().join("work");
            if let Err(error) = std::fs::create_dir_all(&work) {
                panic!("failed to create work dir: {error}");
            }
            let repo = Self { _root: root, work };
            repo.git(&["init", "--quiet", "--initial-branch=main"]);
            repo
        }

        fn git_dir(&self) -> PathBuf {
            self.work.join(".git")
        }

        /// Runs `git <args>` in the work tree and returns its trimmed stdout.
        fn git(&self, args: &[&str]) -> String {
            let mut command = Command::new("git");
            command
                .args(args)
                .current_dir(&self.work)
                .env_clear()
                .stdin(Stdio::null());
            if let Some(path) = std::env::var_os("PATH") {
                command.env("PATH", path);
            }
            command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Scrim Test")
                .env("GIT_AUTHOR_EMAIL", "test@scrim.invalid")
                .env("GIT_COMMITTER_NAME", "Scrim Test")
                .env("GIT_COMMITTER_EMAIL", "test@scrim.invalid");
            let output = match command.output() {
                Ok(output) => output,
                Err(error) => panic!("failed to run git {args:?}: {error}"),
            };
            if !output.status.success() {
                panic!(
                    "git {args:?} failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            match String::from_utf8(output.stdout) {
                Ok(stdout) => stdout.trim().to_owned(),
                Err(error) => panic!("git {args:?} printed non-UTF-8 output: {error}"),
            }
        }

        fn write(&self, path: &str, contents: &str) {
            let full_path = self.work.join(path);
            if let Some(parent) = full_path.parent()
                && let Err(error) = std::fs::create_dir_all(parent)
            {
                panic!("failed to create {}: {error}", parent.display());
            }
            if let Err(error) = std::fs::write(&full_path, contents) {
                panic!("failed to write {path}: {error}");
            }
        }

        fn commit_all(&self, message: &str) -> String {
            self.git(&["add", "--all"]);
            self.git(&["commit", "--quiet", "-m", message]);
            self.rev_parse("HEAD")
        }

        fn rev_parse(&self, revision: &str) -> String {
            self.git(&["rev-parse", revision])
        }
    }

    fn groups(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Withholds `config/billing/**` from everyone outside `billing`.
    fn billing_policy() -> WithholdPolicy {
        let rule = match WithholdRule::new("config/billing/**", ["billing".to_owned()]) {
            Ok(rule) => rule,
            Err(error) => panic!("rule should be valid: {error}"),
        };
        match WithholdPolicy::compile([rule]) {
            Ok(policy) => policy,
            Err(error) => panic!("policy should compile: {error}"),
        }
    }

    fn select(
        repo: &TestRepo,
        args: &[&str],
        stdin: &str,
        member_groups: &[&str],
        visible_tag_refs: &[&str],
    ) -> std::io::Result<PackSelection> {
        compute_allowed_pack_objects(
            &repo.git_dir(),
            &strings(args),
            stdin.as_bytes(),
            &billing_policy(),
            &groups(member_groups),
            &strings(visible_tag_refs),
        )
    }

    fn select_ok(
        repo: &TestRepo,
        args: &[&str],
        stdin: &str,
        member_groups: &[&str],
        visible_tag_refs: &[&str],
    ) -> PackSelection {
        match select(repo, args, stdin, member_groups, visible_tag_refs) {
            Ok(selection) => selection,
            Err(error) => panic!("selection failed: {error}"),
        }
    }

    fn selected_ids(selection: &PackSelection) -> HashSet<String> {
        selection
            .objects
            .iter()
            .map(|(object_id, _)| object_id.to_string())
            .collect()
    }

    const PACK_ARGS: [&str; 5] = ["git", "pack-objects", "--revs", "--thin", "--stdout"];

    /// `public/readme.txt`, `public/shared.txt` (same content as
    /// `config/billing/shared.txt`), `config/billing/secret.txt`, a symlink
    /// and a submodule entry.
    fn seed_billing_repo() -> (TestRepo, String) {
        let repo = TestRepo::new();
        repo.write("public/readme.txt", "hello\n");
        repo.write("public/shared.txt", "shared content\n");
        repo.write("config/billing/shared.txt", "shared content\n");
        repo.write("config/billing/secret.txt", "s3cret billing key\n");
        repo.write("config/app.toml", "name = 'app'\n");
        #[cfg(unix)]
        if let Err(error) =
            std::os::unix::fs::symlink("public/readme.txt", repo.work.join("readme-link"))
        {
            panic!("failed to create symlink: {error}");
        }
        repo.git(&["add", "--all"]);
        // A submodule gitlink pointing at a commit that is not in this repo.
        repo.git(&[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{COMMIT_A},vendor/lib"),
        ]);
        repo.git(&["commit", "--quiet", "-m", "seed"]);
        let commit = repo.rev_parse("HEAD");
        (repo, commit)
    }

    #[test]
    fn full_fetch_keeps_history_and_trees_but_drops_withheld_blobs() {
        let (repo, commit) = seed_billing_repo();
        let secret = repo.rev_parse("HEAD:config/billing/secret.txt");
        let shared = repo.rev_parse("HEAD:public/shared.txt");
        let readme = repo.rev_parse("HEAD:public/readme.txt");
        let app = repo.rev_parse("HEAD:config/app.toml");
        let trees = [
            repo.rev_parse("HEAD^{tree}"),
            repo.rev_parse("HEAD:public"),
            repo.rev_parse("HEAD:config"),
            repo.rev_parse("HEAD:config/billing"),
        ];

        let selection = select_ok(&repo, &PACK_ARGS, &format!("{commit}\n--not\n\n"), &[], &[]);
        let ids = selected_ids(&selection);
        assert!(selection.withheld_any_blob);
        assert!(ids.contains(&commit));
        for tree in &trees {
            assert!(ids.contains(tree), "tree {tree} missing");
        }
        assert!(ids.contains(&readme));
        assert!(ids.contains(&app));
        // Also reachable at the visible `public/shared.txt`.
        assert!(ids.contains(&shared));
        assert!(!ids.contains(&secret), "withheld blob was selected");
        assert!(!ids.contains(COMMIT_A), "submodule commit was selected");
        #[cfg(unix)]
        assert!(ids.contains(&repo.rev_parse("HEAD:readme-link")));
        // Path hints never name a withheld file.
        assert!(
            selection
                .objects
                .iter()
                .all(|(_, hint)| hint.as_deref() != Some("config/billing/secret.txt"))
        );
        assert_eq!(
            selection
                .objects
                .iter()
                .filter(|(id, _)| *id == object_id(&shared))
                .count(),
            1
        );

        // A member of `billing` gets everything.
        let allowed = select_ok(
            &repo,
            &PACK_ARGS,
            &format!("{commit}\n--not\n\n"),
            &["billing"],
            &[],
        );
        assert!(!allowed.withheld_any_blob);
        assert!(selected_ids(&allowed).contains(&secret));
    }

    #[test]
    fn blob_filters_apply_to_visible_blobs_only() {
        let (repo, commit) = seed_billing_repo();
        let readme = repo.rev_parse("HEAD:public/readme.txt");
        let secret = repo.rev_parse("HEAD:config/billing/secret.txt");
        let tree = repo.rev_parse("HEAD^{tree}");
        let stdin = format!("{commit}\n");

        let none = select_ok(
            &repo,
            &["git", "pack-objects", "--revs", "--filter=blob:none"],
            &stdin,
            &[],
            &[],
        );
        let ids = selected_ids(&none);
        assert_eq!(none.filter, ClientObjectFilter::BlobNone);
        assert!(ids.contains(&commit) && ids.contains(&tree));
        assert!(!ids.contains(&readme) && !ids.contains(&secret));

        // "hello\n" is 6 bytes: kept under a 7-byte limit, dropped at 6.
        let under = select_ok(
            &repo,
            &["git", "pack-objects", "--revs", "--filter=blob:limit=7"],
            &stdin,
            &[],
            &[],
        );
        assert!(selected_ids(&under).contains(&readme));
        assert!(!selected_ids(&under).contains(&secret));
        let at = select_ok(
            &repo,
            &["git", "pack-objects", "--revs", "--filter=blob:limit=6"],
            &stdin,
            &[],
            &[],
        );
        assert!(!selected_ids(&at).contains(&readme));
    }

    #[test]
    fn moving_a_withheld_file_to_a_visible_path_sends_it_on_the_next_fetch() {
        let (repo, first) = seed_billing_repo();
        let secret = repo.rev_parse("HEAD:config/billing/secret.txt");
        let readme = repo.rev_parse("HEAD:public/readme.txt");
        repo.git(&["mv", "config/billing/secret.txt", "public/secret.txt"]);
        let second = repo.commit_all("publish");

        let selection = select_ok(
            &repo,
            &PACK_ARGS,
            &format!("{second}\n--not\n{first}\n"),
            &[],
            &[],
        );
        let ids = selected_ids(&selection);
        assert!(ids.contains(&second));
        assert!(!ids.contains(&first), "a had commit was sent again");
        assert!(ids.contains(&secret), "the newly visible blob was not sent");
        assert!(!ids.contains(&readme), "a had blob was sent again");
    }

    #[test]
    fn moving_a_visible_file_to_a_withheld_path_withholds_it() {
        let repo = TestRepo::new();
        repo.write("public/a.txt", "a\n");
        let first = repo.commit_all("first");
        let blob = repo.rev_parse("HEAD:public/a.txt");
        repo.write("config/billing/.keep", "");
        repo.git(&["add", "config/billing/.keep"]);
        repo.git(&["mv", "public/a.txt", "config/billing/a.txt"]);
        repo.write("public/b.txt", "b\n");
        let second = repo.commit_all("second");

        // Without history, the blob is only at a withheld path.
        let shallow = select_ok(
            &repo,
            &PACK_ARGS,
            &format!("--shallow {second}\n{second}\n"),
            &[],
            &[],
        );
        assert!(!selected_ids(&shallow).contains(&blob));
        assert!(shallow.withheld_any_blob);
        // With history it was public in `first`, so it is sent once.
        let full = select_ok(&repo, &PACK_ARGS, &format!("{second}\n"), &[], &[]);
        assert!(selected_ids(&full).contains(&first));
        assert!(selected_ids(&full).contains(&blob));
    }

    #[test]
    fn subtree_reused_at_a_visible_path_is_judged_there() {
        let repo = TestRepo::new();
        repo.write("config/billing/key.txt", "key\n");
        repo.write("public/copy/key.txt", "key\n");
        let commit = repo.commit_all("aliased");
        let subtree = repo.rev_parse("HEAD:config/billing");
        assert_eq!(subtree, repo.rev_parse("HEAD:public/copy"));
        let blob = repo.rev_parse("HEAD:public/copy/key.txt");

        let selection = select_ok(&repo, &PACK_ARGS, &format!("{commit}\n"), &[], &[]);
        let ids = selected_ids(&selection);
        assert!(ids.contains(&subtree));
        assert!(ids.contains(&blob), "blob at the visible alias was dropped");
        assert!(selection.withheld_any_blob);
    }

    #[test]
    fn include_tag_adds_only_visible_tags() {
        let (repo, commit) = seed_billing_repo();
        repo.git(&["tag", "-a", "-m", "release", "v1"]);
        repo.git(&["tag", "-a", "-m", "hidden", "hidden-tag"]);
        let visible_tag = repo.rev_parse("refs/tags/v1");
        let hidden_tag = repo.rev_parse("refs/tags/hidden-tag");
        let args = ["git", "pack-objects", "--revs", "--include-tag"];
        let stdin = format!("{commit}\n");

        let selection = select_ok(&repo, &args, &stdin, &[], &["refs/tags/v1"]);
        let ids = selected_ids(&selection);
        assert!(ids.contains(&visible_tag));
        assert!(!ids.contains(&hidden_tag), "a hidden tag was included");

        let without = select_ok(&repo, &PACK_ARGS, &stdin, &[], &["refs/tags/v1"]);
        assert!(!selected_ids(&without).contains(&visible_tag));

        // A wanted tag is sent with its commit.
        let wanted = select_ok(&repo, &PACK_ARGS, &format!("{visible_tag}\n"), &[], &[]);
        let ids = selected_ids(&wanted);
        assert!(ids.contains(&visible_tag) && ids.contains(&commit));
    }

    #[test]
    fn wants_must_be_commits_or_tags_of_commits() {
        let (repo, commit) = seed_billing_repo();
        let secret = repo.rev_parse("HEAD:config/billing/secret.txt");
        let readme = repo.rev_parse("HEAD:public/readme.txt");
        let subtree = repo.rev_parse("HEAD:config/billing");
        repo.git(&["tag", "-a", "-m", "blob tag", "blob-tag", &secret]);
        repo.git(&["tag", "-a", "-m", "tree tag", "tree-tag", &subtree]);
        let blob_tag = repo.rev_parse("refs/tags/blob-tag");
        let tree_tag = repo.rev_parse("refs/tags/tree-tag");

        for want in [&secret, &readme, &subtree, &blob_tag, &tree_tag] {
            assert!(
                select(&repo, &PACK_ARGS, &format!("{want}\n"), &[], &[]).is_err(),
                "want {want} should be refused"
            );
            assert!(
                select(&repo, &PACK_ARGS, &format!("{commit}\n{want}\n"), &[], &[]).is_err(),
                "want {want} next to a commit should be refused"
            );
        }
        // Even for members who may read every path.
        assert!(select(&repo, &PACK_ARGS, &format!("{secret}\n"), &["billing"], &[]).is_err());
        // Missing objects fail closed.
        assert!(select(&repo, &PACK_ARGS, &format!("{COMMIT_B}\n"), &[], &[]).is_err());
    }

    #[test]
    fn shallow_boundaries_stop_the_walk() {
        let (repo, first) = seed_billing_repo();
        repo.write("public/next.txt", "next\n");
        let second = repo.commit_all("second");

        let stdin = format!("--shallow {second}\n{second}\n");
        let selection = select_ok(&repo, &PACK_ARGS, &stdin, &[], &[]);
        let ids = selected_ids(&selection);
        assert!(ids.contains(&second));
        assert!(
            !ids.contains(&first),
            "commit beyond the shallow boundary was sent"
        );

        let shallow_file = repo.work.join("shallow-list");
        if let Err(error) = std::fs::write(&shallow_file, format!("{second}\n")) {
            panic!("failed to write shallow file: {error}");
        }
        let Some(shallow_path) = shallow_file.to_str() else {
            panic!("shallow path is not UTF-8");
        };
        let args = [
            "git",
            "--shallow-file",
            shallow_path,
            "pack-objects",
            "--revs",
            "--shallow",
        ];
        let selection = select_ok(&repo, &args, &format!("{second}\n"), &[], &[]);
        assert!(!selected_ids(&selection).contains(&first));

        let missing = [
            "git",
            "--shallow-file",
            "/nonexistent/shallow",
            "pack-objects",
            "--revs",
        ];
        assert!(select(&repo, &missing, &format!("{second}\n"), &[], &[]).is_err());
    }

    #[test]
    fn nothing_new_yields_an_empty_pack_list() {
        let (repo, commit) = seed_billing_repo();
        let selection = select_ok(
            &repo,
            &PACK_ARGS,
            &format!("{commit}\n--not\n{commit}\n"),
            &[],
            &[],
        );
        assert!(selection.objects.is_empty());
        assert!(selection.object_list().is_empty());
        let empty = select_ok(&repo, &PACK_ARGS, "", &[], &[]);
        assert!(empty.objects.is_empty());
    }

    #[test]
    fn replace_refs_are_ignored() {
        let (repo, commit) = seed_billing_repo();
        repo.write("public/other.txt", "other\n");
        let replacement = repo.commit_all("replacement");
        repo.git(&["replace", &commit, &replacement]);
        let other = repo.rev_parse(&format!("{replacement}:public/other.txt"));
        let selection = select_ok(&repo, &PACK_ARGS, &format!("{commit}\n"), &[], &[]);
        assert!(!selected_ids(&selection).contains(&other));
    }

    #[test]
    fn finds_blobs_held_only_at_withheld_paths() {
        let (repo, _commit) = seed_billing_repo();
        let secret = object_id(&repo.rev_parse("HEAD:config/billing/secret.txt"));
        let shared = object_id(&repo.rev_parse("HEAD:public/shared.txt"));
        let readme = object_id(&repo.rev_parse("HEAD:public/readme.txt"));
        let absent = object_id(COMMIT_C);
        let candidates = HashSet::from([secret, shared, readme, absent]);
        let find = |member_groups: &[&str], refs: &[&str]| match find_withheld_only_blobs(
            &repo.git_dir(),
            &strings(refs),
            &candidates,
            &billing_policy(),
            &groups(member_groups),
        ) {
            Ok(found) => found,
            Err(error) => panic!("classification failed: {error}"),
        };
        assert_eq!(find(&[], &["refs/heads/main"]), HashSet::from([secret]));
        assert!(find(&[], &[]).is_empty());
        assert!(find(&[], &["refs/heads/missing"]).is_empty());
        assert!(find(&["billing"], &["refs/heads/main"]).is_empty());
    }
}
