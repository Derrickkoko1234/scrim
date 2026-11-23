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
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet, VecDeque},
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    rc::Rc,
    sync::Arc,
};

use gix::{
    ObjectId,
    date::SecondsSinceUnixEpoch,
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

/// A commit's tree, parents and committer time.
#[derive(Clone)]
struct CommitInfo {
    tree: ObjectId,
    /// Shared with the memo in [`ObjectGraph`], so handing a commit out costs
    /// a reference-count bump instead of a copy.
    parents: Rc<[ObjectId]>,
    /// Committer time in seconds since the epoch, or 0 if it cannot be
    /// parsed (as Git does). It only orders the commit walk; see
    /// [`select_commits`].
    committer_time: SecondsSinceUnixEpoch,
}

/// An object reached by peeling annotated tags.
struct PeeledObject {
    /// The tags passed through, outermost first.
    tags: Vec<ObjectId>,
    target: ObjectId,
    kind: Kind,
}

/// Most decoded objects [`DeltaBaseCache`] keeps.
const DELTA_BASE_CACHE_ENTRIES: usize = 64;

/// Most bytes [`DeltaBaseCache`] keeps.
const DELTA_BASE_CACHE_BYTES: usize = 96 * 1024 * 1024;

/// Recently decoded pack objects, so reading a tree whose delta base was
/// just read does not inflate its whole delta chain again.
///
/// The walks read neighbouring versions of the same trees one after the
/// other, so without it most of their time went to zlib. gix only ships such
/// a cache behind features this crate does not enable; this is the same
/// most-recently-used list as its `StaticLinkedList`, capped at
/// [`DELTA_BASE_CACHE_ENTRIES`] objects and [`DELTA_BASE_CACHE_BYTES`].
/// Entries are keyed by pack and offset, as gix requires, and live only as
/// long as one [`ObjectGraph`].
#[derive(Default)]
struct DeltaBaseCache {
    /// Most recently used first.
    entries: VecDeque<CachedPackObject>,
    total_bytes: usize,
}

struct CachedPackObject {
    pack_id: u32,
    offset: u64,
    kind: Kind,
    data: Vec<u8>,
    /// Size of the entry in the pack, which gix expects back from `get`.
    compressed_size: usize,
}

impl gix::odb::pack::cache::DecodeEntry for DeltaBaseCache {
    fn put(&mut self, pack_id: u32, offset: u64, data: &[u8], kind: Kind, compressed_size: usize) {
        if data.len() > DELTA_BASE_CACHE_BYTES / 4 {
            return;
        }
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.pack_id == pack_id && entry.offset == offset)
            && let Some(stale) = self.entries.remove(index)
        {
            self.total_bytes -= stale.data.len();
        }
        while self.entries.len() >= DELTA_BASE_CACHE_ENTRIES
            || self.total_bytes + data.len() > DELTA_BASE_CACHE_BYTES
        {
            match self.entries.pop_back() {
                Some(evicted) => self.total_bytes -= evicted.data.len(),
                None => break,
            }
        }
        self.total_bytes += data.len();
        self.entries.push_front(CachedPackObject {
            pack_id,
            offset,
            kind,
            data: data.to_vec(),
            compressed_size,
        });
    }

    fn get(&mut self, pack_id: u32, offset: u64, out: &mut Vec<u8>) -> Option<(Kind, usize)> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.pack_id == pack_id && entry.offset == offset);
        let Some(entry) = (match index {
            Some(index) => self.entries.remove(index),
            None => None,
        }) else {
            return None;
        };
        out.clear();
        out.extend_from_slice(&entry.data);
        let hit = (entry.kind, entry.compressed_size);
        self.entries.push_front(entry);
        Some(hit)
    }
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
        let mut repo = match gix::open_opts(repo_dir, options) {
            Ok(repo) => repo,
            Err(_) => return Err(io::Error::other("cannot open the repository")),
        };
        repo.objects
            .set_pack_cache(|| Box::new(DeltaBaseCache::default()));
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

    /// The tree, parents and committer time of `commit`, memoized.
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
                committer_time: match parsed.committer() {
                    Ok(committer) => committer.seconds(),
                    Err(_) => 0,
                },
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

    /// The raw data of the tree `tree`, which must be stored as a tree. Its
    /// entries are read with [`Self::tree_entries`].
    fn read_tree(&self, tree: ObjectId) -> io::Result<Vec<u8>> {
        let (kind, data) = match self.read(tree) {
            Ok(object) => object,
            Err(error) => return Err(error),
        };
        if kind != Kind::Tree {
            return Err(invalid_data("expected a tree"));
        }
        Ok(data)
    }

    /// The entries of tree data read by [`Self::read_tree`], borrowing their
    /// names from it instead of copying them.
    fn tree_entries<'data>(&self, data: &'data [u8]) -> gix::objs::TreeRefIter<'data> {
        gix::objs::TreeRefIter::from_bytes(data, self.hash_kind)
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

/// Uninteresting commits [`select_commits`] still pops once none queued can
/// reach a selected commit by committer time, like the `SLOP` of Git's
/// `limit_list`. It only matters when committer times are skewed, and only
/// makes the walk notice more of what the client has.
const COMMIT_WALK_SLOP: usize = 32;

/// The commits [`select_commits`] chose.
struct CommitSelection {
    /// Commits to send, in walk order (newest committer time first).
    send_commits: Vec<ObjectId>,
    send_commit_set: HashSet<ObjectId>,
    /// Parents of the non-shallow `send_commits` that the client has.
    boundary_commits: BTreeSet<ObjectId>,
}

/// What [`select_commits`] knows about one commit it reached.
#[derive(Clone, Copy)]
struct CommitWalkState {
    /// Reachable from a have (so the client has it). Never cleared.
    is_uninteresting: bool,
    /// Taken off the queue: its parents were queued or marked.
    is_popped: bool,
}

/// A queued commit; the queue pops the newest committer time first and, on a
/// tie, the commit queued first.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct QueuedCommit {
    committer_time: SecondsSinceUnixEpoch,
    sequence: Reverse<u64>,
    commit: ObjectId,
}

/// The state of one [`select_commits`] walk.
struct CommitWalk<'walk, 'policy> {
    graph: &'walk mut ObjectGraph<'policy>,
    shallow_commits: &'walk HashSet<ObjectId>,
    states: HashMap<ObjectId, CommitWalkState>,
    queue: BinaryHeap<QueuedCommit>,
    next_sequence: u64,
    /// Queued commits not marked uninteresting.
    interesting_in_queue: usize,
}

impl CommitWalk<'_, '_> {
    /// The parents of `commit` the walk follows: none for a shallow commit,
    /// whose parents the client does not have.
    fn parents(&mut self, commit: ObjectId) -> io::Result<Rc<[ObjectId]>> {
        if self.shallow_commits.contains(&commit) {
            return Ok(Rc::from([]));
        }
        match self.graph.commit(commit) {
            Ok(info) => Ok(info.parents),
            Err(error) => Err(error),
        }
    }

    /// Queues `commit`, which the walk has not reached before.
    fn enqueue(&mut self, commit: ObjectId, is_uninteresting: bool) -> io::Result<()> {
        let info = match self.graph.commit(commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        self.states.insert(
            commit,
            CommitWalkState {
                is_uninteresting,
                is_popped: false,
            },
        );
        if !is_uninteresting {
            self.interesting_in_queue += 1;
        }
        self.queue.push(QueuedCommit {
            committer_time: info.committer_time,
            sequence: Reverse(self.next_sequence),
            commit,
        });
        self.next_sequence += 1;
        Ok(())
    }

    /// Marks `commit` uninteresting. A queued commit passes the mark on to its
    /// parents when popped; a popped one passes it on now, down through every
    /// popped ancestor (Git's `mark_parents_uninteresting`).
    fn mark_uninteresting(&mut self, commit: ObjectId) -> io::Result<()> {
        let mut pending = vec![commit];
        while let Some(commit) = pending.pop() {
            let Some(state) = self.states.get_mut(&commit) else {
                if let Err(error) = self.enqueue(commit, true) {
                    return Err(error);
                }
                continue;
            };
            if state.is_uninteresting {
                continue;
            }
            state.is_uninteresting = true;
            if !state.is_popped {
                self.interesting_in_queue -= 1;
                continue;
            }
            match self.parents(commit) {
                Ok(parents) => pending.extend(parents.iter().copied()),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn is_uninteresting(&self, commit: &ObjectId) -> bool {
        matches!(
            self.states.get(commit),
            Some(CommitWalkState {
                is_uninteresting: true,
                ..
            })
        )
    }
}

/// Selects the commits reachable from `want_commits` that are not reachable
/// from `have_commits`, never following the parents of `shallow_commits`.
///
/// Like Git's `limit_list`, the walk pops commits newest committer time
/// first from one queue holding both sides, and marks everything below a
/// have uninteresting as it meets it, so an incremental fetch only reads
/// the commits near the boundary instead of the haves' whole history.
///
/// - A commit is only marked uninteresting by a chain of parent links from a
///   have, so the client has every commit left out. The walk only stops when
///   no interesting commit is queued (and checks that at the end), so every
///   interesting commit's parents were reached: nothing the client lacks is
///   left out.
/// - The walk keeps going while a queued uninteresting commit is at least
///   as new as the oldest selected commit, then for [`COMMIT_WALK_SLOP`] more
///   pops. If no parent is newer than its child, a queued commit cannot reach
///   an older selected commit, so the selection is then exactly the one a
///   full walk of the haves' history gives. With skewed times, a commit the
///   client has may still be selected; that sends it again (as Git does),
///   never anything withheld, since blobs are judged by path alone.
fn select_commits(
    graph: &mut ObjectGraph<'_>,
    want_commits: &[ObjectId],
    have_commits: &[ObjectId],
    shallow_commits: &HashSet<ObjectId>,
) -> io::Result<CommitSelection> {
    let mut walk = CommitWalk {
        graph,
        shallow_commits,
        states: HashMap::new(),
        queue: BinaryHeap::new(),
        next_sequence: 0,
        interesting_in_queue: 0,
    };
    for have in have_commits {
        if let Err(error) = walk.mark_uninteresting(*have) {
            return Err(error);
        }
    }
    for want in want_commits {
        if !walk.states.contains_key(want)
            && let Err(error) = walk.enqueue(*want, false)
        {
            return Err(error);
        }
    }

    let mut send_commits = Vec::new();
    let mut oldest_send_time: Option<SecondsSinceUnixEpoch> = None;
    let mut slop = COMMIT_WALK_SLOP;
    loop {
        if walk.interesting_in_queue == 0 {
            // Only uninteresting commits are queued: they can still turn a
            // selected commit uninteresting, but nothing new can be selected.
            let (Some(oldest_send_time), Some(newest_queued)) =
                (oldest_send_time, walk.queue.peek())
            else {
                break;
            };
            if newest_queued.committer_time >= oldest_send_time {
                slop = COMMIT_WALK_SLOP;
            } else if slop == 0 {
                break;
            } else {
                slop -= 1;
            }
        }
        let Some(queued) = walk.queue.pop() else {
            break;
        };
        let commit = queued.commit;
        let Some(state) = walk.states.get_mut(&commit) else {
            return Err(io::Error::other("commit walk lost track of a commit"));
        };
        state.is_popped = true;
        let is_uninteresting = state.is_uninteresting;
        let parents = match walk.parents(commit) {
            Ok(parents) => parents,
            Err(error) => return Err(error),
        };
        if is_uninteresting {
            for parent in parents.iter() {
                if let Err(error) = walk.mark_uninteresting(*parent) {
                    return Err(error);
                }
            }
            continue;
        }
        walk.interesting_in_queue -= 1;
        send_commits.push(commit);
        oldest_send_time = Some(match oldest_send_time {
            Some(oldest) => oldest.min(queued.committer_time),
            None => queued.committer_time,
        });
        for parent in parents.iter() {
            if !walk.states.contains_key(parent)
                && let Err(error) = walk.enqueue(*parent, false)
            {
                return Err(error);
            }
        }
    }
    // Never stop with an interesting commit unexpanded: its parents might be
    // missing from the pack. The loop guarantees this; checked so a bug fails
    // the fetch instead of sending an incomplete pack.
    if walk
        .queue
        .iter()
        .any(|queued| !walk.is_uninteresting(&queued.commit))
    {
        return Err(io::Error::other("commit walk stopped early"));
    }

    // Commits marked uninteresting after they were popped are not sent.
    send_commits.retain(|commit| !walk.is_uninteresting(commit));
    let mut boundary_commits = BTreeSet::new();
    for commit in &send_commits {
        let parents = match walk.parents(*commit) {
            Ok(parents) => parents,
            Err(error) => return Err(error),
        };
        boundary_commits.extend(
            parents
                .iter()
                .filter(|parent| walk.is_uninteresting(parent))
                .copied(),
        );
    }
    let send_commit_set = send_commits.iter().copied().collect();
    Ok(CommitSelection {
        send_commits,
        send_commit_set,
        boundary_commits,
    })
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

/// Index of a directory in a [`PathTable`].
type DirectoryId = usize;

/// The repository root.
const ROOT_DIRECTORY: DirectoryId = 0;

/// Every directory at or below a non-UTF-8 name: paths there cannot be
/// judged, so every blob in it is withheld.
const NON_UTF8_DIRECTORY: DirectoryId = 1;

/// The repository paths one tree walk met, each judged by
/// [`ObjectGraph::is_withheld`] at most once.
///
/// Walks name a directory by its [`DirectoryId`] and look entries up by
/// their raw name in it, so no path string is built or hashed per tree
/// entry: only when a directory or a name in it is met for the first time,
/// and for the path hints of emitted objects. Directories are interned by
/// full path, so two routes to the same path share one id exactly as equal
/// path strings would.
struct PathTable {
    directories: Vec<Directory>,
    directory_ids: HashMap<String, DirectoryId>,
}

/// One directory of a [`PathTable`].
struct Directory {
    /// Full path, empty at the root; `None` for [`NON_UTF8_DIRECTORY`].
    path: Option<String>,
    names: HashMap<Box<[u8]>, NameInfo>,
}

/// What is known about one name in one [`Directory`].
#[derive(Clone, Copy, Default)]
struct NameInfo {
    /// The directory of a tree at this name, once one was met.
    directory: Option<DirectoryId>,
    /// Whether a blob at this name is withheld, once one was met.
    is_withheld: Option<bool>,
}

impl PathTable {
    fn new() -> Self {
        Self {
            directories: vec![
                Directory {
                    path: Some(String::new()),
                    names: HashMap::new(),
                },
                Directory {
                    path: None,
                    names: HashMap::new(),
                },
            ],
            directory_ids: HashMap::from([(String::new(), ROOT_DIRECTORY)]),
        }
    }

    /// The full path of `directory` (`None` if not UTF-8).
    fn directory_path(&self, directory: DirectoryId) -> Option<&str> {
        match self.directories.get(directory) {
            Some(entry) => entry.path.as_deref(),
            None => None,
        }
    }

    /// The full path of `name` in `directory` (`None` if not UTF-8).
    fn entry_path(&self, directory: DirectoryId, name: &[u8]) -> Option<String> {
        child_path(self.directory_path(directory), name)
    }

    fn cached(&self, directory: DirectoryId, name: &[u8]) -> Option<NameInfo> {
        match self.directories.get(directory) {
            Some(entry) => entry.names.get(name).copied(),
            None => None,
        }
    }

    /// Records `update` for `name` in `directory`.
    fn remember(
        &mut self,
        directory: DirectoryId,
        name: &[u8],
        update: impl FnOnce(&mut NameInfo),
    ) {
        if let Some(entry) = self.directories.get_mut(directory) {
            update(
                entry
                    .names
                    .entry(Box::from(name))
                    .or_insert(NameInfo::default()),
            );
        }
    }

    /// The directory of a tree at `name` in `directory`.
    fn subdirectory(&mut self, directory: DirectoryId, name: &[u8]) -> DirectoryId {
        if directory == NON_UTF8_DIRECTORY {
            return NON_UTF8_DIRECTORY;
        }
        if let Some(NameInfo {
            directory: Some(subdirectory),
            ..
        }) = self.cached(directory, name)
        {
            return subdirectory;
        }
        let subdirectory = match self.entry_path(directory, name) {
            Some(path) => match self.directory_ids.get(&path) {
                Some(subdirectory) => *subdirectory,
                None => {
                    let subdirectory = self.directories.len();
                    self.directories.push(Directory {
                        path: Some(path.clone()),
                        names: HashMap::new(),
                    });
                    self.directory_ids.insert(path, subdirectory);
                    subdirectory
                }
            },
            None => NON_UTF8_DIRECTORY,
        };
        self.remember(directory, name, |info| info.directory = Some(subdirectory));
        subdirectory
    }

    /// Whether a blob at `name` in `directory` is withheld from the member.
    fn is_blob_withheld(
        &mut self,
        graph: &ObjectGraph<'_>,
        directory: DirectoryId,
        name: &[u8],
    ) -> bool {
        if directory == NON_UTF8_DIRECTORY {
            return true;
        }
        if let Some(NameInfo {
            is_withheld: Some(is_withheld),
            ..
        }) = self.cached(directory, name)
        {
            return is_withheld;
        }
        let is_withheld = graph.is_withheld(self.entry_path(directory, name).as_deref());
        self.remember(directory, name, |info| info.is_withheld = Some(is_withheld));
        is_withheld
    }
}

/// Memo key of one walked subtree: the tree and its directory, so a tree
/// reused at a withheld and a visible path is judged at each.
type SubtreeKey = (ObjectId, DirectoryId);

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
        paths: &mut PathTable,
        tree: ObjectId,
        directory: DirectoryId,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(invalid_data("trees nested too deeply"));
        }
        if !self.walked.insert((tree, directory)) {
            return Ok(());
        }
        self.trees.insert(tree);
        let data = match graph.read_tree(tree) {
            Ok(data) => data,
            Err(error) => return Err(error),
        };
        for entry in graph.tree_entries(&data) {
            let Ok(entry) = entry else {
                return Err(invalid_data("malformed tree"));
            };
            match entry.mode.kind() {
                EntryKind::Tree => {
                    let subdirectory = paths.subdirectory(directory, entry.filename);
                    if let Err(error) =
                        self.walk(graph, paths, entry.oid.to_owned(), subdirectory, depth + 1)
                    {
                        return Err(error);
                    }
                }
                EntryKind::Commit => {}
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    let blob = entry.oid.to_owned();
                    if !self.visible_blobs.contains(&blob)
                        && !paths.is_blob_withheld(graph, directory, entry.filename)
                    {
                        self.visible_blobs.insert(blob);
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
        paths: &mut PathTable,
        tree: ObjectId,
        directory: DirectoryId,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(invalid_data("trees nested too deeply"));
        }
        let key = (tree, directory);
        // A subtree the client has at this very path holds nothing new: its
        // visible blobs are had and its withheld blobs stay withheld.
        if self.client.walked.contains(&key) || !self.walked.insert(key) {
            return Ok(());
        }
        if !self.client.trees.contains(&tree) {
            self.emit(tree, paths.directory_path(directory));
        }
        let data = match graph.read_tree(tree) {
            Ok(data) => data,
            Err(error) => return Err(error),
        };
        for entry in graph.tree_entries(&data) {
            let Ok(entry) = entry else {
                return Err(invalid_data("malformed tree"));
            };
            match entry.mode.kind() {
                EntryKind::Tree => {
                    let subdirectory = paths.subdirectory(directory, entry.filename);
                    if let Err(error) =
                        self.walk(graph, paths, entry.oid.to_owned(), subdirectory, depth + 1)
                    {
                        return Err(error);
                    }
                }
                // A submodule commit lives in another repository.
                EntryKind::Commit => {}
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    let blob = entry.oid.to_owned();
                    let is_had_or_sent =
                        self.client.visible_blobs.contains(&blob) || self.emitted.contains(&blob);
                    // Such a blob is never emitted here, so once a withheld
                    // blob was seen the path check cannot change anything.
                    if is_had_or_sent && self.withheld_any_blob {
                        continue;
                    }
                    if paths.is_blob_withheld(graph, directory, entry.filename) {
                        self.withheld_any_blob = true;
                        continue;
                    }
                    if is_had_or_sent {
                        continue;
                    }
                    // The stored type is checked so a crafted entry cannot
                    // smuggle a commit or tag out under a blob mode.
                    let (kind, size) = match graph.header(blob) {
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
                        let path_hint = paths.entry_path(directory, entry.filename);
                        self.emit(blob, path_hint.as_deref());
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

    let commits = match select_commits(graph, &want_commits, &have_commits, &input.shallow_commits)
    {
        Ok(commits) => commits,
        Err(error) => return Err(error),
    };

    // Like `git pack-objects --revs` without `--thin`, only the trees of the
    // boundary commits count as had. Missing some had objects only sends
    // more, never anything withheld.
    let mut paths = PathTable::new();
    let mut client = ClientObjects::default();
    for commit in &commits.boundary_commits {
        let info = match graph.commit(*commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        if let Err(error) = client.walk(graph, &mut paths, info.tree, ROOT_DIRECTORY, 0) {
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
            if peeled.kind == Kind::Commit && commits.send_commit_set.contains(&peeled.target) {
                for tag in peeled.tags {
                    collector.emit(tag, None);
                }
            }
        }
    }
    for commit in &commits.send_commits {
        collector.emit(*commit, None);
    }
    for commit in &commits.send_commits {
        let info = match graph.commit(*commit) {
            Ok(info) => info,
            Err(error) => return Err(error),
        };
        if let Err(error) = collector.walk(graph, &mut paths, info.tree, ROOT_DIRECTORY, 0) {
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
    let mut paths = PathTable::new();
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
        if let Err(error) = classifier.walk(&graph, &mut paths, info.tree, ROOT_DIRECTORY, 0) {
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
        paths: &mut PathTable,
        tree: ObjectId,
        directory: DirectoryId,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_TREE_DEPTH {
            return Err(invalid_data("trees nested too deeply"));
        }
        if !self.walked.insert((tree, directory)) {
            return Ok(());
        }
        let data = match graph.read_tree(tree) {
            Ok(data) => data,
            Err(error) => return Err(error),
        };
        for entry in graph.tree_entries(&data) {
            let Ok(entry) = entry else {
                return Err(invalid_data("malformed tree"));
            };
            match entry.mode.kind() {
                EntryKind::Tree => {
                    let subdirectory = paths.subdirectory(directory, entry.filename);
                    if let Err(error) =
                        self.walk(graph, paths, entry.oid.to_owned(), subdirectory, depth + 1)
                    {
                        return Err(error);
                    }
                }
                EntryKind::Commit => {}
                EntryKind::Blob | EntryKind::BlobExecutable | EntryKind::Link => {
                    let blob = entry.oid.to_owned();
                    if !self.candidates.contains(&blob) {
                        continue;
                    }
                    if paths.is_blob_withheld(graph, directory, entry.filename) {
                        self.at_withheld_path.insert(blob);
                    } else {
                        self.at_visible_path.insert(blob);
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
        io::Write,
        path::PathBuf,
        process::{Command, Stdio},
    };

    use gix::ObjectId;
    use scrim_policy::{WithholdPolicy, WithholdRule};
    use tempfile::TempDir;

    use super::{
        COMMIT_WALK_SLOP, ClientObjectFilter, CommitSelection, DELTA_BASE_CACHE_BYTES,
        DELTA_BASE_CACHE_ENTRIES, DeltaBaseCache, ObjectGraph, PackObjectsArgs, PackSelection,
        compute_allowed_pack_objects, find_withheld_only_blobs, parse_filter_spec, parse_pack_args,
        parse_pack_stdin, select_commits, shell_quote,
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
            self.git_with_stdin(args, "")
        }

        /// Runs `git <args>` with `stdin` and returns its trimmed stdout.
        fn git_with_stdin(&self, args: &[&str], stdin: &str) -> String {
            let mut command = Command::new("git");
            command
                .args(args)
                .current_dir(&self.work)
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
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
            let mut child = match command.spawn() {
                Ok(child) => child,
                Err(error) => panic!("failed to run git {args:?}: {error}"),
            };
            match child.stdin.take() {
                Some(mut child_stdin) => {
                    if let Err(error) = child_stdin.write_all(stdin.as_bytes()) {
                        panic!("failed to feed git {args:?}: {error}");
                    }
                }
                None => panic!("git {args:?} stdin was not piped"),
            }
            let output = match child.wait_with_output() {
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

    /// One commit of a history built with `git fast-import`.
    struct DagCommit {
        /// Committer time in seconds since the epoch.
        time: i64,
        /// Indexes of earlier commits; the first is the first parent.
        parents: Vec<usize>,
        /// `(path, contents)` to write, or `(path, None)` to delete; `path`
        /// may be C-style quoted for fast-import.
        files: Vec<(String, Option<String>)>,
    }

    fn dag_commit(time: i64, parents: &[usize]) -> DagCommit {
        DagCommit {
            time,
            parents: parents.to_vec(),
            files: Vec::new(),
        }
    }

    /// Imports `commits` (each on its own branch `refs/heads/c<index>`, so
    /// every one is a ref tip) and returns their IDs in order.
    fn import_dag(repo: &TestRepo, commits: &[DagCommit]) -> Vec<ObjectId> {
        let mut stream = String::new();
        for (index, commit) in commits.iter().enumerate() {
            let message = format!("commit {index}\n");
            stream.push_str(&format!(
                "commit refs/heads/c{index}\nmark :{}\ncommitter Scrim Test <test@scrim.invalid> {} +0000\ndata {}\n{message}",
                index + 1,
                commit.time,
                message.len()
            ));
            for (position, parent) in commit.parents.iter().enumerate() {
                let verb = if position == 0 { "from" } else { "merge" };
                stream.push_str(&format!("{verb} :{}\n", parent + 1));
            }
            for (path, contents) in &commit.files {
                match contents {
                    Some(contents) => stream.push_str(&format!(
                        "M 100644 inline {path}\ndata {}\n{contents}\n",
                        contents.len()
                    )),
                    None => stream.push_str(&format!("D {path}\n")),
                }
            }
            stream.push('\n');
        }
        let marks_path = repo.git_dir().join("scrim-test-marks");
        let Some(marks) = marks_path.to_str() else {
            panic!("marks path is not UTF-8");
        };
        repo.git_with_stdin(
            &["fast-import", "--quiet", &format!("--export-marks={marks}")],
            &stream,
        );
        let marks_text = match std::fs::read_to_string(&marks_path) {
            Ok(text) => text,
            Err(error) => panic!("failed to read marks: {error}"),
        };
        let mut ids = vec![None; commits.len()];
        for line in marks_text.lines() {
            let Some((mark, hex)) = line.split_once(' ') else {
                panic!("unexpected marks line {line:?}");
            };
            let Ok(mark) = mark.trim_start_matches(':').parse::<usize>() else {
                panic!("unexpected mark {mark:?}");
            };
            if let Some(slot) = ids.get_mut(mark - 1) {
                *slot = Some(object_id(hex));
            }
        }
        ids.into_iter()
            .enumerate()
            .map(|(index, id)| match id {
                Some(id) => id,
                None => panic!("commit {index} has no mark"),
            })
            .collect()
    }

    fn open_graph<'policy>(
        repo: &TestRepo,
        policy: &'policy WithholdPolicy,
        member_groups: &'policy BTreeSet<String>,
    ) -> ObjectGraph<'policy> {
        match ObjectGraph::open(&repo.git_dir(), policy, member_groups) {
            Ok(graph) => graph,
            Err(error) => panic!("failed to open the repository: {error}"),
        }
    }

    /// Commits reachable from `starts` without passing `stop` or the parents
    /// of `shallow`: the full walk `select_commits` replaced.
    fn reachable(
        graph: &mut ObjectGraph<'_>,
        starts: &[ObjectId],
        stop: &HashSet<ObjectId>,
        shallow: &HashSet<ObjectId>,
    ) -> HashSet<ObjectId> {
        let mut visited = HashSet::new();
        let mut pending = starts.to_vec();
        while let Some(commit) = pending.pop() {
            if stop.contains(&commit) || !visited.insert(commit) || shallow.contains(&commit) {
                continue;
            }
            match graph.commit(commit) {
                Ok(info) => pending.extend(info.parents.iter().copied()),
                Err(error) => panic!("failed to read commit {commit}: {error}"),
            }
        }
        visited
    }

    /// Runs `select_commits` for the given commit indexes, checks it against
    /// the full walk and returns its selection plus how many commits it read.
    ///
    /// Always: every commit the full walk sends is sent, every extra commit
    /// is one the client has, nothing outside the wants' history is sent, and
    /// every boundary commit is had. With `expect_exact`, the selection must
    /// equal the full walk's.
    fn check_commit_walk(
        repo: &TestRepo,
        ids: &[ObjectId],
        wants: &[usize],
        haves: &[usize],
        shallow: &[usize],
        expect_exact: bool,
    ) -> (CommitSelection, usize) {
        let pick = |indexes: &[usize]| -> Vec<ObjectId> {
            indexes
                .iter()
                .map(|index| match ids.get(*index) {
                    Some(id) => *id,
                    None => panic!("no commit {index}"),
                })
                .collect()
        };
        let want_ids = pick(wants);
        let have_ids = pick(haves);
        let shallow_ids: HashSet<ObjectId> = pick(shallow).into_iter().collect();
        let policy = billing_policy();
        let member_groups = groups(&[]);
        let context = format!("wants {wants:?}, haves {haves:?}, shallow {shallow:?}");

        let mut graph = open_graph(repo, &policy, &member_groups);
        let selection = match select_commits(&mut graph, &want_ids, &have_ids, &shallow_ids) {
            Ok(selection) => selection,
            Err(error) => panic!("commit walk failed for {context}: {error}"),
        };
        let commits_read = graph.commits.len();

        let mut reference_graph = open_graph(repo, &policy, &member_groups);
        let had = reachable(
            &mut reference_graph,
            &have_ids,
            &HashSet::new(),
            &shallow_ids,
        );
        let wanted = reachable(
            &mut reference_graph,
            &want_ids,
            &HashSet::new(),
            &shallow_ids,
        );
        let expected_send = reachable(&mut reference_graph, &want_ids, &had, &shallow_ids);
        let mut expected_boundary = BTreeSet::new();
        for commit in &expected_send {
            if shallow_ids.contains(commit) {
                continue;
            }
            match reference_graph.commit(*commit) {
                Ok(info) => expected_boundary
                    .extend(info.parents.iter().filter(|parent| had.contains(*parent))),
                Err(error) => panic!("failed to read commit {commit}: {error}"),
            }
        }

        let send: HashSet<ObjectId> = selection.send_commits.iter().copied().collect();
        assert_eq!(
            send.len(),
            selection.send_commits.len(),
            "duplicate commit for {context}"
        );
        assert_eq!(send, selection.send_commit_set, "{context}");
        assert!(
            expected_send.is_subset(&send),
            "a commit the client lacks was left out for {context}"
        );
        assert!(
            send.is_subset(&wanted),
            "an unwanted commit was sent for {context}"
        );
        assert!(
            send.difference(&expected_send)
                .all(|commit| had.contains(commit)),
            "an extra commit the client lacks for {context}"
        );
        assert!(
            selection
                .boundary_commits
                .iter()
                .all(|commit| had.contains(commit)),
            "a boundary commit the client lacks for {context}"
        );
        assert!(
            expected_boundary
                .iter()
                .all(|commit| selection.boundary_commits.contains(commit) || send.contains(commit)),
            "a boundary commit was neither had nor sent for {context}"
        );
        if expect_exact {
            assert_eq!(send, expected_send, "send set for {context}");
            assert_eq!(
                selection.boundary_commits, expected_boundary,
                "boundary for {context}"
            );
        }
        (selection, commits_read)
    }

    /// A linear history of `length` commits, one second apart.
    fn linear_dag(length: usize) -> Vec<DagCommit> {
        (0..length)
            .map(|index| match index.checked_sub(1) {
                Some(parent) => dag_commit(1_000 + index as i64, &[parent]),
                None => dag_commit(1_000, &[]),
            })
            .collect()
    }

    #[test]
    fn incremental_walk_reads_only_commits_near_the_boundary() {
        let repo = TestRepo::new();
        let ids = import_dag(&repo, &linear_dag(400));
        let (selection, commits_read) = check_commit_walk(&repo, &ids, &[399], &[394], &[], true);
        assert_eq!(
            selection.send_commits,
            ids[395..].iter().rev().copied().collect::<Vec<_>>()
        );
        assert_eq!(selection.boundary_commits, BTreeSet::from([ids[394]]));
        // The five new commits, the have, and at most the slop below it.
        assert!(
            commits_read <= 5 + 1 + COMMIT_WALK_SLOP + 1,
            "read {commits_read} of 400 commits"
        );

        // Nothing new: only the want itself is read.
        let (selection, commits_read) = check_commit_walk(&repo, &ids, &[399], &[399], &[], true);
        assert!(selection.send_commits.is_empty() && selection.boundary_commits.is_empty());
        assert_eq!(commits_read, 1);

        // A have far behind still costs only the commits in between.
        let (selection, commits_read) = check_commit_walk(&repo, &ids, &[399], &[200], &[], true);
        assert_eq!(selection.send_commits.len(), 199);
        assert!(commits_read <= 199 + 1 + COMMIT_WALK_SLOP + 1);

        // A have newer than the want sends nothing.
        let (selection, _) = check_commit_walk(&repo, &ids, &[300], &[399], &[], true);
        assert!(selection.send_commits.is_empty());
        assert_eq!(selection.boundary_commits, BTreeSet::new());

        // No haves: an initial clone sends the whole history.
        let (selection, commits_read) = check_commit_walk(&repo, &ids, &[399], &[], &[], true);
        assert_eq!(selection.send_commits.len(), 400);
        assert_eq!(commits_read, 400);
    }

    #[test]
    fn commit_walk_handles_merges_and_disjoint_histories() {
        let repo = TestRepo::new();
        // 0 - 1 - 3 (diamond merge of 1 and 2) - 5 (octopus of 3, 2, 4)
        //  \- 2 ----/-----------------------/      4 is a separate root
        // 6 - 7 is a disjoint history.
        let ids = import_dag(
            &repo,
            &[
                dag_commit(100, &[]),
                dag_commit(110, &[0]),
                dag_commit(120, &[0]),
                dag_commit(130, &[1, 2]),
                dag_commit(140, &[]),
                dag_commit(150, &[3, 2, 4]),
                dag_commit(160, &[]),
                dag_commit(170, &[6]),
            ],
        );
        let cases: [(&[usize], &[usize], &[usize]); 12] = [
            (&[3], &[1], &[]),
            (&[3], &[2], &[]),
            (&[3], &[1, 2], &[]),
            (&[5], &[1], &[]),
            (&[5], &[3], &[]),
            (&[5], &[4, 1], &[]),
            (&[5, 7], &[6, 3], &[]),
            (&[7], &[5], &[]),
            (&[5], &[7], &[]),
            (&[3, 3], &[3, 0, 0], &[]),
            (&[5], &[], &[3]),
            (&[5], &[0], &[3]),
        ];
        for (wants, haves, shallow) in cases {
            check_commit_walk(&repo, &ids, wants, haves, shallow, true);
        }
        let (selection, _) = check_commit_walk(&repo, &ids, &[3], &[1], &[], true);
        assert_eq!(selection.send_commit_set, HashSet::from([ids[3], ids[2]]));
        assert_eq!(selection.boundary_commits, BTreeSet::from([ids[0], ids[1]]));
        let (selection, _) = check_commit_walk(&repo, &ids, &[7], &[5], &[], true);
        assert_eq!(selection.send_commit_set, HashSet::from([ids[6], ids[7]]));
        assert!(selection.boundary_commits.is_empty());
    }

    #[test]
    fn commit_walk_survives_clock_skew() {
        let repo = TestRepo::new();
        let ids = import_dag(
            &repo,
            &[
                // 0: shared base.
                dag_commit(1_000, &[]),
                // 1: have, older than its parent.
                dag_commit(10, &[0]),
                // 2: want, older than its parent and than the have.
                dag_commit(5, &[0]),
                // 3: a new commit far newer than its child 4 (the want).
                dag_commit(9_000, &[0]),
                dag_commit(20, &[3]),
                // 5: a have whose parent 3 is newer than everything else.
                dag_commit(30, &[3]),
                // 6: merges the have 1 and the new 3 with an old time.
                dag_commit(1, &[1, 3]),
            ],
        );
        for (wants, haves) in [
            (&[2][..], &[1][..]),
            (&[4], &[1]),
            (&[4], &[5]),
            (&[6], &[1]),
            (&[6], &[5]),
            (&[2, 4], &[1, 5]),
            (&[6], &[2]),
        ] {
            check_commit_walk(&repo, &ids, wants, haves, &[], true);
        }
        let (selection, _) = check_commit_walk(&repo, &ids, &[4], &[5], &[], true);
        assert_eq!(selection.send_commits, vec![ids[4]]);
        assert_eq!(selection.boundary_commits, BTreeSet::from([ids[3]]));
    }

    #[test]
    fn severe_clock_skew_only_ever_sends_more() {
        let repo = TestRepo::new();
        // 0..=99: an old history with new times; 100..=199: the have's
        // branch off 99 with times far older than all of it; 200: the want,
        // also off 99. The have is popped last, after the slop ran out.
        let mut commits = linear_dag(100);
        for commit in &mut commits {
            commit.time += 1_000_000;
        }
        for index in 100..200 {
            commits.push(dag_commit(index as i64, &[index - 1]));
        }
        commits.push(dag_commit(2_000_000, &[99]));
        let ids = import_dag(&repo, &commits);
        let (selection, _) = check_commit_walk(&repo, &ids, &[200], &[199], &[], false);
        assert!(selection.send_commit_set.contains(&ids[200]));
        // The skew did cost something: the shared history went out again.
        assert!(selection.send_commit_set.contains(&ids[99]));
    }

    #[test]
    fn commit_walk_matches_the_full_walk_on_generated_histories() {
        // A small deterministic generator (an LCG) keeps the test reproducible.
        let mut seed: u64 = 0x5c41_d00d;
        let mut next = move |bound: u64| -> u64 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % bound
        };
        let mut shape = Vec::new();
        for index in 0..150_usize {
            let mut parents = Vec::new();
            if index > 0 && next(12) != 0 {
                let extra = match next(20) {
                    0 => 2,
                    1..=3 => 1,
                    _ => 0,
                };
                let window = index.min(12) as u64;
                for _ in 0..=extra {
                    let parent = index - 1 - next(window) as usize;
                    if !parents.contains(&parent) {
                        parents.push(parent);
                    }
                }
            }
            shape.push(parents);
        }
        let mut cases = Vec::new();
        for _ in 0..150 {
            let pick = |count: u64, next: &mut dyn FnMut(u64) -> u64| -> Vec<usize> {
                (0..count).map(|_| next(150) as usize).collect()
            };
            let want_count = 1 + next(3);
            let have_count = next(4);
            let shallow_count = if next(4) == 0 { 1 + next(2) } else { 0 };
            cases.push((
                pick(want_count, &mut next),
                pick(have_count, &mut next),
                pick(shallow_count, &mut next),
            ));
        }
        for is_skewed in [false, true] {
            let repo = TestRepo::new();
            let commits: Vec<DagCommit> = shape
                .iter()
                .enumerate()
                .map(|(index, parents)| {
                    // Monotone times make the walk exact; random ones skew
                    // most parent-child pairs.
                    let time = if is_skewed {
                        next(5_000) as i64
                    } else {
                        1_000 + 10 * index as i64
                    };
                    dag_commit(time, parents)
                })
                .collect();
            let ids = import_dag(&repo, &commits);
            for (wants, haves, shallow) in &cases {
                check_commit_walk(&repo, &ids, wants, haves, shallow, !is_skewed);
            }
        }
    }

    /// `(path, contents)` to write in a [`DagCommit`].
    fn file(path: &str, contents: &str) -> (String, Option<String>) {
        (path.to_owned(), Some(contents.to_owned()))
    }

    #[test]
    fn deep_incremental_fetch_sends_a_blob_moved_out_of_a_withheld_path() {
        let repo = TestRepo::new();
        let mut commits = linear_dag(300);
        commits[0].files = vec![
            file("config/billing/key.txt", "billing key\n"),
            file("config/billing/other.txt", "other secret\n"),
            file("public/a.txt", "a\n"),
        ];
        commits[150].files = vec![file("public/b.txt", "b\n")];
        // The move, committed with a clock far behind its parent.
        let mut moved = dag_commit(5, &[299]);
        moved.files = vec![
            ("config/billing/key.txt".to_owned(), None),
            file("public/key.txt", "billing key\n"),
            file("config/billing/new.txt", "new secret\n"),
        ];
        commits.push(moved);
        let ids = import_dag(&repo, &commits);
        let head = ids[300].to_string();
        let have = ids[299].to_string();
        let key = repo.rev_parse(&format!("{head}:public/key.txt"));
        let new_secret = repo.rev_parse(&format!("{head}:config/billing/new.txt"));
        let a = repo.rev_parse(&format!("{head}:public/a.txt"));
        let b = repo.rev_parse(&format!("{head}:public/b.txt"));
        let public_tree = repo.rev_parse(&format!("{head}:public"));

        let selection = select_ok(
            &repo,
            &PACK_ARGS,
            &format!("{head}\n--not\n{have}\n"),
            &[],
            &[],
        );
        let ids_sent = selected_ids(&selection);
        assert!(ids_sent.contains(&head));
        assert!(ids_sent.contains(&public_tree));
        assert!(
            ids_sent.contains(&key),
            "the newly visible blob was not sent"
        );
        assert!(!ids_sent.contains(&new_secret), "a withheld blob was sent");
        assert!(selection.withheld_any_blob);
        for had in [&have, &a, &b] {
            assert!(!ids_sent.contains(had), "{had} was sent again");
        }
        // The commit, the root, `public`, `config` and `config/billing`
        // trees, and the moved blob.
        assert_eq!(ids_sent.len(), 6, "{ids_sent:?}");

        // A member of `billing` gets the new secret too, and still nothing had.
        let allowed = select_ok(
            &repo,
            &PACK_ARGS,
            &format!("{head}\n--not\n{have}\n"),
            &["billing"],
            &[],
        );
        let allowed_ids = selected_ids(&allowed);
        assert!(allowed_ids.contains(&new_secret));
        assert!(
            !allowed_ids.contains(&key),
            "a blob the member had was sent"
        );
    }

    #[test]
    fn non_utf8_paths_are_withheld_and_judged_per_path() {
        let repo = TestRepo::new();
        let mut root = dag_commit(1_000, &[]);
        root.files = vec![
            file("\"public/caf\\351/a.txt\"", "under a non-UTF-8 directory\n"),
            file("\"public/b\\377.txt\"", "non-UTF-8 name\n"),
            file("public/visible.txt", "visible\n"),
            file("public/copy/same.txt", "same\n"),
            file("config/billing/same.txt", "same\n"),
        ];
        let ids = import_dag(&repo, &[root]);
        let commit = ids[0].to_string();
        let blob = |data: &str| repo.git_with_stdin(&["hash-object", "--stdin"], data);
        let selection = select_ok(&repo, &PACK_ARGS, &format!("{commit}\n"), &[], &[]);
        let sent = selected_ids(&selection);
        assert!(selection.withheld_any_blob);
        assert!(!sent.contains(&blob("under a non-UTF-8 directory\n")));
        assert!(!sent.contains(&blob("non-UTF-8 name\n")));
        assert!(sent.contains(&blob("visible\n")));
        assert!(sent.contains(&blob("same\n")));
        assert_eq!(
            selection.objects.len(),
            sent.len(),
            "an object was listed twice"
        );
        assert!(
            selection
                .objects
                .iter()
                .all(|(_, hint)| hint.as_deref().is_none_or(|hint| hint.is_ascii()))
        );

        // A path that cannot be judged stays withheld even from a member
        // every rule allows (such a member never runs the hook anyway).
        let allowed = select_ok(&repo, &PACK_ARGS, &format!("{commit}\n"), &["billing"], &[]);
        assert!(allowed.withheld_any_blob);
        let allowed_ids = selected_ids(&allowed);
        assert!(!allowed_ids.contains(&blob("non-UTF-8 name\n")));
        assert!(allowed_ids.contains(&blob("visible\n")));
    }

    #[test]
    fn delta_base_cache_keeps_the_most_recently_used_objects() {
        use gix::{objs::Kind, odb::pack::cache::DecodeEntry};

        let mut cache = DeltaBaseCache::default();
        let mut out = b"stale".to_vec();
        assert_eq!(cache.get(0, 10, &mut out), None);
        cache.put(0, 10, b"tree data", Kind::Tree, 7);
        assert_eq!(cache.get(0, 10, &mut out), Some((Kind::Tree, 7)));
        assert_eq!(out, b"tree data");
        // Keyed by pack and offset.
        assert_eq!(cache.get(1, 10, &mut out), None);

        // Filling it evicts the least recently used: offset 10 was just read,
        // so offset 11 goes first.
        cache.put(0, 11, b"x", Kind::Blob, 1);
        assert!(cache.get(0, 10, &mut out).is_some());
        for offset in 0..(DELTA_BASE_CACHE_ENTRIES as u64 - 2) {
            cache.put(1, offset, b"y", Kind::Blob, 1);
        }
        assert_eq!(cache.entries.len(), DELTA_BASE_CACHE_ENTRIES);
        cache.put(2, 0, b"z", Kind::Commit, 1);
        assert_eq!(cache.entries.len(), DELTA_BASE_CACHE_ENTRIES);
        assert_eq!(cache.get(0, 11, &mut out), None);
        assert!(cache.get(0, 10, &mut out).is_some());

        // Replacing an entry keeps the byte count right; huge objects are skipped.
        cache.put(2, 0, b"zz", Kind::Commit, 2);
        let bytes: usize = cache.entries.iter().map(|entry| entry.data.len()).sum();
        assert_eq!(cache.total_bytes, bytes);
        cache.put(
            3,
            0,
            &vec![0; DELTA_BASE_CACHE_BYTES / 4 + 1],
            Kind::Blob,
            1,
        );
        assert_eq!(cache.get(3, 0, &mut out), None);
    }
}
