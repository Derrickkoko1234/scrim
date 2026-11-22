//! Server-owned `pre-receive` guard for every push.
//!
//! `git receive-pack` always runs with `core.hooksPath` pointing at a
//! [`HookDir`] whose only hook, `pre-receive`, is a link to the scrim-server
//! binary itself. Started by git with [`PRE_RECEIVE_HOOK_MODE_ENV`] set, the
//! binary runs [`run_pre_receive_hook_process`] instead of the server: it
//! forwards git's update lines, quarantine paths and push options to a
//! callback listener the server opened for that request
//! ([`start_pre_receive_session`]), and exits with the server's verdict.
//!
//! # Callback transport
//!
//! On Unix the listener is a Unix socket with a random name inside the
//! `0700` [`HookDir`], so no other user can connect to it or squat its
//! address; elsewhere it is an ephemeral loopback TCP port. Both sides prove
//! knowledge of a random per-request token without sending it: the hook sends
//! `hex(sha256("scrim-hook-request:" || token))` and the server answers with
//! `hex(sha256("scrim-hook-response:" || token))`. The hook treats a verdict
//! without the right response proof as a rejection, and the listener keeps
//! waiting (up to [`MAX_REJECTED_CALLBACK_CONNECTIONS`] bad connections) for
//! the real hook instead of giving up after a stray connection.
//!
//! # Checks
//!
//! The server decides with full knowledge of the member and the branch rules
//! ([`evaluate_pre_receive`]), in six checks:
//!
//! 1. every update line is well formed and names a UTF-8 `refs/...` ref, and
//!    a push updates at most [`MAX_REF_UPDATES_PER_PUSH`] refs;
//! 2. the member may see every ref they create, update or delete, with rules
//!    also applied ignoring ASCII case, and no update names a ref that differs
//!    only in case from an existing ref (on a case-insensitive file system both
//!    names are the same loose ref file);
//! 3. a member who cannot see every ref only points refs at objects they sent
//!    in this push or that are reachable from refs they can see, so an empty
//!    pack naming a hidden object ID cannot publish it. An object found in
//!    the quarantine directory that also exists in the repository must be
//!    reachable from a visible ref: `index-pack --fix-thin` copies the base
//!    of a `REF_DELTA` from the repository into the quarantined pack, so a
//!    thin pack naming a hidden object as a delta base would otherwise make
//!    that object look "sent";
//! 4. no commit reachable only from refs with a narrower audience lands in a
//!    wider-audience ref, unless the pusher passes
//!    [`ALLOW_MERGE_LEAK_PUSH_OPTION`], which is recorded in the audit log.
//!    This check is about commit ancestry only: a ref pointed straight at a
//!    tree or blob (for example a tag), or a squash of restricted content, is
//!    not a merge leak. For members who cannot see the restricted refs, check
//!    3 already refuses every object they could not otherwise read; members
//!    who can see them may squash by design;
//! 5. no commit new to the repository (and no blob or tree a ref is pointed
//!    at directly) adds a plaintext dotenv file or a file containing a
//!    high-confidence credential (see [`crate::secret_scan`]), and a push
//!    introduces at most [`MAX_SCANNED_COMMITS`] new commits, unless the
//!    pusher passes [`ALLOW_SECRET_SCAN_PUSH_OPTION`], which is recorded in the
//!    audit log. This applies to every member, admins included; only what
//!    changed in each new commit is scanned (merges by combined diff, so a
//!    file taken unchanged from a parent is not rescanned), so content
//!    already accepted never has to be overridden again;
//! 6. a member with withheld paths (see [`scrim_policy::WithholdPolicy`])
//!    neither changes a withheld path (matched also ignoring ASCII case; a
//!    non-UTF-8 path counts as withheld) in a new commit, nor publishes a blob
//!    the repository only holds at withheld paths: not at a visible path of a
//!    new commit, not as a ref's direct target, and not as a thin pack's
//!    `REF_DELTA` base (an existing object in the quarantine). A merge may
//!    only take a withheld path unchanged from one parent, and only where the
//!    other side left it untouched since their merge bases, so neither an
//!    evil merge nor picking an older side rewrites it. Never overridable.
//!
//! Every failure (bad framing, an unreachable server, a git error, a failed
//! audit write) rejects the push.
//!
//! # Residual oracle
//!
//! `index-pack` runs before the hook. A pusher who names a hidden object ID
//! as a `REF_DELTA` base sees a different error for an object that does not
//! exist ("unresolved deltas" / "bad object") than for one that exists but
//! does not match the delta's declared base size ("failed to apply delta"),
//! so a pusher can learn whether an object ID they already know exists, and
//! its size by repeated attempts. Its content is never revealed: check 3
//! rejects the push whenever the object is not reachable from a visible ref.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet, btree_map},
    env::VarError,
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    net::Shutdown,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio_util::task::AbortOnDropHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::sha256_zeroizing,
    git_service::{RepoRefEntry, list_repo_refs, run_isolated_git},
    pack_withhold::find_withheld_only_blobs,
    policy_store::{AuditLogEntry, AuthenticatedMember, MemberRepoPolicy, PolicyStore},
    secret_scan::{MAX_SCANNED_BLOB_BYTES, check_blocked_path_bytes, scan_blob_bytes},
};

/// The hook's end of the callback connection.
#[cfg(unix)]
pub(crate) type HookStream = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
pub(crate) type HookStream = std::net::TcpStream;

/// The server's callback listener and its accepted connections.
#[cfg(unix)]
pub(crate) type CallbackListener = tokio::net::UnixListener;
#[cfg(unix)]
pub(crate) type CallbackConnection = tokio::net::UnixStream;
#[cfg(not(unix))]
pub(crate) type CallbackListener = tokio::net::TcpListener;
#[cfg(not(unix))]
pub(crate) type CallbackConnection = tokio::net::TcpStream;

/// Environment variable that switches the scrim-server binary into hook mode
/// when set to [`PRE_RECEIVE_HOOK_MODE`].
pub const PRE_RECEIVE_HOOK_MODE_ENV: &str = "SCRIM_HOOK_MODE";

/// Value of [`PRE_RECEIVE_HOOK_MODE_ENV`] that runs the `pre-receive` hook.
pub const PRE_RECEIVE_HOOK_MODE: &str = "pre-receive";

/// Push option (`git push -o scrim.allow-merge-leak=true`) that lets an
/// authorized member land commits from more restricted refs in a wider ref.
/// Each use is written to the audit log. It never bypasses checks 1-3.
pub const ALLOW_MERGE_LEAK_PUSH_OPTION: &str = "scrim.allow-merge-leak=true";

/// Push option (`git push -o scrim.allow-secret-scan=true`) that lets a
/// member land content check 5 flagged as a plaintext secret, for confirmed
/// false positives. Each use is written to the audit log, naming the findings
/// but never their content. It never bypasses checks 1-4.
pub const ALLOW_SECRET_SCAN_PUSH_OPTION: &str = "scrim.allow-secret-scan=true";

/// Address of the request's callback listener: the socket path on Unix, a
/// loopback `127.0.0.1:<port>` elsewhere.
const HOOK_ADDR_ENV: &str = "SCRIM_HOOK_ADDR";

/// Per-request token both sides derive their proofs from.
const HOOK_TOKEN_ENV: &str = "SCRIM_HOOK_TOKEN";

/// Domain prefix of the proof the hook sends with its request.
const REQUEST_PROOF_DOMAIN: &str = "scrim-hook-request:";

/// Domain prefix of the proof the server sends with its verdict.
const RESPONSE_PROOF_DOMAIN: &str = "scrim-hook-response:";

/// Overrides the binary the hook directory links to.
const HOOK_BIN_ENV: &str = "SCRIM_HOOK_BIN";

/// Path of the server binary that cargo sets when running integration tests.
const CARGO_SERVER_BINARY_ENV: &str = "CARGO_BIN_EXE_scrim-server";

/// File stem of the server binary.
const SERVER_BINARY_STEM: &str = "scrim-server";

/// Name of the hook inside the hook directory.
const PRE_RECEIVE_HOOK_NAME: &str = "pre-receive";

/// Name of the `uploadpack.packObjectsHook` link inside the hook directory
/// (see [`crate::pack_withhold`]). Not a git hook name, so it never runs as a
/// `core.hooksPath` hook.
const PACK_OBJECTS_HOOK_NAME: &str = "pack-objects";

/// Most bytes of update lines the hook forwards.
const MAX_HOOK_STDIN_BYTES: usize = 16 * 1024 * 1024;

/// Most push options the hook forwards.
const MAX_PUSH_OPTIONS: usize = 64;

/// Most ref updates one push may carry; bounds the per-update history walks
/// of check 4.
const MAX_REF_UPDATES_PER_PUSH: usize = 1000;

/// Largest callback request the server accepts: base64 of
/// [`MAX_HOOK_STDIN_BYTES`] plus generous room for paths and push options.
const MAX_HOOK_REQUEST_BYTES: usize = MAX_HOOK_STDIN_BYTES / 3 * 4 + 1024 * 1024;

/// Largest callback response the hook accepts.
const MAX_HOOK_RESPONSE_BYTES: usize = 64 * 1024;

/// How long the hook waits to connect to the callback listener.
#[cfg(not(unix))]
pub(crate) const HOOK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the hook waits for the verdict; the history walks of checks 3 and
/// 4 can take a while on large repositories.
pub(crate) const HOOK_READ_TIMEOUT: Duration = Duration::from_secs(600);

/// How long the hook may block sending its request.
pub(crate) const HOOK_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the callback listener waits for one connection to send its whole
/// request before dropping it and waiting for the next.
const CALLBACK_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections without a valid request proof the callback listener drops
/// before giving up on the real hook (which then rejects the push).
const MAX_REJECTED_CALLBACK_CONNECTIONS: usize = 16;

/// Number of random bytes in a callback token.
pub(crate) const TOKEN_BYTES: usize = 32;

/// Number of random bytes in a callback socket's file name. Kept short so the
/// socket path fits in `sun_path` (104 bytes on macOS) even under a long
/// temporary directory; the `0700` hook directory, not the name, keeps other
/// users out.
#[cfg(unix)]
const CALLBACK_SOCKET_NAME_BYTES: usize = 8;

/// Prefix of the temporary hook directory (`scrim-XXXXXX`, 12 bytes).
const HOOK_DIR_PREFIX: &str = "scrim-";

/// Longest Unix domain socket parent path accepted by [`hook_dir_parent_from`].
///
/// macOS limits `sockaddr_un.sun_path` to 104 bytes (103 + NUL) and Linux to
/// 108 bytes. Leaving room for `/scrim-XXXXXX/s-<16-hex>` (32 bytes) plus a
/// small margin ensures `UnixListener::bind` never fails under a deeply nested
/// `TMPDIR` or `XDG_RUNTIME_DIR`.
#[cfg(unix)]
const MAX_UNIX_SOCKET_PARENT_BYTES: usize = 68;

/// Most leaked commit IDs stored in one audit entry.
const MAX_AUDITED_LEAKED_COMMITS: usize = 10;

/// Most new commits check 5 scans in one push; a push introducing more is
/// refused (unless overridden) rather than partly scanned.
const MAX_SCANNED_COMMITS: usize = 4096;

/// Most check-5 findings listed in a rejection message or an audit entry.
const MAX_REPORTED_FINDINGS: usize = 10;

/// Longest path, in characters, shown for a check-5 finding.
const MAX_DISPLAYED_PATH_CHARS: usize = 200;

/// Object types `git cat-file --batch-check` reports for an existing object.
const OBJECT_TYPES: [&str; 4] = ["commit", "tree", "blob", "tag"];

const MALFORMED_UPDATE_MESSAGE: &str = "scrim: push rejected: malformed ref update";
const NON_UTF8_REF_MESSAGE: &str = "scrim: push rejected: non-UTF-8 ref names are not allowed";
const INVALID_REF_MESSAGE: &str = "scrim: push rejected: invalid ref name";
const TOO_MANY_REF_UPDATES_MESSAGE: &str = "scrim: push rejected: too many ref updates in one push";
const REF_CASE_CONFLICT_MESSAGE: &str =
    "scrim: push rejected: ref name conflicts with an existing ref";
const UNAUTHENTICATED_VERDICT_MESSAGE: &str =
    "scrim: push rejected: the pre-receive verdict could not be authenticated";
const HIDDEN_OBJECTS_MESSAGE: &str = "scrim: push rejected: contains objects not supplied in this push and not reachable from visible refs";
const INTERNAL_ERROR_MESSAGE: &str = "scrim: push rejected: internal error while checking the push";
const INVALID_HOOK_REQUEST_MESSAGE: &str = "scrim: push rejected: invalid pre-receive request";
const WITHHELD_CONTENT_MESSAGE: &str =
    "scrim: push rejected: references the content of a path withheld from you";

/// The empty blob: its content is known to everyone, so it is never treated
/// as withheld content.
const EMPTY_BLOB_ID: &str = "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";

/// What the hook sends to the callback listener.
#[derive(Serialize, Deserialize)]
struct HookRequest {
    /// `hex(sha256(REQUEST_PROOF_DOMAIN || token))` for the token in
    /// [`HOOK_TOKEN_ENV`]. The token itself is never sent, so whoever answers
    /// the connection cannot compute the response proof from it.
    request_proof: String,
    /// git's raw `pre-receive` stdin, base64-encoded so non-UTF-8 ref names
    /// reach the server (and are rejected there) intact.
    stdin_b64: String,
    /// Absolute `GIT_OBJECT_DIRECTORY`, if git set it.
    git_object_directory: Option<String>,
    /// Absolute `GIT_QUARANTINE_PATH`, if git set it.
    git_quarantine_path: Option<String>,
    /// `GIT_PUSH_OPTION_0 .. N-1`.
    push_options: Vec<String>,
}

impl CallbackRequest for HookRequest {
    const MAX_BYTES: usize = MAX_HOOK_REQUEST_BYTES;

    fn request_proof_mut(&mut self) -> &mut String {
        &mut self.request_proof
    }
}

/// A request a hook sends to its callback listener, authenticated by a
/// request proof (see [`accept_authenticated_callback`]).
pub(crate) trait CallbackRequest: serde::de::DeserializeOwned {
    /// Largest serialized request the listener reads.
    const MAX_BYTES: usize;

    /// The request proof, zeroized by the listener once checked.
    fn request_proof_mut(&mut self) -> &mut String;
}

/// The server's verdict.
#[derive(Serialize, Deserialize)]
struct HookResponse {
    /// Whether git may apply the updates.
    allow: bool,
    /// Text the hook prints to stderr, which git relays to the pusher.
    message: String,
    /// `hex(sha256(RESPONSE_PROOF_DOMAIN || token))`, filled in just before
    /// sending. A missing or wrong proof makes the hook reject the push.
    #[serde(default)]
    response_proof: String,
}

impl HookResponse {
    fn allow() -> Self {
        Self {
            allow: true,
            message: String::new(),
            response_proof: String::new(),
        }
    }

    fn reject(message: impl Into<String>) -> Self {
        Self {
            allow: false,
            message: message.into(),
            response_proof: String::new(),
        }
    }
}

/// Runs the `pre-receive` hook: forwards git's hook input to the server and
/// returns the process exit code, `0` iff the server allowed the push.
///
/// Uses only blocking `std` I/O, so no async runtime is started in the hook
/// process. Any error (missing environment, oversized input, an unreachable
/// server, an unreadable verdict) prints a short reason and returns `1`.
pub fn run_pre_receive_hook_process() -> i32 {
    let response = match exchange_with_server() {
        Ok(response) => response,
        Err(error) => HookResponse::reject(format!(
            "scrim: push rejected: the pre-receive check could not run ({error})"
        )),
    };
    if !response.message.is_empty() {
        // Nothing useful can be done if stderr is gone; the exit code still
        // carries the verdict.
        let _ = writeln!(io::stderr(), "{}", response.message);
    }
    if response.allow { 0 } else { 1 }
}

/// Collects the hook input, sends it to the callback listener and reads the
/// verdict.
fn exchange_with_server() -> io::Result<HookResponse> {
    let callback_address = match std::env::var_os(HOOK_ADDR_ENV) {
        Some(address) if !address.is_empty() => address,
        _ => return Err(invalid_input(format!("{HOOK_ADDR_ENV} is not set"))),
    };
    let token = match std::env::var(HOOK_TOKEN_ENV) {
        Ok(token) => Zeroizing::new(token),
        Err(_) => return Err(invalid_input(format!("{HOOK_TOKEN_ENV} is not set"))),
    };

    let mut stdin_bytes = Vec::new();
    let mut limited_stdin = io::stdin().lock().take(MAX_HOOK_STDIN_BYTES as u64 + 1);
    if let Err(error) = limited_stdin.read_to_end(&mut stdin_bytes) {
        return Err(error);
    }
    if stdin_bytes.len() > MAX_HOOK_STDIN_BYTES {
        return Err(invalid_input("too many ref updates".to_owned()));
    }

    let git_object_directory = match read_absolute_path_env("GIT_OBJECT_DIRECTORY") {
        Ok(path) => path,
        Err(error) => return Err(error),
    };
    let git_quarantine_path = match read_absolute_path_env("GIT_QUARANTINE_PATH") {
        Ok(path) => path,
        Err(error) => return Err(error),
    };
    let push_options = match read_push_options() {
        Ok(push_options) => push_options,
        Err(error) => return Err(error),
    };

    let request_proof = derive_proof(REQUEST_PROOF_DOMAIN, &token);
    let expected_response_proof = derive_proof(RESPONSE_PROOF_DOMAIN, &token);
    let mut request = HookRequest {
        request_proof: request_proof.as_str().to_owned(),
        stdin_b64: BASE64.encode(&stdin_bytes),
        git_object_directory,
        git_quarantine_path,
        push_options,
    };
    let serialized = serde_json::to_vec(&request);
    request.request_proof.zeroize();
    let request_bytes = match serialized {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(error) => return Err(io::Error::other(error)),
    };
    exchange_over_callback(&callback_address, &request_bytes, &expected_response_proof)
}

/// Sends `request_bytes` to the callback listener at `callback_address` and
/// reads its verdict.
///
/// A verdict whose `response_proof` is missing or differs from
/// `expected_response_proof` (compared in constant time) is replaced by a
/// rejection, whatever it says: only the server that issued the token can
/// compute the proof.
fn exchange_over_callback(
    callback_address: &OsStr,
    request_bytes: &[u8],
    expected_response_proof: &str,
) -> io::Result<HookResponse> {
    let response_bytes =
        match send_callback_request(callback_address, request_bytes, MAX_HOOK_RESPONSE_BYTES) {
            Ok(response_bytes) => response_bytes,
            Err(error) => return Err(error),
        };
    let mut response = match serde_json::from_slice::<HookResponse>(&response_bytes) {
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
        Ok(HookResponse::reject(UNAUTHENTICATED_VERDICT_MESSAGE))
    }
}

/// Connects to the callback listener at `callback_address`, sends
/// `request_bytes`, closes the write side and returns the whole answer, at
/// most `max_response_bytes` long.
pub(crate) fn send_callback_request(
    callback_address: &OsStr,
    request_bytes: &[u8],
    max_response_bytes: usize,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut stream = match connect_to_callback(callback_address) {
        Ok(stream) => stream,
        Err(error) => return Err(error),
    };
    if let Err(error) = stream.set_read_timeout(Some(HOOK_READ_TIMEOUT)) {
        return Err(error);
    }
    if let Err(error) = stream.set_write_timeout(Some(HOOK_WRITE_TIMEOUT)) {
        return Err(error);
    }
    if let Err(error) = stream.write_all(request_bytes) {
        return Err(error);
    }
    // Signals the end of the request; the server reads until EOF.
    if let Err(error) = stream.shutdown(Shutdown::Write) {
        return Err(error);
    }

    let mut response_bytes = Zeroizing::new(Vec::new());
    let mut limited_stream = (&stream).take(max_response_bytes as u64 + 1);
    if let Err(error) = limited_stream.read_to_end(&mut response_bytes) {
        return Err(error);
    }
    if response_bytes.len() > max_response_bytes {
        return Err(invalid_input(
            "oversized response from the server".to_owned(),
        ));
    }
    Ok(response_bytes)
}

/// Connects to the callback socket at path `callback_address`.
#[cfg(unix)]
pub(crate) fn connect_to_callback(callback_address: &OsStr) -> io::Result<HookStream> {
    HookStream::connect(Path::new(callback_address))
}

/// Connects to the loopback callback listener at `callback_address`
/// (`127.0.0.1:<port>`).
#[cfg(not(unix))]
pub(crate) fn connect_to_callback(callback_address: &OsStr) -> io::Result<HookStream> {
    let address = match callback_address
        .to_str()
        .and_then(|text| text.parse::<std::net::SocketAddr>().ok())
    {
        Some(address) => address,
        None => return Err(invalid_input(format!("{HOOK_ADDR_ENV} is invalid"))),
    };
    HookStream::connect_timeout(&address, HOOK_CONNECT_TIMEOUT)
}

/// Returns `hex(sha256(domain || token))`, the proof of knowing `token` used
/// in one direction of the callback exchange.
pub(crate) fn derive_proof(domain: &str, token: &str) -> Zeroizing<String> {
    let mut input = Zeroizing::new(Vec::with_capacity(domain.len() + token.len()));
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(token.as_bytes());
    encode_hex(sha256_zeroizing(&input).as_slice())
}

/// Lowercase hex encoding of `bytes`.
pub(crate) fn encode_hex(bytes: &[u8]) -> Zeroizing<String> {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Returns `byte_count` random bytes from the operating system, hex-encoded.
pub(crate) fn generate_random_hex(byte_count: usize) -> io::Result<Zeroizing<String>> {
    let mut random_bytes = Zeroizing::new(vec![0_u8; byte_count]);
    if let Err(error) = getrandom::fill(random_bytes.as_mut_slice()) {
        return Err(io::Error::other(format!(
            "cannot generate random bytes: {error}"
        )));
    }
    Ok(encode_hex(&random_bytes))
}

/// Reads the path in environment variable `name` as an absolute UTF-8 string.
///
/// git runs hooks inside the repository directory and may set relative paths,
/// which would mean nothing to the server, so they are resolved here.
fn read_absolute_path_env(name: &str) -> io::Result<Option<String>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    let absolute = match std::path::absolute(PathBuf::from(value)) {
        Ok(absolute) => absolute,
        Err(error) => return Err(error),
    };
    match absolute.into_os_string().into_string() {
        Ok(text) => Ok(Some(text)),
        Err(_) => Err(invalid_input(format!("{name} is not valid UTF-8"))),
    }
}

/// Reads `GIT_PUSH_OPTION_COUNT` and `GIT_PUSH_OPTION_0 .. N-1`, failing on an
/// invalid count, more than [`MAX_PUSH_OPTIONS`] options, or a non-UTF-8 value.
fn read_push_options() -> io::Result<Vec<String>> {
    let count = match std::env::var("GIT_PUSH_OPTION_COUNT") {
        Ok(text) => match text.parse::<usize>() {
            Ok(count) => count,
            Err(_) => return Err(invalid_input("invalid push option count".to_owned())),
        },
        Err(VarError::NotPresent) => return Ok(Vec::new()),
        Err(VarError::NotUnicode(_)) => {
            return Err(invalid_input("invalid push option count".to_owned()));
        }
    };
    if count > MAX_PUSH_OPTIONS {
        return Err(invalid_input(format!(
            "at most {MAX_PUSH_OPTIONS} push options are allowed"
        )));
    }
    let mut push_options = Vec::with_capacity(count);
    for index in 0..count {
        match std::env::var(format!("GIT_PUSH_OPTION_{index}")) {
            Ok(push_option) => push_options.push(push_option),
            Err(_) => {
                return Err(invalid_input("push options must be valid UTF-8".to_owned()));
            }
        }
    }
    Ok(push_options)
}

pub(crate) fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// A private directory holding the server-owned `pre-receive` hook, used as
/// `core.hooksPath` for every `git receive-pack`, so hooks inside a
/// repository never run, and the `pack-objects` link used as
/// `uploadpack.packObjectsHook` for fetches with withheld paths. On Unix it
/// also holds each request's callback socket. Deleted when dropped.
#[derive(Debug)]
pub(crate) struct HookDir {
    dir: TempDir,
}

impl HookDir {
    /// Creates a `0700` temporary directory containing `pre-receive` and
    /// `pack-objects`, each a symbolic link (a copy on non-Unix platforms) to
    /// the scrim-server binary.
    ///
    /// The directory goes under `XDG_RUNTIME_DIR` when that names an existing
    /// directory (it is private to the user and not swept by
    /// `systemd-tmpfiles` like `/tmp`), otherwise under the system temporary
    /// directory.
    ///
    /// The binary is the first of: `SCRIM_HOOK_BIN`; the running executable
    /// if it is `scrim-server`; `CARGO_BIN_EXE_scrim-server` (set by
    /// `cargo test`); `scrim-server` two directories up from the running
    /// executable (cargo's older `target/<profile>/deps/` test layout). Fails
    /// if that path is not a regular file.
    pub(crate) fn create() -> io::Result<Self> {
        let binary = match resolve_server_binary() {
            Ok(binary) => binary,
            Err(error) => return Err(error),
        };
        let mut builder = tempfile::Builder::new();
        builder.prefix(HOOK_DIR_PREFIX);
        #[cfg(unix)]
        let private_permissions = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::Permissions::from_mode(0o700)
        };
        #[cfg(unix)]
        builder.permissions(private_permissions);
        let dir = match builder.tempdir_in(hook_dir_parent()) {
            Ok(dir) => dir,
            Err(error) => return Err(error),
        };
        for hook_name in [PRE_RECEIVE_HOOK_NAME, PACK_OBJECTS_HOOK_NAME] {
            let hook_path = dir.path().join(hook_name);
            // A link runs the binary directly: no shell script, so no quoting
            // issues and nothing extra needed in minimal containers.
            #[cfg(unix)]
            let link_result = std::os::unix::fs::symlink(&binary, &hook_path);
            #[cfg(not(unix))]
            let link_result = std::fs::copy(&binary, &hook_path).map(|_| ());
            if let Err(error) = link_result {
                return Err(error);
            }
        }
        let hook_dir = Self { dir };
        match hook_dir.verify_installed() {
            Ok(()) => Ok(hook_dir),
            Err(error) => Err(error),
        }
    }

    /// The directory to pass as `core.hooksPath`.
    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The `pack-objects` link, to run as `uploadpack.packObjectsHook`.
    pub(crate) fn pack_objects_hook_path(&self) -> PathBuf {
        self.dir.path().join(PACK_OBJECTS_HOOK_NAME)
    }

    /// Fails unless `pre-receive` and `pack-objects` still resolve to
    /// executable regular files.
    ///
    /// git silently skips a hook it cannot execute, which would accept the
    /// push unchecked, so this runs before every `receive-pack` (for example
    /// to catch the binary being replaced or removed during an upgrade), and
    /// before every fetch that relies on the `pack-objects` hook.
    pub(crate) fn verify_installed(&self) -> io::Result<()> {
        for hook_name in [PRE_RECEIVE_HOOK_NAME, PACK_OBJECTS_HOOK_NAME] {
            let hook_path = self.dir.path().join(hook_name);
            let metadata = match std::fs::metadata(&hook_path) {
                Ok(metadata) => metadata,
                Err(error) => return Err(error),
            };
            if !metadata.is_file() {
                return Err(io::Error::other(format!(
                    "{hook_name} hook is not a regular file"
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o111 == 0 {
                    return Err(io::Error::other(format!(
                        "{hook_name} hook is not executable"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// The directory [`HookDir::create`] creates the hook directory in:
/// `XDG_RUNTIME_DIR` if it is set, non-empty and an existing directory,
/// otherwise [`std::env::temp_dir`]. On Unix, candidates whose path is too long
/// for a `sun_path` callback socket are skipped in favour of `/tmp`.
fn hook_dir_parent() -> PathBuf {
    hook_dir_parent_from(
        std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        std::env::temp_dir(),
    )
}

fn hook_dir_parent_from(runtime_dir: Option<PathBuf>, temp_dir: PathBuf) -> PathBuf {
    #[cfg(unix)]
    let fits_unix_socket = |dir: &Path| {
        let raw_bytes = dir.as_os_str().as_encoded_bytes();
        let trimmed_len = match raw_bytes.iter().rposition(|&byte| byte != b'/') {
            Some(last) => last + 1,
            None => raw_bytes.len(),
        };
        trimmed_len <= MAX_UNIX_SOCKET_PARENT_BYTES
    };
    #[cfg(not(unix))]
    let fits_unix_socket = |_dir: &Path| true;

    let is_usable =
        |dir: &Path| !dir.as_os_str().is_empty() && dir.is_dir() && fits_unix_socket(dir);

    if let Some(runtime_dir) = runtime_dir
        && is_usable(&runtime_dir)
    {
        return runtime_dir;
    }
    if is_usable(&temp_dir) {
        return temp_dir;
    }
    #[cfg(unix)]
    {
        let fallback = PathBuf::from("/tmp");
        if is_usable(&fallback) {
            return fallback;
        }
    }
    temp_dir
}

/// Finds the scrim-server binary the hook directory links to (see
/// [`HookDir::create`]) and returns its canonical path.
fn resolve_server_binary() -> io::Result<PathBuf> {
    let candidate = if let Some(configured) = std::env::var_os(HOOK_BIN_ENV) {
        PathBuf::from(configured)
    } else {
        let current_exe = match std::env::current_exe() {
            Ok(current_exe) => current_exe,
            Err(error) => return Err(error),
        };
        if current_exe.file_stem() == Some(OsStr::new(SERVER_BINARY_STEM)) {
            current_exe
        } else if let Some(cargo_binary) = std::env::var_os(CARGO_SERVER_BINARY_ENV) {
            PathBuf::from(cargo_binary)
        } else {
            match current_exe.parent().and_then(Path::parent) {
                Some(profile_dir) => profile_dir.join(format!(
                    "{SERVER_BINARY_STEM}{}",
                    std::env::consts::EXE_SUFFIX
                )),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "cannot locate the scrim-server binary for the pre-receive hook",
                    ));
                }
            }
        }
    };
    let canonical = match candidate.canonicalize() {
        Ok(canonical) => canonical,
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "pre-receive hook binary {} is unavailable: {error}",
                    candidate.display()
                ),
            ));
        }
    };
    match std::fs::metadata(&canonical) {
        Ok(metadata) if metadata.is_file() => Ok(canonical),
        Ok(_) => Err(io::Error::other(format!(
            "pre-receive hook binary {} is not a regular file",
            canonical.display()
        ))),
        Err(error) => Err(error),
    }
}

/// Everything the guard needs to judge one push.
pub(crate) struct PreReceiveContext {
    /// Canonical directory of the bare repository.
    pub repo_dir: PathBuf,
    /// Canonical key of the repository, e.g. `team/app.git`.
    pub canonical_key: String,
    /// The pushing member.
    pub member: AuthenticatedMember,
    /// The member's groups and the repository's branch rules.
    pub policy: MemberRepoPolicy,
    /// Where override audit entries are written.
    pub policy_store: Arc<dyn PolicyStore>,
}

/// The hook environment for one `git receive-pack`, plus what must outlive
/// it: the hook directory and the callback listener task.
///
/// Dropping the session aborts the listener (and on Unix removes its socket
/// file), so it must live exactly as long as the git process (it is kept in
/// the response stream).
pub(crate) struct PreReceiveSession {
    // Declared first so they are dropped before `hook_dir`, which may be the
    // last reference to the directory holding the socket.
    _callback_task: AbortOnDropHandle<()>,
    #[cfg(unix)]
    _callback_socket: CallbackSocketFile,
    hook_dir: Arc<HookDir>,
    callback_address: OsString,
    token: Zeroizing<String>,
}

/// Removes a callback socket file when dropped, so socket files never
/// accumulate in the hook directory.
#[cfg(unix)]
pub(crate) struct CallbackSocketFile {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for CallbackSocketFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "cannot remove a hook callback socket");
        }
    }
}

impl PreReceiveSession {
    /// The hook directory, to pass as `core.hooksPath`.
    pub(crate) fn hooks_dir(&self) -> &Path {
        self.hook_dir.path()
    }

    /// See [`HookDir::verify_installed`].
    pub(crate) fn verify_hook_installed(&self) -> io::Result<()> {
        self.hook_dir.verify_installed()
    }

    /// The `(name, value)` environment variables `git receive-pack` passes on
    /// to the hook.
    pub(crate) fn hook_env(&self) -> [(&'static str, OsString); 3] {
        [
            (
                PRE_RECEIVE_HOOK_MODE_ENV,
                OsString::from(PRE_RECEIVE_HOOK_MODE),
            ),
            (HOOK_ADDR_ENV, self.callback_address.clone()),
            (HOOK_TOKEN_ENV, OsString::from(self.token.as_str())),
        ]
    }
}

/// Opens the callback listener for one `POST git-receive-pack`.
///
/// On Unix the listener is a socket with a random name in `hook_dir`; on
/// other platforms an ephemeral loopback TCP port. It answers exactly one
/// connection, the first to present the session's request proof (see
/// [`accept_authenticated_request`]), with [`evaluate_pre_receive`]'s
/// verdict.
pub(crate) async fn start_pre_receive_session(
    hook_dir: Arc<HookDir>,
    context: PreReceiveContext,
) -> io::Result<PreReceiveSession> {
    let token = match generate_random_hex(TOKEN_BYTES) {
        Ok(token) => token,
        Err(error) => return Err(error),
    };

    let bound = match bind_callback_listener(&hook_dir).await {
        Ok(bound) => bound,
        Err(error) => return Err(error),
    };
    let callback_task = AbortOnDropHandle::new(tokio::spawn(answer_hook_callback(
        bound.listener,
        derive_proof(REQUEST_PROOF_DOMAIN, &token),
        derive_proof(RESPONSE_PROOF_DOMAIN, &token),
        context,
    )));
    Ok(PreReceiveSession {
        _callback_task: callback_task,
        #[cfg(unix)]
        _callback_socket: bound.socket_file,
        hook_dir,
        callback_address: bound.address,
        token,
    })
}

/// A freshly bound per-request callback listener.
pub(crate) struct BoundCallbackListener {
    pub(crate) listener: CallbackListener,
    /// The address the hook connects to (see [`connect_to_callback`]).
    pub(crate) address: OsString,
    /// Removes the socket file when dropped.
    #[cfg(unix)]
    pub(crate) socket_file: CallbackSocketFile,
}

/// Binds a callback listener for one request: on Unix a socket with a random
/// name in `hook_dir`, elsewhere an ephemeral loopback TCP port.
pub(crate) async fn bind_callback_listener(
    hook_dir: &HookDir,
) -> io::Result<BoundCallbackListener> {
    #[cfg(unix)]
    {
        let socket_name = match generate_random_hex(CALLBACK_SOCKET_NAME_BYTES) {
            Ok(socket_name) => socket_name,
            Err(error) => return Err(error),
        };
        let socket_path = hook_dir.path().join(format!("s-{}", socket_name.as_str()));
        let listener = match CallbackListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => return Err(error),
        };
        Ok(BoundCallbackListener {
            listener,
            address: socket_path.clone().into_os_string(),
            socket_file: CallbackSocketFile { path: socket_path },
        })
    }
    #[cfg(not(unix))]
    {
        let _ = hook_dir;
        let listener = match CallbackListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => return Err(error),
        };
        let address = match listener.local_addr() {
            Ok(address) => OsString::from(address.to_string()),
            Err(error) => return Err(error),
        };
        Ok(BoundCallbackListener { listener, address })
    }
}

/// Waits for the hook's authenticated request on `listener`, judges the push
/// and sends the verdict with `response_proof`.
async fn answer_hook_callback(
    listener: CallbackListener,
    expected_request_proof: Zeroizing<String>,
    response_proof: Zeroizing<String>,
    context: PreReceiveContext,
) {
    let Some((mut stream, request)) =
        accept_authenticated_request(listener, &expected_request_proof).await
    else {
        return;
    };
    let response = evaluate_pre_receive(&context, &request).await;
    if !response.allow {
        tracing::info!(
            repository = %context.canonical_key,
            member_id = context.member.id,
            "pre-receive guard rejected a push"
        );
    }
    send_hook_response(&mut stream, response, &response_proof).await;
}

/// Accepts connections on `listener` until one sends a well-formed request
/// carrying `expected_request_proof` (compared in constant time), then closes
/// the listener and returns that connection and its request.
///
/// A connection with a wrong proof, or that sends a malformed or oversized
/// request or none within [`CALLBACK_REQUEST_READ_TIMEOUT`], is dropped
/// without an answer while the listener keeps waiting, so a stray or hostile
/// local connection cannot use up the hook's only chance to be heard. Gives
/// up (returns `None`, and the hook then rejects the push) after
/// [`MAX_REJECTED_CALLBACK_CONNECTIONS`] such connections or failed accepts.
async fn accept_authenticated_request(
    listener: CallbackListener,
    expected_request_proof: &str,
) -> Option<(CallbackConnection, HookRequest)> {
    accept_authenticated_callback(listener, expected_request_proof).await
}

/// [`accept_authenticated_request`] for any [`CallbackRequest`] type.
pub(crate) async fn accept_authenticated_callback<T: CallbackRequest>(
    listener: CallbackListener,
    expected_request_proof: &str,
) -> Option<(CallbackConnection, T)> {
    for _ in 0..MAX_REJECTED_CALLBACK_CONNECTIONS {
        let mut stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "failed to accept a hook callback");
                continue;
            }
        };
        let mut request = match read_callback_request::<T>(&mut stream).await {
            Ok(request) => request,
            Err(reason) => {
                tracing::warn!("dropped a hook callback connection: {reason}");
                continue;
            }
        };
        let request_proof = request.request_proof_mut();
        let is_proof_valid = bool::from(
            request_proof
                .as_bytes()
                .ct_eq(expected_request_proof.as_bytes()),
        );
        request_proof.zeroize();
        if is_proof_valid {
            // Only one hook runs per git process, so nothing else may
            // connect from here on.
            drop(listener);
            return Some((stream, request));
        }
        tracing::warn!("hook callback presented an invalid request proof");
    }
    tracing::warn!("too many invalid hook callback connections; giving up");
    None
}

/// Reads one whole request (until the peer closes its write side) from
/// `stream`, within [`CALLBACK_REQUEST_READ_TIMEOUT`] and
/// [`CallbackRequest::MAX_BYTES`]. Returns why on failure, for the log.
async fn read_callback_request<T: CallbackRequest>(
    stream: &mut CallbackConnection,
) -> Result<T, &'static str> {
    let mut request_bytes = Zeroizing::new(Vec::new());
    let mut limited_stream = stream.take(T::MAX_BYTES as u64 + 1);
    let read_result = tokio::time::timeout(
        CALLBACK_REQUEST_READ_TIMEOUT,
        limited_stream.read_to_end(&mut request_bytes),
    )
    .await;
    match read_result {
        Err(_) => Err("timed out reading the request"),
        Ok(Err(_)) => Err("failed to read the request"),
        Ok(Ok(_)) if request_bytes.len() > T::MAX_BYTES => Err("oversized request"),
        Ok(Ok(_)) => match serde_json::from_slice::<T>(&request_bytes) {
            Ok(request) => Ok(request),
            Err(_) => Err("malformed request"),
        },
    }
}

/// Sends `response`, authenticated with `response_proof`, to the hook.
async fn send_hook_response(
    stream: &mut CallbackConnection,
    mut response: HookResponse,
    response_proof: &str,
) {
    response.response_proof = response_proof.to_owned();
    let serialized = serde_json::to_vec(&response);
    response.response_proof.zeroize();
    let response_bytes = match serialized {
        Ok(bytes) => Zeroizing::new(bytes),
        // Unreachable for this plain struct, but never answer "allow" by
        // accident: an unauthenticated reply makes the hook reject.
        Err(_) => Zeroizing::new(b"{\"allow\":false,\"message\":\"\"}".to_vec()),
    };
    if let Err(error) = stream.write_all(&response_bytes).await {
        tracing::warn!(%error, "failed to answer the pre-receive callback");
        return;
    }
    if let Err(error) = stream.shutdown().await {
        tracing::debug!(%error, "failed to close the pre-receive callback");
    }
}

/// Judges one push and returns the verdict sent back to the hook.
async fn evaluate_pre_receive(context: &PreReceiveContext, request: &HookRequest) -> HookResponse {
    match check_push(context, request).await {
        Ok(()) => HookResponse::allow(),
        Err(message) => HookResponse::reject(message),
    }
}

/// Runs the five checks described in the module documentation, then writes
/// any override audit entries. Returns the rejection message on failure.
async fn check_push(context: &PreReceiveContext, request: &HookRequest) -> Result<(), String> {
    let policy = &context.policy;

    // Check 1: framing, object IDs and UTF-8 `refs/...` names.
    let stdin_bytes = match BASE64.decode(&request.stdin_b64) {
        Ok(bytes) => bytes,
        Err(_) => return Err(INVALID_HOOK_REQUEST_MESSAGE.to_owned()),
    };
    let updates = match parse_ref_updates(&stdin_bytes) {
        Ok(updates) => updates,
        Err(message) => return Err(message.to_owned()),
    };
    if request.push_options.len() > MAX_PUSH_OPTIONS {
        return Err(INVALID_HOOK_REQUEST_MESSAGE.to_owned());
    }

    // Defense in depth: the object paths must lie inside this repository's
    // object directory, so a confused request cannot point checks 3 and 4 at
    // another repository's objects.
    let objects_dir = match tokio::fs::canonicalize(context.repo_dir.join("objects")).await {
        Ok(objects_dir) => objects_dir,
        Err(error) => {
            return Err(internal_error(
                "cannot resolve the object directory",
                &error,
            ));
        }
    };
    let object_directory =
        match validate_object_path(request.git_object_directory.as_deref(), &objects_dir, true)
            .await
        {
            Ok(path) => path,
            Err(message) => return Err(message),
        };
    let quarantine_directory =
        match validate_object_path(request.git_quarantine_path.as_deref(), &objects_dir, false)
            .await
        {
            Ok(path) => path,
            Err(message) => return Err(message),
        };

    let repo_refs = match list_repo_refs(&context.repo_dir).await {
        Ok(repo_refs) => repo_refs,
        Err(error) => return Err(internal_error("cannot list repository refs", &error)),
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

    for (index, update) in updates.iter().enumerate() {
        // Check 2: exact ref-write authorization, for creates, updates and
        // deletes alike. Never overridable, and the message never names the
        // groups that would grant access. Rules also apply ignoring case: on
        // a case-insensitive file system `refs/heads/VAULT` is the loose ref
        // file of `refs/heads/vault`. (Stricter than `is_ref_visible`.)
        if !policy
            .branch_policy
            .is_ref_visible_case_insensitive(&update.ref_name, &policy.member_groups)
        {
            return Err(format!(
                "scrim: push rejected: you do not have access to ref {}",
                update.ref_name
            ));
        }
        // For the same reason, a name differing only in case from an existing
        // ref (or another ref in this push) could overwrite it. The message
        // never repeats the existing ref's spelling, which may be hidden.
        let is_case_conflict = repo_refs
            .iter()
            .map(|entry| entry.name.as_str())
            .chain(
                updates
                    .iter()
                    .enumerate()
                    .filter(|(other_index, _)| *other_index != index)
                    .map(|(_, other)| other.ref_name.as_str()),
            )
            .any(|name| name != update.ref_name && name.eq_ignore_ascii_case(&update.ref_name));
        if is_case_conflict {
            return Err(REF_CASE_CONFLICT_MESSAGE.to_owned());
        }
        // Writing through a symbolic ref would update its target, which the
        // checks above judged by the symbolic ref's own name.
        if symrefs.contains_key(update.ref_name.as_str()) {
            return Err(format!(
                "scrim: push rejected: {} is a symbolic ref and cannot be pushed to",
                update.ref_name
            ));
        }
    }

    if updates.iter().all(RefUpdate::is_delete) {
        return Ok(());
    }

    // `git receive-pack` keeps pushed objects in the quarantine directory
    // (GIT_OBJECT_DIRECTORY) until the hook accepts them; the repository's own
    // objects are reachable as its alternate.
    let mut walk_env: Vec<(&str, &OsStr)> = Vec::new();
    if let Some(object_directory) = &object_directory {
        // git splits this variable on ':' (and unquotes a leading '"'), so
        // such a path would silently name a different directory.
        let objects_dir_text = objects_dir.as_os_str();
        if objects_dir_text.as_encoded_bytes().contains(&b':')
            || objects_dir_text.as_encoded_bytes().starts_with(b"\"")
        {
            return Err(internal_error(
                "unsupported object directory path",
                &io::Error::other("path contains ':' or starts with '\"'"),
            ));
        }
        walk_env.push(("GIT_OBJECT_DIRECTORY", object_directory.as_os_str()));
        walk_env.push(("GIT_ALTERNATE_OBJECT_DIRECTORIES", objects_dir_text));
    }

    if let Err(message) = check_hidden_objects(
        context,
        &updates,
        &repo_refs,
        &symrefs,
        &walk_env,
        quarantine_directory.as_deref(),
    )
    .await
    {
        return Err(message);
    }

    // Check 6: withheld paths and withheld blobs, never overridable.
    if let Err(message) = check_withheld_paths(
        context,
        &updates,
        &repo_refs,
        &symrefs,
        &walk_env,
        quarantine_directory.as_deref(),
    )
    .await
    {
        return Err(message);
    }

    let mut audit_entries = match check_merge_leaks(
        context,
        &updates,
        &repo_refs,
        &symrefs,
        &walk_env,
        &request.push_options,
    )
    .await
    {
        Ok(audit_entries) => audit_entries,
        Err(message) => return Err(message),
    };

    // Check 5: plaintext secrets in new content, for every member.
    let secret_scan = match scan_pushed_content(context, &updates, &repo_refs, &walk_env).await {
        Ok(report) => report,
        Err(message) => return Err(message),
    };
    if !secret_scan.is_clean() {
        let has_override = request
            .push_options
            .iter()
            .any(|push_option| push_option == ALLOW_SECRET_SCAN_PUSH_OPTION);
        if !has_override {
            return Err(secret_scan.rejection_message());
        }
        audit_entries.push(secret_scan.override_audit_entry(context));
    }

    // Written only once every update passed every check, so a rejected push
    // never leaves an override entry behind. An override that cannot be
    // recorded is refused.
    for entry in audit_entries {
        if let Err(error) = context.policy_store.record_audit_event(entry).await {
            return Err(internal_error("cannot record the audit event", &error));
        }
    }
    Ok(())
}

/// Check 3 (closes `H1`): when the member cannot see every ref, every object
/// the new ref values reach must either be reachable from a ref the member
/// can see or have been sent in this push (be in the quarantine directory).
///
/// Without this, an empty pack naming the ID of a hidden commit or blob would
/// pass git's connectivity check (the object exists in the repository) and
/// publish it under a visible ref.
///
/// Being in the quarantine directory is not proof enough on its own:
/// `index-pack --fix-thin` copies the base of every `REF_DELTA` it cannot
/// resolve within the pack from the repository into the quarantined pack. A
/// thin pack naming a hidden blob as a delta base would therefore make that
/// blob look sent. So every quarantined object that already exists in the
/// repository must also be reachable from a visible ref (see
/// [`check_existing_objects_visible`]).
async fn check_hidden_objects(
    context: &PreReceiveContext,
    updates: &[RefUpdate],
    repo_refs: &[RepoRefEntry],
    symrefs: &BTreeMap<&str, &str>,
    walk_env: &[(&str, &OsStr)],
    quarantine_directory: Option<&Path>,
) -> Result<(), String> {
    let policy = &context.policy;
    if !policy
        .branch_policy
        .hidden_ref_plan(&policy.member_groups)
        .has_unsatisfied_rules()
    {
        return Ok(());
    }

    let visible_refs: Vec<&str> = repo_refs
        .iter()
        .filter(|entry| {
            policy
                .branch_policy
                .is_ref_chain_visible(&entry.name, symrefs, &policy.member_groups)
        })
        .map(|entry| entry.name.as_str())
        .collect();
    let mut walk_input = String::new();
    for update in updates.iter().filter(|update| !update.is_delete()) {
        walk_input.push_str(&update.new_oid);
        walk_input.push('\n');
    }
    for visible_ref in &visible_refs {
        walk_input.push('^');
        walk_input.push_str(visible_ref);
        walk_input.push('\n');
    }
    let walk_output = match run_isolated_git(
        &context.repo_dir,
        &["rev-list", "--objects", "--stdin"],
        walk_env,
        walk_input.into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot walk the pushed objects", &error)),
    };
    let unreachable_objects = match parse_object_ids(&walk_output) {
        Ok(object_ids) => object_ids,
        Err(error) => return Err(internal_error("unexpected rev-list output", &error)),
    };
    if unreachable_objects.is_empty() {
        return Ok(());
    }
    let Some(quarantine_directory) = quarantine_directory else {
        return Err(HIDDEN_OBJECTS_MESSAGE.to_owned());
    };

    // Look the objects up in the quarantine directory alone (no alternates),
    // i.e. among the objects this push actually sent.
    let mut lookup_input = String::new();
    for object_id in &unreachable_objects {
        lookup_input.push_str(object_id);
        lookup_input.push('\n');
    }
    let lookup_output = match run_isolated_git(
        &context.repo_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        &[("GIT_OBJECT_DIRECTORY", quarantine_directory.as_os_str())],
        lookup_input.clone().into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot look up the pushed objects", &error)),
    };
    let Some(lookup_results) = parse_batch_check(&lookup_output, &unreachable_objects) else {
        return Err(HIDDEN_OBJECTS_MESSAGE.to_owned());
    };
    if lookup_results.iter().any(|exists| !exists) {
        return Err(HIDDEN_OBJECTS_MESSAGE.to_owned());
    }

    check_existing_objects_visible(context, &unreachable_objects, lookup_input, &visible_refs).await
}

/// Second half of check 3: of `pushed_objects` (all present in the
/// quarantine directory; `lookup_input` lists them one per line), those that
/// already exist in the repository's own object store may have been copied
/// into the quarantine by `index-pack --fix-thin` rather than sent, so each
/// must be reachable from one of `visible_refs`.
///
/// Legitimate pushes reach this walk when they reuse older content (for
/// example re-adding a deleted file), which is reachable from a visible ref's
/// history even though not from its tip. The walk is exact (no negative
/// revisions), so its cost is proportional to the visible history; it only
/// runs when such objects exist.
async fn check_existing_objects_visible(
    context: &PreReceiveContext,
    pushed_objects: &[String],
    lookup_input: String,
    visible_refs: &[&str],
) -> Result<(), String> {
    // No GIT_OBJECT_DIRECTORY override: the repository's objects alone.
    let repo_lookup_output = match run_isolated_git(
        &context.repo_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        &[],
        lookup_input.into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => {
            return Err(internal_error(
                "cannot look up the pushed objects in the repository",
                &error,
            ));
        }
    };
    let Some(repo_lookup_results) = parse_batch_check(&repo_lookup_output, pushed_objects) else {
        return Err(HIDDEN_OBJECTS_MESSAGE.to_owned());
    };
    let already_in_repo: Vec<&String> = pushed_objects
        .iter()
        .zip(repo_lookup_results)
        .filter(|(_, exists)| *exists)
        .map(|(object_id, _)| object_id)
        .collect();
    if already_in_repo.is_empty() {
        return Ok(());
    }
    if visible_refs.is_empty() {
        return Err(HIDDEN_OBJECTS_MESSAGE.to_owned());
    }

    let mut walk_input = String::new();
    for visible_ref in visible_refs {
        walk_input.push_str(visible_ref);
        walk_input.push('\n');
    }
    let walk_output = match run_isolated_git(
        &context.repo_dir,
        &["rev-list", "--objects", "--stdin"],
        &[],
        walk_input.into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot walk the visible objects", &error)),
    };
    let visible_objects: BTreeSet<String> = match parse_object_ids(&walk_output) {
        Ok(object_ids) => object_ids.into_iter().collect(),
        Err(error) => return Err(internal_error("unexpected rev-list output", &error)),
    };
    if already_in_repo
        .iter()
        .all(|object_id| visible_objects.contains(*object_id))
    {
        Ok(())
    } else {
        Err(HIDDEN_OBJECTS_MESSAGE.to_owned())
    }
}

/// Parses `git cat-file --batch-check=%(objectname) %(objecttype)` output for
/// `object_ids` (in the same order): `true` for `<id> <type>`, `false` for
/// `<id> missing`. Returns `None` on any other output, so callers fail
/// closed.
fn parse_batch_check(output: &[u8], object_ids: &[String]) -> Option<Vec<bool>> {
    let Ok(text) = std::str::from_utf8(output) else {
        return None;
    };
    let lines: Vec<&str> = text.split_terminator('\n').collect();
    if lines.len() != object_ids.len() {
        return None;
    }
    let mut results = Vec::with_capacity(lines.len());
    for (line, object_id) in lines.iter().zip(object_ids) {
        let Some((reported_id, object_type)) = line.split_once(' ') else {
            return None;
        };
        if reported_id != object_id {
            return None;
        }
        if object_type == "missing" {
            results.push(false);
        } else if OBJECT_TYPES.contains(&object_type) {
            results.push(true);
        } else {
            return None;
        }
    }
    Some(results)
}

/// Check 4: refuses to land, in any target ref, commits that are reachable
/// only from refs (or other refs updated in this push) whose audience does not
/// include the target's whole audience.
///
/// With [`ALLOW_MERGE_LEAK_PUSH_OPTION`] such updates are allowed and one
/// audit entry per update is returned, for the caller to write once the whole
/// push has passed.
async fn check_merge_leaks(
    context: &PreReceiveContext,
    updates: &[RefUpdate],
    repo_refs: &[RepoRefEntry],
    symrefs: &BTreeMap<&str, &str>,
    walk_env: &[(&str, &OsStr)],
    push_options: &[String],
) -> Result<Vec<AuditLogEntry>, String> {
    let branch_policy = &context.policy.branch_policy;
    if branch_policy.is_empty() {
        return Ok(Vec::new());
    }
    let has_override = push_options
        .iter()
        .any(|push_option| push_option == ALLOW_MERGE_LEAK_PUSH_OPTION);

    let mut pending_audit_entries = Vec::new();
    for (index, update) in updates.iter().enumerate() {
        if update.is_delete() {
            continue;
        }
        let target_ref = update.ref_name.as_str();

        let mut allowed_bases = String::new();
        let mut more_restricted_tips = String::new();
        for entry in repo_refs {
            if branch_policy.is_ref_chain_at_least_as_visible_as(&entry.name, symrefs, target_ref) {
                allowed_bases.push('^');
                allowed_bases.push_str(&entry.name);
                allowed_bases.push('\n');
            } else {
                more_restricted_tips.push_str(&entry.name);
                more_restricted_tips.push('\n');
            }
        }
        // New values of narrower refs in the same push count too, or
        // `git push origin private/wip main` could carry a brand-new private
        // commit into `main` in one go.
        for (other_index, other) in updates.iter().enumerate() {
            if other_index != index
                && !other.is_delete()
                && !branch_policy.is_ref_at_least_as_visible_as(&other.ref_name, target_ref)
            {
                more_restricted_tips.push_str(&other.new_oid);
                more_restricted_tips.push('\n');
            }
        }
        if more_restricted_tips.is_empty() {
            continue;
        }

        let new_commits = match list_commits(
            context,
            walk_env,
            format!("{}\n{allowed_bases}", update.new_oid),
        )
        .await
        {
            Ok(commits) => commits,
            Err(message) => return Err(message),
        };
        if new_commits.is_empty() {
            continue;
        }
        let restricted_only_commits: BTreeSet<String> = match list_commits(
            context,
            walk_env,
            format!("{more_restricted_tips}{allowed_bases}"),
        )
        .await
        {
            Ok(commits) => commits.into_iter().collect(),
            Err(message) => return Err(message),
        };
        let leaked_commits: Vec<&String> = new_commits
            .iter()
            .filter(|commit| restricted_only_commits.contains(*commit))
            .collect();
        if leaked_commits.is_empty() {
            continue;
        }

        if !has_override {
            // Names only the pusher's own target ref: never the narrower refs
            // the commits come from, nor the commits or their count.
            return Err(format!(
                "scrim: push to {target_ref} rejected: introduces commits reachable only \
                 from more-restricted branches.\n\
                 scrim: squash the changes into a new commit, or re-push with \
                 `-o {ALLOW_MERGE_LEAK_PUSH_OPTION}` (recorded in the audit log)."
            ));
        }
        pending_audit_entries.push(AuditLogEntry {
            actor_member_id: Some(context.member.id),
            action: "branch.merge_leak_override".to_owned(),
            target_type: "repository_ref".to_owned(),
            target_name: format!("{}:{target_ref}", context.canonical_key),
            details: serde_json::json!({
                "repository": context.canonical_key,
                "ref_name": target_ref,
                "old_oid": update.old_oid,
                "new_oid": update.new_oid,
                "leaked_commit_count": leaked_commits.len(),
                "sample_leaked_commits": leaked_commits
                    .iter()
                    .take(MAX_AUDITED_LEAKED_COMMITS)
                    .collect::<Vec<_>>(),
            }),
        });
    }
    Ok(pending_audit_entries)
}

/// Check 6: for a member with withheld paths, refuses new commits that change
/// a withheld path, and any push that would publish a blob the repository
/// only holds at withheld paths (see the module documentation).
///
/// Collects the blob IDs this push could expose (new or changed entries of
/// new commits, blobs and trees refs point at directly, and every object in
/// the quarantine directory, which includes `REF_DELTA` bases copied in by
/// `index-pack --fix-thin`), then asks
/// [`find_withheld_only_blobs`] which of them already exist in the repository
/// only at withheld paths of the member's visible history.
async fn check_withheld_paths(
    context: &PreReceiveContext,
    updates: &[RefUpdate],
    repo_refs: &[RepoRefEntry],
    symrefs: &BTreeMap<&str, &str>,
    walk_env: &[(&str, &OsStr)],
    quarantine_directory: Option<&Path>,
) -> Result<(), String> {
    let policy = &context.policy;
    if !policy
        .withhold_policy
        .has_withheld_rules(&policy.member_groups)
    {
        return Ok(());
    }
    let pushed: Vec<&RefUpdate> = updates
        .iter()
        .filter(|update| !update.is_delete())
        .collect();
    if pushed.is_empty() {
        return Ok(());
    }

    let mut peel_input = String::new();
    for update in &pushed {
        peel_input.push_str(&update.new_oid);
        peel_input.push_str("^{}\n");
    }
    let peel_output = match run_isolated_git(
        &context.repo_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        walk_env,
        peel_input.into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot peel the pushed objects", &error)),
    };
    let peeled = match parse_peeled_objects(&peel_output, pushed.len()) {
        Ok(peeled) => peeled,
        Err(error) => return Err(internal_error("unexpected cat-file output", &error)),
    };

    let mut candidate_blobs: BTreeSet<String> = BTreeSet::new();
    let mut commit_tips = String::new();
    for (update, (object_id, object_type)) in pushed.iter().zip(peeled) {
        match object_type.as_str() {
            "commit" => {
                commit_tips.push_str(&object_id);
                commit_tips.push('\n');
            }
            "blob" => {
                candidate_blobs.insert(object_id);
            }
            "tree" => {
                let output = match run_isolated_git(
                    &context.repo_dir,
                    &["ls-tree", "-r", "-z", &object_id],
                    walk_env,
                    Vec::new(),
                )
                .await
                {
                    Ok(output) => output,
                    Err(error) => return Err(internal_error("cannot list a pushed tree", &error)),
                };
                let ref_location = ContentLocation {
                    commit: None,
                    ref_name: Some(update.ref_name.clone()),
                    path: None,
                };
                match parse_ls_tree_entries(&output, &ref_location) {
                    Ok(files) => candidate_blobs.extend(
                        files
                            .into_iter()
                            .filter(|file| file.mode != "160000")
                            .map(|file| file.blob_id),
                    ),
                    Err(error) => return Err(internal_error("unexpected ls-tree output", &error)),
                }
            }
            _ => {
                return Err(internal_error(
                    "unexpected peeled object type",
                    &object_type,
                ));
            }
        }
    }

    // Symbolic refs are skipped: their targets are listed themselves.
    let visible_refs: Vec<String> = repo_refs
        .iter()
        .filter(|entry| {
            entry.symref_target.is_none()
                && policy.branch_policy.is_ref_chain_visible(
                    &entry.name,
                    symrefs,
                    &policy.member_groups,
                )
        })
        .map(|entry| entry.name.clone())
        .collect();

    if !commit_tips.is_empty() {
        for visible_ref in &visible_refs {
            commit_tips.push('^');
            commit_tips.push_str(visible_ref);
            commit_tips.push('\n');
        }
        let walk_output = match run_isolated_git(
            &context.repo_dir,
            &["rev-list", "--parents", "--stdin"],
            walk_env,
            commit_tips.into_bytes(),
        )
        .await
        {
            Ok(output) => output,
            Err(error) => return Err(internal_error("cannot walk the new commits", &error)),
        };
        let new_commits = match parse_commit_parents(&walk_output) {
            Ok(new_commits) => new_commits,
            Err(error) => return Err(internal_error("unexpected rev-list output", &error)),
        };

        let mut diff_input = String::new();
        for (commit, parents) in &new_commits {
            if parents.len() < 2 {
                diff_input.push_str(commit);
                diff_input.push('\n');
            }
        }
        if !diff_input.is_empty() {
            let diff_output = match run_isolated_git(
                &context.repo_dir,
                &[
                    "diff-tree",
                    "--stdin",
                    "-r",
                    "--root",
                    "--no-renames",
                    "--raw",
                    "-z",
                ],
                walk_env,
                diff_input.into_bytes(),
            )
            .await
            {
                Ok(output) => output,
                Err(error) => return Err(internal_error("cannot diff the new commits", &error)),
            };
            let entries = match parse_raw_diff_entries(&diff_output) {
                Ok(entries) => entries,
                Err(error) => return Err(internal_error("unexpected diff-tree output", &error)),
            };
            for entry in entries {
                if is_withheld_write_path(context, &entry.path) {
                    return Err(withheld_path_message(&entry.path));
                }
                if let Some(blob_id) = entry.new_blob_id() {
                    candidate_blobs.insert(blob_id);
                }
            }
        }
        for (commit, parents) in &new_commits {
            if parents.len() >= 2
                && let Err(message) = check_merge_withheld_paths(
                    context,
                    walk_env,
                    commit,
                    parents,
                    &mut candidate_blobs,
                )
                .await
            {
                return Err(message);
            }
        }
    }

    if let Some(quarantine_directory) = quarantine_directory {
        // The quarantine alone (no alternates): the objects this push holds.
        let listing = match run_isolated_git(
            &context.repo_dir,
            &[
                "cat-file",
                "--batch-all-objects",
                "--unordered",
                "--batch-check=%(objectname)",
            ],
            &[("GIT_OBJECT_DIRECTORY", quarantine_directory.as_os_str())],
            Vec::new(),
        )
        .await
        {
            Ok(output) => output,
            Err(error) => {
                return Err(internal_error(
                    "cannot list the quarantined objects",
                    &error,
                ));
            }
        };
        match parse_object_ids(&listing) {
            Ok(object_ids) => candidate_blobs.extend(object_ids),
            Err(error) => return Err(internal_error("unexpected cat-file output", &error)),
        }
    }

    candidate_blobs.remove(EMPTY_BLOB_ID);
    if candidate_blobs.is_empty() {
        return Ok(());
    }
    let mut candidates = HashSet::with_capacity(candidate_blobs.len());
    for blob_id in &candidate_blobs {
        match gix::ObjectId::from_hex(blob_id.as_bytes()) {
            Ok(object_id) => {
                candidates.insert(object_id);
            }
            Err(error) => return Err(internal_error("unexpected object ID", &error)),
        }
    }
    let repo_dir = context.repo_dir.clone();
    let withhold_policy = policy.withhold_policy.clone();
    let member_groups = policy.member_groups.clone();
    let joined = tokio::task::spawn_blocking(move || {
        find_withheld_only_blobs(
            &repo_dir,
            &visible_refs,
            &candidates,
            &withhold_policy,
            &member_groups,
        )
    })
    .await;
    match joined {
        Ok(Ok(withheld_only)) if withheld_only.is_empty() => Ok(()),
        Ok(Ok(_)) => Err(WITHHELD_CONTENT_MESSAGE.to_owned()),
        Ok(Err(error)) => Err(internal_error("cannot classify the pushed blobs", &error)),
        Err(error) => Err(internal_error("the blob classification panicked", &error)),
    }
}

/// Check 6 for one new merge commit `merge` with `parents`.
///
/// An entry differing from every parent is new content (what a combined
/// diff shows): rejected at a withheld path, and otherwise added to
/// `candidate_blobs`. An entry at a withheld path that differs from parent
/// `i` must equal another parent `j`'s entry, and parent `i` must have left
/// the path untouched since its merge bases with parent `j`: the merge then
/// takes `j`'s side exactly as git's own merge would. Otherwise the merge
/// would delete, revert or replace a withheld file (as `git merge -s ours`
/// from a branch lacking it would).
async fn check_merge_withheld_paths(
    context: &PreReceiveContext,
    walk_env: &[(&str, &OsStr)],
    merge: &str,
    parents: &[String],
    candidate_blobs: &mut BTreeSet<String>,
) -> Result<(), String> {
    let mut parent_diffs: Vec<BTreeMap<Vec<u8>, RawDiffEntry>> = Vec::with_capacity(parents.len());
    for parent in parents {
        match diff_trees(context, walk_env, parent, merge).await {
            Ok(entries) => parent_diffs.push(
                entries
                    .into_iter()
                    .map(|entry| (entry.path.clone(), entry))
                    .collect(),
            ),
            Err(message) => return Err(message),
        }
    }
    let Some(first_diff) = parent_diffs.first() else {
        return Ok(());
    };
    for (path, entry) in first_diff {
        if parent_diffs.iter().all(|diff| diff.contains_key(path)) {
            if is_withheld_write_path(context, path) {
                return Err(withheld_path_message(path));
            }
            if let Some(blob_id) = entry.new_blob_id() {
                candidate_blobs.insert(blob_id);
            }
        }
    }

    // Paths parent `i` changed since its merge bases with parent `j`,
    // computed on demand; `None` when no merge base could be found.
    let mut changed_since_bases: BTreeMap<(usize, usize), Option<BTreeSet<Vec<u8>>>> =
        BTreeMap::new();
    for (index, diff) in parent_diffs.iter().enumerate() {
        for path in diff.keys() {
            if !is_withheld_write_path(context, path) {
                continue;
            }
            let mut is_clean_take = false;
            for (other_index, other_diff) in parent_diffs.iter().enumerate() {
                if other_index == index || other_diff.contains_key(path) {
                    continue;
                }
                let key = (index, other_index);
                if let btree_map::Entry::Vacant(entry) = changed_since_bases.entry(key) {
                    let (Some(parent), Some(other)) =
                        (parents.get(index), parents.get(other_index))
                    else {
                        continue;
                    };
                    let changed =
                        match paths_changed_since_merge_bases(context, walk_env, parent, other)
                            .await
                        {
                            Ok(changed) => changed,
                            Err(message) => return Err(message),
                        };
                    entry.insert(changed);
                }
                if let Some(Some(changed)) = changed_since_bases.get(&key)
                    && !changed.contains(path)
                {
                    is_clean_take = true;
                    break;
                }
            }
            if !is_clean_take {
                return Err(withheld_path_message(path));
            }
        }
    }
    Ok(())
}

/// The paths `parent` changed since any of its merge bases with `other`, or
/// `None` if they have no merge base (or git cannot tell), which callers
/// treat as "changed".
async fn paths_changed_since_merge_bases(
    context: &PreReceiveContext,
    walk_env: &[(&str, &OsStr)],
    parent: &str,
    other: &str,
) -> Result<Option<BTreeSet<Vec<u8>>>, String> {
    // `merge-base` exits 1 without output when there is no common ancestor.
    let Ok(output) = run_isolated_git(
        &context.repo_dir,
        &["merge-base", "--all", parent, other],
        walk_env,
        Vec::new(),
    )
    .await
    else {
        return Ok(None);
    };
    let bases = match parse_object_ids(&output) {
        Ok(bases) => bases,
        Err(error) => return Err(internal_error("unexpected merge-base output", &error)),
    };
    if bases.is_empty() {
        return Ok(None);
    }
    let mut changed = BTreeSet::new();
    for base in &bases {
        match diff_trees(context, walk_env, base, parent).await {
            Ok(entries) => changed.extend(entries.into_iter().map(|entry| entry.path)),
            Err(message) => return Err(message),
        }
    }
    Ok(Some(changed))
}

/// Runs `git diff-tree -r --no-renames --raw -z <from> <to>`.
async fn diff_trees(
    context: &PreReceiveContext,
    walk_env: &[(&str, &OsStr)],
    from: &str,
    to: &str,
) -> Result<Vec<RawDiffEntry>, String> {
    let output = match run_isolated_git(
        &context.repo_dir,
        &["diff-tree", "-r", "--no-renames", "--raw", "-z", from, to],
        walk_env,
        Vec::new(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot diff a merge", &error)),
    };
    match parse_raw_diff_entries(&output) {
        Ok(entries) => Ok(entries),
        Err(error) => Err(internal_error("unexpected diff-tree output", &error)),
    }
}

/// Whether the member may not write `path`: withheld exactly or ignoring
/// ASCII case (a case-insensitive checkout would write the withheld file), or
/// not UTF-8 (fail closed).
fn is_withheld_write_path(context: &PreReceiveContext, path: &[u8]) -> bool {
    let policy = &context.policy;
    match std::str::from_utf8(path) {
        Ok(path) => {
            policy
                .withhold_policy
                .is_path_withheld(path, &policy.member_groups)
                || policy
                    .withhold_policy
                    .is_path_withheld_case_insensitive(path, &policy.member_groups)
        }
        Err(_) => true,
    }
}

/// The rejection for a change to the withheld `path`. Never names the groups
/// that would grant access.
fn withheld_path_message(path: &[u8]) -> String {
    format!(
        "scrim: push rejected: you do not have access to modify withheld path {}",
        display_path(path)
    )
}

/// One entry of `git diff-tree -r --raw -z` output for a single pair of
/// trees.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RawDiffEntry {
    path: Vec<u8>,
    /// Mode after the change; `000000` for a deletion.
    new_mode: String,
    new_oid: String,
}

impl RawDiffEntry {
    /// The resulting blob, unless the entry was deleted or is a submodule
    /// commit.
    fn new_blob_id(&self) -> Option<String> {
        if self.new_mode == "000000" || self.new_mode == "160000" || is_zero_oid(&self.new_oid) {
            None
        } else {
            Some(self.new_oid.clone())
        }
    }
}

/// Parses `git diff-tree -r --raw -z` output for single-parent diffs:
/// `:<old mode> <new mode> <old id> <new id> <status>` and a path per entry,
/// optionally preceded (with `--stdin`) by the commit ID. Combined (`-c`)
/// entries are an error.
pub(crate) fn parse_raw_diff_entries(output: &[u8]) -> io::Result<Vec<RawDiffEntry>> {
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected diff-tree output: {reason}"),
        )
    };
    let mut entries = Vec::new();
    let mut tokens = output.split(|byte| *byte == 0);
    while let Some(token) = tokens.next() {
        if token.is_empty() {
            continue;
        }
        let Some(header) = token.strip_prefix(b":") else {
            if parse_oid(token).is_none() {
                return Err(invalid("expected a commit ID"));
            }
            continue;
        };
        let Some(path) = tokens.next() else {
            return Err(invalid("entry without a path"));
        };
        if path.is_empty() {
            return Err(invalid("empty path"));
        }
        let Ok(header) = std::str::from_utf8(header) else {
            return Err(invalid("non-UTF-8 entry header"));
        };
        let fields: Vec<&str> = header.split(' ').collect();
        let [_old_mode, new_mode, _old_oid, new_oid, _status] = fields.as_slice() else {
            return Err(invalid("wrong number of entry fields"));
        };
        let Some(new_oid) = parse_oid(new_oid.as_bytes()) else {
            return Err(invalid("bad object ID"));
        };
        if new_mode.len() != 6 || !new_mode.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
            return Err(invalid("bad mode"));
        }
        entries.push(RawDiffEntry {
            path: path.to_vec(),
            new_mode: (*new_mode).to_owned(),
            new_oid,
        });
    }
    Ok(entries)
}

/// Parses `git rev-list --parents` output into `(commit, parents)` pairs.
fn parse_commit_parents(output: &[u8]) -> io::Result<Vec<(String, Vec<String>)>> {
    let mut commits = Vec::new();
    for line in output.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let mut object_ids = Vec::new();
        for field in line.split(|byte| *byte == b' ') {
            match parse_oid(field) {
                Some(object_id) => object_ids.push(object_id),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "rev-list printed an unexpected line",
                    ));
                }
            }
        }
        let mut object_ids = object_ids.into_iter();
        if let Some(commit) = object_ids.next() {
            commits.push((commit, object_ids.collect()));
        }
    }
    Ok(commits)
}

/// Runs `git rev-list --stdin` with `revisions` (tips and `^excluded` lines)
/// and returns the listed commit IDs.
async fn list_commits(
    context: &PreReceiveContext,
    walk_env: &[(&str, &OsStr)],
    revisions: String,
) -> Result<Vec<String>, String> {
    let output = match run_isolated_git(
        &context.repo_dir,
        &["rev-list", "--stdin"],
        walk_env,
        revisions.into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot walk the pushed commits", &error)),
    };
    match parse_object_ids(&output) {
        Ok(commits) => Ok(commits),
        Err(error) => Err(internal_error("unexpected rev-list output", &error)),
    }
}

/// Where check 5 found content: a path in a new commit, or a blob or tree a
/// ref is pointed at directly.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ContentLocation {
    /// The new commit that adds or changes the file.
    commit: Option<String>,
    /// The ref pointed straight at the blob or tree, for content outside any
    /// commit.
    ref_name: Option<String>,
    /// Path inside the commit or tree; `None` for a ref pointed at a blob.
    path: Option<Vec<u8>>,
}

impl ContentLocation {
    /// `<short commit or ref> <path>`, with the path lossily decoded,
    /// escaped (so a newline in a file name cannot forge a message line) and
    /// shortened to [`MAX_DISPLAYED_PATH_CHARS`].
    fn describe(&self) -> String {
        let mut text = match (&self.commit, &self.ref_name) {
            (Some(commit), _) => match commit.get(..12) {
                Some(short) => short.to_owned(),
                None => commit.clone(),
            },
            (None, Some(ref_name)) => ref_name.clone(),
            (None, None) => String::new(),
        };
        if let Some(path) = &self.path {
            text.push(' ');
            text.push_str(&display_path(path));
        }
        text
    }
}

/// See [`ContentLocation::describe`].
fn display_path(path: &[u8]) -> String {
    let decoded = String::from_utf8_lossy(path);
    let mut text: String = decoded
        .chars()
        .take(MAX_DISPLAYED_PATH_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if decoded.chars().nth(MAX_DISPLAYED_PATH_CHARS).is_some() {
        text.push_str("...");
    }
    text
}

/// One check-5 finding. Never holds any part of the secret.
#[derive(Debug)]
struct SecretFinding {
    location: ContentLocation,
    rule: &'static str,
    /// 1-based line of a content match; `None` for a file-name match.
    line: Option<usize>,
}

/// The outcome of [`scan_pushed_content`].
#[derive(Debug, Default)]
struct SecretScanReport {
    /// The first [`MAX_REPORTED_FINDINGS`] findings.
    findings: Vec<SecretFinding>,
    /// Number of findings, including those not kept.
    total_findings: usize,
    /// The push introduces more than [`MAX_SCANNED_COMMITS`] new commits, so
    /// nothing was scanned.
    commit_limit_exceeded: bool,
}

impl SecretScanReport {
    fn record(&mut self, location: ContentLocation, rule: &'static str, line: Option<usize>) {
        self.total_findings += 1;
        if self.findings.len() < MAX_REPORTED_FINDINGS {
            self.findings.push(SecretFinding {
                location,
                rule,
                line,
            });
        }
    }

    fn is_clean(&self) -> bool {
        self.total_findings == 0 && !self.commit_limit_exceeded
    }

    /// The message for the pusher: where and which rule, never the content.
    fn rejection_message(&self) -> String {
        let advice = format!(
            "scrim: remove them from the pushed commits and store secrets with \
             `scrim secrets set`, or, for a confirmed false positive, re-push with \
             `-o {ALLOW_SECRET_SCAN_PUSH_OPTION}` (recorded in the audit log)."
        );
        if self.commit_limit_exceeded {
            return format!(
                "scrim: push rejected: introduces more than {MAX_SCANNED_COMMITS} new commits, \
                 too many to scan for plaintext secrets.\n\
                 scrim: push the history in smaller batches, or re-push with \
                 `-o {ALLOW_SECRET_SCAN_PUSH_OPTION}` (recorded in the audit log)."
            );
        }
        let mut message =
            "scrim: push rejected: plaintext secrets found in pushed content:\n".to_owned();
        for finding in &self.findings {
            message.push_str(&format!(
                "scrim:   {}: {}",
                finding.location.describe(),
                finding.rule
            ));
            if let Some(line) = finding.line {
                message.push_str(&format!(" (line {line})"));
            }
            message.push('\n');
        }
        if self.total_findings > self.findings.len() {
            message.push_str(&format!(
                "scrim:   ... and {} more\n",
                self.total_findings - self.findings.len()
            ));
        }
        message.push_str(&advice);
        message
    }

    /// The audit entry recording an override of this report.
    fn override_audit_entry(&self, context: &PreReceiveContext) -> AuditLogEntry {
        let findings: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|finding| {
                serde_json::json!({
                    "commit": finding.location.commit,
                    "ref_name": finding.location.ref_name,
                    "path": finding.location.path.as_deref().map(display_path),
                    "rule": finding.rule,
                    "line": finding.line,
                })
            })
            .collect();
        AuditLogEntry {
            actor_member_id: Some(context.member.id),
            action: "secret_scan.override".to_owned(),
            target_type: "repository".to_owned(),
            target_name: context.canonical_key.clone(),
            details: serde_json::json!({
                "repository": context.canonical_key,
                "findings": findings,
                "total_findings": self.total_findings,
                "commit_limit_exceeded": self.commit_limit_exceeded,
            }),
        }
    }
}

/// A file a new commit (or a pushed tree) adds or changes.
#[derive(Debug, PartialEq, Eq)]
struct ChangedFile {
    location: ContentLocation,
    /// git file mode, e.g. `100644`.
    mode: String,
    blob_id: String,
}

impl ChangedFile {
    /// Whether the entry is a regular or executable file, whose blob holds
    /// file content (not a symbolic link target or a submodule commit).
    fn is_regular_file(&self) -> bool {
        self.mode == "100644" || self.mode == "100755"
    }
}

/// Check 5: finds plaintext dotenv files and known credential formats in
/// content this push introduces.
///
/// "New" means commits not reachable from any existing ref (at most
/// [`MAX_SCANNED_COMMITS`]), plus blobs and trees a ref is pointed at
/// directly (also through annotated tags). Of each new commit, only the files
/// it adds or changes are examined (a merge by combined diff, so files taken
/// unchanged from a parent are skipped); every blob is read once, up to
/// [`MAX_SCANNED_BLOB_BYTES`].
async fn scan_pushed_content(
    context: &PreReceiveContext,
    updates: &[RefUpdate],
    repo_refs: &[RepoRefEntry],
    walk_env: &[(&str, &OsStr)],
) -> Result<SecretScanReport, String> {
    let mut report = SecretScanReport::default();
    let pushed: Vec<&RefUpdate> = updates
        .iter()
        .filter(|update| !update.is_delete())
        .collect();
    if pushed.is_empty() {
        return Ok(report);
    }

    // Peel every new value (through annotated tags) to find what it is.
    let mut peel_input = String::new();
    for update in &pushed {
        peel_input.push_str(&update.new_oid);
        peel_input.push_str("^{}\n");
    }
    let peel_output = match run_isolated_git(
        &context.repo_dir,
        &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
        walk_env,
        peel_input.into_bytes(),
    )
    .await
    {
        Ok(output) => output,
        Err(error) => return Err(internal_error("cannot peel the pushed objects", &error)),
    };
    let peeled = match parse_peeled_objects(&peel_output, pushed.len()) {
        Ok(peeled) => peeled,
        Err(error) => return Err(internal_error("unexpected cat-file output", &error)),
    };

    let mut changed_files = Vec::new();
    let mut commit_tips = String::new();
    let mut pushed_blobs = Vec::new();
    for (update, (object_id, object_type)) in pushed.iter().zip(peeled) {
        let ref_location = ContentLocation {
            commit: None,
            ref_name: Some(update.ref_name.clone()),
            path: None,
        };
        match object_type.as_str() {
            "commit" => {
                commit_tips.push_str(&object_id);
                commit_tips.push('\n');
            }
            "blob" => pushed_blobs.push((ref_location, object_id)),
            "tree" => {
                let output = match run_isolated_git(
                    &context.repo_dir,
                    &["ls-tree", "-r", "-z", &object_id],
                    walk_env,
                    Vec::new(),
                )
                .await
                {
                    Ok(output) => output,
                    Err(error) => return Err(internal_error("cannot list a pushed tree", &error)),
                };
                match parse_ls_tree_entries(&output, &ref_location) {
                    Ok(files) => changed_files.extend(files),
                    Err(error) => return Err(internal_error("unexpected ls-tree output", &error)),
                }
            }
            _ => {
                return Err(internal_error(
                    "unexpected peeled object type",
                    &object_type,
                ));
            }
        }
    }

    if !commit_tips.is_empty() {
        // Symbolic refs are skipped: their targets are listed themselves, and
        // a dangling one would make rev-list fail.
        for entry in repo_refs
            .iter()
            .filter(|entry| entry.symref_target.is_none())
        {
            commit_tips.push('^');
            commit_tips.push_str(&entry.name);
            commit_tips.push('\n');
        }
        let max_count = format!("--max-count={}", MAX_SCANNED_COMMITS + 1);
        let walk_output = match run_isolated_git(
            &context.repo_dir,
            &["rev-list", "--reverse", &max_count, "--stdin"],
            walk_env,
            commit_tips.into_bytes(),
        )
        .await
        {
            Ok(output) => output,
            Err(error) => return Err(internal_error("cannot walk the new commits", &error)),
        };
        let new_commits = match parse_object_ids(&walk_output) {
            Ok(commits) => commits,
            Err(error) => return Err(internal_error("unexpected rev-list output", &error)),
        };
        if new_commits.len() > MAX_SCANNED_COMMITS {
            report.commit_limit_exceeded = true;
            return Ok(report);
        }
        if !new_commits.is_empty() {
            let mut diff_input = new_commits.join("\n");
            diff_input.push('\n');
            let diff_output = match run_isolated_git(
                &context.repo_dir,
                &["diff-tree", "--stdin", "-r", "--root", "-c", "--raw", "-z"],
                walk_env,
                diff_input.into_bytes(),
            )
            .await
            {
                Ok(output) => output,
                Err(error) => return Err(internal_error("cannot diff the new commits", &error)),
            };
            match parse_diff_tree_entries(&diff_output) {
                Ok(files) => changed_files.extend(files),
                Err(error) => return Err(internal_error("unexpected diff-tree output", &error)),
            }
        }
    }

    // File names first; then each distinct blob once, remembering where it
    // first appeared. A blocked file's content is not scanned again.
    let mut seen_blobs = BTreeSet::new();
    let mut blobs_to_scan: Vec<(ContentLocation, String)> = Vec::new();
    for (location, blob_id) in pushed_blobs {
        if seen_blobs.insert(blob_id.clone()) {
            blobs_to_scan.push((location, blob_id));
        }
    }
    for file in changed_files {
        let path = match &file.location.path {
            Some(path) => path.as_slice(),
            None => &[],
        };
        if let Some(rule) = check_blocked_path_bytes(path) {
            report.record(file.location, rule, None);
            continue;
        }
        if file.is_regular_file() && seen_blobs.insert(file.blob_id.clone()) {
            blobs_to_scan.push((file.location, file.blob_id));
        }
    }

    let blob_ids: Vec<String> = blobs_to_scan
        .iter()
        .map(|(_, blob_id)| blob_id.clone())
        .collect();
    let mut content_matches = Vec::new();
    let read_result =
        read_blob_prefixes(&context.repo_dir, walk_env, &blob_ids, |index, prefix| {
            if let Some(found) = scan_blob_bytes(prefix) {
                content_matches.push((index, found));
            }
        })
        .await;
    if let Err(error) = read_result {
        return Err(internal_error("cannot read the pushed files", &error));
    }
    for (index, found) in content_matches {
        if let Some((location, _)) = blobs_to_scan.get(index) {
            report.record(location.clone(), found.rule, Some(found.line));
        }
    }
    Ok(report)
}

/// Parses `git cat-file --batch-check=%(objectname) %(objecttype)` output for
/// `expected_count` peeled (`<id>^{}`) inputs into `(id, type)` pairs. A
/// missing object or any other unexpected output is an error.
fn parse_peeled_objects(output: &[u8], expected_count: usize) -> io::Result<Vec<(String, String)>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "unexpected peeled object");
    let Ok(text) = std::str::from_utf8(output) else {
        return Err(invalid());
    };
    let mut peeled = Vec::with_capacity(expected_count);
    for line in text.split_terminator('\n') {
        let Some((object_id, object_type)) = line.split_once(' ') else {
            return Err(invalid());
        };
        let Some(object_id) = parse_oid(object_id.as_bytes()) else {
            return Err(invalid());
        };
        if !OBJECT_TYPES.contains(&object_type) {
            return Err(invalid());
        }
        peeled.push((object_id, object_type.to_owned()));
    }
    if peeled.len() == expected_count {
        Ok(peeled)
    } else {
        Err(invalid())
    }
}

/// Parses `git diff-tree --stdin -r --root -c --raw -z` output: each commit
/// ID (NUL-terminated) is followed by its entries, each a raw header
/// (`:<modes> <ids> <status>`, with one leading `:` per parent) and a path.
///
/// Returns the entries whose resulting file exists (not deletions), with the
/// resulting mode and blob ID.
fn parse_diff_tree_entries(output: &[u8]) -> io::Result<Vec<ChangedFile>> {
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected diff-tree output: {reason}"),
        )
    };
    let mut files = Vec::new();
    let mut current_commit: Option<String> = None;
    let mut tokens = output.split(|byte| *byte == 0);
    while let Some(token) = tokens.next() {
        if token.is_empty() {
            continue;
        }
        let parent_count = token.iter().take_while(|byte| **byte == b':').count();
        if parent_count == 0 {
            match parse_oid(token) {
                Some(commit) => current_commit = Some(commit),
                None => return Err(invalid("expected a commit ID")),
            }
            continue;
        }
        let Some(path) = tokens.next() else {
            return Err(invalid("entry without a path"));
        };
        if path.is_empty() || current_commit.is_none() {
            return Err(invalid("entry without a path or commit"));
        }
        // `<parent modes..> <result mode> <parent ids..> <result id> <status>`
        let Ok(header) = std::str::from_utf8(&token[parent_count..]) else {
            return Err(invalid("non-UTF-8 entry header"));
        };
        let fields: Vec<&str> = header.split(' ').collect();
        if fields.len() != 2 * (parent_count + 1) + 1 {
            return Err(invalid("wrong number of entry fields"));
        }
        let (Some(result_mode), Some(result_id)) =
            (fields.get(parent_count), fields.get(2 * parent_count + 1))
        else {
            return Err(invalid("missing entry fields"));
        };
        let Some(result_id) = parse_oid(result_id.as_bytes()) else {
            return Err(invalid("bad object ID"));
        };
        if *result_mode == "000000" || is_zero_oid(&result_id) {
            continue;
        }
        files.push(ChangedFile {
            location: ContentLocation {
                commit: current_commit.clone(),
                ref_name: None,
                path: Some(path.to_vec()),
            },
            mode: (*result_mode).to_owned(),
            blob_id: result_id,
        });
    }
    Ok(files)
}

/// Parses `git ls-tree -r -z` output (`<mode> <type> <id>\t<path>`, each
/// NUL-terminated) into files located under `tree_location`.
fn parse_ls_tree_entries(
    output: &[u8],
    tree_location: &ContentLocation,
) -> io::Result<Vec<ChangedFile>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "unexpected ls-tree entry");
    let mut files = Vec::new();
    for entry in output.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let Some(tab) = entry.iter().position(|byte| *byte == b'\t') else {
            return Err(invalid());
        };
        let Ok(header) = std::str::from_utf8(&entry[..tab]) else {
            return Err(invalid());
        };
        let fields: Vec<&str> = header.split(' ').collect();
        let [mode, _object_type, object_id] = fields.as_slice() else {
            return Err(invalid());
        };
        let Some(object_id) = parse_oid(object_id.as_bytes()) else {
            return Err(invalid());
        };
        files.push(ChangedFile {
            location: ContentLocation {
                commit: None,
                ref_name: tree_location.ref_name.clone(),
                path: Some(entry[tab + 1..].to_vec()),
            },
            mode: (*mode).to_owned(),
            blob_id: object_id,
        });
    }
    Ok(files)
}

/// Streams every blob in `blob_ids` through one `git cat-file --batch` and
/// calls `inspect(index, prefix)` with at most the first
/// [`MAX_SCANNED_BLOB_BYTES`] of each; the rest of a larger blob is read and
/// discarded, never buffered.
///
/// git runs with the same isolated environment as
/// [`run_isolated_git`] (which buffers whole outputs, so cannot be used for
/// arbitrarily large blobs), plus `extra_env`.
async fn read_blob_prefixes(
    repo_dir: &Path,
    extra_env: &[(&str, &OsStr)],
    blob_ids: &[String],
    mut inspect: impl FnMut(usize, &[u8]),
) -> io::Result<()> {
    if blob_ids.is_empty() {
        return Ok(());
    }
    let mut command = tokio::process::Command::new("git");
    command
        .arg("--git-dir")
        .arg(repo_dir)
        .args(["cat-file", "--batch"]);
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1");
    for (name, value) in extra_env {
        command.env(name, value);
    }
    #[cfg(unix)]
    command.process_group(0);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Err(error),
    };
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        return Err(io::Error::other("git pipes were not set up"));
    };

    let mut input = Vec::with_capacity(blob_ids.len() * 65);
    for blob_id in blob_ids {
        input.extend_from_slice(blob_id.as_bytes());
        input.push(b'\n');
    }
    // Written from its own task so git never blocks on a full stdout pipe
    // while this side is still writing; dropped (and git killed) on error.
    let writer = AbortOnDropHandle::new(tokio::spawn(async move {
        let result = stdin.write_all(&input).await;
        drop(stdin);
        result
    }));

    let mut reader = tokio::io::BufReader::new(stdout);
    let mut header = Vec::new();
    let mut prefix = Vec::new();
    for (index, blob_id) in blob_ids.iter().enumerate() {
        header.clear();
        // A header is `<id> blob <size>\n`; the limit only guards the buffer.
        let mut limited_reader = (&mut reader).take(256);
        if let Err(error) = limited_reader.read_until(b'\n', &mut header).await {
            return Err(error);
        }
        let Some(size) = parse_blob_header(&header, blob_id) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unexpected cat-file header",
            ));
        };
        let kept = size.min(MAX_SCANNED_BLOB_BYTES);
        prefix.clear();
        prefix.resize(kept, 0);
        if let Err(error) = reader.read_exact(&mut prefix).await {
            return Err(error);
        }
        // The rest of the blob, then the newline git prints after it.
        let skipped = (size - kept) as u64 + 1;
        let mut remainder = (&mut reader).take(skipped);
        match tokio::io::copy(&mut remainder, &mut tokio::io::sink()).await {
            Ok(copied) if copied == skipped => {}
            Ok(_) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Err(error) => return Err(error),
        }
        inspect(index, &prefix);
    }

    match writer.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(error) => return Err(io::Error::other(error)),
    }
    match child.wait().await {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(io::Error::other(format!(
            "git cat-file exited with {status}"
        ))),
        Err(error) => Err(error),
    }
}

/// Parses a `git cat-file --batch` header, `<expected_id> blob <size>\n`,
/// into the size.
fn parse_blob_header(header: &[u8], expected_id: &str) -> Option<usize> {
    let Some(line) = header.strip_suffix(b"\n") else {
        return None;
    };
    let Ok(text) = std::str::from_utf8(line) else {
        return None;
    };
    let mut fields = text.split(' ');
    match (fields.next(), fields.next(), fields.next(), fields.next()) {
        (Some(object_id), Some("blob"), Some(size), None) if object_id == expected_id => {
            size.parse::<usize>().ok()
        }
        _ => None,
    }
}

/// Canonicalizes an object path from the hook and requires it to lie inside
/// `objects_dir` (or, with `may_equal_objects_dir`, to be `objects_dir`).
///
/// The quarantine directory must be strictly inside: were it the repository's
/// object directory itself, check 3 would accept every existing object.
async fn validate_object_path(
    path: Option<&str>,
    objects_dir: &Path,
    may_equal_objects_dir: bool,
) -> Result<Option<PathBuf>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let canonical = match tokio::fs::canonicalize(path).await {
        Ok(canonical) => canonical,
        Err(error) => return Err(internal_error("cannot resolve a hook object path", &error)),
    };
    let is_inside = canonical.starts_with(objects_dir)
        && (may_equal_objects_dir || canonical.as_path() != objects_dir);
    if is_inside {
        Ok(Some(canonical))
    } else {
        tracing::error!(
            path = %canonical.display(),
            "pre-receive object path is outside the repository"
        );
        Err(INTERNAL_ERROR_MESSAGE.to_owned())
    }
}

/// Logs an internal failure and returns the generic rejection message, so
/// paths and git output stay out of what the pusher sees.
fn internal_error(context: &str, error: &dyn std::fmt::Display) -> String {
    tracing::error!(%error, "pre-receive guard: {context}");
    INTERNAL_ERROR_MESSAGE.to_owned()
}

/// One `<old-oid> <new-oid> <ref-name>` line of `pre-receive` input.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RefUpdate {
    old_oid: String,
    new_oid: String,
    ref_name: String,
}

impl RefUpdate {
    /// Whether the update deletes the ref (its new value is the zero ID).
    fn is_delete(&self) -> bool {
        is_zero_oid(&self.new_oid)
    }
}

/// Parses git's raw `pre-receive` stdin: one or more newline-terminated
/// `<old-oid> <new-oid> <ref-name>` lines.
///
/// Rejects (with the message for the pusher) empty input, more than
/// [`MAX_REF_UPDATES_PER_PUSH`] lines, empty or malformed lines, object IDs that are not 40 or 64 lowercase hex digits (or differ in
/// length), lines with both IDs zero, non-UTF-8 ref names (closes `L4`), and
/// names that do not start with `refs/` or contain control characters,
/// whitespace, `..` or `//`.
pub(crate) fn parse_ref_updates(stdin_bytes: &[u8]) -> Result<Vec<RefUpdate>, &'static str> {
    let Some(body) = stdin_bytes.strip_suffix(b"\n") else {
        return Err(MALFORMED_UPDATE_MESSAGE);
    };
    if body.is_empty() {
        return Err(MALFORMED_UPDATE_MESSAGE);
    }
    let mut updates = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        if updates.len() == MAX_REF_UPDATES_PER_PUSH {
            return Err(TOO_MANY_REF_UPDATES_MESSAGE);
        }
        let mut fields = line.splitn(3, |byte| *byte == b' ');
        let (Some(old_field), Some(new_field), Some(ref_field)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return Err(MALFORMED_UPDATE_MESSAGE);
        };
        let (Some(old_oid), Some(new_oid)) = (parse_oid(old_field), parse_oid(new_field)) else {
            return Err(MALFORMED_UPDATE_MESSAGE);
        };
        if old_oid.len() != new_oid.len() || (is_zero_oid(&old_oid) && is_zero_oid(&new_oid)) {
            return Err(MALFORMED_UPDATE_MESSAGE);
        }
        let Ok(ref_name) = std::str::from_utf8(ref_field) else {
            return Err(NON_UTF8_REF_MESSAGE);
        };
        if !is_acceptable_ref_name(ref_name) {
            return Err(INVALID_REF_MESSAGE);
        }
        updates.push(RefUpdate {
            old_oid,
            new_oid,
            ref_name: ref_name.to_owned(),
        });
    }
    Ok(updates)
}

/// Parses a SHA-1 (40) or SHA-256 (64) object ID of lowercase hex digits.
fn parse_oid(field: &[u8]) -> Option<String> {
    let is_valid = matches!(field.len(), 40 | 64)
        && field
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if !is_valid {
        return None;
    }
    match std::str::from_utf8(field) {
        Ok(oid) => Some(oid.to_owned()),
        Err(_) => None,
    }
}

fn is_zero_oid(oid: &str) -> bool {
    oid.bytes().all(|byte| byte == b'0')
}

/// Whether `ref_name` is a `refs/...` name without control characters,
/// whitespace, `..` or `//`. git applies its full ref-name rules after the
/// hook; this keeps names the guard reasons about unambiguous.
fn is_acceptable_ref_name(ref_name: &str) -> bool {
    ref_name.len() > "refs/".len()
        && ref_name.starts_with("refs/")
        && !ref_name
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        && !ref_name.contains("..")
        && !ref_name.contains("//")
}

/// Collects the object ID at the start of every line of `rev-list` output
/// (`--objects` appends a path after a space).
fn parse_object_ids(output: &[u8]) -> io::Result<Vec<String>> {
    let mut object_ids = Vec::new();
    for line in output.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let first_field = match line.split(|byte| *byte == b' ').next() {
            Some(first_field) => first_field,
            None => line,
        };
        match parse_oid(first_field) {
            Some(object_id) => object_ids.push(object_id),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rev-list printed a line without an object ID",
                ));
            }
        }
    }
    Ok(object_ids)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::{
        ALLOW_SECRET_SCAN_PUSH_OPTION, ContentLocation, MAX_REPORTED_FINDINGS, SecretScanReport,
        parse_blob_header, parse_diff_tree_entries, parse_ls_tree_entries, parse_peeled_objects,
    };
    use super::{
        CallbackListener, HookRequest, HookResponse, INVALID_REF_MESSAGE, MALFORMED_UPDATE_MESSAGE,
        MAX_REF_UPDATES_PER_PUSH, NON_UTF8_REF_MESSAGE, REQUEST_PROOF_DOMAIN,
        RESPONSE_PROOF_DOMAIN, RefUpdate, TOO_MANY_REF_UPDATES_MESSAGE,
        UNAUTHENTICATED_VERDICT_MESSAGE, accept_authenticated_request, derive_proof,
        exchange_over_callback, parse_batch_check, parse_object_ids, parse_ref_updates,
        send_hook_response,
    };
    #[cfg(unix)]
    use super::{
        HOOK_DIR_PREFIX, MAX_UNIX_SOCKET_PARENT_BYTES, hook_dir_parent, hook_dir_parent_from,
    };

    const SHA1_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA1_ZERO: &str = "0000000000000000000000000000000000000000";
    const SHA256_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SHA256_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn update(old_oid: &str, new_oid: &str, ref_name: &str) -> RefUpdate {
        RefUpdate {
            old_oid: old_oid.to_owned(),
            new_oid: new_oid.to_owned(),
            ref_name: ref_name.to_owned(),
        }
    }

    #[test]
    fn parses_sha1_and_sha256_updates() {
        let input =
            format!("{SHA1_ZERO} {SHA1_A} refs/heads/main\n{SHA1_A} {SHA1_ZERO} refs/tags/v1\n");
        match parse_ref_updates(input.as_bytes()) {
            Ok(updates) => {
                assert_eq!(
                    updates,
                    [
                        update(SHA1_ZERO, SHA1_A, "refs/heads/main"),
                        update(SHA1_A, SHA1_ZERO, "refs/tags/v1"),
                    ]
                );
                assert!(!updates[0].is_delete());
                assert!(updates[1].is_delete());
            }
            Err(message) => panic!("valid SHA-1 input rejected: {message}"),
        }

        let input = format!("{SHA256_ZERO} {SHA256_A} refs/heads/feature/x\n");
        match parse_ref_updates(input.as_bytes()) {
            Ok(updates) => assert_eq!(
                updates,
                [update(SHA256_ZERO, SHA256_A, "refs/heads/feature/x")]
            ),
            Err(message) => panic!("valid SHA-256 input rejected: {message}"),
        }
    }

    #[test]
    fn rejects_non_utf8_ref_names() {
        let mut input = format!("{SHA1_ZERO} {SHA1_A} refs/heads/caf").into_bytes();
        input.extend_from_slice(b"\xff\n");
        assert_eq!(parse_ref_updates(&input), Err(NON_UTF8_REF_MESSAGE));
    }

    #[test]
    fn rejects_malformed_lines_and_bad_object_ids() {
        let upper_case = SHA1_A.to_uppercase();
        let malformed = [
            String::new(),
            "\n".to_owned(),
            // Missing trailing newline.
            format!("{SHA1_ZERO} {SHA1_A} refs/heads/main"),
            // Empty line between updates.
            format!("{SHA1_ZERO} {SHA1_A} refs/heads/a\n\n{SHA1_ZERO} {SHA1_A} refs/heads/b\n"),
            format!("{SHA1_ZERO} {SHA1_A}\n"),
            format!("{SHA1_ZERO} refs/heads/main\n"),
            format!("{SHA1_ZERO} {upper_case} refs/heads/main\n"),
            format!("{SHA1_ZERO} {} refs/heads/main\n", &SHA1_A[..39]),
            format!("{SHA1_ZERO} {SHA1_A}0 refs/heads/main\n"),
            format!("{SHA1_ZERO} zz23456789abcdef0123456789abcdef01234567 refs/heads/main\n"),
            format!("{SHA1_ZERO} {SHA256_A} refs/heads/main\n"),
            format!("{SHA1_ZERO} {SHA1_ZERO} refs/heads/main\n"),
        ];
        for input in malformed {
            assert_eq!(
                parse_ref_updates(input.as_bytes()),
                Err(MALFORMED_UPDATE_MESSAGE),
                "{input:?}"
            );
        }
    }

    #[test]
    fn rejects_refs_outside_refs_and_unsafe_names() {
        let invalid_names = [
            "HEAD",
            "refs/",
            "heads/main",
            "refs/heads/a b",
            "refs/heads/a\tb",
            "refs/heads/a\rb",
            "refs/heads/a\0b",
            "refs/heads/a\u{7f}b",
            "refs/heads/../main",
            "refs/heads//main",
        ];
        for ref_name in invalid_names {
            let input = format!("{SHA1_ZERO} {SHA1_A} {ref_name}\n");
            assert_eq!(
                parse_ref_updates(input.as_bytes()),
                Err(INVALID_REF_MESSAGE),
                "{ref_name:?}"
            );
        }
    }

    #[test]
    fn caps_ref_updates_per_push() {
        let line = format!("{SHA1_ZERO} {SHA1_A} refs/heads/main\n");
        let at_limit = line.repeat(MAX_REF_UPDATES_PER_PUSH);
        match parse_ref_updates(at_limit.as_bytes()) {
            Ok(updates) => assert_eq!(updates.len(), MAX_REF_UPDATES_PER_PUSH),
            Err(message) => panic!("push at the limit rejected: {message}"),
        }
        let over_limit = line.repeat(MAX_REF_UPDATES_PER_PUSH + 1);
        assert_eq!(
            parse_ref_updates(over_limit.as_bytes()),
            Err(TOO_MANY_REF_UPDATES_MESSAGE)
        );
    }

    #[test]
    fn parses_batch_check_output_and_fails_closed() {
        let object_ids = [SHA1_A.to_owned(), SHA1_ZERO.to_owned()];
        let output = format!("{SHA1_A} blob\n{SHA1_ZERO} missing\n");
        assert_eq!(
            parse_batch_check(output.as_bytes(), &object_ids),
            Some(vec![true, false])
        );
        for bad_output in [
            format!("{SHA1_A} blob\n"),
            format!("{SHA1_ZERO} blob\n{SHA1_A} blob\n"),
            format!("{SHA1_A} blob\n{SHA1_ZERO} ambiguous\n"),
            format!("{SHA1_A}\n{SHA1_ZERO} missing\n"),
        ] {
            assert_eq!(
                parse_batch_check(bad_output.as_bytes(), &object_ids),
                None,
                "{bad_output:?}"
            );
        }
    }

    #[test]
    fn request_and_response_proofs_are_domain_separated() {
        let request_proof = derive_proof(REQUEST_PROOF_DOMAIN, "token");
        let response_proof = derive_proof(RESPONSE_PROOF_DOMAIN, "token");
        assert_eq!(request_proof.len(), 64);
        assert_ne!(request_proof.as_str(), response_proof.as_str());
        assert_ne!(
            response_proof.as_str(),
            derive_proof(RESPONSE_PROOF_DOMAIN, "other").as_str()
        );
    }

    /// Binds a callback listener like [`super::start_pre_receive_session`]
    /// does, returning the directory holding its socket (Unix only), the
    /// listener and its address.
    async fn bind_test_listener() -> (Option<tempfile::TempDir>, CallbackListener, OsString) {
        #[cfg(unix)]
        {
            let dir = match tempfile::Builder::new()
                .prefix(HOOK_DIR_PREFIX)
                .tempdir_in(hook_dir_parent())
            {
                Ok(dir) => dir,
                Err(error) => panic!("failed to create socket dir: {error}"),
            };
            let socket_path = dir.path().join("s-test");
            let listener = match CallbackListener::bind(&socket_path) {
                Ok(listener) => listener,
                Err(error) => panic!("failed to bind callback socket: {error}"),
            };
            (Some(dir), listener, socket_path.into_os_string())
        }
        #[cfg(not(unix))]
        {
            let listener = match CallbackListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(error) => panic!("failed to bind callback listener: {error}"),
            };
            let address = match listener.local_addr() {
                Ok(address) => OsString::from(address.to_string()),
                Err(error) => panic!("listener has no address: {error}"),
            };
            (None, listener, address)
        }
    }

    /// A serialized hook request carrying `request_proof`, with `marker` as
    /// its (otherwise unused) stdin field.
    fn hook_request_bytes(request_proof: &str, marker: &str) -> Vec<u8> {
        let request = HookRequest {
            request_proof: request_proof.to_owned(),
            stdin_b64: marker.to_owned(),
            git_object_directory: None,
            git_quarantine_path: None,
            push_options: Vec::new(),
        };
        match serde_json::to_vec(&request) {
            Ok(bytes) => bytes,
            Err(error) => panic!("failed to serialize request: {error}"),
        }
    }

    /// Runs the hook side of the exchange on a blocking thread.
    async fn exchange_in_background(
        address: OsString,
        request_bytes: Vec<u8>,
        token: &str,
    ) -> std::io::Result<HookResponse> {
        let expected_response_proof = derive_proof(RESPONSE_PROOF_DOMAIN, token);
        let joined = tokio::task::spawn_blocking(move || {
            exchange_over_callback(&address, &request_bytes, &expected_response_proof)
        })
        .await;
        match joined {
            Ok(result) => result,
            Err(error) => panic!("hook exchange panicked: {error}"),
        }
    }

    #[tokio::test]
    async fn rogue_callback_connections_do_not_lock_out_the_hook() {
        const TOKEN: &str = "session-token";
        let (_socket_dir, listener, address) = bind_test_listener().await;
        let server = tokio::spawn(async move {
            let expected_request_proof = derive_proof(REQUEST_PROOF_DOMAIN, TOKEN);
            let response_proof = derive_proof(RESPONSE_PROOF_DOMAIN, TOKEN);
            match accept_authenticated_request(listener, &expected_request_proof).await {
                Some((mut stream, request)) => {
                    send_hook_response(&mut stream, HookResponse::allow(), &response_proof).await;
                    Some(request.stdin_b64)
                }
                None => None,
            }
        });

        // A wrong proof, a proof for the wrong direction and garbage are
        // dropped without an answer (the hook would see no verdict)...
        let wrong_direction_proof = derive_proof(RESPONSE_PROOF_DOMAIN, TOKEN);
        for rogue_request in [
            hook_request_bytes("wrong", "rogue"),
            hook_request_bytes(&wrong_direction_proof, "rogue"),
            b"not json".to_vec(),
        ] {
            let rogue = exchange_in_background(address.clone(), rogue_request, TOKEN).await;
            assert!(rogue.is_err(), "a rogue connection got a verdict");
        }

        // ...and the real hook still gets its verdict afterwards.
        let real_proof = derive_proof(REQUEST_PROOF_DOMAIN, TOKEN);
        let hook = exchange_in_background(
            address.clone(),
            hook_request_bytes(&real_proof, "real"),
            TOKEN,
        )
        .await;
        match hook {
            Ok(response) => assert!(response.allow, "{}", response.message),
            Err(error) => panic!("the real hook got no verdict: {error}"),
        }
        match server.await {
            Ok(Some(marker)) => assert_eq!(marker, "real"),
            Ok(None) => panic!("the listener gave up"),
            Err(error) => panic!("the listener panicked: {error}"),
        }
    }

    #[tokio::test]
    async fn verdict_without_a_valid_response_proof_is_a_rejection() {
        const TOKEN: &str = "session-token";
        let request_proof = derive_proof(REQUEST_PROOF_DOMAIN, TOKEN);
        let valid_proof = derive_proof(RESPONSE_PROOF_DOMAIN, TOKEN);
        let other_token_proof = derive_proof(RESPONSE_PROOF_DOMAIN, "other-token");
        let cases = [
            (
                r#"{"allow":true,"message":"","response_proof":"wrong"}"#.to_owned(),
                false,
            ),
            (r#"{"allow":true,"message":""}"#.to_owned(), false),
            // A rogue server only ever sees the request proof.
            (
                format!(
                    r#"{{"allow":true,"message":"","response_proof":"{}"}}"#,
                    request_proof.as_str()
                ),
                false,
            ),
            (
                format!(
                    r#"{{"allow":true,"message":"","response_proof":"{}"}}"#,
                    other_token_proof.as_str()
                ),
                false,
            ),
            // Control: the real server's proof.
            (
                format!(
                    r#"{{"allow":true,"message":"","response_proof":"{}"}}"#,
                    valid_proof.as_str()
                ),
                true,
            ),
        ];
        for (reply, is_allowed) in cases {
            let (_socket_dir, listener, address) = bind_test_listener().await;
            let server_reply = reply.clone();
            let server = tokio::spawn(async move {
                let mut stream = match listener.accept().await {
                    Ok((stream, _)) => stream,
                    Err(error) => panic!("rogue server failed to accept: {error}"),
                };
                let mut request = Vec::new();
                if let Err(error) = stream.read_to_end(&mut request).await {
                    panic!("rogue server failed to read: {error}");
                }
                if let Err(error) = stream.write_all(server_reply.as_bytes()).await {
                    panic!("rogue server failed to reply: {error}");
                }
                if let Err(error) = stream.shutdown().await {
                    panic!("rogue server failed to close: {error}");
                }
            });
            let response =
                exchange_in_background(address, hook_request_bytes(&request_proof, "real"), TOKEN)
                    .await;
            match response {
                Ok(response) => {
                    assert_eq!(response.allow, is_allowed, "{reply}");
                    if !is_allowed {
                        assert_eq!(response.message, UNAUTHENTICATED_VERDICT_MESSAGE);
                    }
                }
                Err(error) => panic!("no verdict for {reply}: {error}"),
            }
            if let Err(error) = server.await {
                panic!("rogue server panicked: {error}");
            }
        }
    }

    #[test]
    fn parses_rev_list_object_lines() {
        let output = format!("{SHA1_A}\n{SHA1_ZERO} path/to file\n");
        match parse_object_ids(output.as_bytes()) {
            Ok(object_ids) => assert_eq!(object_ids, [SHA1_A, SHA1_ZERO]),
            Err(error) => panic!("valid rev-list output rejected: {error}"),
        }
        assert!(parse_object_ids(b"not-an-object-id\n").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn hook_dir_parent_falls_back_when_path_exceeds_unix_socket_limit() {
        let long_base = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(error) => panic!("failed to create temp dir: {error}"),
        };
        let nested = long_base.path().join("a".repeat(40)).join("b".repeat(40));
        if let Err(error) = std::fs::create_dir_all(&nested) {
            panic!("failed to create nested dir: {error}");
        }
        assert!(nested.as_os_str().as_encoded_bytes().len() > MAX_UNIX_SOCKET_PARENT_BYTES);

        let chosen = hook_dir_parent_from(Some(nested.clone()), nested);
        assert!(
            chosen.as_os_str().as_encoded_bytes().len() <= MAX_UNIX_SOCKET_PARENT_BYTES,
            "expected short fallback parent, got {}",
            chosen.display()
        );
    }

    #[test]
    fn parses_diff_tree_entries_of_plain_root_and_merge_commits() {
        const SHA1_B: &str = "89abcdef0123456789abcdef0123456789abcdef";
        let mut output = Vec::new();
        // A commit adding a file whose name contains a space and a newline,
        // and deleting another.
        output.extend_from_slice(format!("{SHA1_A}\0").as_bytes());
        output.extend_from_slice(format!(":000000 100644 {SHA1_ZERO} {SHA1_B} A\0").as_bytes());
        output.extend_from_slice(b"dir/a b\nc\0");
        output.extend_from_slice(format!(":100644 000000 {SHA1_B} {SHA1_ZERO} D\0").as_bytes());
        output.extend_from_slice(b"gone.txt\0");
        // A merge whose result differs from both parents.
        output.extend_from_slice(format!("{SHA1_B}\0").as_bytes());
        output.extend_from_slice(
            format!("::100644 000000 100755 {SHA1_A} {SHA1_ZERO} {SHA1_B} MA\0").as_bytes(),
        );
        output.extend_from_slice(b".env\0");
        let files = match parse_diff_tree_entries(&output) {
            Ok(files) => files,
            Err(error) => panic!("valid diff-tree output rejected: {error}"),
        };
        assert_eq!(files.len(), 2, "{files:?}");
        assert_eq!(files[0].location.commit.as_deref(), Some(SHA1_A));
        assert_eq!(files[0].location.path.as_deref(), Some(&b"dir/a b\nc"[..]));
        assert_eq!(files[0].blob_id, SHA1_B);
        assert!(files[0].is_regular_file());
        assert_eq!(files[1].location.commit.as_deref(), Some(SHA1_B));
        assert_eq!(files[1].location.path.as_deref(), Some(&b".env"[..]));
        assert_eq!(files[1].mode, "100755");

        for malformed in [
            format!(":000000 100644 {SHA1_ZERO} {SHA1_B} A\0x\0"),
            format!("{SHA1_A}\0:000000 100644 {SHA1_ZERO} A\0x\0"),
            format!("{SHA1_A}\0:000000 100644 {SHA1_ZERO} {SHA1_B} A\0"),
            "not-a-commit\0".to_owned(),
        ] {
            assert!(
                parse_diff_tree_entries(malformed.as_bytes()).is_err(),
                "{malformed:?}"
            );
        }
    }

    #[test]
    fn parses_ls_tree_peeled_objects_and_blob_headers() {
        let tree = ContentLocation {
            commit: None,
            ref_name: Some("refs/tags/tree".to_owned()),
            path: None,
        };
        let output = format!("100644 blob {SHA1_A}\tdeploy/.env\0120000 blob {SHA1_A}\tlink\0");
        match parse_ls_tree_entries(output.as_bytes(), &tree) {
            Ok(files) => {
                assert_eq!(files.len(), 2);
                assert_eq!(files[0].location.path.as_deref(), Some(&b"deploy/.env"[..]));
                assert_eq!(
                    files[0].location.ref_name.as_deref(),
                    Some("refs/tags/tree")
                );
                assert!(!files[1].is_regular_file());
            }
            Err(error) => panic!("valid ls-tree output rejected: {error}"),
        }
        assert!(parse_ls_tree_entries(b"100644 blob nothex\tx\0", &tree).is_err());

        let peeled = format!("{SHA1_A} commit\n{SHA256_A} blob\n");
        match parse_peeled_objects(peeled.as_bytes(), 2) {
            Ok(objects) => {
                assert_eq!(objects[0], (SHA1_A.to_owned(), "commit".to_owned()));
                assert_eq!(objects[1], (SHA256_A.to_owned(), "blob".to_owned()));
            }
            Err(error) => panic!("valid peel output rejected: {error}"),
        }
        assert!(parse_peeled_objects(peeled.as_bytes(), 3).is_err());
        assert!(parse_peeled_objects(format!("{SHA1_A}^{{}} missing\n").as_bytes(), 1).is_err());

        let header = format!("{SHA1_A} blob 1234\n");
        assert_eq!(parse_blob_header(header.as_bytes(), SHA1_A), Some(1234));
        assert_eq!(parse_blob_header(header.as_bytes(), SHA256_A), None);
        assert_eq!(
            parse_blob_header(format!("{SHA1_A} tree 12\n").as_bytes(), SHA1_A),
            None
        );
        assert_eq!(
            parse_blob_header(format!("{SHA1_A} blob 12").as_bytes(), SHA1_A),
            None
        );
    }

    #[test]
    fn secret_scan_report_names_locations_and_caps_findings() {
        let mut report = SecretScanReport::default();
        assert!(report.is_clean());
        for index in 0..MAX_REPORTED_FINDINGS + 2 {
            report.record(
                ContentLocation {
                    commit: Some(SHA1_A.to_owned()),
                    ref_name: None,
                    path: Some(format!("dir/evil\nscrim: ok {index}").into_bytes()),
                },
                "aws-access-key-id",
                Some(index + 1),
            );
        }
        assert!(!report.is_clean());
        assert_eq!(report.findings.len(), MAX_REPORTED_FINDINGS);
        let message = report.rejection_message();
        assert!(
            message.contains(
                "scrim:   0123456789ab dir/evil\\nscrim: ok 0: aws-access-key-id (line 1)"
            ),
            "{message}"
        );
        assert!(message.contains("... and 2 more"), "{message}");
        assert!(message.contains(ALLOW_SECRET_SCAN_PUSH_OPTION), "{message}");
        assert!(message.contains("scrim secrets set"), "{message}");
        // Every line is a `scrim:` line: a file name cannot forge another.
        assert!(
            message.lines().all(|line| line.starts_with("scrim:")),
            "{message}"
        );

        let limited = SecretScanReport {
            commit_limit_exceeded: true,
            ..SecretScanReport::default()
        };
        assert!(!limited.is_clean());
        assert!(limited.rejection_message().contains("too many to scan"));
    }
}
