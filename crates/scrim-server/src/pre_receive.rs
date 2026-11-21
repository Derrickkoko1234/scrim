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
//! ([`evaluate_pre_receive`]), in four checks:
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
//!    who can see them may squash by design.
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
    collections::{BTreeMap, BTreeSet},
    env::VarError,
    ffi::{OsStr, OsString},
    io::{self, Read, Write},
    net::Shutdown,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::task::AbortOnDropHandle;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    auth::sha256_zeroizing,
    git_service::{RepoRefEntry, list_repo_refs, run_isolated_git},
    policy_store::{AuditLogEntry, AuthenticatedMember, MemberRepoPolicy, PolicyStore},
};

/// The hook's end of the callback connection.
#[cfg(unix)]
type HookStream = std::os::unix::net::UnixStream;
#[cfg(not(unix))]
type HookStream = std::net::TcpStream;

/// The server's callback listener and its accepted connections.
#[cfg(unix)]
type CallbackListener = tokio::net::UnixListener;
#[cfg(unix)]
type CallbackConnection = tokio::net::UnixStream;
#[cfg(not(unix))]
type CallbackListener = tokio::net::TcpListener;
#[cfg(not(unix))]
type CallbackConnection = tokio::net::TcpStream;

/// Environment variable that switches the scrim-server binary into hook mode
/// when set to [`PRE_RECEIVE_HOOK_MODE`].
pub const PRE_RECEIVE_HOOK_MODE_ENV: &str = "SCRIM_HOOK_MODE";

/// Value of [`PRE_RECEIVE_HOOK_MODE_ENV`] that runs the `pre-receive` hook.
pub const PRE_RECEIVE_HOOK_MODE: &str = "pre-receive";

/// Push option (`git push -o scrim.allow-merge-leak=true`) that lets an
/// authorized member land commits from more restricted refs in a wider ref.
/// Each use is written to the audit log. It never bypasses checks 1-3.
pub const ALLOW_MERGE_LEAK_PUSH_OPTION: &str = "scrim.allow-merge-leak=true";

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
const HOOK_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the hook waits for the verdict; the history walks of checks 3 and
/// 4 can take a while on large repositories.
const HOOK_READ_TIMEOUT: Duration = Duration::from_secs(600);

/// How long the hook may block sending its request.
const HOOK_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long the callback listener waits for one connection to send its whole
/// request before dropping it and waiting for the next.
const CALLBACK_REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Connections without a valid request proof the callback listener drops
/// before giving up on the real hook (which then rejects the push).
const MAX_REJECTED_CALLBACK_CONNECTIONS: usize = 16;

/// Number of random bytes in a callback token.
const TOKEN_BYTES: usize = 32;

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

    let mut response_bytes = Vec::new();
    let mut limited_stream = (&stream).take(MAX_HOOK_RESPONSE_BYTES as u64 + 1);
    if let Err(error) = limited_stream.read_to_end(&mut response_bytes) {
        return Err(error);
    }
    if response_bytes.len() > MAX_HOOK_RESPONSE_BYTES {
        return Err(invalid_input(
            "oversized response from the server".to_owned(),
        ));
    }
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

/// Connects to the callback socket at path `callback_address`.
#[cfg(unix)]
fn connect_to_callback(callback_address: &OsStr) -> io::Result<HookStream> {
    HookStream::connect(Path::new(callback_address))
}

/// Connects to the loopback callback listener at `callback_address`
/// (`127.0.0.1:<port>`).
#[cfg(not(unix))]
fn connect_to_callback(callback_address: &OsStr) -> io::Result<HookStream> {
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
fn derive_proof(domain: &str, token: &str) -> Zeroizing<String> {
    let mut input = Zeroizing::new(Vec::with_capacity(domain.len() + token.len()));
    input.extend_from_slice(domain.as_bytes());
    input.extend_from_slice(token.as_bytes());
    encode_hex(sha256_zeroizing(&input).as_slice())
}

/// Lowercase hex encoding of `bytes`.
fn encode_hex(bytes: &[u8]) -> Zeroizing<String> {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

/// Returns `byte_count` random bytes from the operating system, hex-encoded.
fn generate_random_hex(byte_count: usize) -> io::Result<Zeroizing<String>> {
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

fn invalid_input(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// A private directory holding the server-owned `pre-receive` hook, used as
/// `core.hooksPath` for every `git receive-pack`, so hooks inside a
/// repository never run. On Unix it also holds each push's callback socket.
/// Deleted when dropped.
#[derive(Debug)]
pub(crate) struct HookDir {
    dir: TempDir,
}

impl HookDir {
    /// Creates a `0700` temporary directory containing `pre-receive`, a
    /// symbolic link (a copy on non-Unix platforms) to the scrim-server binary.
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
        let hook_path = dir.path().join(PRE_RECEIVE_HOOK_NAME);
        // A link runs the binary directly: no shell script, so no quoting
        // issues and nothing extra needed in minimal containers.
        #[cfg(unix)]
        let link_result = std::os::unix::fs::symlink(&binary, &hook_path);
        #[cfg(not(unix))]
        let link_result = std::fs::copy(&binary, &hook_path).map(|_| ());
        if let Err(error) = link_result {
            return Err(error);
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

    /// Fails unless `pre-receive` still resolves to an executable regular
    /// file.
    ///
    /// git silently skips a hook it cannot execute, which would accept the
    /// push unchecked, so this runs before every `receive-pack` (for example
    /// to catch the binary being replaced or removed during an upgrade).
    pub(crate) fn verify_installed(&self) -> io::Result<()> {
        let hook_path = self.dir.path().join(PRE_RECEIVE_HOOK_NAME);
        let metadata = match std::fs::metadata(&hook_path) {
            Ok(metadata) => metadata,
            Err(error) => return Err(error),
        };
        if !metadata.is_file() {
            return Err(io::Error::other("pre-receive hook is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o111 == 0 {
                return Err(io::Error::other("pre-receive hook is not executable"));
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
struct CallbackSocketFile {
    path: PathBuf,
}

#[cfg(unix)]
impl Drop for CallbackSocketFile {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(%error, "cannot remove a pre-receive callback socket");
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

    #[cfg(unix)]
    let (listener, callback_address, callback_socket) = {
        let socket_name = match generate_random_hex(CALLBACK_SOCKET_NAME_BYTES) {
            Ok(socket_name) => socket_name,
            Err(error) => return Err(error),
        };
        let socket_path = hook_dir.path().join(format!("s-{}", socket_name.as_str()));
        let listener = match CallbackListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => return Err(error),
        };
        let callback_address = socket_path.clone().into_os_string();
        (
            listener,
            callback_address,
            CallbackSocketFile { path: socket_path },
        )
    };
    #[cfg(not(unix))]
    let (listener, callback_address) = {
        let listener = match CallbackListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) => return Err(error),
        };
        let callback_address = match listener.local_addr() {
            Ok(address) => OsString::from(address.to_string()),
            Err(error) => return Err(error),
        };
        (listener, callback_address)
    };

    let callback_task = AbortOnDropHandle::new(tokio::spawn(answer_hook_callback(
        listener,
        derive_proof(REQUEST_PROOF_DOMAIN, &token),
        derive_proof(RESPONSE_PROOF_DOMAIN, &token),
        context,
    )));
    Ok(PreReceiveSession {
        _callback_task: callback_task,
        #[cfg(unix)]
        _callback_socket: callback_socket,
        hook_dir,
        callback_address,
        token,
    })
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
    for _ in 0..MAX_REJECTED_CALLBACK_CONNECTIONS {
        let mut stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(%error, "failed to accept a pre-receive callback");
                continue;
            }
        };
        let mut request = match read_hook_request(&mut stream).await {
            Ok(request) => request,
            Err(reason) => {
                tracing::warn!("dropped a pre-receive callback connection: {reason}");
                continue;
            }
        };
        let is_proof_valid = bool::from(
            request
                .request_proof
                .as_bytes()
                .ct_eq(expected_request_proof.as_bytes()),
        );
        request.request_proof.zeroize();
        if is_proof_valid {
            // Only one hook runs per receive-pack, so nothing else may
            // connect from here on.
            drop(listener);
            return Some((stream, request));
        }
        tracing::warn!("pre-receive callback presented an invalid request proof");
    }
    tracing::warn!("too many invalid pre-receive callback connections; giving up");
    None
}

/// Reads one whole request (until the peer closes its write side) from
/// `stream`, within [`CALLBACK_REQUEST_READ_TIMEOUT`] and
/// [`MAX_HOOK_REQUEST_BYTES`]. Returns why on failure, for the log.
async fn read_hook_request(stream: &mut CallbackConnection) -> Result<HookRequest, &'static str> {
    let mut request_bytes = Zeroizing::new(Vec::new());
    let mut limited_stream = stream.take(MAX_HOOK_REQUEST_BYTES as u64 + 1);
    let read_result = tokio::time::timeout(
        CALLBACK_REQUEST_READ_TIMEOUT,
        limited_stream.read_to_end(&mut request_bytes),
    )
    .await;
    match read_result {
        Err(_) => Err("timed out reading the request"),
        Ok(Err(_)) => Err("failed to read the request"),
        Ok(Ok(_)) if request_bytes.len() > MAX_HOOK_REQUEST_BYTES => Err("oversized request"),
        Ok(Ok(_)) => match serde_json::from_slice::<HookRequest>(&request_bytes) {
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

/// Runs the four checks described in the module documentation, then writes
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

    let audit_entries = match check_merge_leaks(
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
struct RefUpdate {
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
fn parse_ref_updates(stdin_bytes: &[u8]) -> Result<Vec<RefUpdate>, &'static str> {
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
}
