//! Runs `git upload-pack` / `git receive-pack` for one HTTP request and streams
//! the data between the HTTP body and the child process in both directions.
//!
//! Every request can carry its own [`GitVisibilityConfig`], which git applies
//! through `transfer.hideRefs` so hidden refs are neither advertised nor
//! fetchable by object ID.

use std::{
    io,
    path::Path,
    process::{ExitStatus, Stdio},
};

use axum::body::{Body, Bytes};
use futures_util::{StreamExt, stream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    sync::oneshot,
};
use tokio_util::{io::ReaderStream, task::AbortOnDropHandle};

/// Longest `Git-Protocol` header value that is passed on to git.
const MAX_GIT_PROTOCOL_LENGTH: usize = 256;

/// Git protocol v2 ref advertisements always begin with this 14-byte pkt-line.
const PROTOCOL_V2_PREFACE: &[u8] = b"000eversion 2\n";

/// Maximum bytes buffered for a single git stderr line before flushing.
const MAX_STDERR_LINE_BYTES: usize = 8 * 1024;

/// Largest pkt-line git sends or accepts, header included (`LARGE_PACKET_MAX`).
const MAX_PKT_LINE_BYTES: usize = 65520;

/// Which refs a single request must not see.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GitVisibilityConfig {
    /// `transfer.hideRefs` patterns, e.g. `refs/heads/private/` or a full ref
    /// name. A pattern hides the matching ref and everything below it; see
    /// git-config(1) for the full syntax.
    pub hidden_refs: Vec<String>,
    /// Whether the member may be denied some refs, even if `hidden_refs` is
    /// currently empty (a rule may match no ref yet).
    ///
    /// While this is set or `hidden_refs` is non-empty, git is forced to
    /// protocol v0 (see `spawn_git`) and `upload-pack` requests may not use
    /// `deepen-not` (see [`UploadPackRequestFilter`]).
    pub enforce_visibility: bool,
}

impl GitVisibilityConfig {
    /// Whether the restrictions for members who may not see every ref apply.
    fn is_enforced(&self) -> bool {
        self.enforce_visibility || !self.hidden_refs.is_empty()
    }
}

/// One ref listed by [`list_repo_refs`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoRefEntry {
    /// Full ref name, e.g. `refs/heads/main`.
    pub name: String,
    /// The ref a symbolic ref points at, as git's `%(symref)` reports it;
    /// `None` for a regular ref.
    pub symref_target: Option<String>,
}

/// The two Git services a client may request over smart HTTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitService {
    /// Serves fetches and clones.
    UploadPack,
    /// Accepts pushes.
    ReceivePack,
}

impl GitService {
    /// Parses a `service=` query value such as `git-upload-pack`.
    pub fn from_service_name(name: &str) -> Option<Self> {
        match name {
            "git-upload-pack" => Some(Self::UploadPack),
            "git-receive-pack" => Some(Self::ReceivePack),
            _ => None,
        }
    }

    /// The service name used in URLs and content types, e.g. `git-upload-pack`.
    pub fn service_name(self) -> &'static str {
        match self {
            Self::UploadPack => "git-upload-pack",
            Self::ReceivePack => "git-receive-pack",
        }
    }

    fn subcommand(self) -> &'static str {
        match self {
            Self::UploadPack => "upload-pack",
            Self::ReceivePack => "receive-pack",
        }
    }
}

/// Returns the `Git-Protocol` header value if it is safe to hand to git as
/// `GIT_PROTOCOL`: at most 256 bytes of `[A-Za-z0-9=:._-]`.
pub fn sanitize_git_protocol(header_value: &str) -> Option<&str> {
    let is_safe = !header_value.is_empty()
        && header_value.len() <= MAX_GIT_PROTOCOL_LENGTH
        && header_value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'=' | b':' | b'.' | b'_' | b'-')
        });
    is_safe.then_some(header_value)
}

/// Owns a spawned `git` child process and ensures its entire process group is
/// killed on drop if the child has not already been reaped.
struct ManagedChild {
    child: Child,
}

impl ManagedChild {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.child.stdin.take()
    }

    fn take_stdout(&mut self) -> Option<ChildStdout> {
        self.child.stdout.take()
    }

    async fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait().await
    }

    #[cfg(unix)]
    fn kill_process_group(&self) {
        if let Some(pid) = self.child.id()
            && let Ok(process_group_id) = libc::pid_t::try_from(pid)
            // Never 0 or 1: `kill(0, ..)` would hit the server's own group and
            // `kill(-1, ..)` every process the server may signal.
            && process_group_id > 1
        {
            // SAFETY: `process_group_id` is the positive PID of our still-unreaped
            // child spawned with `process_group(0)`, so `-process_group_id`
            // addresses only that child's process group and cannot have been reused.
            unsafe {
                libc::kill(-process_group_id, libc::SIGKILL);
            }
        }
    }

    #[cfg(not(unix))]
    fn kill_process_group(&self) {}
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill_process_group();
        // `self.child` then drops with `kill_on_drop(true)` as fallback.
    }
}

/// Streams the ref advertisement for `GET info/refs`.
///
/// Peeks the start of git's stdout before returning so early git failures
/// surface as an error (HTTP 500) and the `# service=...` pkt-line prefix is
/// omitted only when git actually emits a protocol v2 preface.
pub async fn advertise_refs(
    service: GitService,
    repo_dir: &Path,
    git_protocol: Option<&str>,
    visibility: &GitVisibilityConfig,
) -> io::Result<Body> {
    let mut child = match spawn_git(
        service,
        true,
        repo_dir,
        git_protocol,
        visibility,
        Stdio::null(),
    ) {
        Ok(child) => child,
        Err(error) => return Err(error),
    };
    let mut stdout = match child.take_stdout() {
        Some(stdout) => stdout,
        None => return Err(io::Error::other("git stdout was not piped")),
    };

    let mut peeked = Vec::with_capacity(PROTOCOL_V2_PREFACE.len());
    let mut scratch = [0_u8; 64];
    let mut reached_end_of_output = false;
    while peeked.len() < PROTOCOL_V2_PREFACE.len() {
        let count = match stdout.read(&mut scratch).await {
            Ok(count) => count,
            Err(error) => return Err(error),
        };
        if count == 0 {
            reached_end_of_output = true;
            break;
        }
        peeked.extend_from_slice(&scratch[..count]);
    }

    // If git already finished, its exit status is known before any response
    // is sent, so a failure can still become a clean HTTP 500.
    if reached_end_of_output {
        let status = match child.wait().await {
            Ok(status) => status,
            Err(error) => return Err(error),
        };
        if peeked.is_empty() || !status.success() {
            return Err(io::Error::other(format!(
                "git {} failed to advertise refs (exit status: {status}, {} bytes of output)",
                service.subcommand(),
                peeked.len()
            )));
        }
    }

    let mut initial_bytes = Vec::new();
    if !peeked.starts_with(PROTOCOL_V2_PREFACE) {
        let line = format!("# service={}\n", service.service_name());
        let header = format!("{:04x}{line}0000", line.len() + 4);
        initial_bytes.extend_from_slice(header.as_bytes());
    }
    initial_bytes.extend_from_slice(&peeked);

    Ok(stream_child_output(
        child,
        stdout,
        Some(Bytes::from(initial_bytes)),
        None,
        None,
    ))
}

/// Streams a stateless-RPC exchange for `POST git-upload-pack|git-receive-pack`:
/// the request body feeds git's stdin while git's stdout becomes the response.
pub fn serve_rpc(
    service: GitService,
    repo_dir: &Path,
    git_protocol: Option<&str>,
    visibility: &GitVisibilityConfig,
    request_body: Body,
) -> io::Result<Body> {
    let mut child = match spawn_git(
        service,
        false,
        repo_dir,
        git_protocol,
        visibility,
        Stdio::piped(),
    ) {
        Ok(child) => child,
        Err(error) => return Err(error),
    };
    let mut stdin = match child.take_stdin() {
        Some(stdin) => stdin,
        None => return Err(io::Error::other("git stdin was not piped")),
    };
    let stdout = match child.take_stdout() {
        Some(stdout) => stdout,
        None => return Err(io::Error::other("git stdout was not piped")),
    };

    // Restricted members may not send `deepen-not <ref>`: git resolves the ref
    // before applying `transfer.hideRefs`, so its success or failure would
    // reveal whether a hidden ref exists and which commits it reaches.
    let mut request_filter = (service == GitService::UploadPack && visibility.is_enforced())
        .then(UploadPackRequestFilter::default);

    let (body_error_tx, body_error_rx) = oneshot::channel();
    let stdin_pump = AbortOnDropHandle::new(tokio::spawn(async move {
        let mut data_stream = request_body.into_data_stream();
        while let Some(chunk_result) = data_stream.next().await {
            let chunk = match chunk_result {
                Ok(chunk) => chunk,
                Err(error) => {
                    tracing::debug!(%error, "request body error while streaming to git");
                    if body_error_tx.send(io::Error::other(error)).is_ok() {
                        // Hold `stdin` open so git cannot observe a clean EOF
                        // before the response stream kills git and aborts us.
                        std::future::pending::<()>().await;
                    }
                    return;
                }
            };
            let chunk = match request_filter.as_mut() {
                Some(filter) => match filter.filter_chunk(&chunk) {
                    Ok(allowed) => Bytes::from(allowed),
                    Err(error) => {
                        tracing::debug!(%error, "rejected upload-pack request");
                        if body_error_tx.send(error).is_ok() {
                            std::future::pending::<()>().await;
                        }
                        return;
                    }
                },
                None => chunk,
            };
            if let Err(error) = stdin.write_all(&chunk).await {
                if error.kind() == io::ErrorKind::BrokenPipe {
                    // Normal when git exits before reading the full request.
                    return;
                }
                tracing::debug!(%error, "failed writing request body to git stdin");
                if body_error_tx.send(error).is_ok() {
                    std::future::pending::<()>().await;
                }
                return;
            }
        }
        if let Some(filter) = &request_filter
            && let Err(error) = filter.finish()
        {
            tracing::debug!(%error, "rejected upload-pack request");
            if body_error_tx.send(error).is_ok() {
                std::future::pending::<()>().await;
            }
            return;
        }
        // Only close stdin cleanly when the request body ended without error.
        if let Err(error) = stdin.shutdown().await
            && error.kind() != io::ErrorKind::BrokenPipe
        {
            tracing::debug!(%error, "failed closing git stdin");
        }
    }));

    Ok(stream_child_output(
        child,
        stdout,
        None,
        Some(body_error_rx),
        Some(stdin_pump),
    ))
}

/// Checks the pkt-lines of an `upload-pack` request up to its first flush
/// packet (the wants, capabilities and shallow/deepen lines), rejecting
/// malformed framing and any `deepen-not` line before git sees it. The rest
/// of the request (`have` and `done` lines) passes through unchanged.
#[derive(Debug, Default)]
struct UploadPackRequestFilter {
    /// Bytes of an incomplete pkt-line carried over to the next chunk.
    pending: Vec<u8>,
    /// Set once the first flush packet has been forwarded.
    is_past_first_flush: bool,
}

impl UploadPackRequestFilter {
    /// Returns the bytes of `chunk` that may be forwarded to git now.
    ///
    /// Fails with `InvalidData`, forwarding nothing from `chunk`, on an
    /// invalid length header, a length of 1-3 or above
    /// [`MAX_PKT_LINE_BYTES`], or a `deepen-not` line.
    fn filter_chunk(&mut self, chunk: &[u8]) -> io::Result<Vec<u8>> {
        if self.is_past_first_flush {
            return Ok(chunk.to_vec());
        }
        self.pending.extend_from_slice(chunk);
        let mut allowed = Vec::with_capacity(self.pending.len());
        let mut offset = 0;
        while let Some(header) = self.pending.get(offset..offset + 4) {
            let length = match parse_pkt_line_length(header) {
                Some(length) => length,
                None => return Err(invalid_request("invalid pkt-line length")),
            };
            if length == 0 {
                allowed.extend_from_slice(b"0000");
                allowed.extend_from_slice(&self.pending[offset + 4..]);
                self.pending.clear();
                self.is_past_first_flush = true;
                return Ok(allowed);
            }
            if !(4..=MAX_PKT_LINE_BYTES).contains(&length) {
                return Err(invalid_request("invalid pkt-line length"));
            }
            let Some(pkt_line) = self.pending.get(offset..offset + length) else {
                break;
            };
            if pkt_line[4..].starts_with(b"deepen-not") {
                return Err(invalid_request("deepen-not is not allowed"));
            }
            allowed.extend_from_slice(pkt_line);
            offset += length;
        }
        self.pending.drain(..offset);
        Ok(allowed)
    }

    /// Fails if the request ended inside a pkt-line before the first flush.
    fn finish(&self) -> io::Result<()> {
        if self.pending.is_empty() {
            Ok(())
        } else {
            Err(invalid_request("request ended inside a pkt-line"))
        }
    }
}

/// Parses a 4-byte hexadecimal pkt-line length header.
fn parse_pkt_line_length(header: &[u8]) -> Option<usize> {
    let Ok(header) = std::str::from_utf8(header) else {
        return None;
    };
    if header.len() != 4 || !header.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    usize::from_str_radix(header, 16).ok()
}

fn invalid_request(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// Spawns `git <service>` for `repo_dir` with an empty environment, the
/// SHA-in-want hardening, and one `transfer.hideRefs` per hidden ref.
///
/// While visibility is enforced (see [`GitVisibilityConfig::enforce_visibility`]),
/// `git_protocol` is dropped so git speaks protocol
/// v0: v2 `fetch` accepts any object ID as a want regardless of the
/// `uploadpack.allow*SHA1InWant` settings (see gitprotocol-v2(5)), which would
/// let a client fetch a hidden ref's commits by their ID. Git clients fall back
/// to v0 transparently.
///
/// Returns `InvalidInput` without spawning if a hidden-ref pattern is empty or
/// contains NUL, CR or LF.
fn spawn_git(
    service: GitService,
    advertise_refs: bool,
    repo_dir: &Path,
    git_protocol: Option<&str>,
    visibility: &GitVisibilityConfig,
    stdin: Stdio,
) -> io::Result<ManagedChild> {
    for pattern in &visibility.hidden_refs {
        // An empty pattern would hide nothing (or confuse git's matching) and
        // a line break or NUL could smuggle extra config into git's parsing.
        if pattern.is_empty() || pattern.contains(['\0', '\n', '\r']) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid hidden ref pattern {pattern:?}"),
            ));
        }
    }

    let mut command = Command::new("git");
    // Only advertised tips may be wanted; never reachable or arbitrary objects,
    // which could include commits only reachable from hidden refs.
    for setting in [
        "uploadpack.allowTipSHA1InWant=false",
        "uploadpack.allowReachableSHA1InWant=false",
        "uploadpack.allowAnySHA1InWant=false",
    ] {
        command.arg("-c").arg(setting);
    }
    for pattern in &visibility.hidden_refs {
        command
            .arg("-c")
            .arg(format!("transfer.hideRefs={pattern}"));
    }
    command.arg(service.subcommand());
    if service == GitService::UploadPack {
        // Prevent git from falling back to `<dir>/.git` or `<dir>.git`.
        command.arg("--strict");
    }
    command.arg("--stateless-rpc");
    if advertise_refs {
        command.arg("--advertise-refs");
    }
    command.arg("--").arg(repo_dir);

    // Start from an empty environment so nothing from the server's process
    // (credentials, GIT_DIR, GIT_* overrides) or from system/user git config
    // can influence git. PATH is kept only so `git` can find its helpers.
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    if let Some(git_protocol) = git_protocol
        && !visibility.is_enforced()
    {
        command.env("GIT_PROTOCOL", git_protocol);
    }

    #[cfg(unix)]
    command.process_group(0);

    command
        .stdin(stdin)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Fallback if the platform-specific process-group kill does not apply.
        .kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return Err(error),
    };
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(log_stderr(service, stderr));
    }
    Ok(ManagedChild::new(child))
}

/// Lists every ref in the bare repository at `repo_dir`, e.g.
/// `refs/heads/main` and `refs/tags/v1`, with the target of each symbolic
/// ref, in git's sort order.
///
/// Runs git with the same isolated environment as the protocol services.
/// Fails if git exits unsuccessfully or prints anything that is not UTF-8 or
/// not one `<refname>NUL<symref>` line per ref: a silently skipped ref could
/// never be matched by a hide rule.
pub async fn list_repo_refs(repo_dir: &Path) -> io::Result<Vec<RepoRefEntry>> {
    let mut command = Command::new("git");
    command
        .arg("--git-dir")
        .arg(repo_dir)
        .arg("for-each-ref")
        .arg("--format=%(refname)%00%(symref)");
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::null())
        .kill_on_drop(true);

    let output = match command.output().await {
        Ok(output) => output,
        Err(error) => return Err(error),
    };
    if !output.status.success() {
        tracing::warn!(
            status = %output.status,
            "git for-each-ref stderr: {}",
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
        return Err(io::Error::other(format!(
            "git for-each-ref exited with {}",
            output.status
        )));
    }
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(error) => return Err(io::Error::new(io::ErrorKind::InvalidData, error)),
    };
    parse_ref_listing(&stdout)
}

/// Parses `git for-each-ref --format=%(refname)%00%(symref)` output.
fn parse_ref_listing(listing: &str) -> io::Result<Vec<RepoRefEntry>> {
    let mut entries = Vec::new();
    for line in listing.split_terminator('\n') {
        let Some((name, symref_target)) = line.split_once('\0') else {
            return Err(invalid_ref_line(line));
        };
        if name.is_empty() || symref_target.contains('\0') {
            return Err(invalid_ref_line(line));
        }
        entries.push(RepoRefEntry {
            name: name.to_owned(),
            symref_target: (!symref_target.is_empty()).then(|| symref_target.to_owned()),
        });
    }
    Ok(entries)
}

fn invalid_ref_line(line: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected git for-each-ref line {line:?}"),
    )
}

/// Drains git's stderr so git can never block on a full pipe, logging each line
/// and flushing partial lines once they reach [`MAX_STDERR_LINE_BYTES`].
async fn log_stderr(service: GitService, mut stderr: ChildStderr) {
    let mut line = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read_count = match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(count) => count,
        };
        let mut remaining = &buffer[..read_count];
        while !remaining.is_empty() {
            let available = MAX_STDERR_LINE_BYTES - line.len();
            if let Some(newline_index) = remaining
                .iter()
                .take(available)
                .position(|&byte| byte == b'\n')
            {
                line.extend_from_slice(&remaining[..newline_index]);
                tracing::warn!(
                    service = service.service_name(),
                    "git stderr: {}",
                    String::from_utf8_lossy(&line).trim_end()
                );
                line.clear();
                remaining = &remaining[newline_index + 1..];
            } else {
                let take_count = remaining.len().min(available);
                line.extend_from_slice(&remaining[..take_count]);
                remaining = &remaining[take_count..];
                if line.len() >= MAX_STDERR_LINE_BYTES {
                    tracing::warn!(
                        service = service.service_name(),
                        "git stderr: {}",
                        String::from_utf8_lossy(&line).trim_end()
                    );
                    line.clear();
                }
            }
        }
    }
    if !line.is_empty() {
        tracing::warn!(
            service = service.service_name(),
            "git stderr: {}",
            String::from_utf8_lossy(&line).trim_end()
        );
    }
}

struct OutputStream {
    // Declared before `_stdin_pump` so dropping the stream kills git before
    // aborting the pump closes its stdin pipe.
    child: ManagedChild,
    _stdin_pump: Option<AbortOnDropHandle<()>>,
    reader: ReaderStream<ChildStdout>,
    body_error_rx: Option<oneshot::Receiver<io::Error>>,
}

async fn recv_body_error(body_error_rx: &mut Option<oneshot::Receiver<io::Error>>) -> io::Error {
    match body_error_rx {
        Some(receiver) => match receiver.await {
            Ok(error) => {
                *body_error_rx = None;
                error
            }
            Err(_) => {
                *body_error_rx = None;
                std::future::pending().await
            }
        },
        None => std::future::pending().await,
    }
}

/// Turns git's stdout into a response body, optionally preceded by `prefix`.
///
/// `ManagedChild` and the stdin-pump handle live in the stream state so a
/// client disconnect kills git's process group and aborts the pump. Any request
/// body error or non-zero git exit yields an `Err` item so hyper aborts the
/// response instead of terminating it cleanly.
fn stream_child_output(
    child: ManagedChild,
    stdout: ChildStdout,
    prefix: Option<Bytes>,
    body_error_rx: Option<oneshot::Receiver<io::Error>>,
    stdin_pump: Option<AbortOnDropHandle<()>>,
) -> Body {
    let initial_state = Some(Box::new(OutputStream {
        child,
        _stdin_pump: stdin_pump,
        reader: ReaderStream::new(stdout),
        body_error_rx,
    }));
    let output = stream::unfold(initial_state, |state| async move {
        match state {
            None => None,
            Some(mut stream_state) => {
                let next_stdout = tokio::select! {
                    biased;
                    error = recv_body_error(&mut stream_state.body_error_rx) => {
                        // Kill git before `_stdin_pump` drops and closes stdin.
                        drop(stream_state);
                        return Some((Err(error), None));
                    }
                    chunk = stream_state.reader.next() => chunk,
                };

                match next_stdout {
                    Some(Ok(chunk)) => Some((Ok(chunk), Some(stream_state))),
                    Some(Err(error)) => {
                        drop(stream_state);
                        Some((Err(error), None))
                    }
                    None => {
                        if let Some(receiver) = stream_state.body_error_rx.as_mut()
                            && let Ok(error) = receiver.try_recv()
                        {
                            drop(stream_state);
                            return Some((Err(error), None));
                        }
                        // git can close stdout while still reading stdin, so a
                        // request-body error may still arrive while waiting for
                        // it to exit; racing them avoids a deadlock (the pump
                        // holds stdin open) and keeps the error from being lost.
                        let exit = tokio::select! {
                            biased;
                            error = recv_body_error(&mut stream_state.body_error_rx) => {
                                drop(stream_state);
                                return Some((Err(error), None));
                            }
                            exit = stream_state.child.wait() => exit,
                        };
                        match exit {
                            Ok(status) if status.success() => None,
                            Ok(status) => {
                                tracing::warn!(%status, "git exited unsuccessfully");
                                Some((
                                    Err(io::Error::other(format!("git exited with {status}"))),
                                    None,
                                ))
                            }
                            Err(error) => {
                                tracing::warn!(%error, "failed to wait for git");
                                Some((Err(error), None))
                            }
                        }
                    }
                }
            }
        }
    });

    let prefix_stream = stream::iter(prefix.map(Ok));
    Body::from_stream(prefix_stream.chain(output))
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        process::{Command, Stdio},
    };

    use axum::body::Body;
    use tempfile::TempDir;

    use super::{
        GitService, GitVisibilityConfig, RepoRefEntry, UploadPackRequestFilter, advertise_refs,
        list_repo_refs, parse_ref_listing, sanitize_git_protocol, serve_rpc, spawn_git,
    };

    /// A bare repository with `refs/heads/main` (commit `main_commit`, also
    /// `HEAD`), `refs/heads/private/secret` (commit `secret_commit`, a child of
    /// `main_commit`) and `refs/tags/v1`.
    struct TestRepo {
        _root: TempDir,
        dir: PathBuf,
        main_commit: String,
        secret_commit: String,
    }

    /// Runs `git <args>` with no access to user or system config and returns
    /// its trimmed stdout, panicking on failure.
    fn run_git(args: &[&str]) -> String {
        let mut command = Command::new("git");
        command.args(args).env_clear().stdin(Stdio::null());
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

    fn create_test_repo() -> TestRepo {
        let root = match TempDir::new() {
            Ok(root) => root,
            Err(error) => panic!("failed to create temp dir: {error}"),
        };
        let dir = root.path().join("repo.git");
        let Some(git_dir) = dir.to_str() else {
            panic!("temp dir path is not UTF-8: {dir:?}");
        };
        run_git(&[
            "init",
            "--quiet",
            "--bare",
            "--initial-branch=main",
            git_dir,
        ]);
        // An empty `mktree` input (stdin is null) writes the empty tree.
        let empty_tree = run_git(&["--git-dir", git_dir, "mktree"]);
        let main_commit = run_git(&[
            "--git-dir",
            git_dir,
            "commit-tree",
            &empty_tree,
            "-m",
            "main",
        ]);
        let secret_commit = run_git(&[
            "--git-dir",
            git_dir,
            "commit-tree",
            &empty_tree,
            "-p",
            &main_commit,
            "-m",
            "secret",
        ]);
        run_git(&[
            "--git-dir",
            git_dir,
            "update-ref",
            "refs/heads/main",
            &main_commit,
        ]);
        run_git(&[
            "--git-dir",
            git_dir,
            "update-ref",
            "refs/heads/private/secret",
            &secret_commit,
        ]);
        run_git(&[
            "--git-dir",
            git_dir,
            "update-ref",
            "refs/tags/v1",
            &main_commit,
        ]);
        TestRepo {
            _root: root,
            dir,
            main_commit,
            secret_commit,
        }
    }

    fn hide_private_branches() -> GitVisibilityConfig {
        GitVisibilityConfig {
            hidden_refs: vec!["refs/heads/private/".to_owned()],
            enforce_visibility: true,
        }
    }

    /// Collects a response body; `Err` means the stream ended with an error
    /// (for example because git exited unsuccessfully).
    async fn collect_body(body: Body) -> Result<Vec<u8>, axum::Error> {
        match axum::body::to_bytes(body, usize::MAX).await {
            Ok(bytes) => Ok(bytes.to_vec()),
            Err(error) => Err(error),
        }
    }

    /// Encodes `payload` as a single pkt-line.
    fn pkt_line(payload: &str) -> String {
        format!("{:04x}{payload}", payload.len() + 4)
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    async fn advertisement(
        repo_dir: &Path,
        git_protocol: Option<&str>,
        visibility: &GitVisibilityConfig,
    ) -> Vec<u8> {
        let body = match advertise_refs(GitService::UploadPack, repo_dir, git_protocol, visibility)
            .await
        {
            Ok(body) => body,
            Err(error) => panic!("advertise_refs failed: {error}"),
        };
        match collect_body(body).await {
            Ok(bytes) => bytes,
            Err(error) => panic!("advertisement body failed: {error}"),
        }
    }

    fn ref_entry(name: &str, symref_target: Option<&str>) -> RepoRefEntry {
        RepoRefEntry {
            name: name.to_owned(),
            symref_target: symref_target.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn lists_branches_tags_and_symref_targets() {
        let repo = create_test_repo();
        let Some(git_dir) = repo.dir.to_str() else {
            panic!("repo path is not UTF-8");
        };
        run_git(&[
            "--git-dir",
            git_dir,
            "symbolic-ref",
            "refs/heads/alias",
            "refs/heads/private/secret",
        ]);
        let refs = match list_repo_refs(&repo.dir).await {
            Ok(refs) => refs,
            Err(error) => panic!("list_repo_refs failed: {error}"),
        };
        assert_eq!(
            refs,
            [
                ref_entry("refs/heads/alias", Some("refs/heads/private/secret")),
                ref_entry("refs/heads/main", None),
                ref_entry("refs/heads/private/secret", None),
                ref_entry("refs/tags/v1", None),
            ]
        );
    }

    #[test]
    fn ref_listing_parsing_fails_closed() {
        match parse_ref_listing("") {
            Ok(entries) => assert!(entries.is_empty()),
            Err(error) => panic!("empty listing should parse: {error}"),
        }
        for invalid in [
            "refs/heads/main\n",
            "\0\n",
            "refs/heads/a\0refs/heads/b\0x\n",
            "refs/heads/main\0\n\n",
        ] {
            assert!(
                parse_ref_listing(invalid).is_err(),
                "{invalid:?} should be rejected"
            );
        }
    }

    /// Runs `chunks` through a fresh [`UploadPackRequestFilter`], returning
    /// everything forwarded or the first error.
    fn filter_request(chunks: &[&[u8]]) -> std::io::Result<Vec<u8>> {
        let mut filter = UploadPackRequestFilter::default();
        let mut forwarded = Vec::new();
        for chunk in chunks {
            match filter.filter_chunk(chunk) {
                Ok(allowed) => forwarded.extend_from_slice(&allowed),
                Err(error) => return Err(error),
            }
        }
        match filter.finish() {
            Ok(()) => Ok(forwarded),
            Err(error) => Err(error),
        }
    }

    #[test]
    fn upload_pack_filter_forwards_valid_requests_across_chunk_boundaries() {
        let request = format!(
            "{}{}0000{}{}",
            pkt_line("want 0123456789abcdef0123456789abcdef01234567 ofs-delta\n"),
            pkt_line("deepen 1\n"),
            // After the first flush everything passes through untouched.
            pkt_line("deepen-not refs/heads/main\n"),
            pkt_line("done\n")
        );
        let bytes = request.as_bytes();
        for split in 0..=bytes.len() {
            let (first, second) = bytes.split_at(split);
            match filter_request(&[first, second]) {
                Ok(forwarded) => assert_eq!(forwarded, bytes, "split at {split}"),
                Err(error) => panic!("valid request rejected at split {split}: {error}"),
            }
        }
    }

    #[test]
    fn upload_pack_filter_rejects_deepen_not_and_bad_framing() {
        let want = pkt_line("want 0123456789abcdef0123456789abcdef01234567\n");
        let deepen_not = format!("{want}{}0000", pkt_line("deepen-not refs/heads/x\n"));
        let invalid_requests = [
            deepen_not.clone(),
            format!("{want}0001{}", pkt_line("done\n")),
            format!("{want}0003"),
            format!("{want}zzzz"),
            format!("{want}fff1"),
            // Truncated before the first flush.
            want[..want.len() - 1].to_owned(),
        ];
        for request in invalid_requests {
            assert!(
                filter_request(&[request.as_bytes()]).is_err(),
                "{request:?} should be rejected"
            );
        }
        // Rejection forwards nothing from the offending chunk.
        let mut filter = UploadPackRequestFilter::default();
        assert!(filter.filter_chunk(deepen_not.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn listing_refs_of_a_missing_repo_fails() {
        let root = match TempDir::new() {
            Ok(root) => root,
            Err(error) => panic!("failed to create temp dir: {error}"),
        };
        assert!(
            list_repo_refs(&root.path().join("missing.git"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn v0_advertisement_omits_hidden_refs() {
        let repo = create_test_repo();
        let visible = advertisement(&repo.dir, None, &GitVisibilityConfig::default()).await;
        assert!(contains(&visible, "refs/heads/private/secret"));

        let filtered = advertisement(&repo.dir, None, &hide_private_branches()).await;
        assert!(contains(&filtered, "refs/heads/main"));
        assert!(contains(&filtered, "refs/tags/v1"));
        assert!(!contains(&filtered, "refs/heads/private/secret"));
        assert!(!contains(&filtered, &repo.secret_commit));
    }

    #[tokio::test]
    async fn v2_request_with_hidden_refs_gets_a_filtered_v0_advertisement() {
        let repo = create_test_repo();
        let unfiltered = advertisement(
            &repo.dir,
            Some("version=2"),
            &GitVisibilityConfig::default(),
        )
        .await;
        assert!(contains(&unfiltered, "version 2"));

        let filtered = advertisement(&repo.dir, Some("version=2"), &hide_private_branches()).await;
        assert!(!contains(&filtered, "version 2"));
        assert!(contains(&filtered, "# service=git-upload-pack"));
        assert!(contains(&filtered, "refs/heads/main"));
        assert!(!contains(&filtered, "refs/heads/private/secret"));
        assert!(!contains(&filtered, &repo.secret_commit));
    }

    #[tokio::test]
    async fn enforced_visibility_forces_v0_even_with_nothing_hidden() {
        let repo = create_test_repo();
        let visibility = GitVisibilityConfig {
            hidden_refs: Vec::new(),
            enforce_visibility: true,
        };
        let advertised = advertisement(&repo.dir, Some("version=2"), &visibility).await;
        assert!(!contains(&advertised, "version 2"));
        assert!(contains(&advertised, "# service=git-upload-pack"));
    }

    #[tokio::test]
    async fn hidden_commit_cannot_be_fetched_by_id() {
        let repo = create_test_repo();
        let v0_request = format!(
            "{}0000{}",
            pkt_line(&format!("want {}\n", repo.secret_commit)),
            pkt_line("done\n")
        );
        let v2_request = format!(
            "{}0001{}{}0000",
            pkt_line("command=fetch\n"),
            pkt_line(&format!("want {}\n", repo.secret_commit)),
            pkt_line("done\n")
        );
        for (git_protocol, request) in [(None, v0_request), (Some("version=2"), v2_request)] {
            let body = match serve_rpc(
                GitService::UploadPack,
                &repo.dir,
                git_protocol,
                &hide_private_branches(),
                Body::from(request),
            ) {
                Ok(body) => body,
                Err(error) => panic!("serve_rpc failed: {error}"),
            };
            if let Ok(response) = collect_body(body).await {
                assert!(
                    !contains(&response, "PACK") && !contains(&response, "packfile"),
                    "hidden commit was served under {git_protocol:?}"
                );
            }
        }
    }

    #[tokio::test]
    async fn visible_commit_can_still_be_fetched() {
        let repo = create_test_repo();
        let request = format!(
            "{}0000{}",
            pkt_line(&format!("want {}\n", repo.main_commit)),
            pkt_line("done\n")
        );
        let body = match serve_rpc(
            GitService::UploadPack,
            &repo.dir,
            None,
            &hide_private_branches(),
            Body::from(request),
        ) {
            Ok(body) => body,
            Err(error) => panic!("serve_rpc failed: {error}"),
        };
        let response = match collect_body(body).await {
            Ok(bytes) => bytes,
            Err(error) => panic!("fetch body failed: {error}"),
        };
        assert!(contains(&response, "PACK"));
    }

    #[tokio::test]
    async fn invalid_hidden_ref_patterns_are_rejected() {
        let repo = create_test_repo();
        for pattern in ["", "refs/heads/a\0b", "refs/heads/a\nb", "refs/heads/a\rb"] {
            let visibility = GitVisibilityConfig {
                hidden_refs: vec![pattern.to_owned()],
                enforce_visibility: true,
            };
            match spawn_git(
                GitService::UploadPack,
                true,
                &repo.dir,
                None,
                &visibility,
                Stdio::null(),
            ) {
                Ok(_) => panic!("{pattern:?} should be rejected"),
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput),
            }
        }
    }

    #[test]
    fn sanitizes_git_protocol_values() {
        assert_eq!(sanitize_git_protocol("version=2"), Some("version=2"));
        assert_eq!(
            sanitize_git_protocol("version=2:object-format=sha1"),
            Some("version=2:object-format=sha1")
        );
        assert_eq!(sanitize_git_protocol(""), None);
        assert_eq!(sanitize_git_protocol("version=2\nX=1"), None);
        assert_eq!(sanitize_git_protocol("a b"), None);
        assert_eq!(sanitize_git_protocol(&"a".repeat(257)), None);
        assert!(sanitize_git_protocol(&"a".repeat(256)).is_some());
    }
}
