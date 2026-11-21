//! Runs `git upload-pack` / `git receive-pack` for one HTTP request and streams
//! the data between the HTTP body and the child process in both directions.

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
) -> io::Result<Body> {
    let mut child = spawn_git(service, true, repo_dir, git_protocol, Stdio::null())?;
    let mut stdout = child
        .take_stdout()
        .ok_or_else(|| io::Error::other("git stdout was not piped"))?;

    let mut peeked = Vec::with_capacity(PROTOCOL_V2_PREFACE.len());
    let mut scratch = [0_u8; 64];
    let mut reached_end_of_output = false;
    while peeked.len() < PROTOCOL_V2_PREFACE.len() {
        let count = stdout.read(&mut scratch).await?;
        if count == 0 {
            reached_end_of_output = true;
            break;
        }
        peeked.extend_from_slice(&scratch[..count]);
    }

    // If git already finished, its exit status is known before any response
    // is sent, so a failure can still become a clean HTTP 500.
    if reached_end_of_output {
        let status = child.wait().await?;
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
    request_body: Body,
) -> io::Result<Body> {
    let mut child = spawn_git(service, false, repo_dir, git_protocol, Stdio::piped())?;
    let mut stdin = child
        .take_stdin()
        .ok_or_else(|| io::Error::other("git stdin was not piped"))?;
    let stdout = child
        .take_stdout()
        .ok_or_else(|| io::Error::other("git stdout was not piped"))?;

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

fn spawn_git(
    service: GitService,
    advertise_refs: bool,
    repo_dir: &Path,
    git_protocol: Option<&str>,
    stdin: Stdio,
) -> io::Result<ManagedChild> {
    let mut command = Command::new("git");
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
    if let Some(git_protocol) = git_protocol {
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

    let mut child = command.spawn()?;
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(log_stderr(service, stderr));
    }
    Ok(ManagedChild::new(child))
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
    use super::sanitize_git_protocol;

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
