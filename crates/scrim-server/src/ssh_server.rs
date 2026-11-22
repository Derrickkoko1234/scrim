//! Git over SSH: an embedded SSH server that serves the bare repositories
//! under the repository root to members authenticated by their registered SSH
//! public keys (see [`crate::PolicyStore::authenticate_ssh_key`]).
//!
//! Only `publickey` authentication is offered, and the only commands run are
//! `git-upload-pack '<repo>'` and `git-receive-pack '<repo>'`, parsed without
//! a shell; shells, PTYs, subsystems, forwarding and every other command are
//! refused. Each command is served exactly like a smart-HTTP request: the
//! member's `transfer.hideRefs` visibility (with git forced to protocol v0
//! while visibility is enforced), the `deepen-not` request filter, the
//! `pack-objects` withholding hook and the `pre-receive` guard, all through
//! the hook directory shared with the HTTP router.

use std::{
    collections::HashMap,
    future::Future,
    io::{self, Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::body::Bytes;
use russh::{
    Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, MethodKind, MethodSet,
    keys::{
        PrivateKey,
        ssh_key::{LineEnding, private::Ed25519Keypair},
    },
    server::{
        Auth, ChannelOpenHandle, Handler, Msg, PublicKeyOffer, Server, Session, VerifiedPublicKey,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::ChildStdin,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    SharedHookDir, Visibility, compute_visibility,
    git_service::{
        GitService, HookSession, ManagedChild, UploadPackRequestFilter, sanitize_git_protocol,
        spawn_git_interactive,
    },
    pack_withhold::PackWithholdSession,
    policy_store::{
        AuthenticatedMember, PolicyStore, is_allowed_ssh_key_algorithm, ssh_key_fingerprint,
    },
    pre_receive::PreReceiveSession,
    repo_path::resolve_bare_repo,
    start_hook_sessions,
};

/// Largest host key file read by [`load_or_create_ssh_host_key`].
const MAX_HOST_KEY_FILE_BYTES: u64 = 16 * 1024;

/// Largest `exec` command accepted.
const MAX_EXEC_COMMAND_BYTES: usize = 1024;

/// Most session channels one connection may have open at once.
const MAX_SESSION_CHANNELS: usize = 8;

/// Most `env` requests honored per channel; later ones are refused.
const MAX_ENV_REQUESTS_PER_CHANNEL: usize = 16;

/// Largest chunk of git output sent in one SSH channel message.
const OUTPUT_CHUNK_BYTES: usize = 32 * 1024;

/// Connections idle for this long are closed.
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);

/// The SSH "extended data" stream code of stderr (RFC 4254 §5.2).
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// Exit status reported when a command is refused before git runs.
const REFUSED_EXIT_STATUS: u32 = 128;

/// What [`serve_ssh`] serves and with which host key.
pub struct SshServerConfig {
    /// Canonical directory containing the bare repositories, as for the HTTP
    /// router.
    pub repo_root: PathBuf,
    /// Source of members, SSH keys and repository policy.
    pub policy_store: Arc<dyn PolicyStore>,
    /// The server's host key (see [`load_or_create_ssh_host_key`]).
    pub host_key: PrivateKey,
    /// Hook directory, shared with the HTTP router so both transports use the
    /// same server-owned hooks.
    pub hook_dir: SharedHookDir,
}

/// Loads the SSH host key at `path`, or creates one there if `path` does not
/// exist.
///
/// An existing key must be a regular file (not a symlink) of at most 16 KiB
/// holding an unencrypted OpenSSH private key of an algorithm member keys may
/// use too (Ed25519, ECDSA P-256 or P-384). A new key is a random Ed25519 key,
/// written in OpenSSH format with mode `0600` (on Unix) to a temporary file
/// that is then linked into place, so a crash never leaves a partial key and
/// a key created concurrently by another process is loaded, not replaced.
/// Missing parent directories are created.
///
/// Fails with `InvalidData` for an unreadable, encrypted or unsupported key.
pub fn load_or_create_ssh_host_key(path: &Path) -> io::Result<PrivateKey> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "SSH host key {} must be a regular file, not a symlink",
                        path.display()
                    ),
                ));
            }
            read_host_key(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_host_key(path),
        Err(error) => Err(error),
    }
}

/// Reads and validates the existing host key at `path`.
fn read_host_key(path: &Path) -> io::Result<PrivateKey> {
    let mut open_options = std::fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Never follow a symlink swapped in after the metadata check, and
        // never block on a FIFO.
        open_options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match open_options.open(path) {
        Ok(file) => file,
        Err(error) => return Err(error),
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return Err(error),
    };
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SSH host key {} must be a regular file", path.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            tracing::warn!(
                path = %path.display(),
                "SSH host key is accessible by other users; restrict it to mode 0600"
            );
        }
    }

    let mut contents = Zeroizing::new(Vec::new());
    if let Err(error) = file
        .take(MAX_HOST_KEY_FILE_BYTES + 1)
        .read_to_end(&mut contents)
    {
        return Err(error);
    }
    if contents.len() as u64 > MAX_HOST_KEY_FILE_BYTES {
        return Err(invalid_host_key(path, "the file is too large"));
    }
    let key = match PrivateKey::from_openssh(contents.as_slice()) {
        Ok(key) => key,
        Err(_) => return Err(invalid_host_key(path, "not an OpenSSH private key")),
    };
    if key.is_encrypted() {
        return Err(invalid_host_key(path, "the key is encrypted"));
    }
    if !is_allowed_ssh_key_algorithm(&key.algorithm()) {
        return Err(invalid_host_key(
            path,
            "use an Ed25519 or ECDSA (nistp256 or nistp384) key",
        ));
    }
    Ok(key)
}

fn invalid_host_key(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid SSH host key {}: {reason}", path.display()),
    )
}

/// Generates a new Ed25519 host key and stores it at `path`, which must not
/// exist yet (see [`load_or_create_ssh_host_key`]).
fn create_host_key(path: &Path) -> io::Result<PrivateKey> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if let Err(error) = std::fs::create_dir_all(parent) {
        return Err(error);
    }

    let mut seed = [0_u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        return Err(io::Error::other(format!(
            "cannot generate an SSH host key: {error}"
        )));
    }
    let mut key = PrivateKey::from(Ed25519Keypair::from_seed(&seed));
    seed.zeroize();
    key.set_comment("scrim-server host key");
    let encoded = match key.to_openssh(LineEnding::LF) {
        Ok(encoded) => encoded,
        Err(error) => {
            return Err(io::Error::other(format!(
                "cannot encode the SSH host key: {error}"
            )));
        }
    };

    let temporary = match tempfile::Builder::new()
        .prefix(".scrim-host-key-")
        .tempfile_in(parent)
    {
        Ok(temporary) => temporary,
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `tempfile` already creates the file with mode 0600; make sure.
        if let Err(error) = temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
        {
            return Err(error);
        }
    }
    let written = temporary
        .as_file()
        .write_all(encoded.as_bytes())
        .and_then(|()| temporary.as_file().sync_all());
    if let Err(error) = written {
        return Err(error);
    }
    // A hard link never replaces an existing file, unlike a rename: if
    // another process created the key meanwhile, its key wins and is loaded.
    match std::fs::hard_link(temporary.path(), path) {
        Ok(()) => {
            tracing::info!(path = %path.display(), "created a new SSH host key");
            Ok(key)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_host_key(path),
        Err(error) => Err(error),
    }
    // `temporary` is deleted on drop; the linked key stays.
}

/// Serves Git over SSH on `listener` until `shutdown` completes, then asks
/// every connection to disconnect and returns once the accept loop stopped.
///
/// Fails if accepting a connection fails.
pub async fn serve_ssh(
    listener: TcpListener,
    config: SshServerConfig,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let russh_config = Arc::new(russh::server::Config {
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        // OpenSSH probes with `none` first; answering it at once saves every
        // command a second. Real failures still take the constant delay.
        auth_rejection_time_initial: Some(Duration::ZERO),
        keys: vec![config.host_key],
        inactivity_timeout: Some(INACTIVITY_TIMEOUT),
        max_auth_attempts: 6,
        nodelay: true,
        ..Default::default()
    });
    let mut server = ScrimSshServer {
        shared: Arc::new(SshShared {
            repo_root: config.repo_root,
            policy_store: config.policy_store,
            hook_dir: config.hook_dir,
        }),
    };
    let mut running = server.run_on_socket(russh_config, &listener);
    let handle = running.handle();
    tokio::pin!(shutdown);
    tokio::select! {
        result = &mut running => result,
        () = &mut shutdown => {
            handle.shutdown("server shutting down".to_owned());
            running.await
        }
    }
}

/// State shared by every SSH connection.
struct SshShared {
    repo_root: PathBuf,
    policy_store: Arc<dyn PolicyStore>,
    hook_dir: SharedHookDir,
}

/// Creates one [`SshConnection`] per accepted connection.
struct ScrimSshServer {
    shared: Arc<SshShared>,
}

impl Server for ScrimSshServer {
    type Handler = SshConnection;

    fn new_client(&mut self, peer_address: Option<SocketAddr>) -> SshConnection {
        SshConnection {
            shared: Arc::clone(&self.shared),
            peer_address,
            authenticated: None,
            channels: HashMap::new(),
        }
    }

    fn handle_session_error(&mut self, error: russh::Error) {
        tracing::debug!(%error, "SSH connection failed");
    }
}

/// The member a connection authenticated as, and with which key.
#[derive(Clone)]
struct AuthenticatedKey {
    member: AuthenticatedMember,
    fingerprint: String,
}

/// A session channel that has not run its command yet.
struct PendingChannel {
    /// Taken by the `exec` request that runs the channel's command.
    channel: Option<Channel<Msg>>,
    /// Sanitized `GIT_PROTOCOL` from an `env` request.
    git_protocol: Option<String>,
    env_request_count: usize,
}

/// One SSH connection.
struct SshConnection {
    shared: Arc<SshShared>,
    peer_address: Option<SocketAddr>,
    authenticated: Option<AuthenticatedKey>,
    channels: HashMap<ChannelId, PendingChannel>,
}

impl SshConnection {
    /// Looks up the active member owning the active key `fingerprint`; a
    /// store failure is logged and treated as no match.
    async fn find_member(&self, fingerprint: &str) -> Option<AuthenticatedMember> {
        match self
            .shared
            .policy_store
            .authenticate_ssh_key(fingerprint)
            .await
        {
            Ok(member) => member,
            Err(error) => {
                tracing::error!(%error, "cannot look up an SSH key");
                None
            }
        }
    }
}

/// Refuses a channel request.
fn refuse(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
    session.channel_failure(channel)
}

impl Handler for SshConnection {
    type Error = russh::Error;

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> Result<Auth, Self::Error> {
        // Spare the signature check for keys that could never be accepted.
        if !is_allowed_ssh_key_algorithm(&offer.public_key.algorithm()) {
            return Ok(Auth::reject());
        }
        let fingerprint = ssh_key_fingerprint(offer.public_key);
        match self.find_member(&fingerprint).await {
            Some(_) => Ok(Auth::Accept),
            None => Ok(Auth::reject()),
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        if !is_allowed_ssh_key_algorithm(&key.public_key.algorithm()) {
            return Ok(Auth::reject());
        }
        let fingerprint = ssh_key_fingerprint(key.public_key);
        match self.find_member(&fingerprint).await {
            Some(member) => {
                tracing::debug!(
                    member = %member.name,
                    peer = ?self.peer_address,
                    "SSH member authenticated"
                );
                self.authenticated = Some(AuthenticatedKey {
                    member,
                    fingerprint,
                });
                Ok(Auth::Accept)
            }
            None => Ok(Auth::reject()),
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.authenticated.is_none() || self.channels.len() >= MAX_SESSION_CHANNELS {
            // Dropping the handle rejects the channel.
            drop(reply);
            return Ok(());
        }
        self.channels.insert(
            channel.id(),
            PendingChannel {
                channel: Some(channel),
                git_protocol: None,
                env_request_count: 0,
            },
        );
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(pending) = self.channels.get_mut(&channel) else {
            return refuse(channel, session);
        };
        pending.env_request_count += 1;
        if pending.env_request_count > MAX_ENV_REQUESTS_PER_CHANNEL
            || pending.channel.is_none()
            || variable_name != "GIT_PROTOCOL"
        {
            return refuse(channel, session);
        }
        match sanitize_git_protocol(variable_value) {
            Some(git_protocol) => {
                pending.git_protocol = Some(git_protocol.to_owned());
                session.channel_success(channel)
            }
            None => refuse(channel, session),
        }
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(authenticated) = self.authenticated.clone() else {
            return refuse(channel, session);
        };
        let Some(pending) = self.channels.get_mut(&channel) else {
            return refuse(channel, session);
        };
        // A channel runs at most one command.
        let Some(open_channel) = pending.channel.take() else {
            return refuse(channel, session);
        };
        let request = ExecRequest {
            command: data.to_vec(),
            git_protocol: pending.git_protocol.clone(),
            authenticated,
        };
        // Accept the request itself; refusals are then explained on stderr
        // with an exit status, which git shows the user.
        if let Err(error) = session.channel_success(channel) {
            return Err(error);
        }
        tokio::spawn(run_exec(Arc::clone(&self.shared), request, open_channel));
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse(channel, session)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse(channel, session)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _col_width: u32,
        _row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse(channel, session)
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single_connection: bool,
        _x11_auth_protocol: &str,
        _x11_auth_cookie: &str,
        _x11_screen_number: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        refuse(channel, session)
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }

    async fn streamlocal_forward(
        &mut self,
        _socket_path: &str,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// One accepted `exec` request.
struct ExecRequest {
    command: Vec<u8>,
    git_protocol: Option<String>,
    authenticated: AuthenticatedKey,
}

/// A command refused before or while git ran, with the message shown to the
/// client. Messages never say more than the HTTP transport would.
struct ExecRefusal {
    message: &'static str,
}

impl ExecRefusal {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }

    const fn internal() -> Self {
        Self::new("internal server error")
    }
}

/// How the command on a channel ended.
enum ExecOutcome {
    /// Git exited with this status.
    Exited(u32),
    /// The client closed the channel (or the connection) first.
    ClientGone,
}

/// Runs the command of `request` on `channel` and closes the channel.
async fn run_exec(shared: Arc<SshShared>, request: ExecRequest, channel: Channel<Msg>) {
    let (mut reader, writer) = channel.split();
    let exit_status = match serve_exec(&shared, request, &mut reader, &writer).await {
        Ok(ExecOutcome::Exited(exit_status)) => exit_status,
        Ok(ExecOutcome::ClientGone) => {
            // Best effort: the peer may already be gone.
            let _ = writer.close().await;
            return;
        }
        Err(refusal) => {
            let message = format!("scrim: {}\n", refusal.message);
            let _ = writer
                .extended_data_bytes(SSH_EXTENDED_DATA_STDERR, Bytes::from(message))
                .await;
            REFUSED_EXIT_STATUS
        }
    };
    // Best effort: the peer may close at any time.
    let _ = writer.eof().await;
    let _ = writer.exit_status(exit_status).await;
    let _ = writer.close().await;
}

/// The git child and the hook sessions it runs with.
struct GitProcess {
    // Declared before the sessions so dropping the process kills git's
    // process group before a hook's callback listener goes away (git would
    // otherwise see the hook fail, or skip a deleted one).
    child: ManagedChild,
    _pre_receive: Option<PreReceiveSession>,
    _pack_withhold: Option<PackWithholdSession>,
}

/// Authorizes and runs the command of `request`, streaming between the
/// channel and git.
async fn serve_exec(
    shared: &SshShared,
    request: ExecRequest,
    reader: &mut ChannelReadHalf,
    writer: &ChannelWriteHalf<Msg>,
) -> Result<ExecOutcome, ExecRefusal> {
    let Some((service, repo_path)) = parse_git_ssh_command(&request.command) else {
        return Err(ExecRefusal::new(
            "only git-upload-pack and git-receive-pack are supported",
        ));
    };

    // Re-check the key for every command: a multiplexed connection can
    // outlive the revocation of its key or member.
    let member = match shared
        .policy_store
        .authenticate_ssh_key(&request.authenticated.fingerprint)
        .await
    {
        Ok(Some(member)) if member.id == request.authenticated.member.id => member,
        Ok(_) => return Err(ExecRefusal::new("access denied")),
        Err(error) => {
            tracing::error!(%error, "cannot look up an SSH key");
            return Err(ExecRefusal::internal());
        }
    };

    // `ssh://host/team/app.git` arrives as `/team/app.git`.
    let repo_path = match repo_path.strip_prefix('/') {
        Some(stripped) => stripped,
        None => repo_path.as_str(),
    };
    // Same answer for malformed, missing and out-of-root repositories.
    let Some(resolved_repo) = resolve_bare_repo(&shared.repo_root, repo_path).await else {
        return Err(ExecRefusal::new("repository not found"));
    };
    tracing::debug!(
        repository = %resolved_repo.canonical_key,
        member = %member.name,
        service = service.service_name(),
        "serving git over SSH"
    );

    let policy = match shared
        .policy_store
        .load_member_repo_policy(member.id, &resolved_repo.canonical_key)
        .await
    {
        Ok(policy) => policy,
        Err(error) => {
            tracing::error!(
                %error,
                repository = %resolved_repo.canonical_key,
                "failed to load repository policy"
            );
            return Err(ExecRefusal::internal());
        }
    };
    let visibility = match compute_visibility(&policy, &resolved_repo.dir).await {
        Ok(Visibility::Allowed(visibility)) => visibility,
        Ok(Visibility::HeadHidden) => return Err(ExecRefusal::new("access denied")),
        Ok(Visibility::HeadInvalid) => return Err(ExecRefusal::new("repository not found")),
        Err(error) => {
            tracing::error!(%error, "failed to list repository refs");
            return Err(ExecRefusal::internal());
        }
    };

    let (pre_receive, pack_withhold) = match start_hook_sessions(
        service,
        &shared.hook_dir,
        &resolved_repo,
        &member,
        policy,
        &shared.policy_store,
    )
    .await
    {
        Ok(sessions) => sessions,
        Err(error) => {
            tracing::error!(%error, "cannot start the git hook session");
            return Err(ExecRefusal::internal());
        }
    };
    let hook_session = match (&pre_receive, &pack_withhold) {
        (Some(session), _) => Some(HookSession::PreReceive(session)),
        (None, Some(session)) => Some(HookSession::PackWithhold(session)),
        (None, None) => None,
    };
    let child = match spawn_git_interactive(
        service,
        &resolved_repo.dir,
        request.git_protocol.as_deref(),
        &visibility,
        hook_session,
    ) {
        Ok(child) => child,
        Err(error) => {
            tracing::error!(%error, "failed to run git");
            return Err(ExecRefusal::internal());
        }
    };
    let mut process = GitProcess {
        child,
        _pre_receive: pre_receive,
        _pack_withhold: pack_withhold,
    };

    // Restricted members may not send `deepen-not <ref>`: git resolves the ref
    // before applying `transfer.hideRefs`, so its success or failure would
    // reveal whether a hidden ref exists and which commits it reaches.
    let request_filter = (service == GitService::UploadPack && visibility.is_enforced())
        .then(UploadPackRequestFilter::default);
    let outcome = bridge_git(&mut process.child, reader, writer, request_filter).await;
    // Kill git (if still running) before the hook sessions end.
    drop(process);
    outcome
}

/// How the channel's input side ended before git exited.
enum InputEnd {
    /// The client closed the channel.
    ClientGone,
    /// The request filter refused the client's request.
    Rejected(io::Error),
}

/// Streams the channel's data into git's stdin and git's stdout and stderr
/// back to the channel until git exits or the client goes away.
async fn bridge_git(
    child: &mut ManagedChild,
    reader: &mut ChannelReadHalf,
    writer: &ChannelWriteHalf<Msg>,
    request_filter: Option<UploadPackRequestFilter>,
) -> Result<ExecOutcome, ExecRefusal> {
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.take_stdin(), child.take_stdout(), child.take_stderr())
    else {
        tracing::error!("git pipes were not set up");
        return Err(ExecRefusal::internal());
    };

    let input = pump_channel_to_git(reader, stdin, request_filter);
    let output = async {
        let (stdout_result, stderr_result) = tokio::join!(
            pump_git_to_channel(stdout, writer, None),
            pump_git_to_channel(stderr, writer, Some(SSH_EXTENDED_DATA_STDERR)),
        );
        if stdout_result.is_err() || stderr_result.is_err() {
            return Err(());
        }
        match child.wait().await {
            Ok(status) => Ok(status),
            Err(error) => {
                tracing::warn!(%error, "failed to wait for git");
                Err(())
            }
        }
    };

    tokio::select! {
        input_end = input => match input_end {
            InputEnd::ClientGone => Ok(ExecOutcome::ClientGone),
            InputEnd::Rejected(error) => {
                tracing::debug!(%error, "rejected upload-pack request");
                Err(ExecRefusal::new("invalid upload-pack request"))
            }
        },
        exit = output => match exit {
            Ok(status) => {
                if !status.success() {
                    tracing::debug!(%status, "git exited unsuccessfully");
                }
                let exit_status = match status.code().map(u32::try_from) {
                    Some(Ok(code)) => code,
                    _ => 1,
                };
                Ok(ExecOutcome::Exited(exit_status))
            }
            // Writing to the channel failed: the client is gone.
            Err(()) => Ok(ExecOutcome::ClientGone),
        },
    }
}

/// Forwards channel data (through `request_filter`, if any) to git's stdin,
/// closing stdin on the client's EOF, until the client closes the channel or
/// the filter refuses the request.
async fn pump_channel_to_git(
    reader: &mut ChannelReadHalf,
    stdin: ChildStdin,
    mut request_filter: Option<UploadPackRequestFilter>,
) -> InputEnd {
    let mut stdin = Some(stdin);
    loop {
        match reader.wait().await {
            Some(ChannelMsg::Data { data }) => {
                let Some(pipe) = stdin.as_mut() else {
                    // Git closed its input (or the client sent EOF): discard.
                    continue;
                };
                let allowed = match request_filter.as_mut() {
                    Some(filter) => match filter.filter_chunk(&data) {
                        Ok(allowed) => Bytes::from(allowed),
                        Err(error) => return InputEnd::Rejected(error),
                    },
                    None => data,
                };
                if let Err(error) = pipe.write_all(&allowed).await {
                    // Normal when git exits before reading all input.
                    if error.kind() != io::ErrorKind::BrokenPipe {
                        tracing::debug!(%error, "failed writing to git stdin");
                    }
                    stdin = None;
                }
            }
            Some(ChannelMsg::Eof) => {
                if let Some(filter) = &request_filter
                    && let Err(error) = filter.finish()
                {
                    return InputEnd::Rejected(error);
                }
                if let Some(mut pipe) = stdin.take()
                    && let Err(error) = pipe.shutdown().await
                    && error.kind() != io::ErrorKind::BrokenPipe
                {
                    tracing::debug!(%error, "failed closing git stdin");
                }
            }
            Some(ChannelMsg::Close) | None => return InputEnd::ClientGone,
            Some(_) => {}
        }
    }
}

/// Copies `source` to the channel, as stderr if `extended` is set, in chunks
/// of at most [`OUTPUT_CHUNK_BYTES`]. Fails if the channel is gone.
async fn pump_git_to_channel(
    mut source: impl AsyncRead + Unpin,
    writer: &ChannelWriteHalf<Msg>,
    extended: Option<u32>,
) -> Result<(), ()> {
    let mut buffer = vec![0_u8; OUTPUT_CHUNK_BYTES];
    loop {
        let read_count = match source.read(&mut buffer).await {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) => {
                tracing::debug!(%error, "failed reading git output");
                return Ok(());
            }
        };
        let chunk = Bytes::copy_from_slice(&buffer[..read_count]);
        let sent = match extended {
            Some(code) => writer.extended_data_bytes(code, chunk).await,
            None => writer.data_bytes(chunk).await,
        };
        if sent.is_err() {
            return Err(());
        }
    }
}

/// Parses an `exec` command as Git's SSH transport sends it,
/// `git-upload-pack '<repo>'` or `git-receive-pack '<repo>'`, into the
/// service and the unquoted repository path. No shell is involved.
///
/// The path is either single-quoted the way git quotes it (`'`, `!` written
/// as `'\''` and `'\!'`) or bare (ASCII letters, digits, `.`, `_`, `-`,
/// `/`). Returns `None` for any other command, extra arguments, control
/// characters, or an empty path.
pub(crate) fn parse_git_ssh_command(command: &[u8]) -> Option<(GitService, String)> {
    if command.len() > MAX_EXEC_COMMAND_BYTES {
        return None;
    }
    let Ok(command) = std::str::from_utf8(command) else {
        return None;
    };
    if command.chars().any(char::is_control) {
        return None;
    }
    let (program, argument) = match command.split_once(' ') {
        Some(split) => split,
        None => return None,
    };
    let service = match program {
        "git-upload-pack" => GitService::UploadPack,
        "git-receive-pack" => GitService::ReceivePack,
        _ => return None,
    };
    let path = if argument.starts_with('\'') {
        match unquote_single_quoted(argument) {
            Some(path) => path,
            None => return None,
        }
    } else if argument
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/'))
    {
        argument.to_owned()
    } else {
        return None;
    };
    if path.is_empty() {
        return None;
    }
    Some((service, path))
}

/// Undoes git's `sq_quote`: one or more `'...'` segments joined only by the
/// escapes `\'` and `\!`. Returns `None` for anything else, such as unquoted
/// text or a second argument.
fn unquote_single_quoted(argument: &str) -> Option<String> {
    let mut unquoted = String::new();
    let mut rest = argument;
    loop {
        let Some(after_quote) = rest.strip_prefix('\'') else {
            return None;
        };
        let Some(end) = after_quote.find('\'') else {
            return None;
        };
        unquoted.push_str(&after_quote[..end]);
        rest = &after_quote[end + 1..];
        if rest.is_empty() {
            return Some(unquoted);
        }
        if let Some(after_escape) = rest.strip_prefix("\\'") {
            unquoted.push('\'');
            rest = after_escape;
        } else if let Some(after_escape) = rest.strip_prefix("\\!") {
            unquoted.push('!');
            rest = after_escape;
        } else {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::{GitService, load_or_create_ssh_host_key, parse_git_ssh_command};

    #[test]
    fn parses_git_ssh_commands() {
        let cases: [(&[u8], GitService, &str); 7] = [
            (
                b"git-upload-pack 'team/app.git'",
                GitService::UploadPack,
                "team/app.git",
            ),
            (
                b"git-receive-pack '/team/app.git'",
                GitService::ReceivePack,
                "/team/app.git",
            ),
            (
                b"git-upload-pack team/app.git",
                GitService::UploadPack,
                "team/app.git",
            ),
            (
                b"git-receive-pack /team/app.git",
                GitService::ReceivePack,
                "/team/app.git",
            ),
            (
                b"git-upload-pack 'it'\\''s.git'",
                GitService::UploadPack,
                "it's.git",
            ),
            (
                b"git-upload-pack 'a'\\!'b.git'",
                GitService::UploadPack,
                "a!b.git",
            ),
            (
                b"git-upload-pack 'app.git'\\'''",
                GitService::UploadPack,
                "app.git'",
            ),
        ];
        for (command, service, path) in cases {
            match parse_git_ssh_command(command) {
                Some((parsed_service, parsed_path)) => {
                    assert_eq!(parsed_service, service, "{command:?}");
                    assert_eq!(parsed_path, path, "{command:?}");
                }
                None => panic!("{:?} should parse", String::from_utf8_lossy(command)),
            }
        }
    }

    #[test]
    fn refuses_other_commands_and_injection() {
        let long_command = format!("git-upload-pack '{}'", "a".repeat(2000));
        let cases: Vec<&[u8]> = vec![
            b"",
            b"sh -c id",
            b"id",
            b"git-upload-pack",
            b"git-upload-pack ",
            b"git-upload-pack ''",
            b"git upload-pack 'team/app.git'",
            b"git-upload-archive 'team/app.git'",
            b"git-upload-pack 'team/app.git' extra",
            b"git-upload-pack 'team/app.git';id",
            b"git-upload-pack 'team/app.git' ; id",
            b"git-upload-pack team/app.git;id",
            b"git-upload-pack $(id)",
            b"git-upload-pack `id`",
            b"git-upload-pack team/app.git|id",
            b"git-upload-pack team/app.git&&id",
            b"git-upload-pack 'team/app.git",
            b"git-upload-pack 'a'b'",
            b"git-upload-pack 'a'\\x'b'",
            b"git-upload-pack 'a'\\'",
            b"git-upload-pack 'team/app.git'\n",
            b"git-upload-pack 'team\napp.git'",
            b"git-upload-pack 'team\0app.git'",
            b"git-upload-pack  'team/app.git'",
            b"git-upload-pack \"team/app.git\"",
            b"git-upload-pack ~/app.git",
            b"git-upload-pack 'team/app.git'\xff",
            long_command.as_bytes(),
        ];
        for command in cases {
            assert!(
                parse_git_ssh_command(command).is_none(),
                "{:?} should be refused",
                String::from_utf8_lossy(command)
            );
        }
    }

    #[test]
    fn traversal_paths_parse_but_are_left_to_repository_resolution() {
        // The parser only unquotes; `resolve_bare_repo` refuses `..`.
        match parse_git_ssh_command(b"git-upload-pack '../etc'") {
            Some((_, path)) => assert_eq!(path, "../etc"),
            None => panic!("a quoted path should parse"),
        }
        assert!(!crate::repo_path::is_valid_repo_path("../etc"));
    }

    #[test]
    fn host_key_is_created_private_and_reloaded() {
        let dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => panic!("cannot create a temporary directory: {error}"),
        };
        let path = dir.path().join("keys").join("ssh_host_ed25519_key");
        let created = match load_or_create_ssh_host_key(&path) {
            Ok(key) => key,
            Err(error) => panic!("creating the host key failed: {error}"),
        };
        assert!(created.algorithm().is_ed25519());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = match std::fs::metadata(&path) {
                Ok(metadata) => metadata.permissions().mode(),
                Err(error) => panic!("cannot stat the host key: {error}"),
            };
            assert_eq!(mode & 0o777, 0o600);
        }
        // Only the key itself is left behind, no temporary file.
        let entries = match std::fs::read_dir(dir.path().join("keys")) {
            Ok(entries) => entries.count(),
            Err(error) => panic!("cannot list the key directory: {error}"),
        };
        assert_eq!(entries, 1);

        let reloaded = match load_or_create_ssh_host_key(&path) {
            Ok(key) => key,
            Err(error) => panic!("reloading the host key failed: {error}"),
        };
        assert_eq!(
            reloaded.public_key().key_data(),
            created.public_key().key_data()
        );
    }

    #[test]
    fn host_key_refuses_symlinks_and_garbage() {
        let dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => panic!("cannot create a temporary directory: {error}"),
        };
        let garbage = dir.path().join("garbage");
        if let Err(error) = std::fs::write(&garbage, b"not a key") {
            panic!("cannot write the garbage key: {error}");
        }
        match load_or_create_ssh_host_key(&garbage) {
            Ok(_) => panic!("a garbage key should be refused"),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidData),
        }

        #[cfg(unix)]
        {
            let real = dir.path().join("real");
            if let Err(error) = load_or_create_ssh_host_key(&real) {
                panic!("creating the host key failed: {error}");
            }
            let link = dir.path().join("link");
            if let Err(error) = std::os::unix::fs::symlink(&real, &link) {
                panic!("cannot create the symlink: {error}");
            }
            match load_or_create_ssh_host_key(&link) {
                Ok(_) => panic!("a symlinked key should be refused"),
                Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput),
            }
        }
    }
}
