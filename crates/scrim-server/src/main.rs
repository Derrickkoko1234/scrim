//! The scrim-server binary: serves bare Git repositories over smart HTTP and,
//! with `--ssh-listen`, over SSH.
//!
//! `scrim-server bootstrap-admin` instead creates the first admin member in
//! the database and prints their token once; `scrim-server backup` and
//! `scrim-server restore` copy the repositories and database to and from
//! Cloudflare R2.
//!
//! The same binary is git's `pre-receive` hook: started by `git receive-pack`
//! with `SCRIM_HOOK_MODE=pre-receive`, it asks the running server for its
//! verdict instead of serving. Started by `git upload-pack` as
//! `uploadpack.packObjectsHook` with `SCRIM_HOOK_MODE=pack-objects`, it builds
//! the fetch's pack without the member's withheld blobs.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::{
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, bail};
use clap::{ArgGroup, Args, Parser, Subcommand};
use scrim_policy::{GitVersion, MIN_GIT_VERSION, parse_git_version};
use scrim_server::{
    BackupConfig, CachedPolicyStore, DEFAULT_R2_PREFIX, MAX_TOKEN_BYTES, PACK_OBJECTS_HOOK_MODE,
    PRE_RECEIVE_HOOK_MODE, PRE_RECEIVE_HOOK_MODE_ENV, PgPolicyStore, PolicyStore, PruneConfig,
    R2Config, RedisPolicyCache, RestoreConfig, SecretString, SharedHookDir, SshServerConfig,
    TokenAuth, list_backups, load_or_create_ssh_host_key, prune_backups, run_backup,
    run_pack_objects_hook_process, run_pre_receive_hook_process, run_restore, serve_ssh,
};
use secrecy::ExposeSecret;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;
use zeroize::{Zeroize, Zeroizing};

/// Maximum number of bytes read from `--token-file` before rejecting it as
/// oversized: [`MAX_TOKEN_BYTES`] plus at most one trailing `\r\n`.
const MAX_TOKEN_FILE_BYTES: usize = MAX_TOKEN_BYTES + 2;

/// Recommended minimum token length in bytes before emitting a weak-token warning.
const RECOMMENDED_MIN_TOKEN_BYTES: usize = 16;

/// Self-hosted Git remote for Scrim for Git.
///
/// Members are authenticated either against PostgreSQL (`--database-url`) or,
/// for a single-user setup, against one shared token (`--token` or
/// `--token-file`). Exactly one of the three must be given.
#[derive(Parser)]
#[command(
    // A subcommand has its own arguments; the server's are only required
    // when serving.
    subcommand_negates_reqs = true,
    group(
        ArgGroup::new("authentication")
            .args(["database_url", "token", "token_file"])
            .required(true)
            .multiple(false)
    )
)]
struct Config {
    #[command(subcommand)]
    command: Option<Command>,

    /// Directory containing the bare repositories to serve.
    #[arg(long, env = "SCRIM_REPO_ROOT", required = true)]
    repo_root: Option<PathBuf>,

    /// Address to listen on. Defaults to loopback; place behind a
    /// TLS-terminating reverse proxy if binding externally.
    #[arg(long, env = "SCRIM_LISTEN", default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// Authentication token required for all HTTP requests. Prefer passing
    /// `SCRIM_TOKEN` or `--token-file` in production so the token does not
    /// appear in process listings.
    #[arg(long, env = "SCRIM_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Path to a file containing the authentication token.
    #[arg(long, env = "SCRIM_TOKEN_FILE")]
    token_file: Option<PathBuf>,

    /// PostgreSQL connection URL holding members, tokens, groups and branch
    /// rules, e.g. `postgres://scrim@localhost/scrim`. Pending migrations are
    /// applied at startup. Prefer the `DATABASE_URL` environment variable so a
    /// password does not appear in process listings. For a remote server, add
    /// `sslmode=verify-full` (and `sslrootcert=...` if needed): the default,
    /// `prefer`, silently falls back to an unencrypted, unauthenticated
    /// connection.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,

    /// Address to serve Git over SSH on, e.g. `0.0.0.0:2222`. Members
    /// authenticate with the SSH keys registered for them, so this requires
    /// `--database-url` and `--ssh-host-key`. Disabled when not given.
    #[arg(long, env = "SCRIM_SSH_LISTEN", requires = "ssh_host_key")]
    ssh_listen: Option<SocketAddr>,

    /// Path of the SSH server's host key (OpenSSH format). A new Ed25519 key
    /// is generated there (mode 0600) if the file does not exist.
    #[arg(long, env = "SCRIM_SSH_HOST_KEY")]
    ssh_host_key: Option<PathBuf>,

    /// Redis URL (`redis://` or, for TLS, `rediss://`) of a cache for each
    /// request's member and repository policy, shared by every server using
    /// the same database. Requires `--database-url`. Authentication is never
    /// cached, and the server falls back to the database if Redis is down.
    #[arg(long, env = "REDIS_URL", hide_env_values = true)]
    redis_url: Option<String>,
}

/// One-off administrative commands.
#[derive(Subcommand)]
enum Command {
    /// Creates the first admin member and prints their API token once.
    /// Fails if an active admin already exists.
    BootstrapAdmin(BootstrapAdminArgs),
    /// Uploads a backup of every bare repository (and, with `DATABASE_URL`,
    /// a `pg_dump` of the database) to Cloudflare R2, then points
    /// `<prefix>/latest.json` at it.
    Backup(BackupArgs),
    /// Lists or prunes backups stored in Cloudflare R2.
    #[command(subcommand)]
    Backups(BackupsCommand),
    /// Restores a backup from Cloudflare R2 into an empty repo root (and,
    /// with `DATABASE_URL`, the database through `pg_restore --clean`).
    Restore(RestoreArgs),
}

/// Subcommands of `scrim-server backups`.
#[derive(Subcommand)]
enum BackupsCommand {
    /// Lists backups stored in Cloudflare R2, newest first.
    List(BackupsListArgs),
    /// Deletes older backups from Cloudflare R2 while retaining the newest N.
    Prune(BackupsPruneArgs),
}

/// Where backups live: an S3-compatible Cloudflare R2 bucket.
#[derive(Args)]
struct R2Args {
    /// R2 endpoint, e.g. `https://<account>.r2.cloudflarestorage.com`.
    #[arg(long, env = "SCRIM_R2_ENDPOINT")]
    r2_endpoint: String,

    /// R2 bucket name.
    #[arg(long, env = "SCRIM_R2_BUCKET")]
    r2_bucket: String,

    /// Access key ID of an R2 API token.
    #[arg(long, env = "SCRIM_R2_ACCESS_KEY_ID", hide_env_values = true)]
    r2_access_key_id: String,

    /// Secret access key of the R2 API token. Prefer the environment variable
    /// so the secret does not appear in process listings.
    #[arg(long, env = "SCRIM_R2_SECRET_ACCESS_KEY", hide_env_values = true)]
    r2_secret_access_key: String,

    /// Key prefix under which backups are stored.
    #[arg(long, env = "SCRIM_R2_PREFIX", default_value = DEFAULT_R2_PREFIX)]
    r2_prefix: String,
}

impl R2Args {
    /// Converts the arguments, moving the secret into a [`SecretString`].
    fn into_config(self) -> R2Config {
        let secret = Zeroizing::new(self.r2_secret_access_key);
        R2Config {
            endpoint: self.r2_endpoint,
            bucket: self.r2_bucket,
            access_key_id: self.r2_access_key_id,
            secret_access_key: SecretString::from(Box::<str>::from(secret.as_str())),
            prefix: self.r2_prefix,
        }
    }
}

/// Arguments of `scrim-server backup`.
#[derive(Args)]
struct BackupArgs {
    /// Directory containing the bare repositories to back up.
    #[arg(long, env = "SCRIM_REPO_ROOT")]
    repo_root: PathBuf,

    /// PostgreSQL connection URL to dump; the database is skipped if unset.
    /// The password reaches `pg_dump` only through `PGPASSWORD`.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,

    #[command(flatten)]
    r2: R2Args,

    /// `pg_dump` executable.
    #[arg(long, default_value = "pg_dump")]
    pg_dump_bin: PathBuf,

    /// Retain at most this many newest backups (plus `latest.json`), pruning
    /// older ones after the backup succeeds.
    #[arg(long)]
    keep: Option<usize>,
}

/// Arguments of `scrim-server backups list`.
#[derive(Args)]
struct BackupsListArgs {
    #[command(flatten)]
    r2: R2Args,
}

/// Arguments of `scrim-server backups prune`.
#[derive(Args)]
struct BackupsPruneArgs {
    #[command(flatten)]
    r2: R2Args,

    /// Number of newest valid backups to retain (must be at least 1).
    #[arg(long)]
    keep: usize,

    /// Show which backups would be pruned without deleting any objects.
    #[arg(long)]
    dry_run: bool,
}

/// Arguments of `scrim-server restore`.
#[derive(Args)]
struct RestoreArgs {
    /// Directory to restore the bare repositories into. Created if missing;
    /// must be empty unless `--force` is given.
    #[arg(long, env = "SCRIM_REPO_ROOT")]
    repo_root: PathBuf,

    /// PostgreSQL connection URL to restore into; the database dump is
    /// skipped if unset. Existing objects in the dump are dropped first.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: Option<String>,

    #[command(flatten)]
    r2: R2Args,

    /// ID of the backup to restore, or `latest`.
    #[arg(long, default_value = "latest")]
    backup_id: String,

    /// Restore into a non-empty repo root, replacing repositories at the
    /// same paths.
    #[arg(long)]
    force: bool,

    /// `pg_restore` executable.
    #[arg(long, default_value = "pg_restore")]
    pg_restore_bin: PathBuf,
}

/// Arguments of `scrim-server bootstrap-admin`.
#[derive(Args)]
struct BootstrapAdminArgs {
    /// PostgreSQL connection URL (see the server's `--database-url`). Pending
    /// migrations are applied first. Prefer the `DATABASE_URL` environment
    /// variable so a password does not appear in process listings.
    #[arg(long, env = "DATABASE_URL", hide_env_values = true)]
    database_url: String,

    /// Name of the admin member to create.
    #[arg(long)]
    name: String,

    /// Label recorded for the admin's first token.
    #[arg(long, default_value = "bootstrap")]
    token_label: String,
}

fn main() -> anyhow::Result<()> {
    // Checked before logging or argument parsing: in hook mode, stderr goes
    // to the pusher and git passes the hook no server arguments. The hook is
    // synchronous, so no async runtime is started for it.
    if let Some(hook_mode) = std::env::var_os(PRE_RECEIVE_HOOK_MODE_ENV) {
        if hook_mode == PRE_RECEIVE_HOOK_MODE {
            std::process::exit(run_pre_receive_hook_process());
        }
        if hook_mode == PACK_OBJECTS_HOOK_MODE {
            std::process::exit(run_pack_objects_hook_process());
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")
    {
        Ok(runtime) => runtime,
        Err(error) => return Err(error),
    };
    let config = Config::parse();
    match config.command {
        Some(Command::BootstrapAdmin(args)) => runtime.block_on(run_bootstrap_admin(args)),
        Some(Command::Backup(args)) => runtime.block_on(run_backup_command(args)),
        Some(Command::Backups(BackupsCommand::List(args))) => {
            runtime.block_on(run_backups_list_command(args))
        }
        Some(Command::Backups(BackupsCommand::Prune(args))) => {
            runtime.block_on(run_backups_prune_command(args))
        }
        Some(Command::Restore(args)) => runtime.block_on(run_restore_command(args)),
        None => runtime.block_on(run_server(config)),
    }
}

/// Creates the first admin member and prints their token to stdout.
async fn run_bootstrap_admin(args: BootstrapAdminArgs) -> anyhow::Result<()> {
    // Keep the URL (and any password in it) out of every error message.
    let database_url = Zeroizing::new(args.database_url);
    let store = match PgPolicyStore::connect(&database_url).await {
        Ok(store) => store,
        Err(error) => {
            return Err(anyhow::Error::new(error)).context("cannot connect to the database");
        }
    };
    drop(database_url);
    if let Err(error) = store.migrate().await {
        return Err(anyhow::Error::new(error)).context("cannot migrate the database");
    }
    let created = match store.bootstrap_admin(&args.name, &args.token_label).await {
        Ok(created) => created,
        Err(error) => {
            return Err(anyhow::Error::new(error)).context("cannot bootstrap the admin member");
        }
    };

    // Write the token straight from the secret, so no unzeroized `String`
    // copy is made; stdout carries only the token, for easy capture.
    let mut stdout = std::io::stdout().lock();
    let written = stdout
        .write_all(created.token.expose_secret().as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush());
    if let Err(error) = written {
        return Err(anyhow::Error::new(error)).context("cannot print the admin token");
    }
    eprintln!(
        "Created admin member {:?} (id {}). The token above is shown only once: store it securely.",
        created.member.name, created.member.id
    );
    Ok(())
}

/// Moves an optional database URL into a [`SecretString`].
fn secret_database_url(database_url: Option<String>) -> Option<SecretString> {
    database_url.map(|url| {
        let url = Zeroizing::new(url);
        SecretString::from(Box::<str>::from(url.as_str()))
    })
}

/// Uploads a backup and prints its ID to stdout.
async fn run_backup_command(args: BackupArgs) -> anyhow::Result<()> {
    init_tracing_to_stderr();
    if let Err(error) = ensure_supported_git().await {
        return Err(error);
    }
    let manifest = match run_backup(BackupConfig {
        repo_root: args.repo_root,
        database_url: secret_database_url(args.database_url),
        r2: args.r2.into_config(),
        pg_dump_bin: args.pg_dump_bin,
        keep: args.keep,
    })
    .await
    {
        Ok(manifest) => manifest,
        Err(error) => return Err(error.context("backup failed")),
    };
    println!("{}", manifest.backup_id);
    eprintln!(
        "Backed up {} repositories{} as {}.",
        manifest.repos.len(),
        if manifest.database.is_some() {
            " and the database"
        } else {
            ""
        },
        manifest.backup_id
    );
    Ok(())
}

/// Lists backups stored in R2, newest first.
async fn run_backups_list_command(args: BackupsListArgs) -> anyhow::Result<()> {
    init_tracing_to_stderr();
    let r2 = args.r2.into_config();
    let backups = match list_backups(&r2).await {
        Ok(backups) => backups,
        Err(error) => return Err(error.context("listing backups failed")),
    };
    if backups.is_empty() {
        println!("No backups found.");
        return Ok(());
    }
    for backup in backups {
        let db_flag = if backup.has_database { "db" } else { "no-db" };
        let latest_marker = if backup.is_latest { " [latest]" } else { "" };
        println!(
            "{}\t{}\t{} repos\t{}\t{} bytes{}",
            backup.backup_id,
            backup.created_at_utc,
            backup.repo_count,
            db_flag,
            backup.total_size_bytes,
            latest_marker
        );
    }
    Ok(())
}

/// Prunes older backups stored in R2 according to `--keep`.
async fn run_backups_prune_command(args: BackupsPruneArgs) -> anyhow::Result<()> {
    init_tracing_to_stderr();
    let report = match prune_backups(PruneConfig {
        r2: args.r2.into_config(),
        keep: args.keep,
        dry_run: args.dry_run,
    })
    .await
    {
        Ok(report) => report,
        Err(error) => return Err(error.context("pruning backups failed")),
    };
    for id in &report.kept {
        println!("keep\t{id}");
    }
    for id in &report.pruned {
        println!("prune\t{id}");
    }
    let verb = if report.dry_run {
        "Would prune"
    } else {
        "Pruned"
    };
    eprintln!(
        "{verb} {} backup(s) ({} object(s) deleted); kept {} backup(s).",
        report.pruned.len(),
        report.deleted_objects,
        report.kept.len()
    );
    Ok(())
}

/// Restores a backup and reports what was restored.
async fn run_restore_command(args: RestoreArgs) -> anyhow::Result<()> {
    init_tracing_to_stderr();
    if let Err(error) = ensure_supported_git().await {
        return Err(error);
    }
    let manifest = match run_restore(RestoreConfig {
        repo_root: args.repo_root,
        database_url: secret_database_url(args.database_url),
        r2: args.r2.into_config(),
        backup_id: Some(args.backup_id),
        force: args.force,
        pg_restore_bin: args.pg_restore_bin,
    })
    .await
    {
        Ok(manifest) => manifest,
        Err(error) => return Err(error.context("restore failed")),
    };
    eprintln!(
        "Restored {} repositories from backup {}.",
        manifest.repos.len(),
        manifest.backup_id
    );
    Ok(())
}

/// Logs to stderr (stdout carries the command's result) at `info`, or as
/// `RUST_LOG` says.
fn init_tracing_to_stderr() {
    let mut env_filter = EnvFilter::new("info");
    if let Ok(from_env) = EnvFilter::try_from_default_env() {
        env_filter = from_env;
    }
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_writer(std::io::stderr)
        .init();
}

/// Decides whether `git --version` output names a Git release the server
/// supports, returning the release found.
///
/// Kept apart from the process spawn so the decision can be tested without
/// Git. Fails when the output cannot be parsed (refusing to guess) or names a
/// release older than [`MIN_GIT_VERSION`]; the message names both versions.
fn check_git_version_output(output: &str) -> Result<GitVersion, String> {
    let first_line = output.lines().next().map_or("", str::trim);
    let Some(found) = parse_git_version(output) else {
        return Err(format!(
            "cannot read the Git version from {first_line:?}; scrim-server requires Git \
             {MIN_GIT_VERSION} or newer"
        ));
    };
    if found < MIN_GIT_VERSION {
        return Err(format!(
            "Git {found} is too old: scrim-server requires Git {MIN_GIT_VERSION} or newer"
        ));
    }
    Ok(found)
}

/// Refuses to continue unless the `git` this process spawns for repositories
/// (the one found on `PATH`) is at least [`MIN_GIT_VERSION`], and logs the
/// version found at `info`.
///
/// Runs `git --version` with the environment the server's library gives every
/// git it spawns (empty but for `PATH`, no system or user configuration), so
/// the binary checked is the binary served with.
async fn ensure_supported_git() -> anyhow::Result<()> {
    let mut command = tokio::process::Command::new("git");
    command.arg("--version").env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    let output = match command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(std::process::Stdio::null())
        .kill_on_drop(true)
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) => {
            return Err(anyhow::Error::new(error)).context(format!(
                "cannot run `git --version`: scrim-server requires Git {MIN_GIT_VERSION} or newer on PATH"
            ));
        }
    };
    if !output.status.success() {
        bail!(
            "`git --version` exited with {}; scrim-server requires Git {MIN_GIT_VERSION} or newer",
            output.status
        );
    }
    match check_git_version_output(&String::from_utf8_lossy(&output.stdout)) {
        Ok(found) => {
            tracing::info!(git_version = %found, required = %MIN_GIT_VERSION, "using git");
            Ok(())
        }
        Err(message) => bail!("{message}"),
    }
}

/// Serves until Ctrl-C with the parsed server configuration.
async fn run_server(config: Config) -> anyhow::Result<()> {
    let mut env_filter = EnvFilter::new("info");
    if let Ok(from_env) = EnvFilter::try_from_default_env() {
        env_filter = from_env;
    }
    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    // clap requires `--repo-root` whenever no subcommand is given.
    let Some(config_repo_root) = config.repo_root else {
        bail!("--repo-root is required");
    };
    if !config_repo_root.is_dir() {
        bail!(
            "repo root {} is not an existing directory",
            config_repo_root.display()
        );
    }
    let repo_root = match config_repo_root
        .canonicalize()
        .with_context(|| format!("cannot resolve repo root {}", config_repo_root.display()))
    {
        Ok(repo_root) => repo_root,
        Err(error) => return Err(error),
    };

    if config.ssh_listen.is_some() && config.database_url.is_none() {
        bail!("--ssh-listen requires --database-url: SSH keys are stored in the database");
    }
    if config.redis_url.is_some() && config.database_url.is_none() {
        bail!("--redis-url requires --database-url: Redis only caches the database's policy");
    }

    // After the argument checks, so a misconfigured start fails on those first;
    // before anything is opened or served.
    if let Err(error) = ensure_supported_git().await {
        return Err(error);
    }

    // One hook directory for both transports.
    let hook_dir = SharedHookDir::default();
    let mut ssh_policy_store: Option<Arc<dyn PolicyStore>> = None;
    let router = if let Some(database_url) = config.database_url {
        // Keep the URL (and any password in it) out of every error message.
        let database_url = Zeroizing::new(database_url);
        let store = match PgPolicyStore::connect(&database_url).await {
            Ok(store) => store,
            Err(error) => {
                return Err(anyhow::Error::new(error)).context("cannot connect to the database");
            }
        };
        if let Err(error) = store.migrate().await {
            return Err(anyhow::Error::new(error)).context("cannot migrate the database");
        }
        let mut store: Arc<dyn PolicyStore> = Arc::new(store);
        if let Some(redis_url) = config.redis_url {
            // Keep the URL (and any password in it) out of every error message.
            let redis_url = Zeroizing::new(redis_url);
            let redis_cache = match RedisPolicyCache::connect(&redis_url).await {
                Ok(redis_cache) => redis_cache,
                Err(error) => bail!("cannot connect to the Redis policy cache: {error}"),
            };
            drop(redis_url);
            store = Arc::new(CachedPolicyStore::new(store, Arc::new(redis_cache)));
            tracing::info!("caching member repository policy in Redis");
        }
        ssh_policy_store = Some(Arc::clone(&store));
        scrim_server::router_with_hook_dir(repo_root.clone(), store, hook_dir.clone())
    } else {
        let auth = match load_token_auth(config.token, config.token_file).await {
            Ok(auth) => auth,
            Err(error) => return Err(error),
        };
        scrim_server::router(repo_root.clone(), auth)
    };

    let listener = match tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("cannot listen on {}", config.listen))
    {
        Ok(listener) => listener,
        Err(error) => return Err(error),
    };
    let local_address = match listener
        .local_addr()
        .context("cannot read listener address")
    {
        Ok(local_address) => local_address,
        Err(error) => return Err(error),
    };
    tracing::info!(repo_root = %repo_root.display(), address = %local_address, "serving");

    let ssh_server = match (config.ssh_listen, config.ssh_host_key, ssh_policy_store) {
        (Some(ssh_address), Some(host_key_path), Some(policy_store)) => {
            let host_key = match load_or_create_ssh_host_key(&host_key_path)
                .with_context(|| format!("cannot load SSH host key {}", host_key_path.display()))
            {
                Ok(host_key) => host_key,
                Err(error) => return Err(error),
            };
            let ssh_listener = match tokio::net::TcpListener::bind(ssh_address)
                .await
                .with_context(|| format!("cannot listen for SSH on {ssh_address}"))
            {
                Ok(listener) => listener,
                Err(error) => return Err(error),
            };
            match ssh_listener.local_addr() {
                Ok(address) => tracing::info!(%address, "serving git over SSH"),
                Err(error) => tracing::warn!(%error, "cannot read SSH listener address"),
            }
            Some((
                ssh_listener,
                SshServerConfig {
                    repo_root: repo_root.clone(),
                    policy_store,
                    host_key,
                    hook_dir,
                },
            ))
        }
        // clap requires `--ssh-host-key` with `--ssh-listen`, and the
        // database was checked above.
        (Some(_), _, _) => bail!("--ssh-listen requires --ssh-host-key and --database-url"),
        (None, _, _) => None,
    };

    let shutdown = CancellationToken::new();
    let ctrl_c_shutdown = shutdown.clone();
    tokio::spawn(async move {
        // If the signal handler cannot be installed, keep serving rather than exit.
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("shutting down");
            ctrl_c_shutdown.cancel();
        }
    });

    // Whichever server stops first (cleanly or not) stops the other.
    let http_server = async {
        let result = axum::serve(listener, router)
            .with_graceful_shutdown(shutdown.clone().cancelled_owned())
            .await
            .context("server error");
        shutdown.cancel();
        result
    };
    let Some((ssh_listener, ssh_config)) = ssh_server else {
        return http_server.await;
    };
    let ssh_server = async {
        let result = serve_ssh(ssh_listener, ssh_config, shutdown.clone().cancelled_owned())
            .await
            .context("SSH server error");
        shutdown.cancel();
        result
    };
    let (http_result, ssh_result) = tokio::join!(http_server, ssh_server);
    http_result.and(ssh_result)
}

/// Loads the configured token from `--token` or `--token-file` and builds a [`TokenAuth`].
async fn load_token_auth(
    token: Option<String>,
    token_file: Option<PathBuf>,
) -> anyhow::Result<TokenAuth> {
    let secret_token = if let Some(raw_token) = token {
        // Allocate an exact-sized Box<str> directly so String -> Box<str>
        // cannot shrink/reallocate an unzeroized copy in freed heap memory.
        let raw_token = Zeroizing::new(raw_token);
        SecretString::from(Box::<str>::from(raw_token.as_str()))
    } else if let Some(path) = token_file {
        match read_token_file(&path).await {
            Ok(secret) => secret,
            Err(error) => return Err(error),
        }
    } else {
        bail!("either --token or --token-file must be provided");
    };

    let token_len = secret_token.expose_secret().len();
    let auth = match TokenAuth::new(secret_token) {
        Ok(auth) => auth,
        Err(error) => {
            return Err(anyhow::Error::new(error)).context("invalid authentication token");
        }
    };

    if token_len < RECOMMENDED_MIN_TOKEN_BYTES {
        tracing::warn!(
            min_recommended_bytes = RECOMMENDED_MIN_TOKEN_BYTES,
            "configured authentication token is short; consider using a longer random token"
        );
    }

    Ok(auth)
}

/// Opens a regular file at `path` without blocking on FIFOs or special files.
async fn open_regular_token_file(path: &Path) -> anyhow::Result<tokio::fs::File> {
    let mut open_options = tokio::fs::OpenOptions::new();
    open_options.read(true);
    #[cfg(unix)]
    {
        // O_NONBLOCK prevents open() from blocking indefinitely on a FIFO with
        // no writer while still following symlinks (e.g. secret volume mounts).
        open_options.custom_flags(libc::O_NONBLOCK);
    }

    let file = match open_options.open(path).await {
        Ok(file) => file,
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot open token file {}", path.display()));
        }
    };
    let metadata = match file.metadata().await {
        Ok(metadata) => metadata,
        Err(error) => {
            return Err(anyhow::Error::new(error))
                .with_context(|| format!("cannot inspect token file {}", path.display()));
        }
    };
    if !metadata.is_file() {
        bail!("token file {} must be a regular file", path.display());
    }
    Ok(file)
}

/// Reads an authentication token from `path`, capping the read and stripping at
/// most one trailing `\r\n` or `\n`.
async fn read_token_file(path: &Path) -> anyhow::Result<SecretString> {
    let file = match open_regular_token_file(path).await {
        Ok(file) => file,
        Err(error) => return Err(error),
    };

    // Pre-allocate the full cap so read_to_end never reallocates token bytes
    // into a larger buffer and leaves an unzeroized prefix behind.
    let mut raw_bytes = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_FILE_BYTES + 1));
    let mut limited = file.take((MAX_TOKEN_FILE_BYTES + 1) as u64);
    if let Err(error) = limited.read_to_end(&mut raw_bytes).await {
        return Err(anyhow::Error::new(error))
            .with_context(|| format!("cannot read token file {}", path.display()));
    }
    if raw_bytes.len() > MAX_TOKEN_FILE_BYTES {
        bail!(
            "token file {} exceeds maximum size of {MAX_TOKEN_FILE_BYTES} bytes",
            path.display()
        );
    }

    let mut text = match String::from_utf8(std::mem::take(&mut *raw_bytes)) {
        Ok(text) => Zeroizing::new(text),
        Err(error) => {
            // Wipe invalid bytes before dropping so secret fragments do not linger.
            let mut invalid_bytes = error.into_bytes();
            invalid_bytes.zeroize();
            bail!("token file {} is not valid UTF-8", path.display());
        }
    };

    // Strip a single trailing newline (`\r\n` or `\n`) commonly written by editors,
    // leaving any other whitespace intact so invalid tokens fail validation.
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }

    // Build an exact-sized Box<str> directly from the slice so String -> Box<str>
    // cannot shrink/reallocate and leave an unzeroized copy in freed heap memory.
    Ok(SecretString::from(Box::<str>::from(text.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_minimum_and_newer_releases() {
        for (output, expected) in [
            ("git version 2.40.0\n", GitVersion::new(2, 40, 0)),
            (
                "git version 2.54.0 (Apple Git-157)\n",
                GitVersion::new(2, 54, 0),
            ),
            ("git version 2.45.0.rc1\n", GitVersion::new(2, 45, 0)),
            ("git version 3.0.1\n", GitVersion::new(3, 0, 1)),
        ] {
            match check_git_version_output(output) {
                Ok(found) => assert_eq!(found, expected, "{output:?}"),
                Err(message) => panic!("{output:?} should be accepted: {message}"),
            }
        }
    }

    #[test]
    fn rejects_older_releases_naming_both_versions() {
        for output in ["git version 2.39.5\n", "git version 1.9.0\n"] {
            match check_git_version_output(output) {
                Ok(found) => panic!("{output:?} should be rejected, got {found}"),
                Err(message) => {
                    assert!(message.contains("too old"), "{message}");
                    assert!(message.contains(&MIN_GIT_VERSION.to_string()), "{message}");
                }
            }
        }
        match check_git_version_output("git version 2.39.5\n") {
            Err(message) => assert!(message.contains("Git 2.39.5"), "{message}"),
            Ok(found) => panic!("2.39.5 should be rejected, got {found}"),
        }
    }

    #[test]
    fn rejects_output_it_cannot_parse() {
        for output in ["", "\n", "not git\n", "git version\n", "git version dev\n"] {
            match check_git_version_output(output) {
                Ok(found) => panic!("{output:?} should be rejected, got {found}"),
                Err(message) => {
                    assert!(message.contains("cannot read the Git version"), "{message}");
                    assert!(message.contains(&MIN_GIT_VERSION.to_string()), "{message}");
                }
            }
        }
    }
}
