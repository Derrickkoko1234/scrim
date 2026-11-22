//! The scrim-server binary: serves bare Git repositories over smart HTTP.
//!
//! `scrim-server bootstrap-admin` instead creates the first admin member in
//! the database and prints their token once.
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
use scrim_server::{
    MAX_TOKEN_BYTES, PACK_OBJECTS_HOOK_MODE, PRE_RECEIVE_HOOK_MODE, PRE_RECEIVE_HOOK_MODE_ENV,
    PgPolicyStore, PolicyStore, SecretString, TokenAuth, run_pack_objects_hook_process,
    run_pre_receive_hook_process,
};
use secrecy::ExposeSecret;
use tokio::io::AsyncReadExt;
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
}

/// One-off administrative commands.
#[derive(Subcommand)]
enum Command {
    /// Creates the first admin member and prints their API token once.
    /// Fails if an active admin already exists.
    BootstrapAdmin(BootstrapAdminArgs),
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
        scrim_server::router_with_policy_store(repo_root.clone(), Arc::new(store))
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

    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            // If the signal handler cannot be installed, keep serving rather than exit.
            if tokio::signal::ctrl_c().await.is_err() {
                std::future::pending::<()>().await;
            }
            tracing::info!("shutting down");
        })
        .await
        .context("server error")
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
