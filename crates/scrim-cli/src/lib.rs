//! Command-line client library for Scrim for Git.
//!
//! Both `scrim` and `git-scrim` binaries delegate directly to [`main_entry`].
//! Tests and embedding harnesses can invoke [`run_from`] with a custom
//! [`CliEnv`] to capture output and override working directory or environment
//! variables without mutating global process state.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod audit_cmd;
mod cli;
pub mod client;
mod clone_cmd;
pub mod config;
mod filter;
mod git;
mod keychain;
mod mirror_cmd;
mod private_cmd;
pub mod private_store;
pub mod secrets_store;
mod ssh_key_cmd;

/// Entry points for the `cargo-fuzz` targets in `fuzz/`. Not a stable API.
#[doc(hidden)]
pub mod fuzz_support {
    pub use crate::filter::fuzz_filter_protocol;
}

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};

use anyhow::{Context, anyhow, bail};
use clap::Parser;
use scrim_crypto::{
    EncryptedSecretsFile, MemberIdentity, MemberPublicKey, ScopeDataKey, ScopeKeysFile,
    SecretBundle, format_dotenv, rotate_scope, validate_scope_name, validate_secret_key,
};
use scrim_policy::{BranchPolicy, BranchRule, GitVersion, MIN_GIT_VERSION, validate_ref_glob};
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{
    AccessCommand, BranchCommand, Cli, Command, ExportFormat, GrantArgs, GroupCommand, InitArgs,
    KeygenArgs, LoginArgs, RunArgs, SecretsCommand, SecretsScopeCommand, SecretsSetArgs,
};
use crate::client::{ScopeRecipientInfo, ScrimClient};
use crate::config::{
    ScrimConfig, load_config, load_member_identity, normalize_server_url, resolve_config_path,
    resolve_identity_path, save_config, save_keychain_account, save_member_identity,
};
use crate::git::{
    MIRROR_MIN_GIT_VERSION, ensure_git_version, git_configure_scrim_filter, git_local_config_get,
    git_local_config_set, git_remote_add, git_remote_get_url, git_remote_set_url, git_toplevel,
    validate_remote_name,
};
use crate::private_store::paths_file_path;
use crate::secrets_store::{
    list_local_scopes, load_and_decrypt_scope, read_scope_keys, read_scope_secrets,
    require_repo_root, write_scope_keys, write_scope_secrets,
};

/// Execution environment passed to [`run_from`] for I/O, working directory, and
/// environment variable resolution.
pub struct CliEnv<'a> {
    /// Working directory used for Git repository discovery and local config.
    pub cwd: PathBuf,
    /// Environment variables consulted for config path, server URL, and token.
    pub env_vars: BTreeMap<String, String>,
    /// Input stream used for interactive or `--token-stdin` token entry.
    pub stdin: &'a mut dyn BufRead,
    /// Output stream for command results.
    pub stdout: &'a mut dyn Write,
    /// Output stream for prompts and diagnostics.
    pub stderr: &'a mut dyn Write,
}

impl<'a> CliEnv<'a> {
    fn env_var(&self, key: &str) -> Option<String> {
        self.env_vars.get(key).cloned()
    }

    fn non_empty_env(&self, key: &str) -> Option<String> {
        match self.env_vars.get(key) {
            Some(value) if !value.is_empty() => Some(value.clone()),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct ChildExitError {
    code: i32,
}

impl ChildExitError {
    fn from_status(status: std::process::ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self { code };
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            if let Some(signal) = status.signal() {
                return Self { code: 128 + signal };
            }
        }
        Self { code: 1 }
    }

    fn to_exit_code(&self) -> ExitCode {
        if self.code == 0 {
            return ExitCode::SUCCESS;
        }
        let byte = (self.code & 0xff) as u8;
        if byte == 0 {
            ExitCode::FAILURE
        } else {
            ExitCode::from(byte)
        }
    }
}

impl std::fmt::Display for ChildExitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "command exited with status {}", self.code)
    }
}

impl std::error::Error for ChildExitError {}

/// Process entry point shared by `scrim` and `git-scrim`.
pub fn main_entry() -> ExitCode {
    let cwd = match std::env::current_dir() {
        Ok(dir) => dir,
        Err(err) => {
            let _ = writeln!(
                io::stderr(),
                "error: failed to read current directory: {err}"
            );
            return ExitCode::FAILURE;
        }
    };

    let env_vars: BTreeMap<String, String> = std::env::vars().collect();
    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let stdout = io::stdout();
    let mut stdout_lock = stdout.lock();
    let stderr = io::stderr();
    let mut stderr_lock = stderr.lock();

    let mut env = CliEnv {
        cwd,
        env_vars,
        stdin: &mut stdin_lock,
        stdout: &mut stdout_lock,
        stderr: &mut stderr_lock,
    };

    let result = run_from_with_options(std::env::args_os(), &mut env, true);
    for value in env.env_vars.values_mut() {
        value.zeroize();
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if let Some(child_err) = err.downcast_ref::<ChildExitError>() {
                return child_err.to_exit_code();
            }
            let _ = writeln!(env.stderr, "error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// Parses `args` and executes the requested Scrim CLI command against `env`.
pub fn run_from<I, T>(args: I, env: &mut CliEnv<'_>) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_from_with_options(args, env, false)
}

fn run_from_with_options<I, T>(
    args: I,
    env: &mut CliEnv<'_>,
    inherit_child_stdio: bool,
) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut cli = match Cli::try_parse_from(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            use clap::error::ErrorKind;
            match err.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    if let Err(io_err) = write!(env.stdout, "{err}") {
                        return Err(anyhow!(io_err)).context("failed to write help output");
                    }
                    return Ok(());
                }
                _ => {
                    if let Err(io_err) = write!(env.stderr, "{err}") {
                        return Err(anyhow!(io_err)).context("failed to write CLI error");
                    }
                    bail!("invalid command-line arguments");
                }
            }
        }
    };

    // Convert any CLI/env token into `SecretString` immediately so raw strings
    // are zeroized even if config resolution or URL validation returns early.
    let raw_token = match cli.token.take() {
        Some(token) => Some(token),
        None => env.non_empty_env("SCRIM_TOKEN"),
    };
    let token_override = take_secret_string(raw_token);

    if cli.config.is_none()
        && let Some(path) = env.non_empty_env("SCRIM_CONFIG")
    {
        cli.config = Some(PathBuf::from(path));
    }
    if cli.server.is_none()
        && let Some(server) = env.non_empty_env("SCRIM_SERVER")
    {
        cli.server = Some(server);
    }

    let config_path_result = resolve_config_path(cli.config.as_deref(), &|key| env.env_var(key));
    let key_file = cli.key_file.take();
    let server_flag = cli.server.take();

    if let Some((minimum, required_by)) = required_git_version(&cli.command)
        && let Err(err) = ensure_git_version(minimum, required_by)
    {
        return Err(err);
    }

    match cli.command {
        Command::Login(login_args) => {
            let config_path = match config_path_result {
                Ok(path) => path,
                Err(err) => return Err(err),
            };
            handle_login(login_args, server_flag, token_override, &config_path, env)
        }
        Command::Whoami => {
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path_result.as_deref().ok(),
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_whoami(&client, env.stdout)
        }
        Command::Keygen(keygen_args) => handle_keygen(
            keygen_args,
            key_file.as_deref(),
            server_flag,
            token_override,
            config_path_result,
            env,
        ),
        Command::Init(init_args) => {
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path_result.as_deref().ok(),
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_init(init_args, &client, env)
        }
        Command::Clone(clone_args) => clone_cmd::handle_clone(
            clone_args,
            key_file.as_deref(),
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            env,
        ),
        Command::Group(group_args) => {
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path_result.as_deref().ok(),
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_group(group_args.command, &client, env.stdout)
        }
        Command::Access(access_args) => {
            let config_path_opt = config_path_result.as_deref().ok();
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path_opt,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_access(
                access_args.command,
                &client,
                key_file.as_deref(),
                config_path_opt,
                env,
            )
        }
        Command::Branch(branch_args) => {
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path_result.as_deref().ok(),
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_branch(branch_args.command, &client, env)
        }
        Command::Secrets(secrets_args) => handle_secrets(
            secrets_args.command,
            key_file.as_deref(),
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            env,
        ),
        Command::Run(run_args) => handle_run(
            run_args,
            key_file.as_deref(),
            config_path_result.as_deref().ok(),
            env,
            inherit_child_stdio,
        ),
        Command::Private(private_args) => private_cmd::handle_private(
            private_args.command,
            key_file.as_deref(),
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            env,
        ),
        Command::Audit(audit_args) => audit_cmd::handle_audit(
            audit_args,
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            env,
        ),
        Command::SshKey(ssh_key_args) => ssh_key_cmd::handle_ssh_key(
            ssh_key_args.command,
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            env,
        ),
        Command::Mirror(mirror_args) => mirror_cmd::handle_mirror(
            mirror_args,
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            env,
        ),
        Command::Keychain(keychain_args) => keychain::handle_keychain(
            keychain_args.command,
            key_file.as_deref(),
            server_flag,
            token_override,
            config_path_result,
            env,
            &keychain::OsKeychain,
        ),
        Command::FilterProcess => private_cmd::handle_filter_process(
            key_file.as_deref(),
            config_path_result.as_deref().ok(),
            env,
        ),
    }
}

/// The Git version `command` needs, or `None` when it does not drive Git.
///
/// Commands that work on a repository (init, clone, secrets, run, private)
/// need Scrim's floor; `mirror` needs a release that honours
/// `GIT_NO_LAZY_FETCH`. Admin-API commands are exempt even when they read a
/// default from `git config` (which works on any Git), and so is `access
/// revoke`, whose local key rotation is best-effort and must never block a
/// revocation. `filter-process` is exempt because Git itself launched it, once
/// per Git command, and the check would only add a process spawn to each.
fn required_git_version(command: &Command) -> Option<(GitVersion, &'static str)> {
    match command {
        Command::Mirror(_) => Some((MIRROR_MIN_GIT_VERSION, "scrim mirror")),
        Command::Init(_)
        | Command::Clone(_)
        | Command::Secrets(_)
        | Command::Run(_)
        | Command::Private(_) => Some((MIN_GIT_VERSION, "Scrim")),
        Command::Login(_)
        | Command::Whoami
        | Command::Keygen(_)
        | Command::Group(_)
        | Command::Access(_)
        | Command::Branch(_)
        | Command::Audit(_)
        | Command::SshKey(_)
        | Command::Keychain(_)
        | Command::FilterProcess => None,
    }
}

fn take_secret_string(raw: Option<String>) -> Option<SecretString> {
    match raw {
        Some(mut value) => {
            let trimmed = value.trim();
            let result = if trimmed.is_empty() {
                None
            } else {
                Some(SecretString::from(trimmed))
            };
            value.zeroize();
            result
        }
        None => None,
    }
}

fn read_token_from_stdin(
    stdin: &mut dyn BufRead,
    stderr: &mut dyn Write,
    prompt: bool,
) -> anyhow::Result<SecretString> {
    if prompt {
        if let Err(err) = write!(stderr, "Token: ") {
            return Err(anyhow!(err)).context("failed to write token prompt");
        }
        if let Err(err) = stderr.flush() {
            return Err(anyhow!(err)).context("failed to flush token prompt");
        }
    }

    let mut line = Zeroizing::new(String::new());
    match stdin.read_line(&mut line) {
        Ok(0) => bail!("no token provided on standard input"),
        Ok(_) => {}
        Err(err) => return Err(anyhow!(err)).context("failed to read token from standard input"),
    }

    let trimmed = line.trim_end_matches(['\r', '\n']).trim();
    if trimmed.is_empty() {
        bail!("token cannot be empty");
    }

    Ok(SecretString::from(trimmed))
}

fn handle_login(
    args: LoginArgs,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: &Path,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let raw_server = match server_flag {
        Some(url) if !url.trim().is_empty() => url,
        _ => bail!("missing server URL: pass --server <URL> or set SCRIM_SERVER"),
    };
    let server = match normalize_server_url(&raw_server) {
        Ok(url) => url,
        Err(err) => return Err(err),
    };

    let token = if args.token_stdin {
        drop(token_override);
        match read_token_from_stdin(env.stdin, env.stderr, false) {
            Ok(tok) => tok,
            Err(err) => return Err(err),
        }
    } else if let Some(tok) = token_override {
        tok
    } else {
        match read_token_from_stdin(env.stdin, env.stderr, true) {
            Ok(tok) => tok,
            Err(err) => return Err(err),
        }
    };

    let client = match ScrimClient::new(&server, token.clone()) {
        Ok(client) => client,
        Err(err) => return Err(err),
    };

    let identity = match client.whoami() {
        Ok(info) => info,
        Err(err) => return Err(err).context("credential verification failed"),
    };

    if let Err(err) = save_config(config_path, &server, &token) {
        return Err(err);
    }

    let role = if identity.is_admin { "admin" } else { "member" };
    write_line(
        env.stdout,
        &format!("Logged in as {} ({role}) on {server}", identity.name),
    )
}

fn build_authenticated_client(
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    cwd: &Path,
) -> anyhow::Result<ScrimClient> {
    let loaded: Option<ScrimConfig> = match config_path {
        Some(path) => match load_config(path) {
            Ok(cfg) => cfg,
            Err(err) => return Err(err),
        },
        None => None,
    };

    let config_server = match &loaded {
        Some(cfg) => cfg.server.clone(),
        None => None,
    };
    let config_token = match loaded {
        Some(cfg) => cfg.token,
        None => None,
    };

    let server = if let Some(raw) = server_flag {
        match normalize_server_url(&raw) {
            Ok(url) => url,
            Err(err) => return Err(err),
        }
    } else if let Some(saved) = config_server {
        saved
    } else if let Some(git_server) = match git_local_config_get(cwd, "scrim.server") {
        Ok(val) => val,
        Err(err) => return Err(err),
    } {
        match normalize_server_url(&git_server) {
            Ok(url) => url,
            Err(err) => {
                return Err(err).context("invalid scrim.server value in local git config");
            }
        }
    } else {
        bail!("no server URL configured; run 'scrim login --server <URL>' or pass --server");
    };

    let token = if let Some(flag_tok) = token_override {
        flag_tok
    } else if let Some(saved_tok) = config_token {
        saved_tok
    } else {
        bail!("not logged in; run 'scrim login --server <URL>' or pass --token");
    };

    ScrimClient::new(&server, token)
}

fn handle_whoami(client: &ScrimClient, stdout: &mut dyn Write) -> anyhow::Result<()> {
    let identity = match client.whoami() {
        Ok(info) => info,
        Err(err) => return Err(err),
    };

    let role = if identity.is_admin { "admin" } else { "member" };
    let groups = format_list_or_none(&identity.groups, "(none)");
    let public_key = match &identity.public_key {
        Some(key) if !key.is_empty() => key.as_str(),
        _ => "(none)",
    };
    if let Err(err) = write_line(stdout, &format!("Member: {} ({role})", identity.name)) {
        return Err(err);
    }
    if let Err(err) = write_line(stdout, &format!("Groups: {groups}")) {
        return Err(err);
    }
    write_line(stdout, &format!("Public key: {public_key}"))
}

fn handle_keygen(
    args: KeygenArgs,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path_result: anyhow::Result<PathBuf>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    if args.keychain {
        return handle_keygen_keychain(
            args.force,
            cli_key_file,
            server_flag,
            token_override,
            config_path_result,
            env,
            &keychain::OsKeychain,
        );
    }

    let identity_path = if let Some(path) = cli_key_file
        && !path.as_os_str().is_empty()
    {
        path.to_path_buf()
    } else if let Some(path) = env.non_empty_env("SCRIM_KEY_FILE") {
        PathBuf::from(path)
    } else {
        let cfg_path = match &config_path_result {
            Ok(path) => path.as_path(),
            Err(err) => return Err(anyhow!("{err}")),
        };
        // A new identity.age would be ignored while config.toml points at
        // the keychain, so refuse rather than write a key nobody uses.
        match load_config(cfg_path) {
            Ok(Some(ScrimConfig {
                keychain_account: Some(account),
                ..
            })) => bail!(
                "the identity is stored in the OS keychain (account \"{account}\"); pass --keychain to replace it there, or run 'scrim keychain disable' first"
            ),
            Ok(_) => {}
            Err(err) => return Err(err),
        }
        resolve_identity_path(None, &|key| env.env_var(key), cfg_path)
    };

    match fs::symlink_metadata(&identity_path) {
        Ok(_) if !args.force => {
            bail!(
                "identity file {} already exists (pass --force to overwrite)",
                identity_path.display()
            );
        }
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| {
                format!(
                    "failed to inspect identity file {}",
                    identity_path.display()
                )
            });
        }
    }

    // Verify credentials before generating or overwriting any key on disk.
    let client = if args.local_only {
        None
    } else {
        match build_authenticated_client(
            server_flag,
            token_override,
            config_path_result.as_deref().ok(),
            &env.cwd,
        ) {
            Ok(c) => Some(c),
            Err(err) => return Err(err),
        }
    };

    let identity = MemberIdentity::generate();
    let public_key = identity.public_key();

    // Register with the server before writing to disk so an auth or network
    // failure never overwrites an existing identity file or leaves an
    // unregistered key behind.
    if let Some(client) = client {
        if let Err(err) = client.set_own_public_key(public_key.as_str()) {
            return Err(err);
        }
        if let Err(err) = save_member_identity(&identity_path, &identity) {
            return Err(err).with_context(|| {
                format!(
                    "public key was registered on the server, but saving identity to {} failed",
                    identity_path.display()
                )
            });
        }
    } else if let Err(err) = save_member_identity(&identity_path, &identity) {
        return Err(err);
    }

    if let Err(err) = write_line(env.stdout, &format!("Public key: {public_key}")) {
        return Err(err);
    }
    write_line(
        env.stdout,
        &format!("Identity saved to {}", identity_path.display()),
    )
}

/// Handles `scrim keygen --keychain`: generates an identity, registers its
/// public key and stores the private key in the OS keychain under
/// `<member>@<server>`, recording that account in `config.toml`.
fn handle_keygen_keychain(
    force: bool,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path_result: anyhow::Result<PathBuf>,
    env: &mut CliEnv<'_>,
    store: &dyn keychain::SecretStore,
) -> anyhow::Result<()> {
    if let Err(err) = keychain::reject_explicit_key_file(cli_key_file, env) {
        return Err(err);
    }
    let config_path = match config_path_result {
        Ok(path) => path,
        Err(err) => return Err(err),
    };
    let identity_path = resolve_identity_path(None, &|key| env.env_var(key), &config_path);
    match fs::symlink_metadata(&identity_path) {
        Ok(_) => bail!(
            "identity file {} already exists; move it into the keychain with 'scrim keychain enable' or remove it first",
            identity_path.display()
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow!(err)).with_context(|| {
                format!(
                    "failed to inspect identity file {}",
                    identity_path.display()
                )
            });
        }
    }
    let recorded_account = match load_config(&config_path) {
        Ok(Some(cfg)) => cfg.keychain_account,
        Ok(None) => None,
        Err(err) => return Err(err),
    };
    if let Some(account) = &recorded_account
        && !force
    {
        bail!(
            "the identity is already stored in the OS keychain (account \"{account}\"); pass --force to replace it"
        );
    }

    let client =
        match build_authenticated_client(server_flag, token_override, Some(&config_path), &env.cwd)
        {
            Ok(client) => client,
            Err(err) => return Err(err),
        };
    let member = match client.whoami() {
        Ok(info) => info.name,
        Err(err) => return Err(err),
    };
    let account = keychain::keychain_account(&member, client.base_url());
    // Reading first also surfaces an unsupported platform or locked keychain
    // before anything is registered on the server.
    match store.read(&account) {
        Ok(Some(_)) if !force => bail!(
            "the OS keychain already holds a Scrim identity for account \"{account}\"; pass --force to replace it"
        ),
        Ok(_) => {}
        Err(err) => return Err(err),
    }

    let identity = MemberIdentity::generate();
    let public_key = identity.public_key();
    // Same order as the file flow: register first so an auth or network
    // failure never replaces a stored identity.
    if let Err(err) = client.set_own_public_key(public_key.as_str()) {
        return Err(err);
    }
    if let Err(err) = keychain::store_new_identity(store, &account, &identity) {
        return Err(err).context(
            "public key was registered on the server, but storing the identity in the OS keychain failed",
        );
    }
    if let Err(err) = save_keychain_account(&config_path, Some(&account)) {
        return Err(err).with_context(|| {
            format!(
                "the identity was stored in the OS keychain (service \"{}\", account \"{account}\"), but recording that in {} failed; add keychain_account = \"{account}\" to it",
                keychain::KEYCHAIN_SERVICE,
                config_path.display()
            )
        });
    }

    if let Err(err) = write_line(env.stdout, &format!("Public key: {public_key}")) {
        return Err(err);
    }
    write_line(
        env.stdout,
        &format!(
            "Identity saved to the OS keychain (service \"{}\", account \"{account}\")",
            keychain::KEYCHAIN_SERVICE
        ),
    )
}

fn handle_init(args: InitArgs, client: &ScrimClient, env: &mut CliEnv<'_>) -> anyhow::Result<()> {
    let toplevel = match git_toplevel(&env.cwd) {
        Ok(dir) => dir,
        Err(err) => return Err(err),
    };

    if toplevel.is_some()
        && !args.no_remote
        && let Err(err) = validate_remote_name(&args.remote)
    {
        return Err(err);
    }

    let repo_path = match args.repo_path {
        Some(path) => {
            let trimmed = path.trim();
            if trimmed.is_empty() {
                bail!("repository path cannot be empty");
            }
            trimmed.to_owned()
        }
        None => {
            let root = match &toplevel {
                Some(path) => path,
                None => {
                    bail!(
                        "not inside a git repository; pass <REPO_PATH> explicitly or run inside a git repository"
                    );
                }
            };
            let dir_name = match root.file_name().and_then(|name| name.to_str()) {
                Some(name) if !name.is_empty() => name,
                _ => bail!(
                    "cannot derive repository name from {}; pass <REPO_PATH> explicitly",
                    root.display()
                ),
            };
            if dir_name.ends_with(".git") {
                dir_name.to_owned()
            } else {
                format!("{dir_name}.git")
            }
        }
    };

    let created = match client.create_repository(&repo_path, !args.no_create) {
        Ok(resp) => resp,
        Err(err) => return Err(err),
    };

    let mut configured_remote_url: Option<String> = None;
    if toplevel.is_some() {
        let remote_action = if args.no_remote {
            None
        } else {
            let remote_url = format!(
                "{}/{}",
                client.base_url(),
                created.path.trim_start_matches('/')
            );
            let existing = match git_remote_get_url(&env.cwd, &args.remote) {
                Ok(url) => url,
                Err(err) => return Err(err),
            };
            match existing {
                None => Some((remote_url, false)),
                Some(current) if current == remote_url => {
                    configured_remote_url = Some(remote_url);
                    None
                }
                Some(current) => {
                    if args.force {
                        Some((remote_url, true))
                    } else {
                        bail!(
                            "git remote '{}' already points to '{}' (pass --force to overwrite with '{}')",
                            args.remote,
                            current,
                            remote_url
                        );
                    }
                }
            }
        };

        if let Err(err) = git_local_config_set(&env.cwd, "scrim.repo", &created.path) {
            return Err(err);
        }
        if let Err(err) = git_local_config_set(&env.cwd, "scrim.server", client.base_url()) {
            return Err(err);
        }
        if let Some(root) = &toplevel
            && paths_file_path(root).exists()
            && let Err(err) = git_configure_scrim_filter(root)
        {
            return Err(err);
        }

        if let Some((remote_url, replace_existing)) = remote_action {
            let result = if replace_existing {
                git_remote_set_url(&env.cwd, &args.remote, &remote_url)
            } else {
                git_remote_add(&env.cwd, &args.remote, &remote_url)
            };
            if let Err(err) = result {
                return Err(err);
            }
            configured_remote_url = Some(remote_url);
        }
    }

    if let Err(err) = write_line(env.stdout, &format!("Repository: {}", created.path)) {
        return Err(err);
    }
    match configured_remote_url {
        Some(url) => write_line(env.stdout, &format!("Remote ({}): {url}", args.remote)),
        None => Ok(()),
    }
}

fn handle_group(
    command: GroupCommand,
    client: &ScrimClient,
    stdout: &mut dyn Write,
) -> anyhow::Result<()> {
    match command {
        GroupCommand::Create { name } => {
            let created = match client.create_group(&name) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            write_line(stdout, &format!("Created group {}", created.name))
        }
        GroupCommand::Add { group, member } => {
            let res = match client.add_group_member(&group, &member) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.added {
                write_line(
                    stdout,
                    &format!("Added {} to group {}", res.member, res.group),
                )
            } else {
                write_line(
                    stdout,
                    &format!("{} is already a member of {}", res.member, res.group),
                )
            }
        }
        GroupCommand::Remove { group, member } => {
            let res = match client.remove_group_member(&group, &member) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.removed {
                write_line(
                    stdout,
                    &format!("Removed {} from group {}", res.member, res.group),
                )
            } else {
                write_line(
                    stdout,
                    &format!("{} was not a member of {}", res.member, res.group),
                )
            }
        }
        GroupCommand::List => {
            let res = match client.list_groups() {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.groups.is_empty() {
                return write_line(stdout, "(no groups)");
            }
            for group in &res.groups {
                let members = format_list_or_none(&group.members, "(no members)");
                if let Err(err) = write_line(stdout, &format!("{}: {members}", group.name)) {
                    return Err(err);
                }
            }
            Ok(())
        }
    }
}

fn handle_access(
    command: AccessCommand,
    client: &ScrimClient,
    cli_key_file: Option<&Path>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    match command {
        AccessCommand::Grant(GrantArgs {
            member,
            groups,
            admin,
            machine,
            token_label,
            public_key,
            generate_key,
        }) => {
            let (resolved_public_key, generated_identity) = match public_key {
                Some(raw_key) => {
                    let parsed = match MemberPublicKey::parse(&raw_key) {
                        Ok(pk) => pk,
                        Err(err) => return Err(anyhow!(err)),
                    };
                    (Some(parsed.as_str().to_owned()), None)
                }
                None if generate_key || machine => {
                    let identity = MemberIdentity::generate();
                    let pk = identity.public_key().as_str().to_owned();
                    (Some(pk), Some(identity))
                }
                None => (None, None),
            };

            let res = match client.create_member(
                &member,
                admin,
                machine,
                resolved_public_key.as_deref(),
                &groups,
                &token_label,
            ) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            let role = if res.member.is_admin {
                "admin"
            } else {
                "member"
            };
            let kind = if res.member.is_machine {
                "machine"
            } else {
                "user"
            };
            let member_groups = format_list_or_none(&res.member.groups, "(none)");
            if let Err(err) = write_line(
                env.stdout,
                &format!(
                    "Granted access to {} ({role}, {kind}, groups: {member_groups})",
                    res.member.name
                ),
            ) {
                return Err(err);
            }
            if let Err(err) = write_line(
                env.stdout,
                &format!("Token (shown only once): {}", res.token.expose_secret()),
            ) {
                return Err(err);
            }
            if let Some(identity) = generated_identity {
                let secret = identity.to_secret_string();
                if let Err(err) = write_line(
                    env.stdout,
                    &format!("SCRIM_KEY (shown only once): {}", secret.expose_secret()),
                ) {
                    return Err(err);
                }
            }
            Ok(())
        }
        AccessCommand::Revoke {
            member,
            repo,
            no_rotate,
        } => {
            let res = match client.revoke_member(&member) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.revoked {
                if let Err(err) =
                    write_line(env.stdout, &format!("Revoked access for {}", res.name))
                {
                    return Err(err);
                }
            } else if let Err(err) = write_line(
                env.stdout,
                &format!("Member {} was already revoked", res.name),
            ) {
                return Err(err);
            }

            if no_rotate {
                return Ok(());
            }

            let rotated_scopes = rotate_scopes_after_revocation(
                &res.name,
                repo,
                client,
                cli_key_file,
                config_path,
                env,
            );
            let rotated_groups = private_cmd::rotate_groups_after_revocation(
                &res.name,
                client,
                cli_key_file,
                config_path,
                env,
            );
            if rotated_scopes || rotated_groups {
                write_line(
                    env.stdout,
                    "Remember to commit and push the updated .scrim/ files.",
                )
            } else {
                Ok(())
            }
        }
        AccessCommand::List { all } => {
            let res = match client.list_members(all) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.members.is_empty() {
                return write_line(env.stdout, "(no members)");
            }
            for member in &res.members {
                let role = if member.is_admin { "admin" } else { "member" };
                let kind = if member.is_machine { "machine" } else { "user" };
                let status = if member.revoked { "revoked" } else { "active" };
                let groups = format_list_or_none(&member.groups, "(none)");
                if let Err(err) = write_line(
                    env.stdout,
                    &format!(
                        "{}: {role}, {kind}, {status}, groups: {groups}",
                        member.name
                    ),
                ) {
                    return Err(err);
                }
            }
            Ok(())
        }
        AccessCommand::Token { member, label } => {
            let res = match client.issue_token(&member, &label) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            write_line(
                env.stdout,
                &format!(
                    "Issued token '{}' for {} (shown only once): {}",
                    res.label,
                    res.member,
                    res.token.expose_secret()
                ),
            )
        }
        AccessCommand::SetKey { member, public_key } => {
            let parsed = match MemberPublicKey::parse(&public_key) {
                Ok(pk) => pk,
                Err(err) => return Err(anyhow!(err)),
            };
            let res = match client.set_member_public_key(&member, parsed.as_str()) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            write_line(
                env.stdout,
                &format!("Set public key for {} to {}", res.name, res.public_key),
            )
        }
    }
}

/// Rotates every local secret scope that lists the revoked `member`, warning
/// (never failing) on local problems. Returns whether any scope was rotated.
fn rotate_scopes_after_revocation(
    member: &str,
    repo_flag: Option<String>,
    client: &ScrimClient,
    cli_key_file: Option<&Path>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> bool {
    let repo_root = match git_toplevel(&env.cwd) {
        Ok(Some(root)) => root,
        Ok(None) => return false,
        Err(err) => {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but local git repository discovery failed ({err}); run 'scrim secrets sync --scope <scope>' if needed"
            );
            return false;
        }
    };

    let local_scopes = match list_local_scopes(&repo_root) {
        Ok(scopes) => scopes,
        Err(err) => {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but local scopes could not be listed ({err}); run 'scrim secrets sync --scope <scope>' if needed"
            );
            return false;
        }
    };
    if local_scopes.is_empty() {
        return false;
    }

    let mut affected = Vec::new();
    for scope in local_scopes {
        match read_scope_keys(&repo_root, &scope) {
            Ok(Some(keys_file)) => {
                if keys_file.recipients.iter().any(|r| r.member == member) {
                    affected.push((scope, keys_file));
                }
            }
            Ok(None) => {}
            Err(err) => {
                let _ = writeln!(
                    env.stderr,
                    "warning: member '{member}' was revoked on the server, but scope '{scope}' could not be read ({err}); run 'scrim secrets sync --scope {scope}' manually"
                );
            }
        }
    }
    if affected.is_empty() {
        return false;
    }

    let identity = match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
        Ok(id) => id,
        Err(err) => {
            let scope_names: Vec<&str> = affected.iter().map(|(s, _)| s.as_str()).collect();
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but local scope(s) ({}) still need rotation ({err}); run 'scrim secrets sync --scope <scope>'",
                scope_names.join(", ")
            );
            return false;
        }
    };

    let optional_repo = match repo_flag {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_owned())
            }
        }
        None => {
            if let Ok(Some(val)) = git_local_config_get(&env.cwd, "scrim.repo") {
                Some(val)
            } else {
                None
            }
        }
    };

    let mut rotated_any = false;
    let mut keys_to_rotate = BTreeSet::new();

    for (scope, keys_file) in affected {
        let mut new_recipients = match &optional_repo {
            Some(repo_key) => match client.get_secret_scope_recipients(repo_key, &scope) {
                Ok(resp) => {
                    warn_members_without_key(env.stderr, &scope, &resp.members_without_key);
                    match recipients_from_server(&resp.recipients) {
                        Ok(map) => map,
                        Err(err) => {
                            let _ = writeln!(
                                env.stderr,
                                "warning: invalid recipient list from server for scope '{scope}' ({err}); falling back to local keys file"
                            );
                            match keys_file.recipient_public_keys() {
                                Ok(map) => map,
                                Err(fallback_err) => {
                                    let _ = writeln!(
                                        env.stderr,
                                        "warning: scope '{scope}' could not be rotated ({fallback_err}); run 'scrim secrets sync --scope {scope}'"
                                    );
                                    continue;
                                }
                            }
                        }
                    }
                }
                Err(_) => match keys_file.recipient_public_keys() {
                    Ok(map) => map,
                    Err(err) => {
                        let _ = writeln!(
                            env.stderr,
                            "warning: scope '{scope}' could not be rotated ({err}); run 'scrim secrets sync --scope {scope}'"
                        );
                        continue;
                    }
                },
            },
            None => match keys_file.recipient_public_keys() {
                Ok(map) => map,
                Err(err) => {
                    let _ = writeln!(
                        env.stderr,
                        "warning: scope '{scope}' could not be rotated ({err}); run 'scrim secrets sync --scope {scope}'"
                    );
                    continue;
                }
            },
        };

        new_recipients.remove(member);
        if new_recipients.is_empty() {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but scope '{scope}' has no remaining recipients; run 'scrim secrets sync --scope {scope}' once another recipient is authorized"
            );
            continue;
        }

        let secrets_file = match read_scope_secrets(&repo_root, &scope) {
            Ok(sf) => sf,
            Err(err) => {
                let _ = writeln!(
                    env.stderr,
                    "warning: member '{member}' was revoked on the server, but secrets for scope '{scope}' could not be read ({err}); run 'scrim secrets sync --scope {scope}'"
                );
                continue;
            }
        };

        let rotated = match rotate_scope(
            &scope,
            &keys_file,
            secrets_file.as_ref(),
            &identity,
            &new_recipients,
        ) {
            Ok(r) => r,
            Err(err) => {
                let _ = writeln!(
                    env.stderr,
                    "warning: member '{member}' was revoked on the server, but scope '{scope}' could not be rotated ({err}); run 'scrim secrets sync --scope {scope}'"
                );
                continue;
            }
        };

        if let Err(err) = write_scope_keys(&repo_root, &scope, &rotated.keys_file) {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but writing rotated keys for scope '{scope}' failed ({err}); run 'scrim secrets sync --scope {scope}'"
            );
            continue;
        }
        if let Some(new_secrets) = &rotated.secrets_file
            && let Err(err) = write_scope_secrets(&repo_root, &scope, new_secrets)
        {
            let _ = writeln!(
                env.stderr,
                "warning: member '{member}' was revoked on the server, but writing rotated secrets for scope '{scope}' failed ({err}); run 'scrim secrets sync --scope {scope}'"
            );
            continue;
        }

        rotated_any = true;
        let _ = write_line(
            env.stdout,
            &format!(
                "Rotated scope '{scope}' to generation {}",
                rotated.keys_file.generation
            ),
        );
        for key in rotated.rotated_secret_keys {
            keys_to_rotate.insert(key);
        }
    }

    if rotated_any && !keys_to_rotate.is_empty() {
        let key_list: Vec<String> = keys_to_rotate.into_iter().collect();
        let _ = print_secrets_to_rotate(env.stdout, &key_list);
    }
    rotated_any
}

fn handle_branch(
    command: BranchCommand,
    client: &ScrimClient,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    match command {
        BranchCommand::Private { glob, groups, repo } => {
            if let Err(err) = validate_ref_glob(&glob) {
                return Err(anyhow!(err));
            }
            let rule = match BranchRule::new(&glob, groups.clone()) {
                Ok(rule) => rule,
                Err(err) => return Err(anyhow!(err)),
            };
            if let Err(err) = BranchPolicy::compile(vec![rule]) {
                return Err(anyhow!(err));
            }

            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let res = match client.put_branch_rule(&repo_key, &glob, &groups) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            let allowed = format_list_or_none(&res.groups, "(none)");
            write_line(
                env.stdout,
                &format!(
                    "Protected {} in {} for groups: {allowed}",
                    res.pattern, res.repository
                ),
            )
        }
        BranchCommand::List { repo } => {
            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let res = match client.list_branch_rules(&repo_key) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.rules.is_empty() {
                return write_line(
                    env.stdout,
                    &format!("(no branch rules for {})", res.repository),
                );
            }
            for rule in &res.rules {
                let groups = format_list_or_none(&rule.groups, "(none)");
                if let Err(err) = write_line(env.stdout, &format!("{}: {groups}", rule.pattern)) {
                    return Err(err);
                }
            }
            Ok(())
        }
        BranchCommand::Rm { glob, repo } => {
            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let res = match client.delete_branch_rule(&repo_key, &glob) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.removed {
                write_line(
                    env.stdout,
                    &format!(
                        "Removed branch rule {} from {}",
                        res.pattern, res.repository
                    ),
                )
            } else {
                write_line(
                    env.stdout,
                    &format!("No branch rule {} found in {}", res.pattern, res.repository),
                )
            }
        }
    }
}

fn resolve_repo_arg(repo_flag: Option<String>, cwd: &Path) -> anyhow::Result<String> {
    if let Some(repo) = repo_flag {
        let trimmed = repo.trim();
        if trimmed.is_empty() {
            bail!("repository key cannot be empty");
        }
        return Ok(trimmed.to_owned());
    }

    match git_local_config_get(cwd, "scrim.repo") {
        Ok(Some(repo)) => Ok(repo),
        Ok(None) => bail!(
            "no repository configured locally (scrim.repo is unset); run 'scrim init' or pass --repo <REPO>"
        ),
        Err(err) => Err(err),
    }
}

fn format_list_or_none(items: &[String], empty_label: &str) -> String {
    if items.is_empty() {
        empty_label.to_owned()
    } else {
        items.join(", ")
    }
}

/// Replaces control characters (including terminal escape sequences) in
/// server- or repository-supplied text with their escaped form so printing it
/// cannot rewrite the user's terminal.
pub(crate) fn escape_control_chars(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            escaped.extend(character.escape_default());
        } else {
            escaped.push(character);
        }
    }
    escaped
}

fn write_line(out: &mut dyn Write, line: &str) -> anyhow::Result<()> {
    match writeln!(out, "{line}") {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(err)).context("failed to write output"),
    }
}

fn handle_secrets(
    command: SecretsCommand,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    match command {
        SecretsCommand::Set(args) => handle_secrets_set(
            args,
            cli_key_file,
            server_flag,
            token_override,
            config_path,
            env,
        ),
        SecretsCommand::Get { key, scope } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            if let Err(err) = validate_secret_key(&key) {
                return Err(anyhow!(err));
            }
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let identity =
                match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
                    Ok(id) => id,
                    Err(err) => return Err(err),
                };
            let (_, _, bundle) = match load_and_decrypt_scope(&repo_root, &scope, &identity) {
                Ok(res) => res,
                Err(err) => return Err(err),
            };
            let Some(value) = bundle.get(&key) else {
                bail!("secret '{key}' not found in scope '{scope}'");
            };
            if let Err(err) = env.stdout.write_all(value.expose_secret().as_bytes()) {
                return Err(anyhow!(err)).context("failed to write secret output");
            }
            if let Err(err) = env.stdout.write_all(b"\n") {
                return Err(anyhow!(err)).context("failed to write secret output");
            }
            Ok(())
        }
        SecretsCommand::List { scope } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let identity =
                match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
                    Ok(id) => id,
                    Err(err) => return Err(err),
                };
            let (_, _, bundle) = match load_and_decrypt_scope(&repo_root, &scope, &identity) {
                Ok(res) => res,
                Err(err) => return Err(err),
            };
            if bundle.is_empty() {
                return write_line(env.stdout, &format!("(no secrets in scope '{scope}')"));
            }
            for key in bundle.keys() {
                if let Err(err) = write_line(env.stdout, key) {
                    return Err(err);
                }
            }
            Ok(())
        }
        SecretsCommand::Rm { key, scope } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            if let Err(err) = validate_secret_key(&key) {
                return Err(anyhow!(err));
            }
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let identity =
                match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
                    Ok(id) => id,
                    Err(err) => return Err(err),
                };
            let (keys_file, data_key, mut bundle) =
                match load_and_decrypt_scope(&repo_root, &scope, &identity) {
                    Ok(res) => res,
                    Err(err) => return Err(err),
                };
            if bundle.remove(&key).is_none() {
                bail!("secret '{key}' not found in scope '{scope}'");
            }
            let new_secrets = match EncryptedSecretsFile::encrypt(
                &scope,
                keys_file.generation,
                &data_key,
                &bundle,
            ) {
                Ok(file) => file,
                Err(err) => return Err(anyhow!(err)).context("failed to re-encrypt scope secrets"),
            };
            if let Err(err) = write_scope_secrets(&repo_root, &scope, &new_secrets) {
                return Err(err);
            }
            write_line(env.stdout, &format!("Removed {key} from scope '{scope}'"))
        }
        SecretsCommand::Export { scope, format } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let identity =
                match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
                    Ok(id) => id,
                    Err(err) => return Err(err),
                };
            let (_, _, bundle) = match load_and_decrypt_scope(&repo_root, &scope, &identity) {
                Ok(res) => res,
                Err(err) => return Err(err),
            };
            match format {
                ExportFormat::Dotenv => {
                    let rendered = format_dotenv(&bundle);
                    if let Err(err) = env.stdout.write_all(rendered.as_bytes()) {
                        return Err(anyhow!(err)).context("failed to write exported secrets");
                    }
                    Ok(())
                }
            }
        }
        SecretsCommand::Sync { scope, repo } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            let repo_root = match require_repo_root(&env.cwd) {
                Ok(root) => root,
                Err(err) => return Err(err),
            };
            let keys_file = match read_scope_keys(&repo_root, &scope) {
                Ok(Some(file)) => file,
                Ok(None) => bail!("secret scope '{scope}' does not exist locally"),
                Err(err) => return Err(err),
            };
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let identity =
                match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
                    Ok(id) => id,
                    Err(err) => return Err(err),
                };
            let secrets_file = match read_scope_secrets(&repo_root, &scope) {
                Ok(sf) => sf,
                Err(err) => return Err(err),
            };
            let resp = match client.get_secret_scope_recipients(&repo_key, &scope) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            warn_members_without_key(env.stderr, &scope, &resp.members_without_key);

            let new_recipients = match recipients_from_server(&resp.recipients) {
                Ok(map) => map,
                Err(err) => return Err(err),
            };
            let removed_members: Vec<String> = keys_file
                .recipients
                .iter()
                .filter(|r| !new_recipients.contains_key(&r.member))
                .map(|r| r.member.clone())
                .collect();

            let rotated = match rotate_scope(
                &scope,
                &keys_file,
                secrets_file.as_ref(),
                &identity,
                &new_recipients,
            ) {
                Ok(r) => r,
                Err(err) => return Err(anyhow!(err)).context("failed to rotate scope"),
            };

            if let Err(err) = write_scope_keys(&repo_root, &scope, &rotated.keys_file) {
                return Err(err);
            }
            if let Some(new_secrets) = &rotated.secrets_file
                && let Err(err) = write_scope_secrets(&repo_root, &scope, new_secrets)
            {
                return Err(err);
            }

            if let Err(err) = write_line(
                env.stdout,
                &format!(
                    "Synced scope '{scope}' to generation {} ({} recipient(s))",
                    rotated.keys_file.generation,
                    rotated.keys_file.recipients.len()
                ),
            ) {
                return Err(err);
            }
            if !removed_members.is_empty() && !rotated.rotated_secret_keys.is_empty() {
                if let Err(err) = write_line(
                    env.stdout,
                    &format!("Removed recipient(s): {}", removed_members.join(", ")),
                ) {
                    return Err(err);
                }
                if let Err(err) = print_secrets_to_rotate(env.stdout, &rotated.rotated_secret_keys)
                {
                    return Err(err);
                }
            }
            Ok(())
        }
        SecretsCommand::Scope(scope_args) => {
            let client = match build_authenticated_client(
                server_flag,
                token_override,
                config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_secrets_scope(scope_args.command, &client, env)
        }
    }
}

fn handle_secrets_set(
    mut args: SecretsSetArgs,
    cli_key_file: Option<&Path>,
    server_flag: Option<String>,
    token_override: Option<SecretString>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    let parsed_entry = parse_secret_entry(&mut args.entry, args.value_stdin, env.stdin);
    let (key, value) = match parsed_entry {
        Ok(pair) => pair,
        Err(err) => return Err(err),
    };

    if let Err(err) = validate_scope_name(&args.scope) {
        return Err(anyhow!(err));
    }

    let repo_root = match require_repo_root(&env.cwd) {
        Ok(root) => root,
        Err(err) => return Err(err),
    };
    let identity = match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
        Ok(id) => id,
        Err(err) => return Err(err),
    };

    match read_scope_keys(&repo_root, &args.scope) {
        Ok(Some(keys_file)) => {
            let data_key = match keys_file.unwrap_key(&args.scope, &identity) {
                Ok(k) => k,
                Err(err) => {
                    return Err(anyhow!(err)).with_context(|| {
                        format!("failed to unwrap key for scope '{}'", args.scope)
                    });
                }
            };
            let mut bundle = match read_scope_secrets(&repo_root, &args.scope) {
                Ok(Some(sf)) => match sf.decrypt(&args.scope, keys_file.generation, &data_key) {
                    Ok(b) => b,
                    Err(err) => {
                        return Err(anyhow!(err)).with_context(|| {
                            format!("failed to decrypt secrets for scope '{}'", args.scope)
                        });
                    }
                },
                Ok(None) => SecretBundle::new(),
                Err(err) => return Err(err),
            };
            if let Err(err) = bundle.set(&key, value) {
                return Err(anyhow!(err));
            }
            let new_secrets = match EncryptedSecretsFile::encrypt(
                &args.scope,
                keys_file.generation,
                &data_key,
                &bundle,
            ) {
                Ok(sf) => sf,
                Err(err) => return Err(anyhow!(err)).context("failed to encrypt scope secrets"),
            };
            if let Err(err) = write_scope_secrets(&repo_root, &args.scope, &new_secrets) {
                return Err(err);
            }
        }
        Ok(None) => {
            let recipients = if args.offline {
                let mut map = BTreeMap::new();
                map.insert("self".to_owned(), identity.public_key());
                map
            } else {
                let client = match build_authenticated_client(
                    server_flag,
                    token_override,
                    config_path,
                    &env.cwd,
                ) {
                    Ok(c) => c,
                    Err(err) => return Err(err),
                };
                let repo_key = match resolve_repo_arg(args.repo, &env.cwd) {
                    Ok(r) => r,
                    Err(err) => return Err(err),
                };
                let resp = match client.get_secret_scope_recipients(&repo_key, &args.scope) {
                    Ok(r) => r,
                    Err(err) => return Err(err),
                };
                warn_members_without_key(env.stderr, &args.scope, &resp.members_without_key);

                let map = match recipients_from_server(&resp.recipients) {
                    Ok(m) => m,
                    Err(err) => return Err(err),
                };
                let my_pk = identity.public_key();
                if !map.values().any(|pk| *pk == my_pk) {
                    bail!(
                        "your public key ({my_pk}) is not an authorized recipient for scope '{}' on {repo_key}; run 'scrim keygen' or ask an admin to add you to the scope's group",
                        args.scope
                    );
                }
                map
            };

            let data_key = match ScopeDataKey::generate() {
                Ok(k) => k,
                Err(err) => return Err(anyhow!(err)).context("failed to generate scope data key"),
            };
            let keys_file =
                match ScopeKeysFile::wrap_for_recipients(&args.scope, 1, &data_key, &recipients) {
                    Ok(kf) => kf,
                    Err(err) => return Err(anyhow!(err)).context("failed to wrap scope data key"),
                };
            let mut bundle = SecretBundle::new();
            if let Err(err) = bundle.set(&key, value) {
                return Err(anyhow!(err));
            }
            let secrets_file =
                match EncryptedSecretsFile::encrypt(&args.scope, 1, &data_key, &bundle) {
                    Ok(sf) => sf,
                    Err(err) => {
                        return Err(anyhow!(err)).context("failed to encrypt scope secrets");
                    }
                };
            if let Err(err) = write_scope_keys(&repo_root, &args.scope, &keys_file) {
                return Err(err);
            }
            if let Err(err) = write_scope_secrets(&repo_root, &args.scope, &secrets_file) {
                return Err(err);
            }
        }
        Err(err) => return Err(err),
    }

    write_line(env.stdout, &format!("Set {key} in scope '{}'", args.scope))
}

fn handle_secrets_scope(
    command: SecretsScopeCommand,
    client: &ScrimClient,
    env: &mut CliEnv<'_>,
) -> anyhow::Result<()> {
    match command {
        SecretsScopeCommand::Set {
            scope,
            groups,
            repo,
        } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let res = match client.put_secret_scope(&repo_key, &scope, &groups) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            let allowed = format_list_or_none(&res.groups, "(none)");
            write_line(
                env.stdout,
                &format!(
                    "Configured secret scope '{}' in {} for groups: {allowed}",
                    res.scope, res.repository
                ),
            )
        }
        SecretsScopeCommand::List { repo } => {
            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let res = match client.list_secret_scopes(&repo_key) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.scopes.is_empty() {
                return write_line(
                    env.stdout,
                    &format!("(no secret scopes for {})", res.repository),
                );
            }
            for scope_info in &res.scopes {
                let groups = format_list_or_none(&scope_info.groups, "(none)");
                if let Err(err) = write_line(env.stdout, &format!("{}: {groups}", scope_info.scope))
                {
                    return Err(err);
                }
            }
            Ok(())
        }
        SecretsScopeCommand::Rm { scope, repo } => {
            if let Err(err) = validate_scope_name(&scope) {
                return Err(anyhow!(err));
            }
            let repo_key = match resolve_repo_arg(repo, &env.cwd) {
                Ok(r) => r,
                Err(err) => return Err(err),
            };
            let res = match client.delete_secret_scope(&repo_key, &scope) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.removed {
                write_line(
                    env.stdout,
                    &format!("Removed secret scope {} from {}", res.scope, res.repository),
                )
            } else {
                write_line(
                    env.stdout,
                    &format!("No secret scope {} found in {}", res.scope, res.repository),
                )
            }
        }
    }
}

fn handle_run(
    args: RunArgs,
    cli_key_file: Option<&Path>,
    config_path: Option<&Path>,
    env: &mut CliEnv<'_>,
    inherit_child_stdio: bool,
) -> anyhow::Result<()> {
    if let Err(err) = validate_scope_name(&args.scope) {
        return Err(anyhow!(err));
    }
    let repo_root = match require_repo_root(&env.cwd) {
        Ok(root) => root,
        Err(err) => return Err(err),
    };
    let identity = match load_member_identity(cli_key_file, &|k| env.env_var(k), config_path) {
        Ok(id) => id,
        Err(err) => return Err(err),
    };
    let (_, _, bundle) = match load_and_decrypt_scope(&repo_root, &args.scope, &identity) {
        Ok(res) => res,
        Err(err) => return Err(err),
    };

    let Some(program) = args.command.first() else {
        bail!("missing command to execute");
    };

    let mut cmd = ProcessCommand::new(program);
    cmd.args(&args.command[1..]).current_dir(&env.cwd);
    for (key, value) in bundle.iter() {
        cmd.env(key, value.expose_secret());
    }

    if inherit_child_stdio {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = match cmd.status() {
            Ok(s) => s,
            Err(err) => {
                return Err(anyhow!(err)).with_context(|| format!("failed to execute '{program}'"));
            }
        };
        if !status.success() {
            return Err(anyhow!(ChildExitError::from_status(status)));
        }
        Ok(())
    } else {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = match cmd.output() {
            Ok(o) => o,
            Err(err) => {
                return Err(anyhow!(err)).with_context(|| format!("failed to execute '{program}'"));
            }
        };
        if !output.stdout.is_empty()
            && let Err(err) = env.stdout.write_all(&output.stdout)
        {
            return Err(anyhow!(err)).context("failed to write child stdout");
        }
        if !output.stderr.is_empty()
            && let Err(err) = env.stderr.write_all(&output.stderr)
        {
            return Err(anyhow!(err)).context("failed to write child stderr");
        }
        if !output.status.success() {
            return Err(anyhow!(ChildExitError::from_status(output.status)));
        }
        Ok(())
    }
}

fn parse_secret_entry(
    entry: &mut String,
    value_stdin: bool,
    stdin: &mut dyn BufRead,
) -> anyhow::Result<(String, SecretString)> {
    if value_stdin {
        let key = entry.clone();
        entry.zeroize();
        if let Err(err) = validate_secret_key(&key) {
            return Err(anyhow!(err));
        }
        let mut raw_val = Zeroizing::new(String::new());
        if let Err(err) = stdin.read_to_string(&mut raw_val) {
            return Err(anyhow!(err)).context("failed to read secret value from standard input");
        }
        let stripped = if let Some(s) = raw_val.strip_suffix("\r\n") {
            s
        } else if let Some(s) = raw_val.strip_suffix('\n') {
            s
        } else {
            raw_val.as_str()
        };
        let value = SecretString::from(stripped);
        return Ok((key, value));
    }

    let Some((raw_key, raw_val)) = entry.split_once('=') else {
        entry.zeroize();
        bail!("secret entry must be KEY=VALUE (or pass --value-stdin)");
    };
    let key = raw_key.to_owned();
    let value = SecretString::from(raw_val);
    entry.zeroize();

    if let Err(err) = validate_secret_key(&key) {
        return Err(anyhow!(err));
    }
    Ok((key, value))
}

fn recipients_from_server(
    entries: &[ScopeRecipientInfo],
) -> anyhow::Result<BTreeMap<String, MemberPublicKey>> {
    let mut map = BTreeMap::new();
    for entry in entries {
        let pk = match MemberPublicKey::parse(&entry.public_key) {
            Ok(key) => key,
            Err(err) => {
                return Err(anyhow!(err)).with_context(|| {
                    format!("server returned invalid public key for '{}'", entry.member)
                });
            }
        };
        if map.insert(entry.member.clone(), pk).is_some() {
            bail!("server returned duplicate recipient '{}'", entry.member);
        }
    }
    Ok(map)
}

fn warn_members_without_key(stderr: &mut dyn Write, scope: &str, members: &[String]) {
    for member in members {
        let _ = writeln!(
            stderr,
            "warning: member '{member}' has no public key registered and cannot decrypt scope '{scope}'"
        );
    }
}

fn print_secrets_to_rotate(stdout: &mut dyn Write, keys: &[String]) -> anyhow::Result<()> {
    if let Err(err) = write_line(stdout, "Secrets to rotate at their source:") {
        return Err(err);
    }
    for key in keys {
        if let Err(err) = write_line(stdout, &format!("  {key}")) {
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn parses_key_value_entries_including_equals_and_stdin() {
        let mut empty_stdin = Cursor::new(b"");
        let mut entry = "DATABASE_URL=postgres://user:p=ss@host/db?sslmode=require".to_owned();
        let (key, val) = match parse_secret_entry(&mut entry, false, &mut empty_stdin) {
            Ok(pair) => pair,
            Err(err) => panic!("parse_secret_entry failed: {err}"),
        };
        assert_eq!(key, "DATABASE_URL");
        assert_eq!(
            val.expose_secret(),
            "postgres://user:p=ss@host/db?sslmode=require"
        );
        assert!(entry.is_empty() || entry.bytes().all(|b| b == 0));

        let mut bad = "NO_EQUALS".to_owned();
        assert!(parse_secret_entry(&mut bad, false, &mut empty_stdin).is_err());

        let mut key_only = "API_TOKEN".to_owned();
        let mut stdin = Cursor::new(b"secret=val\r\n");
        let (k2, v2) = match parse_secret_entry(&mut key_only, true, &mut stdin) {
            Ok(pair) => pair,
            Err(err) => panic!("parse_secret_entry stdin failed: {err}"),
        };
        assert_eq!(k2, "API_TOKEN");
        assert_eq!(v2.expose_secret(), "secret=val");
    }
}
