//! Command-line client library for Scrim for Git.
//!
//! Both `scrim` and `git-scrim` binaries delegate directly to [`main_entry`].
//! Tests and embedding harnesses can invoke [`run_from`] with a custom
//! [`CliEnv`] to capture output and override working directory or environment
//! variables without mutating global process state.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod cli;
pub mod client;
pub mod config;
mod git;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, anyhow, bail};
use clap::Parser;
use scrim_policy::{BranchPolicy, BranchRule, validate_ref_glob};
use secrecy::{ExposeSecret, SecretString};
use zeroize::{Zeroize, Zeroizing};

use crate::cli::{
    AccessCommand, BranchCommand, Cli, Command, GrantArgs, GroupCommand, InitArgs, LoginArgs,
};
use crate::client::ScrimClient;
use crate::config::{
    ScrimConfig, load_config, normalize_server_url, resolve_config_path, save_config,
};
use crate::git::{
    git_local_config_get, git_local_config_set, git_remote_add, git_remote_get_url,
    git_remote_set_url, git_toplevel, validate_remote_name,
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

    let result = run_from(std::env::args_os(), &mut env);
    for value in env.env_vars.values_mut() {
        value.zeroize();
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
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

    let config_path = match resolve_config_path(cli.config.as_deref(), &|key| env.env_var(key)) {
        Ok(path) => path,
        Err(err) => return Err(err),
    };

    match cli.command {
        Command::Login(login_args) => handle_login(
            login_args,
            cli.server.take(),
            token_override,
            &config_path,
            env,
        ),
        Command::Whoami => {
            let client = match build_authenticated_client(
                cli.server.take(),
                token_override,
                &config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_whoami(&client, env.stdout)
        }
        Command::Init(init_args) => {
            let client = match build_authenticated_client(
                cli.server.take(),
                token_override,
                &config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_init(init_args, &client, env)
        }
        Command::Group(group_args) => {
            let client = match build_authenticated_client(
                cli.server.take(),
                token_override,
                &config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_group(group_args.command, &client, env.stdout)
        }
        Command::Access(access_args) => {
            let client = match build_authenticated_client(
                cli.server.take(),
                token_override,
                &config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_access(access_args.command, &client, env.stdout)
        }
        Command::Branch(branch_args) => {
            let client = match build_authenticated_client(
                cli.server.take(),
                token_override,
                &config_path,
                &env.cwd,
            ) {
                Ok(client) => client,
                Err(err) => return Err(err),
            };
            handle_branch(branch_args.command, &client, env)
        }
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
    config_path: &Path,
    cwd: &Path,
) -> anyhow::Result<ScrimClient> {
    let loaded: Option<ScrimConfig> = match load_config(config_path) {
        Ok(cfg) => cfg,
        Err(err) => return Err(err),
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
    if let Err(err) = write_line(stdout, &format!("Member: {} ({role})", identity.name)) {
        return Err(err);
    }
    write_line(stdout, &format!("Groups: {groups}"))
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
    stdout: &mut dyn Write,
) -> anyhow::Result<()> {
    match command {
        AccessCommand::Grant(GrantArgs {
            member,
            groups,
            admin,
            machine,
            token_label,
        }) => {
            let res = match client.create_member(&member, admin, machine, &groups, &token_label) {
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
                stdout,
                &format!(
                    "Granted access to {} ({role}, {kind}, groups: {member_groups})",
                    res.member.name
                ),
            ) {
                return Err(err);
            }
            write_line(
                stdout,
                &format!("Token (shown only once): {}", res.token.expose_secret()),
            )
        }
        AccessCommand::Revoke { member } => {
            let res = match client.revoke_member(&member) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.revoked {
                write_line(stdout, &format!("Revoked access for {}", res.name))
            } else {
                write_line(stdout, &format!("Member {} was already revoked", res.name))
            }
        }
        AccessCommand::List { all } => {
            let res = match client.list_members(all) {
                Ok(resp) => resp,
                Err(err) => return Err(err),
            };
            if res.members.is_empty() {
                return write_line(stdout, "(no members)");
            }
            for member in &res.members {
                let role = if member.is_admin { "admin" } else { "member" };
                let kind = if member.is_machine { "machine" } else { "user" };
                let status = if member.revoked { "revoked" } else { "active" };
                let groups = format_list_or_none(&member.groups, "(none)");
                if let Err(err) = write_line(
                    stdout,
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
                stdout,
                &format!(
                    "Issued token '{}' for {} (shown only once): {}",
                    res.label,
                    res.member,
                    res.token.expose_secret()
                ),
            )
        }
    }
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

fn write_line(out: &mut dyn Write, line: &str) -> anyhow::Result<()> {
    match writeln!(out, "{line}") {
        Ok(()) => Ok(()),
        Err(err) => Err(anyhow!(err)).context("failed to write output"),
    }
}
