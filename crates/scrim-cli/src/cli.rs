//! Clap CLI definitions for `scrim` and `git-scrim`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

/// Scrim for Git command-line client.
#[derive(Debug, Parser)]
#[command(
    name = "scrim",
    version,
    about = "Manage Scrim for Git repositories, groups, access, and branch visibility"
)]
pub struct Cli {
    /// Path to config.toml [env: SCRIM_CONFIG].
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Scrim server base URL, overriding saved config [env: SCRIM_SERVER].
    #[arg(long, global = true, value_name = "URL")]
    pub server: Option<String>,

    /// Bearer token for authenticating to the Scrim server [env: SCRIM_TOKEN].
    #[arg(long, global = true, value_name = "TOKEN")]
    pub token: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Authenticate against a Scrim server and save credentials.
    Login(LoginArgs),
    /// Show the authenticated member and group memberships.
    Whoami,
    /// Register a repository on the Scrim server and configure local Git.
    Init(InitArgs),
    /// Manage Scrim groups and group memberships.
    Group(GroupArgs),
    /// Manage member accounts and API tokens.
    Access(AccessArgs),
    /// Manage private branch visibility rules.
    Branch(BranchArgs),
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Read the authentication token from standard input without prompting.
    #[arg(long)]
    pub token_stdin: bool,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Repository key on the Scrim server (defaults to <repo-dir>.git in a Git repo).
    #[arg(value_name = "REPO_PATH")]
    pub repo_path: Option<String>,

    /// Git remote name to configure locally.
    #[arg(long, default_value = "origin", value_name = "NAME")]
    pub remote: String,

    /// Register the repository without creating a new bare repo on the server.
    #[arg(long)]
    pub no_create: bool,

    /// Do not add or update the local Git remote.
    #[arg(long)]
    pub no_remote: bool,

    /// Overwrite an existing local Git remote URL if it differs.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct GroupArgs {
    #[command(subcommand)]
    pub command: GroupCommand,
}

#[derive(Debug, Subcommand)]
pub enum GroupCommand {
    /// Create a new group.
    Create {
        /// Group name.
        name: String,
    },
    /// Add a member to a group.
    Add {
        /// Group name.
        group: String,
        /// Member name.
        member: String,
    },
    /// Remove a member from a group.
    Remove {
        /// Group name.
        group: String,
        /// Member name.
        member: String,
    },
    /// List all groups and their members.
    List,
}

#[derive(Debug, Args)]
pub struct AccessArgs {
    #[command(subcommand)]
    pub command: AccessCommand,
}

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// Create a member and issue an initial token.
    Grant(GrantArgs),
    /// Revoke a member's access and tokens.
    Revoke {
        /// Member name.
        member: String,
    },
    /// List members.
    List {
        /// Include revoked members.
        #[arg(long)]
        all: bool,
    },
    /// Issue an additional token for an existing member.
    Token {
        /// Member name.
        member: String,
        /// Human-readable label for the issued token.
        #[arg(long, default_value = "default", value_name = "LABEL")]
        label: String,
    },
}

#[derive(Debug, Args)]
pub struct GrantArgs {
    /// Member name.
    pub member: String,

    /// Initial groups to add the member to (repeatable).
    #[arg(long = "group", value_name = "GROUP")]
    pub groups: Vec<String>,

    /// Grant administrator privileges.
    #[arg(long)]
    pub admin: bool,

    /// Mark the account as a machine/CI identity.
    #[arg(long)]
    pub machine: bool,

    /// Label for the initial authentication token.
    #[arg(long, default_value = "default", value_name = "LABEL")]
    pub token_label: String,
}

#[derive(Debug, Args)]
pub struct BranchArgs {
    #[command(subcommand)]
    pub command: BranchCommand,
}

#[derive(Debug, Subcommand)]
pub enum BranchCommand {
    /// Restrict refs matching a glob pattern to specific groups.
    Private {
        /// Ref glob pattern (for example, refs/heads/private/*).
        glob: String,
        /// Groups allowed to see matching refs (repeatable, at least one required).
        #[arg(long = "group", required = true, value_name = "GROUP")]
        groups: Vec<String>,
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
    /// List branch visibility rules for a repository.
    List {
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
    /// Remove a branch visibility rule.
    #[command(visible_alias = "unprotect")]
    Rm {
        /// Ref glob pattern to remove.
        glob: String,
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
}
