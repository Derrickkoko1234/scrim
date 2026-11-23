//! Clap CLI definitions for `scrim` and `git-scrim`.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Scrim for Git command-line client.
#[derive(Debug, Parser)]
#[command(
    name = "scrim",
    version,
    about = "Manage Scrim for Git repositories, groups, access, branch visibility, and secrets"
)]
pub struct Cli {
    /// Path to config.toml [env: SCRIM_CONFIG].
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Path to the age private identity file [env: SCRIM_KEY_FILE].
    #[arg(long, global = true, value_name = "PATH")]
    pub key_file: Option<PathBuf>,

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
    /// Generate a local age identity keypair and register its public key.
    Keygen(KeygenArgs),
    /// Register a repository on the Scrim server and configure local Git.
    Init(InitArgs),
    /// Clone a Scrim repository, excluding paths the server withholds from you.
    Clone(CloneArgs),
    /// Manage Scrim groups and group memberships.
    Group(GroupArgs),
    /// Manage member accounts and API tokens.
    Access(AccessArgs),
    /// Manage private branch visibility rules.
    Branch(BranchArgs),
    /// Manage encrypted repository secrets and scope permissions.
    Secrets(SecretsArgs),
    /// Run a command with decrypted scope secrets injected into its environment.
    Run(RunArgs),
    /// Manage encrypted private files and their access groups.
    Private(PrivateArgs),
    /// Read the server's audit log of access and policy changes.
    Audit(AuditArgs),
    /// Manage SSH public keys used for Git-over-SSH authentication.
    #[command(name = "ssh-key")]
    SshKey(SshKeyArgs),
    /// Push branches and tags visible to everyone to an external mirror,
    /// refusing if any private file in their history is not encrypted.
    Mirror(MirrorArgs),
    /// Move your private key between identity.age and the OS keychain.
    Keychain(KeychainArgs),
    /// Serve Git's long-running clean/smudge filter protocol (invoked by Git).
    #[command(name = "filter-process", hide = true)]
    FilterProcess,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Read the authentication token from standard input without prompting.
    #[arg(long)]
    pub token_stdin: bool,
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    /// Overwrite an existing identity file.
    #[arg(long)]
    pub force: bool,

    /// Save the identity locally without uploading the public key to the server.
    #[arg(long, conflicts_with = "keychain")]
    pub local_only: bool,

    /// Store the private key in the OS keychain (macOS and Windows) instead of
    /// identity.age.
    #[arg(long)]
    pub keychain: bool,
}

#[derive(Debug, Args)]
pub struct KeychainArgs {
    #[command(subcommand)]
    pub command: KeychainCommand,
}

#[derive(Debug, Subcommand)]
pub enum KeychainCommand {
    /// Move the private key from identity.age into the OS keychain.
    Enable,
    /// Move the private key from the OS keychain back into identity.age.
    Disable,
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
pub struct CloneArgs {
    /// Repository URL (https://git.example.com/team/app.git) or repository key
    /// (team/app.git) on the configured server.
    #[arg(value_name = "SOURCE")]
    pub source: String,

    /// Destination directory (defaults to the repository name without .git).
    #[arg(value_name = "DIRECTORY")]
    pub directory: Option<PathBuf>,

    /// Branch to check out instead of the remote's default branch.
    #[arg(short, long, value_name = "BRANCH")]
    pub branch: Option<String>,

    /// Name of the Git remote to create.
    #[arg(long, default_value = "origin", value_name = "NAME")]
    pub remote: String,

    /// Configure the clone without checking out files.
    #[arg(long)]
    pub no_checkout: bool,
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
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
        /// Skip rotating local .scrim/ secret scopes and group keys that include this member.
        #[arg(long)]
        no_rotate: bool,
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
    /// Set or replace a member's age public key.
    SetKey {
        /// Member name.
        member: String,
        /// Canonical age1... X25519 public key.
        public_key: String,
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

    /// Pre-register an existing age1... public key for the member.
    #[arg(long, value_name = "PUBLIC_KEY", conflicts_with = "generate_key")]
    pub public_key: Option<String>,

    /// Generate a fresh age identity and register its public key (default for --machine).
    #[arg(long, conflicts_with = "public_key")]
    pub generate_key: bool,
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

#[derive(Debug, Args)]
pub struct SecretsArgs {
    #[command(subcommand)]
    pub command: SecretsCommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretsCommand {
    /// Encrypt and store a secret in a repository scope.
    Set(SecretsSetArgs),
    /// Decrypt and print a single secret value.
    Get {
        /// Secret key name.
        key: String,
        /// Secret scope name.
        #[arg(long, value_name = "SCOPE")]
        scope: String,
    },
    /// List secret key names in a scope without printing values.
    List {
        /// Secret scope name.
        #[arg(long, value_name = "SCOPE")]
        scope: String,
    },
    /// Remove a secret from a scope.
    Rm {
        /// Secret key name.
        key: String,
        /// Secret scope name.
        #[arg(long, value_name = "SCOPE")]
        scope: String,
    },
    /// Export decrypted secrets in a structured format.
    Export {
        /// Secret scope name.
        #[arg(long, value_name = "SCOPE")]
        scope: String,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
    /// Rotate a scope's data key to match current authorized recipients on the server.
    Sync {
        /// Secret scope name.
        #[arg(long, value_name = "SCOPE")]
        scope: String,
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
    /// Manage server-side secret scope group permissions.
    Scope(SecretsScopeArgs),
}

#[derive(Debug, Args)]
pub struct SecretsSetArgs {
    /// Secret entry as KEY=VALUE, or bare KEY when --value-stdin is set.
    pub entry: String,

    /// Secret scope name.
    #[arg(long, value_name = "SCOPE")]
    pub scope: String,

    /// Read the secret value from standard input instead of KEY=VALUE.
    #[arg(long)]
    pub value_stdin: bool,

    /// Server repository key (defaults to local git config scrim.repo).
    #[arg(long, value_name = "REPO")]
    pub repo: Option<String>,

    /// Create a new scope locally using only the caller's own public key without contacting the server.
    #[arg(long)]
    pub offline: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ExportFormat {
    Dotenv,
}

#[derive(Debug, Args)]
pub struct SecretsScopeArgs {
    #[command(subcommand)]
    pub command: SecretsScopeCommand,
}

#[derive(Debug, Subcommand)]
pub enum SecretsScopeCommand {
    /// Configure groups allowed to access a secret scope on the server.
    Set {
        /// Secret scope name.
        scope: String,
        /// Groups allowed to read secrets in this scope (repeatable, at least one required).
        #[arg(long = "group", required = true, value_name = "GROUP")]
        groups: Vec<String>,
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
    /// List secret scopes configured for a repository on the server.
    List {
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
    /// Remove a secret scope configuration from the server.
    Rm {
        /// Secret scope name.
        scope: String,
        /// Server repository key (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO")]
        repo: Option<String>,
    },
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// Secret scope to decrypt and inject into the child process environment.
    #[arg(long, value_name = "SCOPE")]
    pub scope: String,

    /// Command and arguments to execute.
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    pub command: Vec<String>,
}

#[derive(Debug, Args)]
pub struct PrivateArgs {
    #[command(subcommand)]
    pub command: PrivateCommand,
}

#[derive(Debug, Subcommand)]
pub enum PrivateCommand {
    /// Encrypt files matching a path glob for a group, or with --withhold have
    /// the server withhold them from everyone outside the given groups.
    Add {
        /// Repo-relative .gitattributes-style glob (for example, config/billing/**).
        glob: String,
        /// Group whose members may read matching files (repeatable with --withhold).
        #[arg(long = "group", required = true, value_name = "GROUP")]
        groups: Vec<String>,
        /// Create a new group key locally for only the caller's own public key without contacting the server.
        #[arg(long, conflicts_with = "withhold")]
        offline: bool,
        /// Add a server-side rule so non-members never receive matching file contents.
        #[arg(long)]
        withhold: bool,
        /// Server repository key for --withhold (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO", requires = "withhold")]
        repo: Option<String>,
    },
    /// Stop encrypting files matching a path glob (they are stored as plaintext
    /// again), or with --withhold remove the server-side withholding rule.
    Rm {
        /// Path glob previously passed to 'scrim private add'.
        glob: String,
        /// Remove the server-side withholding rule instead of the encryption rule.
        #[arg(long)]
        withhold: bool,
        /// Server repository key for --withhold (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO", requires = "withhold")]
        repo: Option<String>,
    },
    /// Show private path rules, group keys and the state of tracked private
    /// files, or with --withhold the server-side withholding rules.
    Status {
        /// List the server-side withholding rules instead of local encryption state.
        #[arg(long)]
        withhold: bool,
        /// Server repository key for --withhold (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO", requires = "withhold")]
        repo: Option<String>,
    },
    /// Configure the Git filter and decrypt or refresh checked-out private
    /// files; with --withhold also update sparse checkout to exclude withheld paths.
    Setup {
        /// Also fetch the paths withheld from you and update sparse checkout.
        #[arg(long)]
        withhold: bool,
        /// Server repository key for --withhold (defaults to local git config scrim.repo).
        #[arg(long, value_name = "REPO", requires = "withhold")]
        repo: Option<String>,
    },
    /// Rotate a group's key to match its current members on the server and re-encrypt its files.
    Sync {
        /// Group to rotate.
        #[arg(long, value_name = "GROUP")]
        group: String,
    },
}

/// Default number of audit log entries per page.
pub const DEFAULT_AUDIT_LIMIT: u32 = 50;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Only show entries made by this member.
    #[arg(long, value_name = "MEMBER")]
    pub actor: Option<String>,

    /// Only show entries with this action (for example member.revoke, path_rule.set).
    #[arg(long, value_name = "ACTION")]
    pub action: Option<String>,

    /// Only show entries for this target type (for example member, branch_rule, path_rule).
    #[arg(long, value_name = "TYPE")]
    pub target_type: Option<String>,

    /// Maximum number of entries to return (1-500).
    #[arg(long, default_value_t = DEFAULT_AUDIT_LIMIT, value_name = "N")]
    pub limit: u32,

    /// Only show entries older than this audit log ID (for paging).
    #[arg(long, value_name = "ID")]
    pub before_id: Option<i64>,

    /// Print the raw JSON response for scripting.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct MirrorArgs {
    /// Git remote name (for example github) or URL of the external mirror.
    #[arg(value_name = "TARGET")]
    pub target: String,

    /// Server repository key (defaults to local git config scrim.repo).
    #[arg(long, value_name = "REPO")]
    pub repo: Option<String>,

    /// Run the visibility and encryption checks and report what would be
    /// pushed, without pushing.
    #[arg(long)]
    pub dry_run: bool,

    /// Mirror only branches (refs/heads/*), not tags.
    #[arg(long)]
    pub no_tags: bool,
}

#[derive(Debug, Args)]
pub struct SshKeyArgs {
    #[command(subcommand)]
    pub command: SshKeyCommand,
}

#[derive(Debug, Subcommand)]
pub enum SshKeyCommand {
    /// Register an SSH public key from a .pub file or inline key string.
    Add {
        /// Path to an OpenSSH .pub file, or an inline OpenSSH public key string.
        #[arg(value_name = "KEY")]
        key: String,

        /// Human-readable label for the SSH key.
        #[arg(long, default_value = "", value_name = "LABEL")]
        label: String,

        /// Register the key for another member (admin only).
        #[arg(long, value_name = "MEMBER")]
        member: Option<String>,
    },
    /// List active SSH public keys.
    List {
        /// List keys for another member (admin only).
        #[arg(long, value_name = "MEMBER")]
        member: Option<String>,
    },
    /// Revoke an SSH public key by ID.
    Rm {
        /// Numeric SSH key ID shown by 'scrim ssh-key list'.
        #[arg(value_name = "ID", allow_negative_numbers = true)]
        id: i64,

        /// Revoke a key belonging to another member (admin only).
        #[arg(long, value_name = "MEMBER")]
        member: Option<String>,
    },
}
