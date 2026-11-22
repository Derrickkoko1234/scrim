//! Branch and path visibility rules shared by the Scrim for Git server and CLI.
//!
//! A [`BranchRule`] restricts every ref matching a glob (such as
//! `refs/heads/private/*`) to members of the listed groups. Rules are compiled
//! into a [`BranchPolicy`], which answers whether a member may see a ref and
//! plans the `transfer.hideRefs` values Git needs so that `git upload-pack`
//! never advertises refs the member may not see.
//!
//! A [`PathRule`] maps a `.gitattributes`-compatible path glob (such as
//! `config/billing/**` or `*.secret`) to the group whose key encrypts matching
//! files. Rules are compiled into a [`PathPolicy`], which resolves the
//! protecting group for any repository-relative path and fails closed if
//! overlapping rules map a path to multiple distinct groups.
//!
//! A [`WithholdRule`] maps a `.gitattributes`-compatible path glob to one or
//! more groups whose members may receive matching blobs from `scrim-server`.
//! Rules are compiled into a [`WithholdPolicy`], which evaluates per-member
//! withholding by intersection across overlapping rules and generates Git
//! non-cone sparse-checkout exclusions for partial clones.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod branch_policy;
mod path_glob;
mod path_policy;
mod ref_glob;
mod withhold_policy;

pub use branch_policy::{BranchPolicy, BranchRule, HiddenRefPlan};
pub use path_glob::{
    MAX_GROUP_NAME_BYTES, MAX_PATH_GLOB_BYTES, MAX_PATH_RULES, is_protected_metadata_path,
    normalize_repo_path, validate_group_name, validate_path_glob,
};
pub use path_policy::{PathPolicy, PathRule};
pub use ref_glob::{MAX_REF_GLOB_BYTES, validate_ref_glob};
pub use withhold_policy::{WithholdPolicy, WithholdRule};

/// Errors produced while validating or compiling branch and path rules.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// The pattern is not an acceptable ref glob; `reason` names the broken
    /// constraint (see [`validate_ref_glob`]).
    #[error("invalid ref glob {pattern:?}: {reason}")]
    InvalidRefGlob {
        /// The rejected pattern.
        pattern: String,
        /// Human-readable description of the rule the pattern breaks.
        reason: &'static str,
    },
    /// The pattern is not an acceptable path glob; `reason` names the broken
    /// constraint (see [`validate_path_glob`]).
    #[error("invalid path glob {pattern:?}: {reason}")]
    InvalidPathGlob {
        /// The rejected pattern.
        pattern: String,
        /// Human-readable description of the rule the pattern breaks.
        reason: &'static str,
    },
    /// The group name is not valid; `reason` names the broken constraint (see
    /// [`validate_group_name`]).
    #[error("invalid group name {group:?}: {reason}")]
    InvalidGroupName {
        /// The rejected group name.
        group: String,
        /// Human-readable description of the rule the group name breaks.
        reason: &'static str,
    },
    /// More than `max` path rules were supplied to [`PathPolicy::compile`].
    #[error("too many path rules (maximum is {max})")]
    TooManyPathRules {
        /// Maximum number of allowed path rules.
        max: usize,
    },
    /// Two path rules in the same policy shared the exact same `pattern`.
    #[error("duplicate path rule for pattern {pattern:?}")]
    DuplicatePathRule {
        /// The duplicated path glob pattern.
        pattern: String,
    },
    /// Multiple path rules belonging to different groups matched `path`.
    #[error(
        "ambiguous path rule for {path:?}: matches multiple groups ({})",
        groups.join(", ")
    )]
    AmbiguousPathRule {
        /// The repository-relative path matched by conflicting rules.
        path: String,
        /// Sorted list of distinct group names whose rules matched `path`.
        groups: Vec<String>,
    },
    /// The pattern passed validation but `globset` could not compile it, for
    /// example because of an unclosed `[` character class.
    #[error("cannot compile glob {pattern:?}")]
    GlobCompile {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying `globset` error.
        #[source]
        source: globset::Error,
    },
}
