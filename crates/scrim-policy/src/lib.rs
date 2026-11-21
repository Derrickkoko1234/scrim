//! Branch visibility rules shared by the Scrim for Git server and CLI.
//!
//! A [`BranchRule`] restricts every ref matching a glob (such as
//! `refs/heads/private/*`) to members of the listed groups. Rules are compiled
//! into a [`BranchPolicy`], which answers whether a member may see a ref and
//! plans the `transfer.hideRefs` values Git needs so that `git upload-pack`
//! never advertises refs the member may not see.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

mod branch_policy;
mod ref_glob;

pub use branch_policy::{BranchPolicy, BranchRule, HiddenRefPlan};
pub use ref_glob::{MAX_REF_GLOB_BYTES, validate_ref_glob};

/// Errors produced while validating or compiling branch rules.
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
    /// The pattern passed validation but `globset` could not compile it, for
    /// example because of an unclosed `[` character class.
    #[error("cannot compile ref glob {pattern:?}")]
    GlobCompile {
        /// The pattern that failed to compile.
        pattern: String,
        /// The underlying `globset` error.
        #[source]
        source: globset::Error,
    },
}
