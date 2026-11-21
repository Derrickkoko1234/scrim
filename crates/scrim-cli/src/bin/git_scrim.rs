//! `git-scrim` binary entry point so `git scrim ...` invokes the Scrim CLI.

#![allow(clippy::question_mark)]

use std::process::ExitCode;

fn main() -> ExitCode {
    scrim_cli::main_entry()
}
