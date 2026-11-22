//! Fuzzes `scrim-server`'s parsers of client- and git-supplied bytes: the
//! `upload-pack` request filter, SSH `exec` commands, `pack-objects` hook
//! arguments and stdin, `pre-receive` ref updates, `diff-tree` output and the
//! secret scanner.

#![no_main]
// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    scrim_server::fuzz_support::fuzz_parsers(data);
});
