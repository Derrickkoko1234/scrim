//! Fuzzes the `scrim filter-process` side of Git's long-running filter
//! protocol: pkt-line framing, the version 2 handshake, request headers and
//! clean/smudge dispatch, all in memory with a bounded output buffer.

#![no_main]
// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    scrim_cli::fuzz_support::fuzz_filter_protocol(data);
});
