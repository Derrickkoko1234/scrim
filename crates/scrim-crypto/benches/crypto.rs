//! Criterion benchmarks for the client-side crypto paths: private-file
//! AES-SIV, secret-bundle XChaCha20-Poly1305, and `age` group-key wrapping.

// The `?` operator and the unwrap/expect family are deliberately forbidden in
// this codebase; clippy's suggestion to use `?` is allowed away accordingly.
#![allow(clippy::question_mark)]

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use scrim_crypto::{
    EncryptedSecretsFile, GroupDataKey, GroupKeysFile, MemberIdentity, ScopeDataKey, SecretBundle,
    SecretString, decrypt_file, encrypt_file,
};

const GROUP: &str = "finance";
const SCOPE: &str = "prod";
const GENERATION: u64 = 1;
const FILE_PATH: &str = "config/billing/credentials.json";
/// Entries in the benchmarked secret bundle.
const SECRET_COUNT: usize = 25;
/// Recipients the group key is wrapped for.
const RECIPIENT_COUNT: usize = 10;

/// Unwraps a setup result, panicking with `context` on failure.
fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error}"),
    }
}

fn file_crypto_aes_siv(criterion: &mut Criterion) {
    let data_key = must(GroupDataKey::generate(), "generate group key");
    let mut group = criterion.benchmark_group("file_crypto_aes_siv");
    for (label, size_bytes) in [("1KiB", 1024_usize), ("64KiB", 64 * 1024)] {
        let plaintext: Vec<u8> = (0..size_bytes).map(|index| (index % 251) as u8).collect();
        let blob = must(
            encrypt_file(GROUP, GENERATION, FILE_PATH, &data_key, &plaintext),
            "encrypt file",
        );
        group.throughput(Throughput::Bytes(size_bytes as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt_file", label),
            &plaintext,
            |bencher, plaintext| {
                bencher.iter(|| {
                    black_box(encrypt_file(
                        GROUP,
                        GENERATION,
                        FILE_PATH,
                        &data_key,
                        black_box(plaintext),
                    ))
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("decrypt_file", label),
            &blob,
            |bencher, blob| {
                bencher.iter(|| {
                    black_box(decrypt_file(
                        GROUP,
                        GENERATION,
                        FILE_PATH,
                        &data_key,
                        black_box(blob),
                    ))
                });
            },
        );
    }
    group.finish();
}

fn secrets_xchacha20(criterion: &mut Criterion) {
    let data_key = must(ScopeDataKey::generate(), "generate scope key");
    let mut secrets = SecretBundle::new();
    for index in 0..SECRET_COUNT {
        let value: SecretString = format!("value-{index}-{}", "x".repeat(48)).into();
        must(
            secrets.set(&format!("SERVICE_{index}_API_KEY"), value),
            "set secret",
        );
    }
    let encrypted = must(
        EncryptedSecretsFile::encrypt(SCOPE, GENERATION, &data_key, &secrets),
        "encrypt secrets",
    );
    let mut group = criterion.benchmark_group("secrets_xchacha20");
    group.bench_function("encrypt_secrets_25_entries", |bencher| {
        bencher.iter(|| {
            black_box(EncryptedSecretsFile::encrypt(
                SCOPE,
                GENERATION,
                &data_key,
                black_box(&secrets),
            ))
        });
    });
    group.bench_function("decrypt_secrets_25_entries", |bencher| {
        bencher.iter(|| black_box(black_box(&encrypted).decrypt(SCOPE, GENERATION, &data_key)));
    });
    group.finish();
}

fn group_key_wrap_unwrap(criterion: &mut Criterion) {
    let data_key = must(GroupDataKey::generate(), "generate group key");
    let identities: Vec<MemberIdentity> = (0..RECIPIENT_COUNT)
        .map(|_| MemberIdentity::generate())
        .collect();
    let recipients: BTreeMap<String, _> = identities
        .iter()
        .enumerate()
        .map(|(index, identity)| (format!("member{index:02}"), identity.public_key()))
        .collect();
    let keys_file = must(
        GroupKeysFile::wrap_for_recipients(GROUP, GENERATION, &data_key, &recipients),
        "wrap group key",
    );
    // The last recipient in sorted order, so unwrap scans every entry first.
    let Some(unwrapping_identity) = identities.last() else {
        panic!("no identities generated");
    };
    let mut group = criterion.benchmark_group("group_key_wrap_unwrap");
    group.bench_function("wrap_group_key_10_recipients", |bencher| {
        bencher.iter(|| {
            black_box(GroupKeysFile::wrap_for_recipients(
                GROUP,
                GENERATION,
                &data_key,
                black_box(&recipients),
            ))
        });
    });
    group.bench_function("unwrap_key", |bencher| {
        bencher.iter(|| black_box(black_box(&keys_file).unwrap_key(GROUP, unwrapping_identity)));
    });
    group.finish();
}

criterion_group!(
    benches,
    file_crypto_aes_siv,
    secrets_xchacha20,
    group_key_wrap_unwrap
);
criterion_main!(benches);
