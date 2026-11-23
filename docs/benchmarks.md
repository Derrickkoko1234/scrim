# Benchmarks

Numbers for the M5 performance item: criterion micro-benchmarks, and clone and
fetch timings through a real `scrim-server` on a large public repository
(`git/git`), compared with plain `git`. Everything here was measured on one
machine on 2026-11-23, so read the ratios before the absolute times.

## Machine and versions

| | |
|---|---|
| CPU | Apple M3 (8 cores) |
| Memory | 8 GiB |
| OS | macOS 27.2.1 |
| git | 2.54.0 (Apple Git-157) |
| rustc | 1.100.0 (0ef1bc386 2026-11-09) |
| Build | `--release` (cargo `bench` profile for criterion) |

**Load conditions.** The machine had just rebooted, and macOS background
daemons (Spotlight, `trustd`, the neural-engine compiler) kept the 1-minute
load average at about 3 to 7 on 8 cores throughout. Other development agents
were also compiling on it earlier in the session; this task started no
compiler during the timed runs below, and the load figures are the check. Load averages are printed by the harness: 3.1 before and 4.4
after the end-to-end run; 7.1 at the start of the large-repository criterion
run, falling to 3.2 at its end. The first large-repository smoke run, taken at
a load of 37 to 57, took twice as long and was discarded.

## Test repository

`git/git`, cloned bare on 2026-11-23 from `https://github.com/git/git.git`
(HEAD `f7de81456940dd6f3274e461149bba12965de609` when measured):

| | |
|---|---|
| Commits (all refs) | 86,395 |
| Objects | 425,012 (one pack, 323 MiB) |
| Branches / tags | 8 / 1,019 |
| Files at `HEAD` | 4,876 (2,562 under `t/`, 90 under `contrib/`) |

The end-to-end harness pushed five commits per scenario, so later scenarios
saw up to 86,420 commits.

**Rules used (restricted member `bob`, in no group).** Paths `t/**` and
`contrib/**` are withheld from everyone outside the `internal` group. Refs
`next`, `seen`, `jch`, `test`, `bisect`, `todo`, the `v1.*` and `gitgui-*`
tags and `junio-gpg-pub` are visible only to `core`. Bob therefore sees 546
of 1,029 refs (544 visible wants in the criterion setup) and is missing
35,684 objects (the blobs under `t/` and `contrib/`) in his partial clone.
`alice` is in both groups and sees everything.

## Reproduce

```sh
git clone --bare https://github.com/git/git.git "$TMPDIR/scrim-bench/git.git"

# Synthetic baselines plus the large-repository group (about 8 minutes):
SCRIM_BENCH_REPO="$TMPDIR/scrim-bench/git.git" \
    cargo bench -p scrim-server --bench pack_withhold

# Every synthetic benchmark in the workspace (large repo left out):
cargo bench --workspace

# End-to-end timings, three runs per scenario (about 10 minutes):
cargo build --release -p scrim-server --bin scrim-server
SCRIM_E2E_RUNS=3 SCRIM_E2E_REPO="$TMPDIR/scrim-bench/git.git" \
    cargo run --release -p scrim-server --example e2e_timings
```

`SCRIM_BENCH_REPO` and `SCRIM_E2E_REPO` are opt-in; without them the criterion
bench runs only the synthetic cases and the example prints a hint and exits.
The path rules can be changed with `SCRIM_BENCH_WITHHOLD` /
`SCRIM_E2E_WITHHOLD` and the ref rules with `SCRIM_BENCH_HIDE_REFS` /
`SCRIM_E2E_HIDE_REFS`, all comma-separated globs (the defaults suit git/git).
`SCRIM_BENCH_INCREMENTAL_COMMITS` sets how far behind the criterion
incremental fetch is (default 25).

The harness is an example rather than an `#[ignore]`d test: examples are not
run by `cargo test`, build in release on demand, and do not depend on the
shared `tests/common` helpers.

### What the end-to-end harness does

It copies the repository into a temporary repo root and serves it in-process
over smart HTTP and SSH with a `MemoryPolicyStore`. For each scenario it
makes `SCRIM_E2E_RUNS` fresh `git clone --no-checkout` copies (checkout costs
the same with or without Scrim and `scrim clone` does it afterwards), then
pushes five commits (each edits one public and one withheld file) straight
into the repository and times a `git fetch` in each copy. A fetch must bring
the branch tip to the pushed commit or the run fails. The restricted member
clones with `--filter=blob:limit=2147483647`, as `scrim clone` does. The
baseline is plain `git clone file://<bare>` of the same repository. Commands
run with an isolated `HOME`, `GIT_TERMINAL_PROMPT=0`, no stdin, a
15-minute timeout and `GIT_NO_LAZY_FETCH=1` in partial clones; `ssh` runs
with `-F /dev/null`, `IdentitiesOnly`, `IdentityAgent=none`, `BatchMode`, no
host-key checking and no known-hosts file.

## Results: end to end

Median of three runs, with the range in brackets. Wall-clock time of the
`git` command on loopback.

| Scenario | Clone | Fetch (5 new commits) | Clone pack | Objects in pack |
|---|---|---|---|---|
| Baseline: plain `git clone file://` | 27.3 s (25.0-28.9) | 0.33 s (0.27-0.44) | 322.9 MiB | 425,012 |
| HTTP, `alice`, full clone | 23.5 s (21.6-24.5) | 0.37 s (0.32-0.38) | 322.4 MiB | 425,037 |
| HTTP, `bob`, partial clone + rules | 56.5 s (53.6-59.8) | 0.96 s (0.94-1.02) | 288.6 MiB | 377,344 |
| SSH, `alice`, full clone | 24.9 s (21.6-26.6) | 0.29 s (0.24-0.30) | 322.6 MiB | 425,087 |
| SSH, `bob`, partial clone + rules | 51.7 s (49.2-52.7) | 1.02 s (1.01-1.44) | 288.7 MiB | 377,384 |

Relative to the baseline:

| Scenario | Clone | Fetch |
|---|---|---|
| HTTP, `alice`, full | 0.86x | 1.14x |
| HTTP, `bob`, restricted | 2.07x | 2.92x |
| SSH, `alice`, full | 0.91x | 0.88x |
| SSH, `bob`, restricted | 1.89x | 3.12x |

An unrestricted member costs the same as plain git: the server only spawns
`git upload-pack` and the pack-objects hook is not involved. The clone
timings of the baseline and the unrestricted scenarios overlap, so the 0.86x
to 1.14x spread is noise. A restricted member's clone takes about twice as
long and their fetch about three times as long, in return for a pack that is
10.6% smaller and has 35,684 blobs withheld. Transport made no visible
difference: HTTP and SSH agree within the spread.

## Results: criterion

Selection walk (`compute_allowed_pack_objects`), which is what the
`pack-objects` hook runs for every restricted fetch, compared with plain
`git pack-objects --revs --thin --stdout` for the same request. Large
repository figures are the criterion estimates over ten samples
(`SCRIM_BENCH_REPO`), restricted member in no group, 25 commits behind for
the incremental case.

| Case | Scrim walk | Plain `git pack-objects` | Ratio |
|---|---|---|---|
| Initial clone, 544 wants, 377,304 objects selected | 35.3 s (33.8-38.0) | 5.85 s (5.82-5.90) | 6.0x |
| Incremental fetch, 1 want, 357 objects selected | 703 ms (702-704) | 82 ms (81-83) | 8.5x |

The walk is only part of the hook (the explicit object list is then fed to
`git pack-objects`), so the end-to-end overhead is smaller than the walk:
about +29 s for the clone and +0.65 s for the fetch.

### Synthetic baselines

From `cargo bench --workspace` on the same machine (all fresh unless marked).
Earlier numbers recorded before this task are shown for comparison.

| Benchmark | Fresh | Earlier |
|---|---|---|
| `branch_policy` `is_ref_visible`, 200 refs | 138.5 µs | 134.6 µs |
| `branch_policy` `resolve_hide_refs`, 200 refs | 183.8 µs | n/a |
| `is_path_withheld`, 200 paths | 62.6 µs | 63.2 µs |
| `group_for_path`, 200 paths | 73.6 µs | n/a |
| `sparse_checkout_patterns` | 2.35 µs | n/a |
| AES-256-SIV encrypt, 1 KiB / 64 KiB | 2.24 µs / 93.5 µs | 98.3 µs (64 KiB) |
| AES-256-SIV decrypt, 1 KiB / 64 KiB | 2.80 µs / 122.4 µs | 121.3 µs (64 KiB) |
| XChaCha20 secrets, 25 entries, encrypt / decrypt | 14.1 µs / 18.4 µs | 13.8 / 18.2 µs |
| Group key wrap (10 recipients) / unwrap | 839 µs / 119 µs | n/a |
| gix pack walk, initial (5 commits, 50 files) | 4.66 ms | 4.70 ms |
| gix pack walk, incremental | 1.58 ms | 1.61 ms |

The Redis policy cache has no benchmark here: it needs a Redis server and is
not exercised by these harnesses.

## Findings

These are measurements, not fixes; nothing in the server was changed.

1. **The initial-clone walk costs 6x plain `git pack-objects`** (35.3 s vs
   5.85 s on 425,000 objects). It is single-threaded Rust over the object
   graph, with a path check per tree entry, and it dominates the restricted
   clone: the restricted clone is 29 s slower than the baseline. At
   git/git's size this is tolerable for a one-off clone, but it grows with
   history and tree size and runs on every restricted clone.
2. **The incremental fetch walk is not proportional to the change.** A fetch
   selecting 357 objects takes 703 ms, 8.5x plain pack-objects, and the fetch
   as a whole takes three times the baseline. The cause is visible in
   `select_objects` (`crates/scrim-server/src/pack_withhold.rs`): it first
   collects the full ancestry of every `have` commit
   (`collect_commits(.., &have_commits, ..)`), here 86,000 commits, before
   it can subtract it from the wants. Cost is therefore per request and
   proportional to history length, not to the size of the new push. This was
   read from the code and matches the numbers; it was not profiled.
3. **A tag that names a blob makes every restricted clone fail.** git/git has
   `refs/tags/junio-gpg-pub` pointing at a blob. A restricted member's
   clone aborts with `scrim: fetch refused: the server could not
   prepare the pack (only commits and tags of commits may be fetched)`,
   because the hook refuses wants that are not commits and the advertised
   ref list includes that tag. The benchmarks hide it with a ref rule. A real
   deployment of a repository with such a tag would need the same, or
   the server would need to stop advertising or wanting non-commit tags to
   restricted members.
4. **Unrestricted members pay nothing.** Full clones and fetches over HTTP
   and SSH match plain git within noise, so the cost above only applies to
   repositories where a member is restricted by a path rule.
5. **Policy decisions are cheap.** Ref visibility and path checks for 200
   items take 60 to 140 µs and the pack walk on a small repository takes
   under 5 ms, so per-request policy evaluation is not the bottleneck;
   walking large histories is.

## Caveats

- Three runs per scenario; ranges are shown. The machine was not idle (see
  load conditions above), which inflates and widens the times, especially
  the baseline whose spread is the largest in the unrestricted rows.
- One repository and one set of rules. A repository with fewer, larger files,
  or no deep history, will behave differently.
- Loopback only: no network latency or bandwidth limits, which would shrink
  Scrim's relative overhead.
- Clones skip checkout. A restricted member's checkout is sparse and so
  does less work than the baseline's.
