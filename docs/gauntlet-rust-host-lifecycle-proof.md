# Rust passive host lifecycle proof

Source `0c32a1e7cd4ca9dbe6d16e09c6e6115d7574be48` adds an opt-in
`gauntlet-host` executable and isolated lifecycle storage. It is prepared on
`codex/gauntlet-rust-host-lifecycle-prep-20261022`, based on pending
[PR #3](https://github.com/HGraphPunks/hol-guard/pull/3) head
`6eff2b1e6d70c1851a9b25bb102f3778b8323a46`. That tested code commit includes
upstream `f1f90ae6902a8db9ce885699e4f371871dd3f1f9`. The preparation subsequently
imports PR #3 head `2ab0f15f226cea4c99d833f8e4a9af46f53ed076`, including
upstream `d1ab7bc629f3c5bbd45459424e5b0a39be880fea`. The lifecycle implementation
and retained executable bytes are unchanged by this synchronization.

The new code is local preparation while GitHub rejects workflow dispatch with
HTTP 422, `Actions has been disabled for this repository`. The permissions API
reports enabled, and reapplying that setting did not restore execution. PR #3
remains unmerged. After its five current-head jobs pass and it merges, create
the next child from the fetched integration tip, import current upstream and
merge this preparation. Upstream `d1ab7bc6` was inspected and imported through
PR #3: its only change corrects receipt timestamps in
`tests/test_runner_sync_payload.py`, preventing a global date-dependent judge
failure. All ten tests in that file passed locally with the matching Native
binary after import. Recheck latest `main` before the next child opens. This
preparation has no cloud-check result.

## Behavior and storage

`init`, `status`, `hold`, `resume`, `agent`, `down`, and `enqueue-release` require
an explicit private absolute `--state-parent`. Initialization exclusively creates
its `rust-host-v1` child, with a random instance identity, a 0700 directory and
0600 checkpoint and permanent lock files. Existing or partial initialization
is refused. The writer never opens Python's `agent.lock`, job files, admissions
hold or provider quota. The existing operator entrypoint is unchanged.

The checkpoint schema is `hol-gauntlet-rust-host-state.v1`. Reads require bounded
canonical JSON, exact keys, supported types/states, valid timestamps, distinct
job/tag identities and private ordinary single-link files. Symlinks and replaced
parent/namespace directories are refused. The checkpoint is limited to 8 MiB.
Only v3.48.0 and v3.49.0 are supported, with one retained source tuple per tag.
Repeating that tuple returns its original job ID; a changed source pin or
conflicting ID is refused. Caller-supplied source identity is queue metadata,
not authenticated execution admission.

A transaction lock serializes updates. Each changed checkpoint increments a
generation, fsyncs a new file, atomically renames it and fsyncs the directory.
Errors after rename report an uncertain commit. Partial temporary files are
retained; they cannot replace the committed checkpoint merely by existing.
A separate kernel-held observer lease prevents two cooperative observers from
owning the namespace. Neither lock file is unlinked on shutdown.

`agent` runs in the foreground and updates its heartbeat every five seconds;
`--once` performs one bounded lifecycle. `down` saves a stop request for that
owner. It does not signal a recorded PID or terminate guest work. On startup,
every preparing/running record becomes unknown with the existing Python restart
reason. Unknown work remains unknown after resume or another observer start.
The read-only status also identifies active records orphaned by a stopped
observer before a restart has changed their durable state.

Status schema `hol-gauntlet-rust-host-status.v1` distinguishes a held lease,
heartbeat age, stale heartbeat and stopped owner. Unobserved VM and GitHub gate
state remain unavailable. Admissions default to held, and worker qualification
blocks execution even after `resume`. Execution/qualification eligibility and
production CI activation are always false. This is local metadata integrity;
it is not signed evidence, a rollback-resistant journal or a worker authority.

## Observed validation

| Check | Result |
| --- | --- |
| Entire macOS host crate, including CLI/process tests and doctest targets | 118 passed; zero failures/ignored tests across 58 targets |
| ARM64 Linux lifecycle and real-process suites | 14 passed; zero failures/ignored tests |
| ARM64 host crate, all targets/features, Clippy with warnings denied | Passed |
| Both pinned source-inventory tests | Passed; all 427 Gauntlet source files retain their existing byte pins |
| Rustfmt on changed code, workflow YAML and diff whitespace | Passed |

The process tests run the actual Rust CLI. They demonstrate exclusive ownership
across processes, a durable stop request, kernel lease release after killing
only the test-owned observer, and unknown recovery of a synthetic interrupted
record. They also hold the transaction lock in one process and verify a second
process refuses without a partial write. File tests cover links, loose modes,
missing/partial files, changed namespace/parent/lock identity, duplicate JSON,
unknown fields/versions, clock regression and generation overflow.

The interrupted running/preparing records are synthetic fixtures. The partial
temporary file models interruption before rename; no power failure during
rename/fsync was injected. Initial macOS fixtures used a symlinked temporary
root and were correctly refused. Their paths were canonicalized and made
private; production no-symlink checks were preserved.

## Retained operator demonstration

The separate private artifact directory is
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-host-lifecycle-proof-20261022`.
Its copied macOS executable is `gauntlet-host-8c4cf6f89d4e6358`, 2,207,728 bytes.
The demonstration instance is `6df0a001b11b57259d3cf302e116a02c`.

An outside `git ls-remote` query resolved v3.48.0 to
`3864097f2e4fe623e403c1a948d9882f34c78690` and v3.49.0 to
`e3f9e7eb4e0cc7b1987780a62697e8bb221ae050`. The CLI recorded both release
tuples, started its own observer, reported a held lease/fresh heartbeat,
resumed while keeping worker eligibility false, held admissions again and
exited successfully after `down`. Its final checkpoint has two queued jobs,
held admissions, no observer owner and a retained stop request. These are queue
and lifecycle observations; no release build, VM job or inference was started.

| Retained artifact | SHA-256 |
| --- | --- |
| Copied executable | `8c4cf6f89d4e6358b685b06907e8e0a6d52c5175b311e699703f54ea7fd7bc5b` |
| `operator-lifecycle.v1.json` | `4c87527ea32262429b0c4d466b9b6750a7e795fd72042debde58ead658ea300c` |
| `macos-host-tests.txt` | `66b7334cc6d8e444f889e80881532f246a58610a4ad03cb99f692bb2bab08f28` |
| Final `rust-host-v1/state.json` | `70bdf1475892b873866a723bf6accd021982054c9672d9577b130186abe4d109` |

The authoritative Python observer, VM controller, dashboard and model quota
were not modified by this demonstration. Python history import, a trusted
worker-backed observer, runtime resource/progress integration, public snapshot
publication, signed receipt reconciliation, audit/rollback handling, one-command
host deployment and idle-only observer cutover remain open. The parent host
migration exit remains unchecked; overall exits remain 24/62 (39%).

The 2026-10-26 full workspace run exposed an operator/heartbeat transaction
race: `resume` could encounter the observer's brief transaction lock and fail.
The CLI now uses a five-second wait for store opening, eligible operator
transactions and separate readback. Only `Busy` before mutation is retried;
commit uncertainty, changed identity and invalid state remain final. Store API
methods still refuse contention immediately. A real-process regression holds
a shared lock across `resume`, verifies unchanged state while blocked, then
releases it and verifies exactly one committed generation. Persistent lock
contention still refuses without a partial update. All seven lifecycle process
tests and the 404-test all-feature workspace pass, with no ignored tests; the
earlier failing full-suite log remains retained as
`rust-workspace-native-recovery-002.log`. The successful full log is
`rust-workspace-native-recovery-003.log`, SHA-256
`b635c5b2a4e7c2fa027319bc8154eb3c479e205bed1b03653932d9394c30a2e8`,
under the 2026-10-26 readiness evidence directory. This fixes local lifecycle
contention; the worker-backed observer and cutover exits above remain open.
