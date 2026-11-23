# Current Native runtime through the Rust worker

Rust source `c3a75ccd632164d6ab83f260905680add1f8b368` passes fresh
success, timeout and cancellation in the owned 2-vCPU/16-GiB/48-GiB ARM64 VM
`hol-gauntlet-rust-build-20261026-001`, kernel `6.8.0-134-generic`.
The exact product source is `62aa7ba777a5a4cc0806c34ee94e9822eaa58d32`,
version 3.57.0, including upstream Native `9dd2fefb`. It uses the
[previously published runtime](gauntlet-rust-native-runtime-publication-vm-proof-20261026.md).

| Case | Fresh job | Root report SHA-256 |
| --- | --- | --- |
| Success | `e2c701baf1471901` | `3811b3850014643bf93f252f41ba3d10e3f943d2ad4107ba8c07f6e4ec6f2634` |
| Timeout | `e2c701baf1471902` | `aa4914c1898ad3e1736039a7a60f4f63f22e7dc50d620227f3a7359f3f61f4bb` |
| Cancellation | `e2c701baf1471903` | `8582852bbcbd746e3b5e46fe38f59bbd7a541e6586c163cab44e9eac38c856f0` |

Every controller exits 0 and reports actual Native daemon readiness, the
expected idmapped physical effect, Rust image/supervisor ownership and complete
cleanup. Success additionally preserves binary stdin/stdout and stderr.
Timeout/cancellation interrupt a real sleeping product process. These are
apparatus checks; the effect is released by Root, without a Guard verdict.

The Root worker is mode 0500, 14,900,264 bytes, SHA-256
`b5cc9abd683d1cd475eb1c84a8b8157e090da2c0b9f6b1299d7203fd0f65ec95`.
The actor is the separate GNU release build, 986,696 bytes, SHA-256
`d772b65b17dc0b1605ec9f53a53a9aa36554a2b9ec8313b1348dd86d3c935fb8`.
Its loader is exactly `/lib/ld-linux-aarch64.so.1`. The fixed initializer,
libseccomp library and filter remain pinned. The factory's 23-file source map
is unchanged at `05b2510a6d822ddb105c55acb030e24e38e20c9e2a35ed7a980a6545c80a7f77`;
the fresh 25-payload-file native manifest is
`64fa2a14251571ecf28e89fd71b9fad19bb98d384a4966f60a71c44a08ba4fee`.

Both the standalone inert reader and factory refuse the retained static actor.
The factory refuses before creating an artifact target and leaves its empty
shadow directory unchanged. Wrong actor hash/source map, artifact replay,
wrong worker generation/source and both busy worker leases also refuse. All
26 old failed-artifact files and 26 new artifact files remain unchanged after
their relevant refusals. All three consumed job IDs refuse replay; fixed
read-only reconciliation returns the same source-bound reports.

Each actor has UID/GID 10004, no supplementary groups, zero capabilities,
no-new-privileges, two seccomp filters, enforced AppArmor, six private namespaces
and loopback-only networking without an IPv4 route. A separate passive live
collector for timeout/cancellation holds a pidfd, independently hashes the GNU
actor and matches PID/start/cgroup to the Rust controller observation. It checks
the actual 1-GiB memory, 128-task and one-CPU quota limits. Final independent
inspection finds no job cgroup/mount, container, mounted image or exact active
image pointer. Each held final effect contains the same 25 bytes with physical
UID/GID 10001. This management transport is not independent VM attestation.

The complete prefix remains unchanged: 4,411 entries excluding the root,
117,018,419 file bytes, digest
`cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637`.
All 4,412 inventory rows, including the root, match the prior independently
reconstructed publication exactly. Twenty-four original worker files across
the three new jobs and the retained failed job remain unchanged on replay.

The full Mac workspace passes 427 tests across 216 targets, with no failures
or ignores. Mac/ARM64 warnings-denied Clippy passes. The actual Root worker
library passes 135 tests with 24 preexisting fixture-specific ignores. The
Root evidence library passes all 59 tests, and rootfs passes 23 plus one
subprocess check. The first evidence run retains two missing-build-path fixture
failures. Test-only source `7f62bc36` embeds the unchanged frozen fixtures;
the separate corrected binary passes without changing production code.

The [first static-actor failure](gauntlet-rust-native-current-worker-failure-20261026.md)
remains untouched. Two post-run proof-caller mistakes also remain recorded:
the closed request parser refuses a run-only field in `reconcile`, and the
first inventory check counts the root as an entry. Corrected callers use
separate records. Neither mistake changes worker execution or runtime bytes.

The 117-member export is 1,075,200 bytes, SHA-256
`a31d0ec9eccc8d80c5e4c696103b8fc6d7afa22b4c3ed500e27b87e77a6f9610`.
The ten-member input is 65,546,240 bytes, SHA-256
`03f5e9705e896bf2d4be22923018fe0facab558b429005aae5716e00dddc9d6e`.
The [standalone host reader](../ci/gauntlet-rs/proofs/verify_native_current_worker_20261026.py)
checks every member, ELF loader, terminal/start/running/deployment bindings,
hash-chained supervisor/image journals, captured bytes, outside kernel records,
prior failure preservation and complete unchanged prefix. Its retained run and
Ruff checks pass. It never executes a binary or imports candidate code.

VM records are under
`/var/lib/hol-gauntlet-rust/native-current-cell-proof-20261026-019`.
Local evidence retains `native-current-worker-vm-results-019.tar`,
`native-current-control-input-019.tar`, and
`native-current-worker-host-verify-019.json` in
`gauntlet-rust-pr-ready-evidence-20261026`. Private keys and product state are
excluded from the export.

All terminals remain `invalid-evidence`; artifact admission, execution
eligibility and Guard causality remain false, with zero model requests. Six
independently scored staging/installed roles, fresh conformance, qualified
deployment and broader recovery remain open. The parent ledger stays 24/62.
