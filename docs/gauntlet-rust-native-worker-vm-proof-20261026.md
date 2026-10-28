# Rust native worker VM proof, 2026-10-26

The Rust worker now owns a complete zero-model apparatus job: both worker
leases, one-use reservation, contained Rust controller and private gate,
product preparation/supervisor, image lease, cleanup and terminal custody.
Six fresh final cases pass. A separate Rust recovery proof preserves an
earlier failed job and releases only its verified quiescent image lease.
Completed apparatus jobs remain `invalid-evidence`; recovery records `aborted`
with unknown exit status. Neither result qualifies Guard or authorizes cutover.

The implementation is described in [native worker](gauntlet-rust-native-worker.md).
The worker entered at `0bab80caf54c298c5991b93f13588addab0c340c`;
permission/cleanup/recovery fixes are at
`63ec628fea57045824402f511e695ff8fa3e1a22`. Final proof source is
`2a4c3fa0842eaf878618f84a629ff95d9f75cbf6`, including the host lifecycle race
fix at `ded25af4`. Upstream remains merged through `b5a27d0a`.

## Final cases and independent readback

All cases ran on owned ARM64 Ubuntu VM `hol-beta-bootstrap-20261016-004`,
2 vCPU/16 GiB/48 GiB. Root installed a new immutable eight-file input at
`/opt/hol-gauntlet/native-worker-input-20261026-004`. Evidence is separate at
`/var/lib/hol-gauntlet-rust/native-worker-proof-20261026-004`.

| Case | Job | Verified behavior |
| --- | --- | --- |
| Success | `e2c701baf1470063` | Rust-owned gated physical effect and binary I/O, retained Native daemon, complete cleanup and terminal reopen |
| Timeout | `e2c701baf1470064` | Timed-out product and descendants removed, same worker terminal/reopen checks |
| Cancellation | `e2c701baf1470065` | Product cancellation propagates through Rust cleanup and terminal custody |
| Replay | `e2c701baf1470066` | Completed job cannot reserve/execute again; report bytes remain unchanged |
| Wrong generation | `e2c701baf1470061` | Wrong outside worker hash refuses before reservation |
| Lease busy | `e2c701baf1470062` | Another holder of the worker lock refuses admission before reservation |

Outside readback verifies absent controller cgroup, product slice, AppArmor
profile, dependency-image mount and durable image pointer. It independently
hashes each report against the terminal response and reopens it through a
fresh `reconcile` process. Public bootstrap directories are actually 0755 and
executables 0555 under the worker's 0077 umask. The original failed stage's
0500 actor remains unchanged in the exported metadata.

The candidate is still historical source
`76c31929833b5571d25a56d9783e24a0997d5422`, package 3.49. The retained controller
`dfc948e98c6a1ab94e074dd164c25cbd60831ee1` is read/verified as a fixture;
the worker dispatches its own measured Rust inode. Its controller inventory
remains `33ef5c12f907c80e8d05aa5af10c76510fae5097b23fc2f0a4dcab85c6a21537`;
the installed prefix remains
`67b80a2ba2a54872d53ba0704ad801b99eb1153ce9c8b2d6ab2ff4e2093d2e28`.
The outside Python adapters supply fixtures and inspect results; they do not
launch/stop cells or mount/unmount images for the successful worker cases.

## Preserved failures and recovery

Attempt 001's job `e2c701baf1470043` reached the measured initializer, then
could not execute its actor because the private worker umask reduced public
file/directory modes. Its already-collected systemd service also returned
"unit not loaded" during stop. The worker correctly retained unknown state,
its started/running markers, diagnostic streams and durable active image
lease. No ordinary terminal or success was fabricated.

Attempt 002's recovery adapter refused the legitimate empty stdout stream
before invoking Rust recovery. Its immutable inputs and test logs remain.
The bounded reader was corrected in `02862d55` to admit empty streams while
retaining descriptor, owner/mode/link, length and changed-file checks.

Attempt 003's recovery passed. Wrong started-marker and current-worker pins
refused without changing the image pointer. Rust verified the original job
tuple, held both worker locks, required the historical controller PID/cgroup
and product resources to be absent, rechecked the original journal chain and
mounted image inode/device, and released only that lease. A fresh process
reopened the same immutable repair receipt. All eight original record hashes
match before/after, and no ordinary terminal/report was added. The separate
repair receipt SHA-256 is
`1a119f3268e1969d4f248a52f58f4884f4755739bf5df1bbdec613817c2e4934`.
It records zero model requests, `execution_eligible: false`, `aborted` and
`exit_code: null`. The job remains consumed. Old v1 query readers cannot express
this repair version and continue to show unknown.

Attempt 003's next job `e2c701baf1470053` completed its apparatus and cleanup,
but its proof's reconciliation request contained a forbidden deployment field.
That failed proof result remains retained. `2a4c3fa0` fixes only the adapter's
query frame; outside CLI deployment binding stays required. All six new
attempt-004 cases, including terminal reopen, pass on the same Rust binary.

## Pins, tests and retained artifacts

| Artifact | SHA-256 |
| --- | --- |
| Rust worker, 6,648,920 bytes | `d156b0a8a7ff5861aca35c572673bd7db12ebd2e00e3655b3abff62e0ecb8728` |
| Constructor, 3,634,864 bytes | `fd3f9b83bedcb2c162bbfc53d7e0415d44607214ec220e36c97a55bdba50c2d5` |
| Native rootfs test binary | `0dd2af679c7a0bd6145fec4b162aaecc7dbd5fe73cd0f3afa7b706608633fec1` |
| Native worker test binary | `450567e0758100a79b1485edcc77ef0b6b587258dbbf74ecb2b102c2efae8945` |
| Final eight-file input archive | `a2195590ac98b8f48084ee5bdb3c2c8a1d382ef0f0d470d797a61cf5448efac7` |
| Worker proof adapter | `8f62abe23b8b959ecb76da4a53ab946792191afc999748f38ae04bc62b4bb2ab` |
| Recovery proof adapter | `8cf9454024c756c77d6ecb668a5c0767757dac8905ea8abc5b9dd239a48e231b` |
| Exported 542,720-byte evidence archive | `dd1c0419cd0ca93a5f3643b687367a3c62eabb3c5f126b7ba2d659b6ea388aae` |

The host retained the archive as `native-worker-vm-results-001.tar` under
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-pr-ready-evidence-20261026`.
All 187 members have unique bounded regular paths; an independent host reader
verified the outer digest and every member's manifest hash/size without
extracting it. This includes failed attempts, raw streams, declarations,
supervisor/image/recovery journals and worker receipts, without private keys.

The actual Root VM rootfs suite passes 23 tests, including an isolated child
test under umask 0077. The worker library passes 119 tests; 24 preexisting tests
that require separate privileged fixtures remain explicitly ignored. They are
not counted as passed. The macOS all-feature workspace passes 404 tests with
no failures or ignored tests. Warnings-denied Mac and ARM64 Clippy pass for the
changed cell/worker/host crates. The earlier sandbox-limited socket test and
host lock race logs are retained, not replaced by passing results.
The final source-matched Mac log `rust-workspace-native-worker-final-001.log`
has SHA-256 `a6f3009860544f29fba138315d7e0bf9543fc586ad668342ecfbf857fd5f3aef`
and contains 208 successful test result targets.

## Remaining exits

This is the apparatus profile, not the complete migrated benchmark worker.
Independent Native request/decision/effect scoring, an outside host-key
handoff, six fresh staging plus six installed controls, current-source
conformance, general interrupted-worker recovery, authenticated observer
admission, model/campaign and legacy paths, cutover/rollback and required
current-head CI remain open. The v3.49 missing-capability result stays visible.
No inference was requested, no quota reset, production gate activated or
upstream merge performed. Parent migration exits remain 24/62 (39%).
