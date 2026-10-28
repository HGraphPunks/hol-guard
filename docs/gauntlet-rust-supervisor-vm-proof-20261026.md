# Rust supervisor: owned VM apparatus proof

On 2026-10-26, source `a61815a04e9a7178b8bef2a8f4f02e9b9d718f93`
passed fresh success, timeout and cancellation cases on the owned Linux ARM64
VM `hol-beta-bootstrap-20261016-004` (2 vCPU, 16 GiB RAM, 48 GiB disk).
Rust owned the service, outside kernel collector, initializer and exec gates,
authenticated actor RPCs, capture, private journal and cell cleanup.

All three cases started the retained Native Guard daemon. The success case
observed absence of the physical effect before Root release, then the exact
effect with physical UID/GID 10001 through the product's 10004 idmap. Binary
stdin/stdout, including NUL and non-UTF-8 bytes, and separate stderr matched.
Timeout and asynchronous cancellation interrupted a real released process and
closed the whole cell. Rust verified cgroup, rootfs mount and AppArmor absence
and unchanged runtime prefix. The independent outer adapter needed no cleanup
intervention and released its image lease. Each controller whole-tree check
before and after matched its outside pin.

| Case | Actor PID / start ticks | Supervisor declaration SHA-256 | Events / cleanup |
| --- | --- | --- | --- |
| success | 2760 / 631015 | `98bb6aa77bd390e9c683929cd9c6e497c12ae6a35b7fad2be0433199653407e3` | 36 / complete |
| timeout | 2991 / 634028 | `16068e337226ffcbaaceb3095cebcc57b854e051d370865a38f2de3d2ab11872` | 30 / complete |
| cancel | 3213 / 637253 | `37dd60dfde7540631b2c090b5340882d05c553a1b7db4fdab97e26d52150c45d` | 30 / complete |

The fresh service suffixes were respectively
`9e439f5404c1216e9f07c5aaf85383a0`,
`4d16d261e380e719063276f9a2b13015`, and
`e54265087777617688cbe3bb2bcaf435`. Outside observations required all saved
IDs, empty groups, five zero capability sets, no new privileges, two syscall
filters, enforcing AppArmor, six private namespaces and the original user
namespace, exact executable/argv, actual task idmaps and mount floors,
loopback-only routes and one-CPU/1-GiB/128-task limits. Initializer and actor
shared the same PID/start identity. Every product execution gate was measured
and rechecked before release. The idle actor's extra descriptors were limited
to the counterparts of registered, independently measured child pipes.

## Reproducible input and retained output

The immutable VM input directory is
`/opt/hol-gauntlet/native-supervisor-input-20261026-003`. Its six-file transfer
archive has SHA-256
`2b3290c22a2927de03f468b63806563cc14ea2e5430656c7496d304959db102d`.

| Executable | SHA-256 |
| --- | --- |
| Constructor | `da6c3ed6ff0478024d38d23b508351aced7ae35900c97e8865c3da944dd6e6b5` |
| Rust supervisor proof driver | `6d1097124a8f430eab4a97a3fc11eae639d4ee7ebdcd707ab720ecb0c3518e01` |
| Native unit tests | `74f6342316e46d59e0a9a670033cb1f6403e161d30af634f25db055eadec1185` |

All 16 native ARM64 tests passed in that VM. Twelve macOS rootfs tests, the
complete default-feature macOS workspace (390 tests, zero failures/ignores,
207 result targets), and warnings-denied ARM64 rootfs/macOS workspace Clippy
passed. The evidence library also passed all 41 tests with `--all-features`,
including its five optional quota-writer tests; whole-workspace all-feature
Clippy passed with warnings denied. The complete workspace log is retained in
`gauntlet-rust-pr-ready-evidence-20261026/rust-workspace-native-supervisor.log`
under the outer workspace, SHA-256
`11441f5f8f8d7c44cdeca1e163c6dfac75f258cffdceff12f55cd657d66b69e1`.

VM evidence remains at
`/var/lib/hol-gauntlet-rust/native-supervisor-proof-20261026-003/{success,timeout,cancel}`.
The host retains `native-supervisor-vm-results-003.tar` in that evidence
directory: 235,520 bytes, 71 ordinary members, SHA-256
`489f2859462e3bd2b3e60ff335cc923869a1230c469cf8af7149fdacca7a28f9`.
Both the outside archive pin and every member's size/hash were checked after
transfer. It contains declarations, raw capture streams, journals, process
results and both failed attempts. The earlier metadata-only export remains
on the VM; the complete archive includes its raw stream sidecars.

Failed attempt `001`, source `6a7e60da`, exposed the missing actor
`output_bytes` response field. Attempt `002`, source `3ce5ff4c`, exposed the
collector's rejection of legitimate child-pipe counterparts. Both stopped
truthfully and completed cleanup without outside intervention. Their original
input directories, evidence and raw files were preserved. See the
[implementation notes](gauntlet-rust-native-supervisor.md) for the fixes.

## Claim boundary

The proof still uses the historical controller `dfc948e9` (tree digest
`33ef5c12f907c80e8d05aa5af10c76510fae5097b23fc2f0a4dcab85c6a21537`),
retained candidate/prefix and source-pinned native actor described in the
[previous VM proof](gauntlet-rust-native-cell-vm-proof.md). The outer Python
adapter still owns image staging and its lease. It never calls the Python
cell startup/collector/capture path for these cases.

This proves apparatus ownership and cleanup, not Guard decision/effect
causality, six-role staging/installed conformance, current-main candidate
qualification, reviewed artifact provenance, model execution or production
cutover. Every result reports zero model requests, `execution_eligible: false`
and `guard_causality_verified: false`. The 62-parent ledger remains 24 complete
and 38 open. Fork Actions still prevents the five required current-head jobs;
this local/VM evidence does not replace them.
