# Native cell supervisor implementation

The `NativeCell` API in `gauntlet-cell-rootfs` now owns the Root service launch,
outside kernel measurements, startup gates, private actor bootstrap, authenticated
RPCs, process release/retirement, bounded capture, private journal and cleanup.
Fresh success, timeout and cancellation pass in the owned ARM64 VM; see the
[source-pinned proof](gauntlet-rust-supervisor-vm-proof-20261026.md). Full
worker integration and deterministic conformance remain open.

An outside-SHA-256-pinned `hol-gauntlet-cell-supervisor.v1` declaration contains
the exact Root rootfs declaration path/hash, constructor path/hash, finite wall
deadline, fixed CPU profile, optional exact Rust job slice and the five fixed
host-helper hashes. Neither a candidate nor actor RPC can choose a Root helper,
environment, service name, resource ceiling or AppArmor policy. Every helper
and constructor requires immutable Root filesystem custody and the expected
outside bytes. The AppArmor template is compiled from the existing source.

The service has a fresh CSPRNG name, exclusive stage journal and unchanged
1-GiB/128-task/one-CPU ceilings. All six namespace operations and the existing
Root initializer/actor gates remain mandatory. The collector requires initial
Root UID/GID maps and kernel procfs, then holds pidfds across actual process
observations. It verifies all saved IDs, groups, five capability sets, no new
privileges, syscall filters, exact executable/argv, enforcing profile, three
management pipes, namespaces, task idmaps, mount flags and loopback-only routes.
The initializer-to-actor transition must preserve PID/start tick and namespaces.
Every execution gate is remeasured before release; retirement requires the
held process to be dead. Kernel route counters may change while every new
sample still passes the loopback-only policy.

Fresh Rust-generated bootstrap keys travel only over private pipes. The existing
actor's eight-operation protocol, role/domain separation and frame budgets are
preserved. Captures bind delivered input, validate typed output/terminal fields,
retain stdout/stderr bytes under private exclusive files and append fsynced
hash-linked events. Cancellation, deadline or protocol/identity uncertainty
closes the entire owned cell. Uncertain journal writes remain poisoned.

Cleanup stops only the registered service, bounds client/helper reaping,
checks cgroup and escaped mountpoint absence, removes and independently checks
the owned AppArmor profile, and rehashes the installed prefix. An error retains
unknown state. Image staging/lease ownership is still a separate migration
boundary and is explicitly retained in the current Python VM test adapter.

`gauntlet-native-cell-proof` drives the Rust API with the actual retained Native
daemon, gated physical effect, binary I/O, timeout and cancellation cases.
`proofs/native_supervisor_vm_proof.py` stages the separately verified historical
controller/runtime/image and independently checks terminal state. Any external
cleanup intervention makes the proof fail. It makes no model requests and
cannot publish a qualified verdict.

Current checks: 12 macOS and 16 native ARM64 tests pass, the complete macOS
workspace passes, and Linux ARM64 source builds with warnings-denied Clippy.
All three fresh VM apparatus cases pass. Static cross builds use Rust 1.88 and
Zig 0.15.1; C is compiled without Zig's implicit debug UBSan instrumentation to
match the ordinary unsanitized GNU CI build and avoid an unlinked sanitizer
runtime in Ring's constant-time C helper. This does not alter Rust checks,
test expectations or runtime isolation.

The first live attempt (`native-supervisor-proof-20261026-001`, source
`6a7e60da06c93475ad8e8427fd809e9cc27f6e73`) passed all 15 ARM64 unit tests
and reached authenticated daemon process release after the outside kernel and
mount checks. It then failed on the reader's incomplete exact response schema:
the actor also returns `output_bytes`. The failed evidence remains intact.
Rust closed the cell; the independent adapter confirmed image cleanup and no
outside cleanup intervention. The corrected reader includes the mandatory
cumulative byte count, checks it against actual decoded bytes for each owned
handle, and shares that parser with bounded capture. Malformed replies are
retained before closing the cell. Fresh live evidence is still required.

Attempt `002` (source `3ce5ff4c10659e6a9a133c56db2f2fd091005347`)
passed the same 15 native tests and stream parsing, then refused the idle
actor's descriptors while a daemon child was registered. The actor correctly
holds its children's pipe counterparts; the initial collector allowed only
its three management descriptors. Cleanup again completed without outside
intervention. The correction keeps the strict initial/gated-process floor and
allows the idle actor only additional pipes whose kernel inode identities were
measured on registered children. Unknown pipes, files, sockets and missing
stdio remain failures. The actor's original stdio and all other identity
fields must still match two stable outside samples before every spawn.
