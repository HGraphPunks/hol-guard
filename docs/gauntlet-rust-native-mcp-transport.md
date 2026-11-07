# Rust-owned Native MCP transport

The closed `hol-gauntlet-native-worker-job.v4` declaration selects
`native-mcp-transport-v1`. It binds the original product source, Native/Bwrap
pins, preparation and exact worker generation. Earlier apparatus, hook and
SDK declarations keep their existing versions and behavior.

Rust owns a fresh UID/GID10005 container, exact image and mount inventory,
named inherited unconfined AppArmor template, effective cgroup limits,
namespace/PID/start-time samples and explicit cleanup. The separate product
cell retains its enforcing profile. The MCP container receives a readonly
installed prefix, readonly public adapters/upstream sockets and private
product home/Guard mounts. Neither the Root SQLite database nor signing key
is mounted to it. Public adapters execute exclusively as the unprivileged
product user; Root writes and verifies their bytes.

The binding adapter calls the product's real `ManagedMcpServer` and
`proxy_cli_args`, waits at a Root-owned gate, then execs its normal
`omp-mcp-proxy` CLI. Root observes both interpreter/argv generations through
held pidfds and executable inodes. The proxy's real native resident launches
the fixed readonly `service_relay.py` child. Root checks its socket peer,
saved IDs, groups, zero capability sets, NNP, seccomp, exact interpreter/argv,
cgroup, full LSM label and all held namespaces. This diagnostic does **not**
infer that an arbitrary same-UID relay is the child of a particular proxy;
that causal join remains an explicit open requirement.

The duplex Podman client uses private socket stdio, bounded persistent MCP
framing, retained input attempts/completed writes/output frames, separately
bounded stderr, cancellation, sticky transport failures and explicit host
client reaping. Host `/dev/null` is held and independently rechecked. A host
client's exit does not establish product process drain; the container owner
and outside worker separately require absent container metadata, job cgroup
and scoped profile before the job can terminate.

The execution profile connects the docs and mail CLI proxies to Rust MCP
sessions and a Root-private `gauntlet-world` SQLite database. It initializes
both protocols, obtains the real tool catalogs, reads two fixed synthetic
records and retains exact upstream wire bytes, provider receipts, final
snapshot and cleanup results. An upstream operation ceiling of four is
shared across those two sessions. It is not yet the combined SDK builtin/MCP
budget. The Root-generated diagnostic key has no outside host admission.

Component verification before the first live v4 execution:

- ARM warnings-denied Clippy and static test/worker builds pass.
- On the owned ARM VM as Root, 170 worker tests pass, zero fail, with 24
  existing ignores. Thirteen MCP tests cover custody, actual duplex system
  byte copying, cancellation/reaping, strict profile separation, inspection
  refusals and all seven actual Python CLI binding identifiers.
- macOS worker tests and warnings-denied Clippy pass, covering the shared
  declaration and SDK parser changes. The earlier full 474-test workspace
  checkpoint remains retained.

The first v4 attempt at `038ab99e`, job `e2c701baf1473601`, failed its
`systemctl` digest check after an unattended Ubuntu systemd update. The audit
also found a changed `systemd-run`. Both files match the installed
`255.4-1ubuntu8.18` package's file records.
The reservation was consumed, but no controller marker/log/key, product
stage or workspace output was created. The outside sampler recorded zero
product processes; all 129 earlier worker files and the host null-device
identity remain unchanged. The original 16-member failure export is 30,720
bytes, SHA-256 `d4888d33f62473c133203d33246bed71031bff1aba294bc007e177c3aff1254f`.
The original started-marker digest is
`26dc7efc4fe80b70eeb06b1400e84ae61211471d74572c9a47b6fbeb99ab06ba`.

Rust now validates every pinned host helper and the constructor before
consuming a fresh job, and repeats the ordinary checks at launch. Digest
errors identify the public input path. A distinct pre-controller recovery
requires the outside original reservation digest, both worker leases, no
controller artifacts, the exact original empty Root workspace, absent stage,
controller cgroup, product slice, MCP container/profile and image lease. Its
immutable receipt records aborted/never-released/null-exit state. It neither
creates a terminal/exit result nor makes the consumed ID reusable. Admission
requires exactly one validated terminal, running-controller repair or this
new startup repair; original declarations and evidence remain unchanged.

After this fix, warnings-denied ARM Clippy passes, 173 worker tests pass with
24 existing ignores, and all 31 rootfs tests plus the nested subprocess test
pass natively as Root. The actual startup repair passes wrong-marker and
both lease refusals, records receipt
`76a173e773536f060673017f5fe8dd2d061d2d67a6ac5a4f25c80a3008f41da0`,
preserves all 130 original files and replays byte-identically.

At source `eafefd5b`, the deliberate bad-helper job `e2c701baf1473702`
refuses before reservation. Job `e2c701baf1473701` then correctly refuses
an incorrectly Root-owned fixture workspace before any product process is
started. Its running marker, stderr and invalid-evidence terminal remain
unchanged; the next job uses the required UID/GID10001 workspace.

Fresh job **`e2c701baf1473801` passes** the actual Native MCP diagnostic at
the same source and worker generation. Both normal CLI proxies initialize,
list their actual catalogs and deliver a completed docs/mail read through
the real Native resident to Root-owned Rust sessions and SQLite. Fourteen
upstream frames, two signed receipts, both physical records, 20 outside
kernel samples and full cleanup are retained. All 137 prior worker files
remain byte-identical. The host null-device identity and runtime prefix
remain unchanged. The product prefix retains its historical `62aa7ba7`
source pin; this does not qualify a fresh current-source candidate.

The 95-member, 512,000-byte public export has SHA-256
`3a2b7b83c99b75549d6d68d51ad74e5162f1cb8e350c5765eccee9bd7a6e1420`.
Report SHA-256 is
`38d6c240e339efaa2ee977d7c20d97f83f1d0d831062101b7dee96dabaae280a`;
started-marker SHA-256 is
`29330134686f8094920b0b33cec547ea7909f342e0b713af84e9aae1963f6f41`.
Product home and Guard stores are excluded from the public export. The
synthetic World database contains public metadata, records and receipts;
the signing key was never stored there.

The committed `verify_native_mcp_transport_20261027.py` host reader passes.
It verifies both ELF input bundles and the original failure archive, exact
wire bytes and CLI bindings, proxy/relay PID/start/argv/executable/namespace
matches against outside samples, receipt signatures and chain, physical
SQLite rows/journal, unchanged final snapshot, prior evidence and cleanup.
It distinguishes the locally generated diagnostic signing key from an
outside admitted key. The worker terminal remains `invalid-evidence` and
no migration parent exit closes from this diagnostic.

Actual SDK MCP composition, Git/package developer metadata, the combined
builtin/MCP budget, outside key admission, independent request/decision/effect
scoring, current-source controls and interrupted v4 recovery remain open.
The existing running-controller repair entrypoint refuses v4 instead of
applying an earlier profile's repair contract. All worker terminals remain `invalid-evidence`,
execution-ineligible and Guard-causality-unverified, with zero model requests.
