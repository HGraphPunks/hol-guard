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

Live v4 execution is pending at this checkpoint. Original failed logs remain
retained. No new migration parent exit closes here.

Actual SDK MCP composition, Git/package developer metadata, the combined
builtin/MCP budget, outside key admission, independent request/decision/effect
scoring, current-source controls and interrupted v4 recovery remain open.
The existing repair entrypoint refuses v4 instead of applying an earlier
profile's repair contract. All worker terminals remain `invalid-evidence`,
execution-ineligible and Guard-causality-unverified, with zero model requests.
