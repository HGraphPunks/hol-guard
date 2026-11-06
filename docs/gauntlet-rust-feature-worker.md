# Rust Root feature worker

Updated 2026-11-05. The development worker and fixed host caller implement
`run/read/repair`, including retained kernel ownership for active cleanup.
Current owned-VM feature execution, live restart/recovery proofs and final operator
integration remain open. Parent acceptance stays 24/62; local tests establish
implementation behavior rather than a qualified live audit.

## Ownership and fixed inputs

The Root executable is `gauntlet-feature-worker`; the Mac caller is
`gauntlet-host-feature-audit`. A closed host intent binds the existing
11-field executor spec, exact completed build result, complete controller
tree, builder/base images, rendered audit policy, four VM helper hashes and
the actual Root worker executable. It admits no arbitrary command, selector,
candidate path or resource override.

Root independently opens the successful build result and source/archive,
checks the nested wheel and actual Native bytes as data, verifies the full
controller tree and immutable local image, and repeats those checks after
execution. It never imports or executes a candidate package as Root. The
executor and fixed Node are separately captured as inert, content-addressed
ARM ELFs. Partial asset slots remain consumed.

The feature profile remains two CPUs, 12 GiB, 2048 tasks and a four-hour
deadline. The Root Podman client has its own fixed cgroup and bounded
128-KiB stdout/stderr. Existing candidate/dependency limits remain unchanged.
The unprivileged PID-1 executor still owns the complete fixed 28-group,
52-selector schedule and the source/installed context boundary.

## Durable lifecycle

Initialization v4 creates the private `feature-state` and `feature-jobs`
namespaces and `feature-assets` directory. Existing directories and locks
must already have safe custody; initialization never repairs their modes or
adopts existing job IDs. Historical initialization receipts remain intact.

Under the shared Rust and Python worker leases, the Root owner commits the
complete canonical intent as the one-use reservation before creating its
audit directory, loading a policy or creating a container. An incomplete
intent write consumes the ID and blocks admission. The separate feature
lease covers all feature journal writes.

Container ownership requires a full 64-character CID, exact intent label,
fixed unprivileged user, immutable image and exact security/resource settings.
The CID receipt precedes start. A separate fsynced client-cgroup receipt binds
the intent, kernel boot ID, device and inode before spawning the client. The
running marker binds its actual PID/start ticks and feature cgroup. Cleanup
targets those identities and keeps confinement enforced when teardown cannot
be proved. Shared cgroup custody now lives in `owned_cgroup.rs`; the existing
probe API and fixed limits remain unchanged.

After exact container/client/profile cleanup, Root compares its captured
stdout with the exported report, independently recomputes every XML/log
digest, count and status, and retains immutable Root copies. A closed result
binds those artifacts to the original outside intent. A complete result
always has terminal status `invalid-evidence`; `audit_status` separately
preserves `passed`, `failed`, `incomplete` or `invalid-evidence`.
Qualification, artifact admission and Guard causality remain false; model
requests and tokens remain zero.

New native, candidate and dependency dispatch checks reject unresolved feature
state. Orphan files, unknown sidecars, partial JSON and conflicting completion
records block further admission. Reading a completed result repeats custody,
artifact verification and present cleanup checks.

## Restart and recovery boundary

The host durably records dispatch before opening the VM connection. An
uncertain transport consumes the attempt. A second invocation refuses instead
of replaying the work. Restart opens the retained guest result using the
audit ID and original complete intent digest.

The host's `read` action requires the exact durable intent and dispatch bytes
before calling the pinned worker. It sends no run intent and commits or
compares a canonical private terminal copy. Its `repair` action additionally
requires an outside repair-binary SHA-256 and durably pins that authorization
before contacting the guest. Later reads use that authorized executable and
accept an aborted receipt only with matching original intent and repair pins.
The authorization is immutable; repeated cleanup reconciles the same binary
and never resubmits the workload. A completed host result cannot be repaired.

Local process tests cover completed readback, aborted repair/readback across
restart, transport failure, changed dispatch, partial or changed authorization,
substituted receipts and consumed-run refusal. The host journal tests have one
dedicated test module to keep the implementation below 500 lines. Historical
host-read evidence remains in
`gauntlet-rust-pr-ready-evidence-20261026/feature-host-read-proof-001.json`;
that earlier proof does not establish a new guest execution.

Under all three leases, recovery validates the original container receipt,
full CID/intent label and fixed resource/security settings. An active client
cgroup can be reopened only with its retained boot/device/inode identity.
Cleanup uses its held descriptor, never a historical PID. A name replacement,
missing ownership receipt, changed helper or policy pin, or uncertain custody
refuses before destructive cleanup. The create/receipt gap can retain a CID
only after an exact intent-bound inspect, before removing that container.

The worker keeps AppArmor loaded until the exact container and client cgroups
are absent and the original client has gone. It then removes the pinned policy,
rechecks actual cleanup and appends an exclusive `aborted` receipt with unknown
exit and zero model usage. Reading that receipt rechecks present cleanup.
Existing results and partial records remain immutable; unresolved uncertainty
continues to block dispatch. At `22d29e6e`, eleven feature cases and the explicit
Root cgroup-recovery case pass in the owned VM. The latter observes child and
descendant tasks, the parent's SIGKILL exit, complete drain/removal, forged/partial
receipt refusals and refusal of a replacement group with the same name.
Metadata for all 333 retained worker records is unchanged; no owned container
or cgroup remains. See the execution checklist for exact binary and log pins.
These probes still leave the complete live worker flow unproved.

The first new live run will use the already retained product/build inputs.
It must remain explicitly attributed to that product source rather than the
newer migration implementation or upstream merge. Current-source product
qualification, full operator wiring, interruption coverage and cutover remain
separate acceptance requirements. Required cloud CI remains user-owned and
pending.
