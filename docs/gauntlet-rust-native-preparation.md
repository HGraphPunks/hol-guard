# Native cell preparation and image ownership

`gauntlet-cell-rootfs::prepare_and_start` stages the fixed native cell layout
and transfers its image lease into the Rust supervisor. It reads an
outside-SHA-256-pinned `hol-gauntlet-cell-preparation.v1` declaration from
immutable Root custody. That declaration binds separate stage/artifact/prefix
paths, the native manifest and initializer, installed tree, exact Linux ARM64
dependency image, Podman bytes, task generations and the existing fixed launch
template. It cannot select a Root image command, environment, arbitrary helper,
mount policy, capability or resource ceiling.

Before staging, Rust verifies every manifest-listed artifact, the complete
installed runtime tree, constructor and fixed host helpers. It creates a fresh
private stage, copies only the native public bootstrap, writes the fixed Guard
state configuration and runtime/task declarations, and preserves physical
agent task ownership. Failed stages remain one-use evidence. Candidate Python
and image executables never run as Root.

The image owner uses only pinned Podman `image inspect`, mount inventory,
mount and unmount. Streams and helpers have fixed bounds. A permanent private
lock and fsynced exclusive active pointer precede mounting. A prior active
pointer blocks acquisition even after its process lock is released. Held and
visible file/directory identities are rechecked. Existing mounts are refused
and never borrowed or unmounted. Cleanup responsibility is recorded before a
mount helper can mutate the host; helper failure remains the owner's concern.

The lease enters an uncertain state before the cell service can start. It may
release its mount only after Rust confirms service/process, cgroup, AppArmor
and rootfs cleanup plus runtime custody. Uncertainty retains the mount, active
pointer and journal for reconciliation. Successful cleanup fsyncs its journal
and removes only its exact active pointer; the permanent lock and all evidence
remain. Legacy/Rust worker leases are held by the outside VM proof adapter;
worker admission and operator cutover still require their separate composition.

`proofs/native_preparation_vm_proof.py` constructs only the outside declaration
and physical fixture, checks pinned executables/controller, and reads final
state. It imports no Python factory or product orchestrator. The success,
timeout, cancellation and replay cases delegate all image/cell operations to
Rust. Wrong-pin and borrowed-image cases exercise refusal; only the latter's
deliberately outside-owned negative fixture is unmounted by that adapter.

The implementation passed all six fresh VM cases, 20 native ARM64 tests and
the complete all-feature macOS workspace; see the
[source-pinned VM proof](gauntlet-rust-preparation-vm-proof-20261026.md).
This is not reviewed production provenance, source-matched Guard
conformance or qualification. It requests no inference and cannot issue an
eligible verdict.
