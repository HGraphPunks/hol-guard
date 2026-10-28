# Native Root product filesystem constructor

`gauntlet-cell-rootfs` owns the private namespace filesystem construction that
previously ran in `product_vm_rootfs.py`. This is an implementation boundary,
not an admission decision, complete Rust supervisor, or qualification result.

The only CLI is:

```text
gauntlet-cell-rootfs EXACT_ROOT_DECLARATION OUTSIDE_SHA256
```

The declaration and every parent must be canonical, Root-owned, nonwritable
by other users and free of symlinks. Input files must be regular, single-link,
bounded and stable across descriptor and visible-path checks. The declaration
has exactly these fields:

| Field | Contract |
| --- | --- |
| `schema` | `hol-gauntlet-product-rootfs.v1` |
| `stage` | A separate immutable Root-owned absolute directory |
| `initializer_sha256` | Outside pin for the privilege-dropping initializer |
| `artifact_manifest_sha256` | Outside pin for the exact native v2 artifact manifest |
| `system_spec_sha256` | Outside pin for `system.json`, including image ID, device/inode and fixed workspace |
| `task_spec_sha256` | Outside pin for `task-mounts.json`, including physical agent custody and disjoint destinations |
| `runtime_spec_sha256` | Outside pin for `runtime.json`; the full inert installed-prefix tree must also match |
| `idmap_runtime` | Existing `ubuntu2404-product-v1` or `ubuntu2404-controller-v1`, with fixed mount/libmount hashes |
| `state` | `persistent-v1` (direct private UID/GID10004 stage child) or `memory-v1` |
| `network_profile` | `unix-only-v1` or `private-loopback-v1` |
| `parent_network_namespace` | Null for Unix-only; exact outside `net:[inode]` for private loopback |

Before creating any directory or mount, the constructor requires native Linux
ARM64, real/effective Root IDs, PID1 and six namespaces distinct from the
inherited host proc view. Both network profiles require a loopback-only kernel
topology. All source declarations, image metadata, runtime inventory, physical
task tuples and public artifact bytes are verified before the first mount.
The caller still owns the image lease, cgroup, source provenance and independent
outside process measurement.

The constructor marks propagation private, creates a matching private proc
view for the reviewed idmap helper, mounts a fresh 8-MiB root, exposes the pinned
image `/usr` and fixed Node dependency directory read-only, and copies only
the fixed public OS configuration files. The image allocator preload is accepted
only at its fixed path and content. It exposes six checked safe character
devices, bounded UID10004 temporary/state storage, exact runtime and disjoint
task/provider mounts. The fixed helper has a five-second deadline and an
additional bounded reap. Physical UID10001 and mapped UID10004 metadata must
match before and after every task mount.

After pivoting, it detaches the old root, makes the new root read-only and
executes only `/public/initializer /public/gauntlet-product-cell actor`.
The outside-pinned initializer closes extra descriptors, clears the environment,
drops all identities/groups/capabilities, applies resource limits and waits for
the outside collector. The actor installs the existing pinned seccomp layers.
Candidate code cannot select a Root executable, environment, mount helper or
device. Any failure requires PID1 exit; the supervisor must retain uncertainty
until it independently proves complete cgroup/namespace cleanup.

Seven macOS parser/custody tests, eight native ARM64 tests and the three
proof-launch isolation/interface tests pass.
The complete Linux ARM64 implementation builds, and ARM64 warnings-denied
Clippy passes. Fresh VM success/deadline/cancellation cases also pass with the
retained collector/candidate; see the [live proof](gauntlet-rust-rootfs-vm-proof-20261026.md).
Full Rust supervisor ownership and current-main conformance remain open.
Existing historical artifacts and the parent milestone count remain unchanged.

`proofs/native_rootfs_vm_proof.py` can exercise this constructor through the
retained zero-model VM apparatus. It substitutes only the exact constructor
argv with all namespace switches intact; the original collector keeps its
actual actor, AppArmor, gate, stream, effect and cleanup checks. Its result
explicitly states `rust_supervisor_owned:false` and `execution_eligible:false`.
Do not use this diagnostic as proof that orchestration or Guard causality has
migrated.
