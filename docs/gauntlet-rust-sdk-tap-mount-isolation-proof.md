# SDK tap private mount diagnostic

The opt-in Rust staging launcher now creates a new mount namespace for each
UID/GID-10001 SDK tap child, makes mount propagation private, and mounts a
1-MiB `tmpfs` over the child's `/tmp` with mode `0700`, UID/GID 10001, and
`nosuid,nodev,noexec`. It also masks `/home` and `/opt` with separate 4-KiB,
read-only, mode-`0000` tmpfs mounts. It does this after attaching the one-use
tap cgroup and before dropping privileges or executing the outside-pinned
child ELF. The SDK and Native Unix sockets are held descriptors; the child
still connects to the fixed Native socket through `/proc/self/fd/<held-dir>`.

The Root launcher reads the live child's mount namespace and
`/proc/<pid>/root/{tmp,home,opt}` after checking its PID/start tick/cgroup
and opening a pidfd. It requires a different mount namespace from the
worker, a different device for each masked path, exact owner/mode, `tmpfs`
type, and the required mount restrictions. A child in the
worker's namespace refuses. Failure aborts the diagnostic, after which the
existing cgroup owner handles kill, drain and removal.

The first SHA-matched ARM64 worker test binary
`5a37e6f807c0a71df89bb7a96986ba2dd43b4743ddff86146291f53f897e6014`
proved the private `/tmp` path. The final path-mask test binary
`16f7f5fe7f1a6b1cafaef53ed8da094f987445eec1e7267c8a394139c2be4273`
was installed separately as
`/root/gauntlet-sdk-path-mask-test-16f7f5fe-20261021` on the dedicated
16-GiB VM. Its 98 default tests passed with 12 intentional fixture ignores.
Two separately invoked Root-only tests passed against the retained pinned
child ELF `1a4bf073275aac1114e373d28735af1b717f32f38000fe991a734522a40bf089`:
one real UID-10001/Root docs socket exchange, and one concurrent docs/mail
staging handoff with journal and cgroup tombstones. Both exercised the new
Root checks for all three mounts. The Native socket remained reachable via a
held directory under the masked `/home` path, and the child ELF remained
executable from its held descriptor under masked `/opt`. Linux all-target
warnings-denied Clippy, macOS all-target
`cargo check`, and Rustfmt passed. The container's full unit suite had four
expected failures in tests that assume the VM's fixed cgroup topology; those
same tests passed in the VM suite. VM free disk after the tests was
8,662,355,968 bytes after removing the two verified transfer inboxes,
above the 8-GiB admission floor.

This proves the three private path masks and non-propagating mount changes for the
synthetic tap exchange. The child still shares the host PID namespace and
can see the host `/proc` view used for live SDK/Native peer checks. Other
world-readable host paths are not masked. The real six-role candidate has
not been rerun with this new launcher: the VM has only about 72 MiB above
its 8-GiB admission floor, and its retained candidate images and evidence
are still needed. The PID/mount isolation checklist
exit stays open. The diagnostic remains `execution_eligible:false` and does
not establish Guard effects, conformance or model inference.
