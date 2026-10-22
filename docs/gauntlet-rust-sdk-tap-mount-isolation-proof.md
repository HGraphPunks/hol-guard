# SDK tap private mount diagnostic

The opt-in Rust staging launcher now creates a new mount namespace for each
UID/GID-10001 SDK tap child, makes mount propagation private, and mounts a
1-MiB `tmpfs` over the child's `/tmp` with mode `0700`, UID/GID 10001, and
`nosuid,nodev,noexec`. It does this in the child after attaching the one-use
tap cgroup and before dropping privileges or executing the outside-pinned
child ELF. The SDK and Native Unix sockets are held descriptors; the child
still connects to the fixed Native socket through `/proc/self/fd/<held-dir>`.

The Root launcher reads the live child's mount namespace and `/proc/<pid>/root/tmp`
after checking its PID/start tick/cgroup and opening a pidfd. It requires a
different mount namespace from the worker, a different `/tmp` device, exact
owner/mode, `tmpfs` type, and all three mount restrictions. A child in the
worker's namespace refuses. Failure aborts the diagnostic, after which the
existing cgroup owner handles kill, drain and removal.

The SHA-matched ARM64 worker test binary
`5a37e6f807c0a71df89bb7a96986ba2dd43b4743ddff86146291f53f897e6014`
was installed separately as
`/root/gauntlet-sdk-mount-test-5a37e6f8-20261021` on the dedicated
16-GiB VM. Its 98 default tests passed with 12 intentional fixture ignores.
Two separately invoked Root-only tests passed against the retained pinned
child ELF `1a4bf073275aac1114e373d28735af1b717f32f38000fe991a734522a40bf089`:
one real UID-10001/Root docs socket exchange, and one concurrent docs/mail
staging handoff with journal and cgroup tombstones. Both exercised the new
Root mount checks. Linux all-target warnings-denied Clippy, macOS all-target
`cargo check`, and Rustfmt passed. The container's full unit suite had four
expected failures in tests that assume the VM's fixed cgroup topology; those
same tests passed in the VM suite. VM free disk after the tests was
8,662,360,064 bytes, above the 8-GiB admission floor.

This proves private `/tmp` and non-propagating mount changes for the
synthetic tap exchange. The child still shares the host PID namespace and
can see the host `/proc` view used for live SDK/Native peer checks. Other
world-readable host paths are not masked. The real six-role candidate has
not been rerun with this new launcher, so the PID/mount isolation checklist
exit stays open. The diagnostic remains `execution_eligible:false` and does
not establish Guard effects, conformance or model inference.
