# Versioned prelaunch image interpreter pins

`hol-gauntlet-cell-supervisor.v2` adds two required SHA-256 fields to the
outside preparation: `image_interpreter_sha256` and
`outside_observer_sha256`. Version one retains its exact closed field set;
adding either field to a v1 declaration refuses. Version two requires both
typed digests and permits no caller-selected interpreter path or command.

Before product startup, Root opens the fixed image `usr/bin/python3.12`
through held, no-symlink image/`usr`/`bin` descriptors. It requires Root UID/GID,
mode 0755, one link, a bounded ARM64 ELF and the outside-pinned digest. The
held file and each named ancestor are checked before and after hashing.
Directory/file descriptors are close-on-exec. The generation is rechecked
before launch and every product spawn/release. Replaced inodes, links,
ancestor swaps, writable/nonexecutable files, changed bytes and other
architectures refuse.

Root records the measured generation immediately after `prepared`, before
the first product gate. The Native plane's signed journal checkpoint binds
that event. Rust readback requires the exact v2 preparation pins, complete
journal binding and the early Root file witness before setting
`interpreter_prelaunch_pinned:true`. A v1 report cannot gain that credit from
an invented event. The observer digest is a prelaunch declaration; observer
process authentication and outside key admission remain false and separate.

The Mac workspace passes 561 tests with no failures or ignores, log SHA-256
`db979a098194c5157046a8c998f39cbcdf368441649da0c0c186ddc445927e99`.
After explicitly testing close-on-exec descriptor inheritance, all 41 affected
rootfs tests pass (`dad5c3f226279050868d4f07291b8f5ab24fbc337b87c8265ea7417c454d78bb`).
Warnings-denied all-workspace/all-target/all-feature Clippy passes on Mac
(`5997d3d1e90222ce802ad0596ba3347deb8fb8eb141385438613e16eab46950e`)
and ARM
(`b063917e9c49cc50257ceeb4e0c5024242c860446ed89b273c8a483975ea4df0`).
Seven new tests cover both schema layers, actual held file generations and
the consuming provenance reader. New source files stay below 500 lines.

At committed Rust source `c3c8fa5d3cadc3121967895ca97cb5aadd70283b`, all
seven new tests also pass natively as Root in the owned ARM VM, with both
worker leases held and all 284 prior worker files unchanged. The five-member
input capsule has 46,766,080 bytes and SHA-256
`e2b5c9a0983dd1337e85a41d3127e80169b5bda71a48cb6688b6cf7e1dad0c23`.
Its frozen worker has SHA-256
`ec0e400c9147eb9e17b819b99d302ac8a64f126df93033311e187d99a673c675`;
the rootfs constructor has SHA-256
`9723a562244e3c6b95908b553e527240d4b1a4f5d3d345db626fed1921155e89`.
The frozen Mac host sender and verifier have SHA-256
`9ddcd8994e3063251d999fdb2c6532c9c82215f7234f3902f05212be59cc1473`
and `6bd81d83d456edecb00953792161557ec96b40484dfae3d31b2c4fa4e1f79daa`.

Two actual zero-model controls use those Rust tools and the separately
retained product candidate `9f42d9dd3574ede89d8912a85813f9d817a9de46`,
version 3.58.0. They do not represent final current-source conformance.
The first job, `e2c701baf1475401`, authenticates its failure: npm exits with
SIGABRT inside the unchanged benign fixture. The exact product profile's
kernel log records a task-controller fork refusal at the 128-task ceiling.
The fixed public diagnostic archive has 140 members, 1,310,720 bytes and
SHA-256 `4522753e3a697a66e4847d2ca06d6e5413143292f4efa2903001ef493e08a8f9`.
The retained three-line kernel diagnostic has SHA-256
`50b20fea0eee6a55dfe75680a423acc49a931cef9547cd46fcb6dd3c3d9803e0`.
The failed report is not accepted as a successful control.

The second job, `e2c701baf1475402`, uses the same binaries and resource
ceiling, a fresh host key journal and a separately declared read-only
pressure sampler. It passes. Rust verifies the early interpreter witness,
three actual raw SDK request captures, three acknowledged hook inputs,
the signed journal checkpoint, nine gate/interpreter launches, five Native
clients, all eight output captures and the physical fixture/effect joins.
It preserves all 291 preceding records; the final worker inventory has 298
files. Both jobs report cleanup, leave owned resources absent, preserve the
host null device and retain separate outside samples with no sampler errors.
The 142-member public export has 1,853,440 bytes and SHA-256
`69b8b88dda38161235d97d2b463cce763eb4202cb6711da5bd149280a04d032f`.

The [live courier](../ci/gauntlet-rs/proofs/verify_native_launch_live_20261027.py)
records 20 Rust CLI cases: five actual modes, identical control restart,
authenticated earlier failure and 13 refusals, including altered launch/input
journals with recomputed chains and indexes, changed signed SDK wire bytes,
outside observer, physical effect, role and identity pins. Proof
`native-launch-live-proof-002.json` has SHA-256
`cec433c00ff5e1ea89a99e5ef6c29853090dbb7233f1b14c9b1c90e627f321b5`.
The [legacy courier](../ci/gauntlet-rs/proofs/verify_native_launch_legacy_20261027.py)
records 32 byte-identical old envelope/MCP/process/hook/control/binding/boundary
readbacks, proof SHA-256
`78cffd2794a6c143f9b08424359c963c0bbf8b89e36abb3102f4d1dff406546d`.
Historical archives retain their original missing-pin and missing-input status.

The passing run's 160 pressure snapshots observe at most 122 tasks, while
the kernel's retained peak reaches 126 of 128 with no fork refusal in that
run. Its Guard daemon holds 63 threads and the managed Native resident holds
29. The initial courier incorrectly equated sampled current counts with the
kernel peak; its first attempt and outputs remain retained, and the final
courier checks both distinct quantities. The earlier npm failure remains an
unresolved intermittent resource-pressure issue; no ceiling, fixture assertion
or acceptance criterion was relaxed. Fresh complete-role conformance must
resolve it. Observer execution authentication, all Native descendant custody,
actual writer attribution, outside child-death observation and outside key
admission remain open. No model request runs; qualification, Guard causality
and parent exits remain unchanged at 24/62. CI remains user-owned and pending.
