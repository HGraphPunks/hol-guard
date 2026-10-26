# Native apparatus worker

The new `gauntlet-vm-worker` is an explicit native successor alongside the
historical Python worker and read-only Rust shadow. Its first version runs
only `native-apparatus-v1`, which exercises the real Rust cell boundary.
Completed runs record `invalid-evidence`. It cannot qualify Guard, request inference,
publish a gate or activate host cutover. Live worker proof is pending.

The public CLI accepts outside source, deployment and actual executable SHA-256
pins, plus one bounded v1 worker request on stdin. Queries project retained
state. A run reads only the matching immutable
`/opt/hol-gauntlet/native-deployments/<digest>.json`. Its exact seven-field
`hol-gauntlet-native-worker-job.v1` schema binds source, job, worker bytes,
preparation digest and one fixed apparatus case. Root program, environment,
model and resource selectors are unavailable.

The preparation is fixed at
`/var/lib/hol-gauntlet-rust/native-jobs/<job>/preparation.v1.json`. Stage,
physical workspace, private custody and product slice must belong to that
same job, with the 180-second cell profile. Another job's paths/slice and extra
provider mounts are refused. The Root preparation reader still checks every
outside artifact/runtime/helper pin before its effects.

The dispatcher owns the existing Rust active lease and legacy worker lock.
It blocks new dispatch on unknown/orphan state, surviving product units or an
active/mounted dependency image. An exclusive fsynced started marker consumes
the job ID. The worker launches its already-hashed running inode through
`execveat`, in the fixed 4-GiB/256-task/one-CPU controller cgroup, with empty
groups and no new privileges. The controller blocks on a private execution
gate. Root samples actual PID/start/cgroup, executable bytes, argv and all IDs
around the durable running marker before releasing that gate.

The parent owns a 300-second `CLOCK_BOOTTIME` deadline, bounded logs and signal
handling. Interruption gives the controller's Rust cleanup path a bounded
chance, then kills/drains/reaps its entire cgroup before stopping the exact
job product slice. Input/worker bytes and image-lease absence are rechecked
before a terminal receipt. Uncertain cleanup retains an unknown, consumed job;
it cannot silently retry. Read-only reconciliation does not manufacture a
terminal for an interrupted job.

The private report retains controller output hashes and apparatus measurements,
with zero model requests and explicit unavailable qualification. A producer's
`passed` field never changes the parent's `invalid-evidence` outcome. Host
prelaunch key delivery, independently scored Guard controls, authenticated
benchmark reports, operator repair and source-matched conformance still need
their separate implementation/proof exits before this worker can be admitted
by the passive observer.
