# Native apparatus worker

The new `gauntlet-vm-worker` is an explicit native successor alongside the
historical Python worker and read-only Rust shadow. Its first version runs
only `native-apparatus-v1`, which exercises the real Rust cell boundary.
Completed runs record `invalid-evidence`. It cannot qualify Guard, request inference,
publish a gate or activate host cutover. Six fresh VM cases and quiescent
failed-job recovery pass; see the [worker VM proof](gauntlet-rust-native-worker-vm-proof-20261026.md).

The public CLI accepts outside source, deployment and actual executable SHA-256
pins, plus one bounded v1 worker request on stdin. Queries project retained
state. A run reads only the matching immutable
`/opt/hol-gauntlet/native-deployments/<digest>.json`. Its exact seven-field
`hol-gauntlet-native-worker-job.v1` schema binds source, job, worker bytes,
preparation digest and one fixed apparatus case. Root program, environment,
model and resource selectors are unavailable.

The explicit `--initialize-native GENERATION_SHA256` command creates only the
fixed inert native state/build/deployment namespaces and permanent worker
locks. It requires initial-namespace Root and an exact current-executable pin,
sets modes independently of umask, and refuses unsafe existing directories,
symlinks and multiply linked lock files without repairing them in place.
Both Rust and legacy worker leases cover the remaining namespace/receipt
commit. A private generation-keyed initialization receipt survives identical
reopen and always states no job dispatched, no model use and no eligibility.
It neither adopts unknown jobs nor runs the Python control-plane installer.
The [fresh VM initialization proof](gauntlet-rust-native-initialization-vm-proof-20261026.md)
passes with both competing leases, immutable restart and actual Root custody
tests; no Python worker is installed and no job is dispatched.
That historical v1 layout used 0755 for the build parent. The downstream
candidate reader requires 0700, so the current initializer emits explicit
`hol-gauntlet-native-initialization.v2` / `native-worker-layout-v2` and requires
the private build parent. It refuses a loose existing directory; migration
must preserve any original directory and never silently chmod job history.

`--capture-build-source JOB SOURCE_SHA ARCHIVE_SHA256 BYTES GENERATION` streams
only stdin into an exclusive fixed build slot under both worker leases, with
a 180-second boottime deadline, signal cancellation and 256-MiB ceiling. It
requires exact outside length/hash before committing `source.tar.gz` as 0444,
then reopens it through the actual candidate-build custody reader and writes
a private ineligible source receipt. Mismatch/interruption retains a consumed
partial slot; replay cannot overwrite it. No archive is unpacked or executed,
and the historical guest-home transfer path remains a separate adapter.
The [v2 initialization/source proof](gauntlet-rust-native-source-vm-proof-20261026.md)
passes with the actual 54.8-MB current-source Git archive and candidate reader,
all refusal/replay cases and 122 actual Root tests. Rejected partials and the
original v1 empty directory/receipt remain retained.

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

The first live worker attempt at source `0bab80ca`, job `e2c701baf1470043`,
failed before actor execution: its private 0077 umask reduced public bootstrap
permissions. The collected service also returned "unit not loaded" during
cleanup. The worker preserved unknown state, original journals and an active
image lease. Public staging now explicitly commits each declared mode, with a
separate-process 0077 regression test. Cleanup reconciles an already-collected
service only after the service was independently observed, its systemd client
was reaped, its cgroup disappeared and helper bytes still match.

`--repair-native SOURCE DEPLOYMENT ORIGINAL_GENERATION JOB STARTED_SHA256
REPAIR_GENERATION` is an explicit recovery operation for this zero-model
apparatus profile. It acquires both worker locks and verifies the original
declaration, started/running hashes, dead controller and absent product
resources. It reopens only that stage's private image pointer under its
permanent lock, verifies the original hash-chained mount ownership and current
mount inode/device, then unmounts using pinned Podman. A live/uncertain process,
profile, mount, mismatched lease or different helper history refuses recovery.
Each attempt has a separate audit journal. The exclusive `native-repair.json`
receipt records `aborted`, unknown exit status, zero model use and ineligibility.
Original markers, streams and failure journals remain intact; the job ID stays
consumed. New native admission rechecks that receipt and physical quiescence.
The old v1 read-only projection continues to show unknown because it cannot
express this separate repair version. Live recovery, immutable receipt reopen
and fresh worker jobs pass; original failed attempts remain preserved.

The private report retains controller output hashes and apparatus measurements,
with zero model requests and explicit unavailable qualification. A producer's
`passed` field never changes the parent's `invalid-evidence` outcome. Host
prelaunch key delivery, independently scored Guard controls, authenticated
benchmark reports, general operator repair and source-matched conformance still need
their separate implementation/proof exits before this worker can be admitted
by the passive observer.
