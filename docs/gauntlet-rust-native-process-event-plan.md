# Native process event recording

R3 still needs complete Native descendant custody and actual outside death
observations. The signed launch/input/output proofs do not establish either.
Add an opt-in Rust recorder to the owned product cell before its first private
spawn request. Older launch versions keep their recorded semantics and gain
no event coverage retroactively. All qualification and admission flags remain
false while implementation and native VM proof are incomplete.

The Linux [ptrace contract](https://man7.org/linux/man-pages/man2/ptrace.2.html)
distinguishes fork/clone/exec stops, early exit stops and final death. All three
creation event options are needed. A non-leader exec can replace its thread
ID; its previous ID must be reconciled. Seized group stops require distinct
handling from signal delivery. The [wait contract](https://man7.org/linux/man-pages/man2/waitpid.2.html)
provides `__WNOTHREAD` to isolate a dedicated collector from other controller
threads' children. These requirements govern the implementation below.

- Bind only the already measured, filtered, UID/GID 10004 product PID1 actor,
  with its held PID/start identity, fixed argv, enforcing profile, namespaces
  and exact owned job cgroup. Refuse foreign processes and an existing tracer.
- Seize and interrupt that actor on a dedicated Rust thread before acknowledging
  recorder readiness. Trace fork/vfork/clone/exec/exit events with exit-kill
  ownership. Preserve delivered signals and group stops. Do not use tracing
  operations to write target memory, registers or syscall results.
- Track kernel-created tasks, threads, parent links and exec identity changes
  without equating an early exit event to death. Reconcile auto-attached child
  stops that arrive before the parent's creation event. Bound live tasks,
  total events, executable/argv reads, journal bytes and waits.
- At stopped execs, retain the actual image and argv generation through held
  kernel references. Keep process identity, namespaces, privileges, cgroup
  and source-specific image grading separate from collection.
- Use a private Root journal and bind its exact checkpoint into the existing
  signed Native plane. Refuse incomplete histories, changed bytes or a lost
  recorder. Close and drain through the existing cell owner on failure;
  retain interrupted records. Never detach a surviving owned workload as
  successful cleanup.
- Prove actual fork/clone, detached descendants, non-leader exec, stop/continue,
  normal/signal exits, lost recorder, cancellation and foreign-target refusal
  in fresh owned ARM VM fixtures. Preserve all 298 existing worker records
  under both leases. Then exercise fresh Native controls and the consuming
  Rust reader before claiming any coverage improvement.

The initial implementation exposes `NativeProcessEvents::start` only for an
already held actor. A dedicated Rust thread measures its stopped image,
retains inherited task identities, journals bounded creation/exec/signal/exit
events, and requires final waits or explicit kernel exec replacements before
completion. The normal supervisor launch has not opted into it yet. The
`owned-process-trace-fixture` feature adds a separate Rust fixture executable
that refuses Root execution, and six opt-in Root tests retain their exact
event journals in a designated private proof directory. Fixture entry points
do not expand the production target-selection API.

At the first working-source checkpoint, ARM rootfs warnings-denied Clippy and
all 45 macOS rootfs tests pass. Native VM tests, journal-consuming Rust
verification and launch wiring are still pending; this is implementation
progress with no new coverage credit. Internal Native request bytes,
effect-writer attribution, observer/key admission and the intermittent 128-task
failure remain separate open requirements. No resource ceiling or product
syscall restriction is relaxed by this work.

The first owned ARM VM attempt at `51b59ff2` retains all 298 worker records
under both leases. Four parser/identity tests and the lost-recorder and foreign
cgroup cases pass. The other four fixture cases fail on a duplicate parent
wait: Linux supplies the final status only once when tracer and parent share
the same process. Their journals remain retained, including the distinct
non-leader exec replacement. The fixture correction requires the actual
anchor's recorded final exit-zero status and dead held pidfd before accepting
`ECHILD`; cleanup signals use that pidfd. No recorder event criteria change.
The native rerun is pending. The failed public export is
`native-trace-vm-results-001.tar`, 163840 bytes, SHA-256
`c0e683cb0624d0a0658a6776a6a573214b337aa975064f4d62a63b2a8cd46cb9`.

Attempt 002 at `0259fa90` passes all six native recorder cases plus four wait
and stopped-identity tests. Fork/vfork, detached grandchildren, genuine
SIGTRAP delivery, group stop/continue, 64 immediate children and non-leader
exec retain their actual final-status distinctions. Dropping the recorder
kills its owned descendant, leaves the unrelated fixture alive and refuses a
complete history. Both leases and all 298 worker records remain intact. The
19-member public export is `native-trace-vm-results-002.tar`, 163840 bytes,
SHA-256 `bdf0ae50e8875c1367c3623e4f7a7c3fdc14da3ff25955cf38d6141a312cb64e`.

The consuming Rust reader now replays creation parents, task IDs and start
generations, non-leader exec retirement, signal/early-exit/final status and
complete counts against the exact canonical hash chain and checkpoint. Six
unit tests include rechained impossible histories and changed kernel/image
fields; all pass, along with Mac and ARM warnings-denied evidence Clippy.
Actual exported-journal CLI readback and normal Native launch wiring are the
next steps. The reader explicitly keeps custody, descendant admission,
qualification and Guard causality false.
