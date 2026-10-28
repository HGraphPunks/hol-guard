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
