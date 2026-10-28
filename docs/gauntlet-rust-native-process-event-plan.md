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
Attempt 002 below supplies the native rerun. The failed public export is
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
At reader source `a0439880`, all 30 Mac readback cases pass: the four actual
complete fixture journals, four byte-identical restarts and 22 refusals. They
account for 74 tasks, 73 final waits and one explicit exec retirement, without
turning that retirement into a final wait. Rechained missing-child, wrong
parent/generation/exec/cgroup/tracer and false-completion histories refuse;
changed checkpoint custody, truncation, outside pins and a lost recorder also
refuse. The retained failed unit attempt gains no invented checkpoint.

The same source passes all six replay unit tests and all 30 CLI cases natively
as Root on ARM. The eight positive executions reopen the unchanged original
Root-owned journal/checkpoint files and match Mac output byte for byte.
Independent host readback checks the 96-member public export, all executable,
input, log and filesystem pins, both leases and all 298 unchanged worker
records. This is a focused native fixture proof; normal Native launch wiring
remains pending. Custody admission, complete Native descendant grading,
qualification and Guard causality remain false.

| Frozen executable | Bytes | SHA-256 |
| --- | ---: | --- |
| Mac reader at `a0439880` | 2026752 | `1758bdfb925169ef31279d8a9d431dda502ee86914d09ca91f049c35c03a2c61` |
| ARM reader at `a0439880` | 1418888 | `50643b3da4c075e0b6c0461ca4323b2c779a2fec268e03a913288baaaa028db6` |
| ARM replay unit suite at `a0439880` | 22571448 | `cb27ec04d308b8a0ca9f599adfaa1bde3ae4d2bd94fa1520347740d9ff8d765c` |
| ARM recorder unit suite at `0259fa90` | 10625736 | `ff72932a23882d4ea950a8bc8c23d7cc141a330c3a3f6638cbb5b707e34fad81` |
| Unprivileged Rust fixture | 687152 | `af615c1906d3cd76cc8714e6409e30676efe61b90b65a820b8555401e650537a` |

Evidence is retained in the workspace's
`gauntlet-rust-pr-ready-evidence-20261026` directory:

- Mac proof `native-trace-readback-proof-001.json`, SHA-256
  `f2785942250368c50ed9932f0917828f0b91362121989c8efce694ca79b51fb2`.
- ARM export `native-trace-reader-vm-results-001.tar`, 153600 bytes, SHA-256
  `1f8ccafb3259fa9d0f5ea213791862dc1bd49c654844b144c988d3ca6a9df0b5`.
- Independent ARM readback `native-trace-reader-arm-readback-001.json`, SHA-256
  `fe983e53b6f3f7ce890a5212d98aa0ae04669d1e20cef91ce6cad7d2ef3d6b63`.
- At `a0439880`, all 571 migration workspace tests pass without failures or
  ignores. Mac and ARM all-workspace/all-target/all-feature warnings-denied
  Clippy and Rustfmt pass. Their log SHA-256 values are respectively
  `4eba0835b19573c255f6f404f8d7894631de129a00812b7591778d021e5dcde1`,
  `7d6d9c34ab37f66654607c96b66da690a44f02b0250b62bb127ac0271861264c`,
  `2e6a6e082fe521271bd0bb95c8cbe33a6bf235db7368fd51689c585d721c6db7`
  and the empty successful format log
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
  The first workspace attempt's denied Unix-socket bind remains retained;
  rerunning with authorized host socket access changes no test criteria.

The inert proof couriers are
[`verify_native_process_events_20261027.py`](../ci/gauntlet-rs/proofs/verify_native_process_events_20261027.py)
and [`verify_native_process_events_arm_20261027.py`](../ci/gauntlet-rs/proofs/verify_native_process_events_arm_20261027.py).
The Rust reader owns replay and refusal decisions. No model request, worker
quota reset, resource-ceiling change or production-gate change occurs. The
62-parent checklist stays at 24 complete; this closes no parent exit.
