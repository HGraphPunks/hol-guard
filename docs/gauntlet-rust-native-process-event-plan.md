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

## Launch v3 integration in progress, 2026-10-28

The closed supervisor v3 now requires `process_events: "outside-root-ptrace.v1"`
and both v2 interpreter/observer pins. V1/v2 declarations cannot opt into the
recorder or gain its fields. Root starts the recorder after measuring the
filtered actor and resource floors, before the private bootstrap or any spawn
RPC. Held actor/gate reads accept a trace stop only when the kernel's
`TracerPid` matches the recorder's actual thread; old untraced reads keep
their original contract. A stopped initial actor must remain single threaded.

Cell shutdown stops the owned unit and drains the recorder before declaring
cleanup complete. The separate checkpoint is recorded once in the main Root
journal and exposed only through Native hook-plane v2. A lost or incomplete
recorder leaves cleanup uncertain and cannot manufacture a complete history.
The consuming reader requires the signed main journal, exact file generation,
early actor/start ordering and one matching stopped exec for every held gate.
The old launch and plane versions retain their output shape.

At launch source `cc3ce245`, all 579 Mac migration workspace tests pass, with
zero failures or ignores. Mac and ARM all-target/all-feature warnings-denied
Clippy and Rustfmt pass. All 27 focused Root ARM cases pass, including real
process graphs and the signed trace/lifecycle joins. The new verifier also
reproduces all 32 historical control-mode outputs byte for byte. The initial
Clippy owned-string comparison failure remains retained; the correction
parses the string-typed kernel tracer ID without changing its meaning.

Fresh zero-model Native control `e2c701baf1475403` uses that Rust worker and
launch v3 with the explicitly older product image `9f42d9dd` (3.58.0). Its
contained unittest exits zero, but the SDK correctly withholds output when
the Native Post response reports `native_hook_render_unavailable`. The
authenticated controller record reports `failed`; the worker terminal stays
`invalid-evidence`. The independent Python sampler also fails at its existing
128-observation bound, retaining 129 observations and its assertion. Neither
failure is waived. Native `serve-managed` groups abort with SIGABRT and restart;
the pressure record peaks at 121 tasks and reports zero pids-controller limit
events. This run does not establish why Native aborts or rendering fails.

The Rust recorder itself closes a complete 2678-event, 1191173-byte journal:
559 created tasks, 559 actual final waits, 152 execs and zero exec retirements.
Frozen reader `a0439880` independently accepts that actual Native history and
its byte-identical restart, and refuses a wrong outside pin, truncation and
a false final-wait count. The export's Root file-generation metadata matches
the signed-plane checkpoint and its main-journal close record. This replay
does not admit process custody, an outside observer or complete Native image
grading. Every qualification and Guard-causality flag remains false.

All 298 prior worker records remain unchanged under both leases. The final
305-record baseline is retained at
`/var/lib/hol-gauntlet-rust/native-process-launch-proof-20261028-001-success/final-worker-hashes.json`,
SHA-256 `0eeba1d487fefbaf1e97ddc427e7be92e597e70347d7b4bcb2165663a9288414`.
Future mutating couriers must preserve this set. The public export is
`native-process-launch-vm-results-001-success.tar`, 3891200 bytes, 157 members,
SHA-256 `dca33128e9b01e9edacca87cf509442f3c6de620f3ff99f314b1e543e290a0dc`.
Its full member index is checked by the inert
[`verify_native_process_launch_trace_20261028.py`](../ci/gauntlet-rs/proofs/verify_native_process_launch_trace_20261028.py)
courier. Its five-case proof is
`native-process-launch-trace-readback-proof-001.json`, SHA-256
`203214ce04a9ec572bf475d2d8807edcce168418fcea3d7085e3202b8d9d54d0`.
The 32-case legacy proof is `native-process-launch-legacy-proof-001.json`,
SHA-256 `ad00068a4a7e8cc500b2e7671ce528250bb153831070bf3b1d545642da3d681c`.

The 579-test, Mac Clippy and ARM Clippy log SHA-256 values are respectively
`5f8ae11720248158721fb029b2f61ea8c1a176dd87b958784fffcb4b1ce0d985`,
`b2c7712601065e5d5b0d85ae12a72507e300dc4d15497096135df2171448fc9a`
and `9be2ef24b0da8c8168cc81f9ac665e9038df1e6d72570b9496e8431b576c3dba`.
Successful Rustfmt has the empty-log SHA-256 recorded above. The earlier
fixture/readback proof remains tied to its recorded sources. Complete Native
image/effect grading, outside admission, a successful source-matched Native
control and all parent exits stay open. No resource ceiling, output safety
criterion or inference quota changes.

The first live history measured 3283186512 executable bytes across 152 execs.
A metadata-based reuse attempt at `b434ab73` passes all 583 Mac workspace
tests and Mac/ARM warnings-denied Clippy, but the Root ARM proof catches an
unsafe same-size mutation: filesystem timestamps can remain unchanged across
a rapid write. That attempt passes 35 cases and fails one; its complete
35-member export is `native-trace-image-vm-results-001.tar`, 194560 bytes,
SHA-256 `116928dcf6ffb06b3aa835a85a76af80dc61da19a3e10b5bbd92d0bfd69f0646`.
Both leases and all 305 worker records remain intact. The failed implementation
and proof remain in history; the reuse path is removed in the following change.

The corrected implementation hashes every stopped executable through its
actual held descriptor, including repeated Root-owned inodes. It uses the
existing accelerated SHA-256 engine and retains no executable descriptors
between execs. A same-size Root mutation regression must read the changed
bytes without depending on a timestamp difference. Hash/read bounds, image
output and grading criteria stay the same. At corrected source `e98f4887`,
all 583 Mac workspace tests, Mac/ARM warnings-denied Clippy and Rustfmt pass.
All 36 focused Root ARM cases pass, including rapid same-size Root writes,
inode replacement, ownership/permission changes, read-only close-on-exec
inputs and 256 repeated measurements without descriptor retention. Both
leases and all 305 worker records remain intact. The 35-member passing export
is `native-trace-image-full-vm-results-001.tar`, 194560 bytes, SHA-256
`67d04460ae2587fe234fdf308c6b70eb1dcc4bdcf62cd45026e37c14d76d49e2`.
The independent inert
[`verify_native_process_image_hash_20261028.py`](../ci/gauntlet-rs/proofs/verify_native_process_image_hash_20261028.py)
courier checks all 70 members across the failed and corrected exports, source
and binary pins, Root metadata and every test log. Its proof is
`native-process-image-hash-readback-proof-001.json`, SHA-256
`5c297b9dcba6578c9c54442f5546fd816a6d9450894b107d06d6c6c54d3d7753`.

The corrected 583-test, Mac Clippy and ARM Clippy log SHA-256 values are
`622145063de005a031e24c35410b7451f2c81366368d33991a1d8e1efbcf46e3`,
`f095a883645734b2baaf1184be3851395166be62d203a9a052fb837389b668cf`
and `741b199a472939a09e01883c12737185a8d3e8ea1eb814371082400e8ff3c713`.
A new Native control is pending; no live performance or failure-resolution
claim is made yet. No parent exit closes.

The outside proof sampler now has an explicit v2 declaration with a
2048-observation limit, 32768-byte argv limit and unchanged 128-MiB executable
limit. It fails before dropping a new observation when full and retains the
error. The Rust consumer requires those exact limits, the outside source pin,
an empty error list and closed v2 fields. Only traced launch v3 can consume v2;
historical v1/v2 launches retain their old sampler contract. The v1 sampler and
its failed 129-observation history remain unchanged. This is still an inert
Python VM proof collector, with no runtime, verdict or admission authority;
outside observer/key admission remains open. Capacity, overflow, changed
limits, unknown fields/versions, wrong pins and launch-version refusals are
covered by focused Rust tests. Native rerun and full-slice validation are pending.
All 111 Mac evidence tests and Mac/ARM evidence warnings-denied Clippy pass.
The first compile attempt exposed two remaining legacy callers of the private
parser; both now use the launch-aware entry point, preserving v1 behavior.

At v2 source `8adf90cc`, all 585 Mac workspace tests, Mac/ARM all-target/all-feature
warnings-denied Clippy and Rustfmt pass. All 41 focused Root ARM cases pass,
including the five sampler-version/capacity cases. The current Mac verifier
reproduces all 32 historical outputs byte for byte; that proof is
`native-kernel-v2-legacy-proof-001.json`, SHA-256
`a93013f83bb247be1f1cf7d3961083059139c40363a1191ab58da8c9f3c095d6`.

Fresh zero-model control `e2c701baf1475404` uses this worker, full executable
hashing, the new outside observer pin and the explicitly older `9f42d9dd`
product image. The sampler retains 88 observations with no errors, and the
SDK receives the exact Native-reviewed original output. The control still
fails: its contained unittest observes `npm --version` aborting with SIGABRT.
Outside pressure records a peak of 128 tasks and one pids-limit event; a
separate bounded kernel read confirms a fork rejection in this exact product
cgroup. The Python daemon reaches 61 threads and a Native resident uses 29.
This supplies evidence for reviewing fixed worker-pool sizing; neither the
resource ceiling nor the benign fixture is weakened. After cleanup, no UID
10004 process remains anywhere in the owned VM. Both leases and all 305
previous worker records remain intact.

The Rust recorder closes 2333 events, 1022376 bytes, 460 tasks, 460 actual
final waits and 138 execs. Frozen reader `a0439880` accepts this actual history
and unchanged restart and refuses three changed inputs. The public export is
`native-kernel-v2-vm-results-001-success.tar`, 3297280 bytes, 158 members,
SHA-256 `222e982e883e3d0dbbf94db486699a9b73dc4ccaec9ea024b7d5fff9a23406fd`.
The inert
[`verify_native_kernel_v2_trace_20261028.py`](../ci/gauntlet-rs/proofs/verify_native_kernel_v2_trace_20261028.py)
courier checks every archive member, Root checkpoint metadata, declared sampler
limits, retained failed status and exact reviewed output digest. Its five-case
proof `native-kernel-v2-trace-readback-proof-001.json` has SHA-256
`ce8b586890e6f160176bf540acf45ef17fdca5017dbba7f2aae46d9422b1faa9`.
This is still an authenticated failure, with an `invalid-evidence` terminal;
neither complete Native grading nor outside admission is claimed.

The 312-record baseline at this stage is
`/var/lib/hol-gauntlet-rust/native-kernel-v2-proof-20261028-001-success/final-worker-hashes.json`,
SHA-256 `5530c850da1b4dd4d43052c3189e568dd26a14dc4ddff8db148e3f2d2a7b5383`.
Later mutating couriers must preserve these records. The full Mac test, Mac Clippy
and ARM Clippy log SHA-256 values are
`49b46619c7dd636ca23ea4172f67ccc973bef7350814c428009bbc5a9e60b3b3`,
`dd9a139f74f661dbfa80cf4ed87873aaefed7061d05ab924635ed777f6263229`
and `b651659ed3550dcb9e6fa92f305c03c9384f8b23a3482cde324e74e9ca55d6e5`.
All parent exits, final-source controls, task-pressure resolution and admission
remain open. No model request, quota reset or production-gate change occurs.

## Merged product and traced controls, 2026-10-28

The [merged-source runtime proof](gauntlet-rust-native-pressure-runtime-proof-20261028.md)
records the CPU-aware Native worker budget, exact product/tool source
`dc3b9336`, upstream `73b48265`, fresh 187-test build, locked dependencies,
all 36 inert publication cases and independent complete-prefix reconstruction.
The old product prefix and every failed control remain immutable.

Fresh benign controls `e2c701baf1475601` and `e2c701baf1475602` both pass
the unchanged real Node/npm fixture. Their product task peaks are 108 with
no PID-limit rejections under the original single-CPU/1-GiB/128-task limits.
Root traces close 393/393 and 392/392 created tasks/actual final waits.
The first polling sampler records an assertion after 57 observations; the
failure remains unresolved and receives no complete-observation credit.
The second adds bounded error tracebacks while retaining all assertions,
and completes 70 observations without errors. It does not reproduce the
first failure or establish its cause.

Rust accepts actual/restart trace replay and refuses three corruptions for
each control. The second also passes all nine signature/MCP/process/hook/
control/restart/refusal cases. It joins all nine gates, four actual Native
clients, three acknowledged hook inputs, three raw SDK frames and eight
complete output captures. Both negative probes are independently observed.
The second full artifact output and repeat match byte-for-byte. Internal
Native request bytes, effect-writer attribution, complete descendant grading,
outside observer/key admission and all twelve final-source roles remain open.

The latest 326-record baseline is
`/var/lib/hol-gauntlet-rust/native-pressure-control-proof-20261028-002-success/final-worker-hashes.json`,
SHA-256 `16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be`.
Future mutating couriers must require this exact set until a new owned job
adds records, while preserving every historical record. Cleanup readback
finds no remaining UID-10004 process or thread. Complete Native qualification
and all parent exits remain open; no inference or production change occurs.
