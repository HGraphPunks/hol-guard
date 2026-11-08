# Outside Native client pipe capture

Status: syscall metadata, transfer accounting and the initial outside pipe
snapshot producer are implemented after
verifier checkpoint `98a544f3` and published evidence checkpoint `5ddb5d52`.
The live ARM syscall ABI and pipe fixtures pass in the owned VM. Independent
Rust snapshot replay, framing and signed launch-v4 integration are implemented
and pass 615 macOS workspace tests and Mac/ARM Clippy. A fresh
[launch-v4 Native control](gauntlet-rust-native-stdio-live-proof-20261028.md)
passes with 12 streams and 497 complete frames, reproduced independently on
Mac and ARM. Atomic wire observation and request semantics remain open.
The existing image-lineage proof
does not observe internal Native request bytes. All parent exits remain 24/62.
The latest owned-VM worker baseline has 333 records, preserving all earlier
326 records, SHA-256
`f7e44a5879bfbd8bd19097fc5b81927dfe93103b8db330813266bf25ad327a9d`.

## Root-owned pipe transport checkpoint, November 8

An opt-in launch-v5 component now relays actual kernel pipe bytes through
Root, separately from the historical launch-v4 memory snapshots. Its retained
live job has 43 complete sessions, 317,818 read bytes and five framed Native
clients: 154 complete requests and 154 complete responses. Independent Mac
and ARM Rust replay produces the same 87,064-byte summary, SHA-256
`d04c8102d1bff5043fc5a88542a61f5e0cdcffa0b4bb546bd161a57710cf7aaf`.
The other 38 sessions remain opaque one-shot exchanges. This closes no parent
exit: signed custody, source/preparation admission, exclusive physical writers,
complete operation semantics and request/decision/effect grading remain open.

The live producer is working-source-013, SHA-256
`2a356cc395e3641a2ca1a49fbcefb8f7f8755b16121ed5d28e63469569354dfd`,
over `c03764adb869628a56264d9da954ae20ec29197c`. The installed product is still
3.59.0 at `74d8d00814bfb281e4cf8a8823b083b3656db9bb`, Native SHA-256
`1d37eae8106ba062dcf2963cd3b386cce945e899873695356e2a52401ed07be1`.
It predates the current repository source. Working-source-015 additionally
preserves signal-handler errno, leaves shell launches alone in the thin
adapter and aligns the independent reader's path bound. Its exact source
manifest is listed below; the live job must not borrow that later source pin.

### Ownership and closed contracts

Launch `hol-gauntlet-cell-supervisor.v5` requires
`outside-root-native-pipes.v1`, `outside-root-ptrace.v1` and the actual Native
digest. Rootfs v2 pins a separate Root-owned configuration at
`/etc/hol-native-wire.v1.json`; hook-plane v4 reports the separate pipe journal
and launch-adapter digest. The older launch, rootfs, snapshot and SDK contracts
keep their behavior and false authority flags.

The unprivileged connector runs in the existing product-cell executable. It
hands Root exactly four anonymous pipe descriptors, waits for acknowledgment,
closes every sender copy and releases a separately measured Native exec gate.
Root binds inside the held product network namespace and authenticates actual
UID/GID 10004 peer credentials, executable images, ancestry, task generations,
cgroup, namespaces, enforcing profile and pipe objects. The endpoint name is
not an authentication secret. Root independently checks sender descriptor
closure before changing shared open-description flags or forwarding bytes.

Python retains automatic bundled Native selection, its manifest and the actual
Core digest used for policy snapshots. A small unprivileged adapter routes only
direct subprocess launches of the exact configured Core through the connector;
it does not implement policy, hashing, durable state, grading or publication.
Selecting the connector as the Native identity was tried and correctly refused
by Native's policy-snapshot digest check; that failed history is retained.

The Root pump bounds active sessions at 16 and total sessions at 1,024, uses
64-KiB buffers per direction and a 32-MiB source-byte limit per session, and
honors cancellation and deadlines. Every read, accepted write prefix and real
read-zero EOF is journaled. Input forwarding requires the original live target.
Already-read output can drain after exit while retaining the exec-generation
check; buffered output does not require a still-live `/proc` task. The shared
descriptor primitive also replaces the legacy SDK handoff's duplicated code.

### Independent replay and retained failure

The existing `gauntlet-native-process-events-verify` executable accepts a closed
`hol-gauntlet-native-pipe-replay.v1` input through its existing four arguments:

```text
gauntlet-native-process-events-verify PIPE PIPE_SHA256 REPLAY_INPUT REPLAY_INPUT_SHA256
```

The pinned replay input contains the process-journal path/digest, complete
process checkpoint, pipe binding, expected wire configuration and connector
digest. Replay checks canonical hash chains, exact session phases, all selected
Native client exec joins, privilege floors, pipe objects, accepted byte prefixes,
offsets, drained EOFs and independently recomputed counts. Framing retains
partial or malformed streams explicitly. An empty owner grants no byte credit.
Public pins alone grant no observer, signing-key or preparation admission.
The v5 control-artifact route is implemented in the reader checkpoint below;
fresh signed v5 export/control acceptance and outside admission remain open.

The hook/sink control in job `005` is **failed**, not passed. Its actual Pre response
requires `python-eval-readonly-v1`; the old one-use ledger requires
`workspace-contained-v1`. No sink, Post, physical effect or utility success is
credited. Supporting the current Native containment contract without changing
its decision or weakening the fixture is the next control-plane obligation.

The first five live attempts remain immutable under the owned VM's
`/var/lib/hol-gauntlet-rust/native-wire-live-20261108-001` through `005`:

| Job | Retained result |
| --- | --- |
| `001` | Debug constructor missed the unchanged startup deadline; no Native exec or pipe-session credit. Checked quiescent recovery removed its retained image lease. |
| `002` | Automatic selection ignored the executable override; identity refused, zero pipe sessions. Normal cleanup verified. |
| `003` | Override reached 38 complete sessions, then actual Native rejected wrapper-bound policy snapshots. Normal cleanup verified. |
| `004` | Bundled identity and readiness passed; late live-task checking rejected buffered output during Native exit. Checked recovery removed the image lease without altering failure history. |
| `005` | All 43 sessions and complete process history close; the full control refuses the read-only profile mismatch. Normal cleanup verified independently. |

No failed job is replayed or relabeled. Four Root leases serialize VM work.
Independent readback finds job 005's cgroup, rootfs mount, AppArmor profile,
image mount and active image pointer absent. All 333 historical worker records
and their lock retain their metadata; custom wrappers read none of their bytes
or keys. Current verification passes 692 Mac workspace tests, zero failed or
ignored, warnings-denied Mac/ARM Clippy and 15 measured Linux tests. The ARM
reader's exact executable and UID were measured at its post-exec stop before
its first instruction. Its replay scope drains without forced cleanup.

Evidence remains in the existing external directory under
`native-wire-20261108-tools-001/`; raw private pipe payloads are not reproduced
in this document. The later public-reader source manifest binds five necessary
new source files, no new crate, binary target or external dependency, and one
direct edge to the existing bridge crate. Existing test files are reused; all
changed Rust files remain below 500 lines.

| Evidence | SHA-256 |
| --- | --- |
| `working-source-015.json` | `5c3c907e5a0b46c206254d3b7b6d17b4098f4eac5b5694a75fd2f87ad3072e5c` |
| `mac-tests-002.json` | `688b7f140c2adb9b85a2e4629e02e87bfdd144d696f0da4555206feac9b8fbef` |
| `mac-clippy-003.log` | `b53e652d247680d6bc1ef025da7676f59a70e48542b0f82107943dd0e1e84fa7` |
| `arm-clippy-015.log` | `2148d8109a1b0cfe22ffea578204b1d1906d33a5e1a6a0b8497c29f4fcaf5b80` |
| `arm-unit-tests-005.json` | `2ba101945acef4198ecf67532cd66c5a3d0eaf6e5610c740af1ac01ec3ef4117` |
| `independent-pipe-replay-001/host-replay-002.json` | `edc5d46c3d77321546373b46cd282cd2a13cc28532ca697a377aa921b40f7079` |
| `arm-reader-replay-001.json` | `f685a3c635b01072785f379b8ec4fe0bd8b39fa389c8ceef50cfdfa58caee69a` |
| `live-closed-readback-005.json` | `1e2a4c7fac9998bc4d3c793206115e8ca07408c10a6dce57a05f566cf16d0b28` |

Component commit `734338221` merges upstream `d01a43ae1` without conflicts as
`ff638012d`. All 31 incoming files and 38 component files retain their bytes.
The refreshed source map and current controller expectation pass 692 Mac
workspace tests and warnings-denied Mac/ARM Clippy. Matching Native library,
CLI and test targets compile on both platforms; the existing ARM musl warning
remains visible. Python and Rust independently agree on the new controller
digest `aac18d28…`. This controller is not installed, and the earlier live pipe
proof does not become a fresh merged-product qualification. See the
[upstream checkpoint](gauntlet-rust-execution-checklist.md#0-baseline-inventory-and-differential-corpus)
for exact records and source pins.

The next reader slice changes fifteen existing source/test files, all at most
499 lines, without adding a file, crate, binary target or dependency. V5 binds
the signed-report journal checkpoints to distinct Root file identities and
checks owner readiness before actor release and terminal closure after complete
process history. It recomputes the rootfs/configuration/supervisor/manifest
relations under the supplied preparation pin. Captures must use the reader's
exact embedded launch adapter. Each selected Guard CLI must join to its own
traced Native client and completed Root pipe session; the historical malformed
input exception remains explicit and cannot fabricate a client observation.
Legacy v1–v4 routes cannot borrow v5 fields or pipe journals.

Eight new tests cover these boundaries and refusals. All 700 Mac workspace
tests and warnings-denied Mac/ARM Clippy pass. Nine selected tests also pass as
UID/GID 65532 with no groups/capabilities and no-new-privileges in the ARM VM.
ELF `4549b69a…` is measured at its post-exec stop before its first instruction;
scope 014 is removed with zero OOM/PID-limit events and no forced cleanup.
All four leases and 334 historical metadata rows remain unchanged. The fresh
standalone reader reproduces the earlier 87,064-byte replay exactly.

These are inert artifact-boundary tests, not a successful fresh product run.
The current embedded adapter pin intentionally refuses an older WIP adapter.
Reported preparation relations do not admit the observer, signing key or
outside source; all those flags, request semantics and writer attribution stay
false. The read-only profile mismatch still blocks the full control.

| Reader evidence under `native-wire-20261108-tools-001/` | SHA-256 |
| --- | --- |
| `v5-reader-source-002.json` | `a666e5cf201f7cbd8ffaa44af1c6e90b4224cc6297fcbb74a11f8aa052e4b8cf` |
| `v5-reader-validation-001.json` | `93e9299db5ecdbeb0e54a9c12a153265ae20b5063d0f34181c5c1d3437fb0706` |
| `v5-reader-vm-tests-001.json` | `66a2dd823163696142142667def4484fa00825df0729f6381506a30e0f9486c8` |
| `independent-pipe-replay-001/v5-host-legacy-replay-001.json` | `508241fcdb49007088a4dc2afead4bd11a5a197e5acae07fcea6551cf0aa7b46` |

Model use and quota changes are zero. Remote evidence delivery, independent
review and all five current-head CI jobs remain required. The parent count
stays 24/62; neither the gate nor the observer cutover is enabled.

### Explicit read-only control checkpoint

Preparation `hol-gauntlet-cell-preparation.v2` explicitly selects
`control_profile: python-readonly.v1` and requires launch v5. Rust routes only
the exact Native `deny` / `sandbox-required` / reason/profile pair, consumes
the call before launch and retains Native reauthorization. A legacy preparation,
unknown profile, review, approval or observe response supplies no read-only route.
The full SDK role modes reject this new preparation until their fixtures and
grading have an explicit contract.

The inline v7 fixture keeps the plain command
`python3 -m unittest discover -s tests -v`. Its three tests require workspace
read utility, hidden Guard state and a refused workspace write. The fixed write
probe first runs successfully in the unprotected outer cell; Root checks its
held file, unlinks it and verifies retirement before Native Pre. After cleanup,
Root checks probe absence and exact unchanged fixture/marker bytes. Historical
write/Node/npm fixtures and their assertions remain byte-identical.

Fresh component job `006` uses source manifest `b2d1be88…` over merge
`fc8149d76b02bfcbfd2e2b4715343ddd1ef20c2f`, including upstream main
`5f0abeadc56dfb0ec57cfcbf13228921ad95950c`. Its product remains the explicitly
older `74d8d008` / 3.59.0 runtime. Native Pre selects the exact read-only route;
the normal sink then exits **126** with “could not enforce the validated Linux
execution boundary” before starting the tests. Post allows that error output.
The unprotected write and independent retirement/readback pass, but no utility,
write-refusal, full-control or causality success is credited. The exact failing
kernel stage remains unknown. The bounded kernel log contains profile load and
removal records, without a matching AppArmor denial; that does not identify or
exclude failures in other boundary stages. Never replay job `006`.

All 65 Root pipe sessions close: seven framed clients, 58 opaque exchanges,
470,846 bytes, 262 complete request frames and 261 complete response frames.
The unmatched request stays explicit. Mac and ARM Rust replay produce identical
144,288-byte summaries, SHA-256
`6b6bd192c4f99738a69c6465230b091a15fb416057fb2766159268d96edcf326`.
Complete process history has 525 created tasks/final waits and 81 measured
Native execs. Outside readback finds the product cgroup, profile, rootfs/image
mounts and active image pointer absent. Test/replay scopes 015–017 drain without
forced cleanup; four leases and all 334 historical metadata rows are unchanged.
Historical worker bytes and keys are not read.

All 703 Mac workspace tests, full formatting, warnings-denied Mac/ARM Clippy
and eight unprivileged ARM parser/ledger contracts pass. The first macOS Clippy
failure remains retained; its Linux-only getter now has the matching platform
condition. Native main `5f0abeadc` library/CLI/test targets compile on both
platforms, without product execution on Host or Root. This slice changes eleven
existing Rust files, adds no file/crate/target/dependency and keeps changed
modules under 500 lines except the existing 627-line export file, whose line
count is unchanged by one re-export edit.

| Read-only evidence under `native-wire-20261108-tools-001/` | SHA-256 |
| --- | --- |
| `readonly-source-002.json` | `b2d1be885594d75ef838beca7f36060e50e86a5c38b2fc0737d551cac427bf5d` |
| `readonly-validation-001.json` | `9d41ea5c585e61be247a14513a50c32d12fd8eee299c91cbbabbc9c305eda3ea` |
| `readonly-arm-unit-002.json` | `4fdefd1ada29b04b4176b3afa3912ab7ad8623d2d702fa01fd5fdfdeddc7a479` |
| `readonly-arm-live-001.json` | `1086c39491a150deb580d75d38f5e1fd8f31a34142ecce75c4bcce23a31df609` |
| `readonly-live-closed-readback-001.json` | `88ec37237fe2ba5303afe1d195e793aa70cad7ff134469da73818d28f31533cc` |
| `readonly-independent-replay-001/host-replay-001.json` | `1521a79984db6f6492a7b25c3118b54b1531cd335e88640377b0032d07125f1e` |
| `readonly-arm-replay-001.json` | `dc384928530c8a58d16d5ad7605b76e760dcb14f762edf5cfad607f486179ae0` |

Validation rechecks 38 evidence files. All six failed attempts survive; signed
v5 export/control acceptance, current-main runtime qualification, outside
observer/key/source/preparation admission, operation semantics, actual writers
and twelve-role grading remain open. Remote evidence delivery, five current-head
CI jobs and independent review are still required. No parent exit closes:
24/62 complete, all eligibility/causality flags false and model use zero.

Upstream subsequently adds the names-only environment scenario at
`1d7f8304dd04fafd202fae7855717c55872a6d47`, merged as
`f93ecd24d97829b6a1f3a74b36fa185d0b4989d6`. All eleven incoming files retain
their upstream bytes. The refreshed 440-file map keeps 79 changed/20 added
entries and changes only the scenario digest; its SHA-256 is
`2a36900e7f7661afe76aee4b3b13fd5987c8c9df391b3eda2a67b3d1d966f7bf`.
The original 420-file baseline remains unchanged.

The first merged workspace run correctly refuses the stale `aac18d28…`
controller expectation. An independent Python oracle evaluates only the
bootstrap's file-selection expression, imports no module and invokes no
installer. It checks all 409 hashes and eleven directory modes, calculates
`4e0af628dffecc9b7cf3471f56bed40209616e9651054db0a399b5afe4590c04`, and
reproduces the previous digest by reverting only the scenario file's hash.
Rust agrees after updating the existing test assertion. The initial source
records' claim that the controller was unchanged was incorrect; merged source
v4 and validation below explicitly supersede that field. All failed records
remain retained. No installed controller generation changes.

Merged source `readonly-merged-source-004.json` has SHA-256
`e25ac7ad41580831d655fcb54ef076d210f7652ed042432dfc803711c63b1291`.
All 703 workspace tests, full formatting and warnings-denied Mac/ARM Clippy
pass; Native library/CLI/test targets compile on Mac/ARM without product
execution. Validation `readonly-main1d7-validation-001.json`, SHA-256
`cb72b7bcded752dc1010c341852745a0473ebc97c3332681e46364d817128838`,
rechecks seventeen records, including oracle `f937328c…`. Only the existing
source map, test and three checkpoint documents need this follow-up. The live
read-only failure remains pinned to its earlier source and product; the new
source supplies no fresh runtime, utility or qualification success.

To identify the failure, the existing Native launcher now retains its fixed
boundary error in stderr after the original generic line, still returning 126.
It adds no retry, command execution or enforcement bypass. This is three lines
of diagnostic code in the existing module; its errors contain no paths or plan
bytes. Source `boundary-source-001.json` hashes to
`52f718a495454bfd6428930697b9aeec9a5f92c15efc33bd8f04364cf3950a15`.
All 703 tests, Gauntlet formatting, Mac/ARM Clippy and Native compilation pass.
Validation `boundary-validation-001.json` (`e1f3d824…`) checks eighteen files.

This source merges upstream `311d63cb2` as `99c233ad4`, preserving thirteen
incoming files. The new hidden-home scenario updates only its source-map hash;
the 440-file map/420-file baseline counts stay fixed. Independent Python and
Rust controller plans agree on
`f258113527755ecd7d46aa919ab816ba01efe390798c00769ced4cea51ca3609`.
The fresh build ID `ed8f9da0b49ebde2` is reserved; its preflight verifies worker
and image pins, four leases, an unused slot and 334 unchanged historical metadata
rows. At this source checkpoint no build has started and the new controller is
not installed. Runtime construction/publication and a fresh control are required
before the diagnostic can identify any actual failing stage.

After committing that diagnostic as
`6a764d42b0a566697c75c9a7ce768bfede92a555`, the primary Rust commands capture
and transfer build `ed8f9da0b49ebde2`: 63,345,255 bytes, archive SHA-256
`2131170e3d9cc6d402072ab7cb3481d2d84cf0f67b9e6d6a95645e19220a37dd`.
The new controller is installed as inert data and independently matches all
409 files/420 entries. The first readiness request carries the prior job's
rendered AppArmor hash and refuses before any Host pin, dispatch or candidate.
Readback proves that unused state. The corrected policy is independently
rendered as `c5163109…`; existing Rust context and policy commands pass the
load/remove proof, then readiness accepts the still-unstarted job. Attempt 002
is the first actual builder execution. The refusal and every observer failure
remain immutable.

Outside kernel readback measures container PID 434010/start tick 22643765 as
UID/GID 65532 with empty capabilities, no-new-privileges and seccomp, separate
mount/PID/network/IPC/UTS namespaces, and the source mounted read-only. Limits
are 12 GiB, zero swap, two CPUs and 512 PIDs. The actual label is
`crun//&hol-gauntlet-build-ed8f9da0b49ebde2 (mixed)`; kernel policy lookup
separately reports the exact job profile as `enforce` and `crun` as `unconfined`.
This component lookup follows AppArmor's [stacking documentation](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmorStacking),
which distinguishes the stack's aggregate mode from each profile's mode.
The earlier single-profile assertion remains failed, with its original bytes.
No global profile mode or security setting is changed.

Evidence under `native-boundary-build-host-state-20261108-001/`:

| Record | SHA-256 |
| --- | --- |
| `controller-install-001.json` | `d369bdd11e67ca39d0f4940d7a6767694d8d803e416b2c0d3bda90d1a52e62f4` |
| `source-transfer-001.json` | `cbf73384b817dc6bc76204aea961e7912e3598516b5b47e299c4e0051c728a37` |
| `prelaunch-refusal-readback-001.json` | `14c2df17a115bd46edf1eae08496583be193415e5030fba5cd2ff1d2f8b23e60` |
| `readiness-diagnostic-002.json` | `59079e7cca80ef3003cde95fb23539cbab1b5768757a731ab16fd6cfcc61e9d4` |
| `outside-kernel-004.json` | `588e96b8216adf5e1cfbd77ea0b47d2d36dc1b46496a7f29f92ffec56d82909e` |
| `preparation-validation-001.json` | `92bca3a281664f376822e3ad57d64205180b548097be871e4cc8a629b79dbb74` |

Build `ed8f9da0b49ebde2` completes in 1,520.117 seconds. The host-bound reader
verifies its result and export; the inert wheel reader checks all 1,639 entries.
Native ELF `9b605cbef8296071da173d2395b57bf4c21098a2c57fd2c50c173cbccd7cd392`
is 47,696,360 bytes. Fresh dependency job `d77d88039d6ada35` completes and its
full export verifies, but both live kernel observers miss its container; no
independent live-isolation observation is claimed for that job. Rust composes
and publishes the inert prefix at source `6a764d42b…`, tree `affb2c5f…`.
The build's Python contract report records 185 passes. Runtime publication
record `6a2a152b…` supplies custody evidence, not runtime qualification.

Fresh Native controls `007`–`010` all fail with exit 126 before the three
read-only utility tests run. The new fixed diagnostic identifies executable
mapping mount failure. Temporary kernel-only tracing records the first
remount returning `EPERM`. For job `010`, an independent reader holds the
Native pidfd and namespace descriptors and uses `NS_GET_USERNS` to measure
the mount namespace's owner. PID 451598/start ticks 23230372 join both
observations: Native has setup capabilities in user namespace 4026532459,
but mount namespace 4026532395 belongs to user namespace 4026532394.
Namespace inode values alone are not used to join separate jobs.

Cause record `mount-cause-001.json`, SHA-256
`001099680bb6a18446ed443d0d0b3d15b98fb1938ee03111e9a9a5279f54f8af`,
binds the mount failure, namespace-owner snapshot and closed-job readback.
All temporary observer source edits are removed and checked against HEAD;
their retained binaries remain diagnostic, with no observer-admission claim.
The focused fix in existing `restricted_linux_launch/pipeline.rs` creates a
mount namespace owned by the current user namespace and makes propagation
recursively private before enforcing mappings. An error stops before mapping
or execution. Read-only/noexec, sealed-image and capability-drop requirements
are unchanged. The first ARM compile rejects a direct unsafe syscall under
the crate's `forbid(unsafe_code)`; that failed record is retained. Corrected
source `mount-fix-source-002.json`, SHA-256
`4e62d792f59fbdf66ea6dab970a3812b5cc18fb17b5882a74b0a12f16641a6cc`,
uses the existing `nix` dependency's safe wrapper with Linux-only `sched`.
It adds no file, crate, target, dependency package or lockfile entry.
Corrected Native library/CLI/test compilation passes on Mac and ARM musl in
0.654/149.486 seconds, without product execution. Fix `d3c86f1d3` is preserved
by clean upstream merge `8a4266be7` of `ba94c2f00`, retaining all 31 incoming
files. The refreshed source map remains 440 files/79 changed/20 added. Independent
Python/Rust selection agrees on controller tree `7ae10140…`, still 409 files/
420 entries. All 703 Mac tests, formatting, warnings-denied Mac/ARM Clippy and
Native compilation on both platforms pass at the merged source (Native compile
204.638/133.541 seconds). Validation `mount-fix-merged-validation-001.json`,
SHA-256 `217f5705b705713572533ffa9ee78f0373f1a68a55f8ea166b30e2469b4c4cbd`,
binds 35 source files and ten evidence records. Fresh isolated build job
`05c2c0c7904fd554` is reserved with no dispatch, under
`native-mount-fix-build-host-state-20261108-001`. Its exact committed source
must be built and published before control `011`; the fix has no live success yet.
Never replay any consumed build or pipe job.

All 334 historical metadata rows are unchanged; their bytes/keys and private
Root build argv are not read. No product runs on Host or Root. All admission/
causality flags stay false, model use is zero and parent exits remain 24/62.

## Scope and implementation order

Capture the actual stdin/stdout pipe exchanges of source-pinned Native
`resident-client-stream` processes in the owned synthetic product cell.
Those bytes are distinct from the already captured SDK/controller frames.
Require the actual stopped Native ELF digest, fixed command shape, owned
task lifetime/cgroup, privilege floors and stable pipe endpoint identities
before selecting a process. Inspect only the selected pipe I/O buffers;
private files, resident keys and unrelated process memory are outside scope.
No target memory, register, syscall argument or approval decision is modified.

1. Implement bounded decoding of Linux syscall-stop information and transfer
   accounting, including entry/exit pairing, scalar/vector I/O, partial return
   counts, errors, signal interruption and actual death. Preserve old wait and
   process-history readers unchanged for legacy modes.
2. Extend the dedicated Root tracer with an explicitly versioned capture
   mode. Select syscall stepping only for the identified Native client stream,
   retain exit-kill ownership and distinguish real SIGTRAP delivery. Validate
   pipe identity around each relevant transfer; copy completed read buffers
   and the completed portion of submitted writes. Refuse unavailable, changed,
   oversized or ambiguous measurements. Bound memory, records, bytes and drain.
3. Add closed launch v4 and process-checkpoint v2, with mandatory Native digest
   and capture declaration bound before actor release. Keep v1-v3 behavior
   intact. Bind the separate Root I/O journal into the signed Native plane;
   no older report may borrow its fields or measurement credit.
4. Independently reconstruct framed Native requests/responses in Rust. Join
   each stream to its complete process history and gate, exact input/output
   byte counts and physical outer capture. Treat partial cancellation and
   timeout streams explicitly. Captured request bytes do not alone establish
   every Native helper's semantics, an effect writer or admitted custody.
5. Prove the mechanism with owned ARM scalar/vector/fragmented/short-I/O,
   signal/death, wrong digest/endpoint, truncation, overflow and lost-recorder
   fixtures. Then execute fresh source-pinned benign and negative controls
   under the unchanged single-CPU/1-GiB/128-task product limits. Preserve all
   earlier failures and the current public product prefix.

The first integration covers the Native stream client transport, whose pinned
entrypoint reads framed stdin and writes framed stdout. Other Native command
inputs and the authenticated client-to-resident connection retain their own
identity/semantics obligations; no blanket wire-verification flag is inferred.
No model request, quota reset, production gate or CI bypass is authorized by
this implementation step. Required CI remains user-owned and pending.

## Bounded decoder checkpoint

The first source checkpoint adds an AArch64 entry/exit decoder, scalar/vector
selection for stdin reads and stdout writes, eight-MiB transfer and 1,024-vector
bounds, completed-prefix accounting and poisoned entry/exit sequencing. The
metadata getter exposes no target-memory or register mutation. Nine focused
tests pass, as do all-workspace macOS and ARM Clippy and formatting. The full
locked/offline macOS workspace run passes 603 tests, with zero failures or
ignored tests. Its retained log is
`native-stdio-working-workspace-tests-003.log`, SHA-256
`2da4ed92cb1a6f7b29631d9ea0320790307c294bc4c67e8d56e2efe4ba5b026c`.
The new live fixture uses the existing pinned owned-process executable; its
intentional final exit is 97. No parent checklist exit advances from this step.

Source checkpoint `483c29a0823ab77c48ed593e9867fa382e15f5d5` builds the frozen
ARM test ELF (10,982,032 bytes), SHA-256
`26121816670af4f62fe0b68c1841014b4dd2207ce2747b2d055a9969125f099b`.
Under both worker leases, nine decoder tests and seven process fixtures pass
with zero failures or ignored tests. The live ABI test sees two syscall entries,
one exit and the actual final exit 97. It reads no target memory and executes
no candidate product. The retained public export has 25 members and 337,920
bytes, SHA-256
`61daa708d0253718b83bc626b10d79d60af89f37f72da7740c8536d8256ac256`.
Its host [readback](../ci/gauntlet-rs/proofs/verify_native_stdio_syscall_20261028.py)
checks every archive member, Root metadata, source blob, exact test count and
unchanged 326-record worker baseline. The separately frozen Rust process reader
also accepts four complete legacy fixture histories and refuses the retained
lost-recorder history. The readback output SHA-256 is
`c72343d13378655bb98f60ad8c9ee6787e6d4f53228f0c9469e257eab3815f56`.
This establishes the live metadata ABI; actual pipe bytes and all qualification,
custody, Native semantics and effect-writer claims remain unverified.

## Initial pipe snapshot producer

The opt-in launch-v4 contract requires `outside-root-ptrace.v2`, the fixed
`outside-root-native-stdio.v1` mode and an exact Native executable digest. Its
process checkpoint is v2 and its signed Native plane is v3. Older launch
contracts reject these fields; their tracing options and behavior are unchanged.
The product pin must agree with the launch digest before hook-plane startup.

Only the selected Native stream leaders use syscall stepping. The recorder
retains task lifetime/tracer ownership, actor namespaces/label, privilege floors,
exact command shape and distinct anonymous fd0/fd1 pipe identities. Each relevant
snapshot re-hashes the full executable and rechecks the held/current pipe
objects. `O_PATH` references add no pipe reader or writer. The private memory
backend reads only the selected scalar buffers or bounded iovec table/data.
It rejects partial memory copies. Read snapshots use completed byte counts;
write snapshots retain submitted bytes and credit only a successful returned
prefix. Failed/interrupted calls never invent bytes or EOF.

Bounds are 16 active streams, 1,024 stream lifetimes, 8,192 pipe calls, one million
syscall stops, 16 MiB of pending submitted writes and 32 MiB of captured bytes,
in addition to the existing per-transfer/vector and private-journal bounds.
Separate fixtures exercise actual scalar/vector parent pipe bytes, a nonblocking
short write, wrong ELF pin, descriptor replacement, oversized submission and
death during a pending read. Fixture selection exists only in the owned-test
build and declares its separate scope. The initial producer passes all 607
locked/offline macOS workspace tests (zero failures/ignored), formatting and
Mac/ARM warnings-denied Clippy. The full workspace log
`native-stdio-capture-working-workspace-tests-002.log` has SHA-256
`2c8599a3fb9d3b2d4a0792d90abd1f218a12d20a47d070c2e4f314826aab6f4f`.
Live fixture execution and independent v2 process/I/O readback were pending
at producer source `f137c1b0`; the frozen v1 reader refuses v2 checkpoints.

The first live producer attempt at `f137c1b0` retains six fixture-start permission
failures: the unprivileged executable was beneath a Root-only input directory.
Only the pinned fixture ELF was then copied to a new Root-owned 0555 public
location; private input/proof directories remain 0700. The second attempt
retains four passing cases and two failures. The synthetic driver's buffered
gate could consume payload before exec, and scalar/linger output lacked a
flush before direct exit or a blocking read. The follow-up waits for the
observed leaf exec before sending payload and explicitly flushes that fixture
output. Byte-comparison and refusal assertions are unchanged. The revised
fixture passes Mac/ARM Clippy and the macOS rootfs tests. Both original attempts
remain immutable in the owned VM.

Corrected fixture source `018890172c5a0976f9cad606bf55433d8be8a027` passes
22 owned ARM tests: nine syscall decoder cases, six pipe cases and seven legacy
process fixtures. Four complete pipe histories match actual parent input/output,
including the 4,096-byte nonblocking write prefix and an interrupted pending
read with no credited input or inferred EOF. Three expected refusals occur
before buffer copy. The histories contain 4,161 captured bytes. Both worker
leases remain held and all 326 worker records remain byte-identical.
The public export retains all three attempts: 82 members, 655,360 bytes, SHA-256
`e29a91ec9f5f356f76c0a74828a3124220fe2822e52a493d31280d737856c780`.

The independent Rust reader binds each stream to its actual exec and kernel
ending, validates closed event ordering and completed counts, and reconstructs
framed stdin/stdout separately. It retains partial headers/payloads, malformed
lengths and invalid JSON as explicit diagnostic results. Native request and
response bounds are six and two MiB, matching the pinned product source.
Four actual complete fixture histories verify; three incomplete/refused histories,
three wrong caller pins and re-hashed altered captured bytes refuse. The current
working reader's independent summary is SHA-256
`98bdc64fdec720d8eaf6b519f5853897c7d3605951c465a8ee3b9e9d89092d90`;
source hashes are retained before committing this verifier. All 615 macOS
workspace tests pass with zero failures/ignored, with log SHA-256
`e559ee8b21fa4880cb272516bb2b9d19267413ca197e0dd9c3c88b5b9dcb4fd8`.
Formatting and Mac/ARM warnings-denied Clippy pass.

Committed verifier `bd262dcad72278b58ae1059866a217acf366c90b` reproduces the
working reader bytes. Its 2,372,720-byte Mac stdio reader has SHA-256
`dd9ce2f5e7424e7ec96c71d9111f1434316d5e855a1ffbfb44e8dddb55cfbb80`;
its 3,567,680-byte ARM reader has SHA-256
`1bf6f2053a6c117d11ce12723d17adb7f6dd213b4a1e2ccf553b67e7fd3a2f39`.
On ARM, 27 focused stdio/process/signed-trace/image tests pass. All eleven
snapshot replay/refusal outputs match the Mac results byte for byte, as do
actual/restart/refusal checks against historical Native control `5602`. All
32 legacy control readbacks remain byte-identical with the committed verifier.
The ARM reader export contains 126 members and 1,085,440 bytes, SHA-256
`7fd4b64adaf380b004becedc9387fe959df6b4fa6002ec60105e4a7c4bc9c701`.

The [fixed-generation host verifier](../ci/gauntlet-rs/proofs/verify_native_stdio_pipe_20261028.py)
and [ARM proof helper](../ci/gauntlet-rs/proofs/native_stdio_arm_proof_20261028.py)
verify both public exports, all source/ELF/log/metadata pins, the retained fixture
and SSH failures, all 673 Rust source files against the committed verifier,
the 615-test source match, 32 legacy outputs and both unchanged worker leases/
record sets. A fresh Mac replay reproduces all eleven outcomes. The final
host readback output has SHA-256
`e7c9bd07f82f1baff1f9860176a0e60fcce0c9c62ed480c7fdb0b643e87c4a8c`.
The two long-inline-command SSH failures executed no installer; read-only
reconciliation found both destinations absent. The identical program then
installed successfully from hash-verified file bytes. No validation assertion
or permission check was weakened. No new Native product or model job ran in
these proofs. Fresh launch-v4 Native controls are next; request semantics,
atomic observation, physical writers and all parent exits remain open.

[`process_vm_readv`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
does not promise atomic transfers. The producer explicitly records
`concurrent_tracees_frozen=false` and `atomic_kernel_pipe_bytes_verified=false`.
Other threads can run between stops, and an entry/exit snapshot does not itself
attest the kernel's copied payload. Its read-only observations can support frame
comparison after independent replay; full wire qualification still requires
resolving that concurrency obligation. No parent exit, admission, approval
behavior or effect-writer claim advances from the initial producer.

## Kernel contracts and separate effect work

The [ptrace ABI](https://man7.org/linux/man-pages/man2/ptrace.2.html) provides
typed entry/exit syscall-stop information. `TRACESYSGOOD` must be established
before those stops. The decoder must reject unsupported architectures,
truncated records and unknown stop types. Reading information is separate
from mutation operations, which the collector does not expose. A stopped
task can still die; missing buffers remain unavailable evidence.
The [Linux 6.8 implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/ptrace.c)
returns through the final populated entry/exit field, rather than trailing C
structure padding. The initial decoder requires those exact 80/33-byte records
and rejects unsupported extensions. The pinned libc exposes the structure on
GNU; the musl backend therefore decodes the same fixed ABI from bounded bytes.

The existing staging fanotify collector supplies useful file and pidfd custody
helpers, but its post-close image sample is not an atomic writer-instruction
observation. [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html)
distinguishes modification and writable-close notifications, may merge events,
and does not cover changes through `mmap`, `msync` or `munmap`.
[PIDFD reporting](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
identifies a process lifetime; its combination with thread-ID reporting is
unsupported in the documented interface. A later effect collector must bind
actual object generations and process history, handle descriptor passing,
renames, missed/late writers and queue overflow, and keep unsupported writes
unverified. The new pipe observer supplies none of that writer credit.
