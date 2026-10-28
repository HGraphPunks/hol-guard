# Host-pinned Rust Native diagnostic controls

The explicit v7 worker profile connects the Rust Native controller to a durable
host prelaunch key pin. It is under validation and remains a diagnostic:
`invalid-evidence`, execution eligibility false, Guard causality false and
zero model requests. No parent migration exit is closed by this implementation.

## Closed protocol and ownership

The deployment declares `hol-gauntlet-native-worker-job.v7` with profile
`native-host-pinned-control-v1` and one of the six existing deterministic
roles. Historical v1–v6 deployments and their readback contracts retain their
existing behavior. The v7 declaration cannot run through the historical
unkeyed entrypoint, and the keyed entrypoint refuses an unkeyed declaration.

The Root worker, while holding both worker leases, generates a fresh Ed25519
seed in an anonymous, private, sealed 32-byte memfd. It writes a keyed started
marker and public key sidecar before emitting the canonical prepared frame.
The Mac host compares job, product source, deployment digest and worker
generation with its outside pins, exclusively writes and fsyncs its private
pin record, rereads that record and only then returns the exact acknowledgement.

The worker verifies the acknowledgement, deadline, cancellation, lease and
retained key pin before creating the controller. It delivers the sealed key
only to the descriptor-bound Rust controller, through fixed descriptor 3.
The controller validates and consumes the descriptor, closes it, and starts
unprivileged product/SDK/MCP processes afterward. Its signed record includes
the exact prepared tuple, preparation digest, role, kernel-bound controller
PID/start ticks and complete diagnostic. The seed is never written to disk,
included in an envelope, exported or supplied to a product process.

The worker reauthenticates the envelope against its held key context and
matches the signed process identity to its actual controller. It writes a v7
report and keyed v2 terminal only after outside cleanup checks. The public
completion contains the exact started marker, sidecar, terminal and report;
it has a separate 16-MiB bound. The historical result reader keeps its
8192-byte limit.

The host opens its retained journal again, recomputes every record digest,
checks the complete identity and acknowledgement relation, and verifies the
signature under its previously retained public key. A fresh host process can
reconcile this completion without sending an acknowledgement or rerunning
the job. Unsigned rehashing cannot alter the signed controller identity,
diagnostic, role, preparation or prelaunch context.

## Host command

Build `gauntlet-host-native-control` from `gauntlet-host-state`. The caller
creates a private 0700 pin directory outside the VM and independently verifies
the owned Lima VM and installed Root worker. The installed guest path is
`/opt/hol-gauntlet/rust-native-host-pinned-worker-WORKER_SHA256`.

The positional interface is:

```text
gauntlet-host-native-control run|reconcile PRIVATE_PIN_DIRECTORY VM_NAME LIMA_SHA256 SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_SHA256 PREPARATION_SHA256 ROLE
```

The command holds and hashes the canonical Lima executable against its outside
SHA-256 pin, uses a fixed argv with no shell command interpolation, and checks
its held inode and bytes again after transport completion. The run exchange
is capped at 60 seconds; its subsequent completion wait is capped at 420.
Reconciliation uses a 60-second wait. The transport child is owned before
writing either request. A pipe error or timeout kills and reaps that host
transport while retaining any consumed host pin. Killing Lima alone cannot
prove guest cleanup, so a missing completion remains unresolved until actual
guest reconciliation.

The JSON result exposes both successful and failed authenticated diagnostics
as producer reports. It never turns a signature or successful transport exit
into independently scored Guard effects. VM identity, reviewed source,
independent physical-effect joins and current-source conformance remain
separate acceptance requirements.

## Interrupted pre-controller reservations

Wrong, oversized, lost, cancelled or expired acknowledgements cannot release
the controller. A reservation already written remains consumed. A separate,
explicit v7 repair can record that reservation aborted only when the original
outside prepared tuple and preparation digest still match and all of the
following hold:

- No running marker, controller stdout/stderr, report, terminal or other
  recovery receipt exists.
- The Root job directory contains only its original preparation and declared
  workspace; that workspace is the original private UID/GID 10001 inode and
  remains empty.
- No owned controller cgroup, product slice/stage, SDK/MCP container or scoped
  profile, product cell unit or product image lease remains.

The checks repeat under both leases before exclusive durable publication.
The repair receipt retains the public key and says `aborted`,
`never-released`, null exit, zero model requests and eligibility false.
It does not assert whether the host received an acknowledgement. It never
generates a replacement key, deletes a marker or permits replay. Existing v4
startup repair and historical controller repair cannot accept a keyed v7 job.

The Root repair interface is:

```text
gauntlet-vm-worker --repair-native-keyed-pre-controller-v1 SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 ORIGINAL_WORKER_SHA256 STARTED_SHA256 KEY_PIN_SHA256 PUBLIC_KEY_HEX PREPARATION_SHA256 REPAIR_WORKER_SHA256
```

## Validation and remaining work

The 2026-10-27 affected Mac run completed 405 tests across 192 launched
suites with zero failures and zero ignores. Its retained log is
`rust-native-host-keyed-mac-tests-002.log`, SHA-256
`c0499c855b8ca364e5b3787c5d772c1306c87f5c4e9b2ee1b8312677ff5bc44a`.
The original session ended before Clippy; the separate corrected Mac lint run
`rust-native-host-keyed-mac-clippy-004.log` passed, SHA-256
`01e5165c4222aa9ed9a9177fb89f8a8be6d82e42e784c07efcf61104ab5b9aba`.
The initial unused-expression lint failure remains retained as
`rust-native-host-keyed-mac-clippy-003.log`.

Tests cover signed pass/failure reports remaining ineligible, changed keys
and every outside context field, duplicate/oversized envelopes, forged
qualification, host restart and missing journal, unsigned rehashing of PID,
effects and acknowledgements, immutable host pins, larger native completion
frames and managed readback requests. ARM-only tests add real sealed-key
consumption, acknowledgement failure/cancellation/deadline cases with no
controller state, replay refusal, and recovery refusal for touched/replaced
workspaces, owner/mode changes, symlinks and changed public pins.

ARM warnings-denied Clippy and static unit-test compilation pass:
`rust-native-host-keyed-arm-clippy-004.log`, SHA-256
`3c05bee63a54cd8566793113a20c880eadd9c70b53d1d310d6ae85ad652e712d`,
and `rust-native-host-keyed-arm-build-004.jsonl`, SHA-256
`f95f920b5a5f191336b8cd53f0dbdb8b894ea9ba169200adf639c74009d673fb`.
The Mac host executable also builds successfully.

Root execution now passes 186 worker tests with the 24 existing ignores,
64 evidence tests, and 40 rootfs tests plus its subprocess case. The worker,
evidence and rootfs logs respectively hash to
`770ae71dd6abc4511c1eab21de6c184814e6da3d18e1974f436f5569d81aa927`,
`e843c308ccf45f32b5fd301a43b007f541a224393ea1a0ba04684a358021c622`,
and `690359ba4bfc07b7341d7e70a444c3bbc1a473b6b90066b89f7130608d70df1e`.

## Actual host-to-VM checkpoint

Runtime source `f53bc490f7483ad41a781d62dc4d0d2c6a47c6a9` is pushed
on the fork. The installed worker is 25,393,808 bytes, SHA-256
`49220338c4ecb412ec02c122e3711b740277b74a1ca760a7deea5c957970c9f7`.
The Mac host sender is 2,298,736 bytes, SHA-256
`51f0bb46490eff6825626e5266e9691d7521f50e7e08fe6713920d395cf6d815`.
The six-member input archive is 83,179,520 bytes, SHA-256
`f554628652863c1e03a53b94cab2346ca3cd671569c2322930fa6a9e8da0b435`.

All six fresh v7 jobs pass both the Rust host's retained-key
authentication and independent public-artifact readback:

| Role | Job ID | Root report SHA-256 | Outside samples |
| --- | --- | --- | --- |
| Success | `e2c701baf1475102` | `9db4288246e3f47f442ec5491a785ad63480b11230503e232e63cbbc70485e8c` | 66 |
| Input binding | `e2c701baf1475103` | `47b04b9caca697c0397199bc5566664be23dc2bf792c5dab207533b9544bc09f` | 90 |
| Injection | `e2c701baf1475104` | `31efb131ee33a38031001a1cb99ee8f5a98fd2f550f693bb88f54deb81621887` | 75 |
| Boundary | `e2c701baf1475105` | `783ab402b2115c6689c04aa165c0be423aa9b013a1f1e94f4b45ae5d8993f545` | 65 |
| Timeout | `e2c701baf1475106` | `69eacb8ddc945afefa6ec344b9cdf98af3ac305c1faad03b2ff1fbf4b8dea605` | 64 |
| Cancellation | `e2c701baf1475107` | `2657c493d6b73609e3b12419bc55fe00b6bd1364c26a356ff9154f5e3a101340` | 60 |

Each uses a fresh public key actually retained in the private Mac journal
before the Rust acknowledgement. Readback checks the signature again under
that outside key, the Root controller's actual ELF/argv/PID/start ticks and
cgroup, SDK identity/requests/results, Native captures, MCP transcripts and
physical SQLite/task artifacts. Input binding checks all nine malformed
requests and the unchanged trap. Injection checks the source-pinned catalog
payload through the provider, Native proxy and SDK. The payload is forwarded;
no model-resistance or MCP-withholding result is inferred. The separate
forbidden-command probe and positive deletion/reseed counterfactual pass.
Boundary checks the three original canary inodes/bytes, positive visibility,
six path refusals and two network refusals. Timeout binds the actual 124
capture to the SDK error flag/content and real PostToolUse, held-child death,
unchanged ready bytes and closed overlay/lower absence. Cancellation binds
the Root request to held readiness and child death, preserving the missing
SDK result and Post. All 284 worker files through these six jobs remain
unchanged. The final outside inventory confirms no owned controller cgroup,
product slice/unit, or any of the seven jobs' SDK/MCP containers and scoped
profiles remains.

All six distinct outside keys and completions also pass the passive Rust
verifier. A success completion presented for the input-binding job refuses.
The six-role index is `native-host-keyed-all-six-proof-001.json`, 3,826
bytes, SHA-256
`fffb2f7fac27508353ac1377fbbe3423f40f71aa3a2251bc96f0b8ece8443fa7`.
It records 420 outside kernel samples and explicit ineligible flags.
The final 284-file worker map hashes to
`e85147012c78319b05420b1f164e318783af50645c8e9b29183da42054ae9158`.

A fresh Rust host process reconciles the success completion byte-for-byte
and refuses wrong role, preparation and source context. The new passive
`gauntlet-host-verify-native-control` command also accepts its retained
completion and refuses missing terminal, a qualification claim, substituted
signature, rehashed effect data and a rehashed controller PID. This command
uses only the existing host journal and public completion file:

```text
gauntlet-host-verify-native-control PRIVATE_PIN_DIRECTORY COMPLETION_JSON SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_SHA256 PREPARATION_SHA256 ROLE
```

Its bounded regular-file reader refuses symlinks, hardlinks, empty and
oversized files. The focused test, warnings-denied Clippy and build pass.
The tested executable hashes to
`c803605075ff4a4ed1704d09b2f4d135a94040a413939eb9fb2ba68f50cfc844`.
It grants no execution or qualification eligibility.

The negative courier initially expected an incorrect prepared-schema name
and closed the connection before supplying any acknowledgement. Preserve
that failed courier as `native-host-keyed-ack-refusal-001.py`; it is a
lost-acknowledgement case, not a completed invalid-ack test. The outside
prepared hashes match the retained Root reservation
`e2c701baf1475101`. Rust repair rejects a wrong outside hash, records
`aborted/never-released` with null exit, returns the identical receipt on
restart, and refuses replay. The normal terminal remains unavailable.
The repair receipt hashes to
`99cd622fbcda69344cabd387230ffcf313580c4f32183b127bc8f6a11ea70fc4`.
The initial atime-comparison installer failure and export-copy ownership
correction are also retained; neither changed a runtime verdict or archive
content. The exporter reads only fixed public files and synthetic fixtures.

Evidence is retained outside the repository under
`../gauntlet-rust-pr-ready-evidence-20261026`. The independent
`verify_native_host_keyed_control_20261027.py` reader pins each archive,
source and courier; the historical input-binding and injection readers still
accept their original immutable proofs after the shared helper extraction.

These jobs use the historical product candidate `62aa7ba7` and do not supply the
required current-product-source staging/installed conformance set. All
qualification, Guard-causality and outside-key-admission flags stay false;
model requests remain zero. Parent exits remain 24/62. Complete independent
Rust role scoring, complete crash/restart authority, current-source publication
and twelve fresh conformance runs remain open.

The subsequent [Rust binding artifact verifier](gauntlet-rust-native-binding-artifact-verifier.md)
now independently recomputes the retained input-binding capture/physical subset
under the prior host pin, including actual restart and hostile-archive refusals.
It preserves the other roles' envelope behavior and all qualification limits.

