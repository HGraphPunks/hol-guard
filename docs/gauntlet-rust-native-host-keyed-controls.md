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

Root execution of the new tests, fresh actual host-to-VM
delivery, interrupted acknowledgement repair, restart/substitution proof and
independent live readback are still pending. This document records
implementation and completed local evidence only. All six source-matched
qualified role records and the twelve-run staging/installed conformance set
remain open, as do the other parent migration exits.

