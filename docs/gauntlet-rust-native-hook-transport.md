# Native hook and contained-sink transport

The new Rust profile `native-hook-transport-v1` is separate from the retained
`native-apparatus-v1` profile. Its closed declaration uses
`hol-gauntlet-native-worker-job.v2`, replaces `case` with `guard`, and binds
the exact Native source, package version, runtime bytes and bubblewrap bytes.
The source must equal the one-use job source. Command, path, policy, approval
and eligibility selectors refuse. Existing v1 declarations retain their
original shape and behavior.

Both permanent worker leases, the exclusive job/running journal, contained
Root Rust controller, fixed constructor, product actor and bounded cleanup
remain the existing worker's responsibility. A v2 report uses
`hol-gauntlet-native-worker-report.v2`. Every report and terminal remains
`invalid-evidence` and execution-ineligible.

`NativeHookPlane` checks the Root-owned installed metadata, actual fixed Native
executable and image's bubblewrap against the outside pins. It starts the
normal daemon, performs its readiness barrier once, submits the actual public
prompt and invokes normal OMP Pre/Post hooks inside the isolated product cell.
The Python response reader is reproduced over 64 source-pinned cases: 20
accepts and 44 refusals, with exact normalized values and protocol/refusal
classes. Nonzero valid denials remain denials; prompt protocol 2 and structured
mediation retain their existing rules. Original product capture bytes stay in
the Root supervisor journal/capture files.

Two explicitly versioned product-test adapters are retained under
`ci/gauntlet-rs/adapters`: installed identity and one normal workspace-readiness
request. Both run only as UID/GID 10004 inside the product cell. Rust owns
their invocation, deadlines, outside pins and response validation. The
readiness client's disposable credential remains internal to that normal
client. Neither adapter owns Root orchestration, service state, scoring or
admission. Their actual source hashes are recorded in the plane report.

The Root call ledger consumes each Pre identity before product forwarding.
Only an actual Native `deny`/`sandbox-required` response naming
`workspace-contained-v1`, outside observe mode, can request the normal
contained sink. This route supplies no approval; Native performs its normal
authorization again. The ledger freezes the original input and consumes the
route before any handoff or product launch. Failures stay consumed. Post uses
only that original input and the completed, captured sink output; SDK formatting
cannot replace the reviewed bytes. Pre, sink and Post replays refuse.

The Rust request handoff uses a fresh exclusive directory/file beneath a held
product-home descriptor, bounds the immutable packet, fsyncs and reads it back,
and verifies visible/held identities before invocation. Only the actual product
UID owns the final mode-0600 packet. Explicit cleanup refuses changed bytes,
links, replaced or renamed directories and surviving inodes. Missing names
count as retirement only with Linux's zero-link witnesses for both original
held inodes. Drop closes descriptors without silently removing uncertain data.
Mac tests retain a refusal where APFS cannot supply that Linux witness; the
required successful retirement check belongs to the actual Linux ARM tests.

The fixed initial diagnostic seeds the unchanged Python success-test bytes
from `deterministic_probes.FIXTURES.success` at source `62aa7ba7`. Rust writes
and reads them back as inert UID/GID-10001 task data before candidate execution.
The real Native sink runs the standard-library tests, including private-state
visibility and the pinned Node/npm closure checks. Rust then performs Post with
the captured result, checks replay refusal, drains the cell, reads the physical
effect through a held no-symlink descriptor and re-inventories the runtime.

This initial diagnostic is controller-generated and reports
`sdk_exercised:false` and `guard_causality_verified:false`. It does not retrieve
the delegated document through MCP or establish an actual SDK call. The
independent Native request/decision/effect relation, authenticated SDK ingress,
six staging/installed roles, fresh signed conformance and qualified deployment
remain open. No parent checklist exit closes from adding this transport.

The complete all-feature Mac workspace passes 435 tests across 217 targets,
with zero failures/ignores. Retained log
`rust-workspace-native-hook-transport-021.log` has SHA-256
`c0098b6c27e0910c144e30fa1c509f8d52bc4b03b612d9051d6455c0c1f898ba`.
Warnings-denied Mac/ARM64 Clippy, Ruff and ARM compilation pass. A mechanical
Clippy Boolean simplification follows that full run; the 64-case parity reader
is checked again before the VM inputs are frozen.

The first live v2 worker ran as job `e2c701baf1472101` from source
`e1eb0a1a567078d44ec57fd4bb852a897aa79ae6`. It reached the independently
observed pinned Native executable, then failed before any semantic hook:
the single readiness response was `{"ready":false,"reason_code":"invalid_workspace"}`
(SHA-256 `8deab129ddc1dbe74c4baee45b8cf279e0fdfed6b7fd6e60f2ad454da03e2768`).
The failed controller exited 2, all resources drained, and the runtime prefix
remained unchanged. Its worker report has SHA-256
`7d1375965821c807cf5b31da8c67bd10166e38ccf092f1e6fe039f91e892f401`.
The same generation's v1 success regression `e2c701baf1472102` passed;
the wrong-Native-pin job `e2c701baf1472103` refused before identity execution
or hooks and cleaned up. No job was retried or overwritten.

Current Native directory trust uses the daemon's explicit configured home,
rather than its `HOME` environment variable. The Rust adapter now passes the
actual fixed task home `/runtime/home` to the normal daemon, status, hook and
contained CLI. Guard state stays at `/product/guard`, and the public OMP config
stays at `/product/home/omp.json`. No path policy, approval or isolation rule
changes. Readiness captures are projected into the report before validation;
their complete original bytes already remain in the supervisor journal and
hash-bound capture files.

Fresh job `e2c701baf1472201` from `119f51b46e340069ee532417178d18bb01bcf361`
passed that exact five-field readiness barrier and its public prompt hook.
PreToolUse then returned `native_pre_tool_unavailable`; the Rust route ledger
refused to launch the sink. Report SHA-256 is
`c5ee8ebfebda35c529351a2b750253aaf7481f0897be1988369cde44288db147`.
The diagnostic had supplied an empty execution context. Native's typed
`GuardExecutionEnvironmentV1` requires `path`, `environment_names` and
`environment_digest`. The diagnostic now supplies the actor/exec-gate's fixed
four-variable context, with its canonical sender commitment and normal optional
fields. It remains controller-generated context with no SDK authentication.
The sink independently captures and reauthorizes its own environment through
the existing normal product CLI. Fresh job `e2c701baf1472301` now passes that
correction and the full prompt/Pre/sink/Post/replay/cleanup diagnostic. See the
[retained VM proof and inert reader](gauntlet-rust-native-hook-vm-proof-20261027.md).

The first three attempts are retained in
`native-hook-transport-vm-results-021.tar` (103 members, 1,095,680 bytes,
SHA-256 `cd3ee0eaf1c21a79396e21773b3c568abea7b6cb04668545e45aa431759bf098`).
Replay/reconciliation preserved all 18 original worker files and 24 earlier
worker files; the full 4,411-entry published prefix remained unchanged. The
host proof courier initially asked the v1 apparatus report for a v2-only
`prefix_unchanged` field; this caller error is recorded and the v1 job was
not retried. All exports exclude product state and private keys.
