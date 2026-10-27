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
is checked again before the VM inputs are frozen. The first live v2 worker
execution remains pending at this implementation checkpoint.
