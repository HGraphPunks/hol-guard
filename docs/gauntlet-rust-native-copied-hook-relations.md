# Copied Native hook request and decision relations

The Rust verifier now correlates five actual copied Native hook exchanges with
three acknowledged outer hooks and two contained-execution reauthorizations
in retained launch-v4 control `e2c701baf1475701`. It independently recomputes
the request identity, execution-intent identity and decision-receipt identity,
then checks the gate, exact hook payload, supplied caller context and returned
harness response. This extends the
[live Native pipe proof](gauntlet-rust-native-stdio-live-proof-20261028.md).
It is offline verifier work against the retained product; no fresh product or
model executes. The parent count remains 24/62.

These relations concern copied buffer observations. They do not attest atomic
kernel pipe bytes, concurrent memory, policy evaluation, the review anchor,
metadata-operation semantics, physical writers, complete role grading or
outside custody. All qualification, causality and admission flags stay false.

## Inputs and joins

The retained producer is `77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9`; the
actual product remains `dc3b9336308dab4892bf0c0e0f328a9c8b7efc12` and Native
ELF `bdaf053911cd278930c17e3c58b7741e23334a5156817db78780349f8635eb10`.
The independently pinned 147-member public archive is unchanged:
`24e4ab9b915d32c5d599553a1b38a460d8355e64109d5defb5a0bc07c35e9376`.
Each selected stream is already bound to its actual exec and kernel ending.
Its exec sequence additionally joins the complete Native image inventory and
the actual Root gate, with PID/start ticks, task ID and exact argv digest.

The three outer hooks are UserPromptSubmit, PreToolUse and PostToolUse.
Their Root input receipts bind the exact delivered bytes and handle before
release. The copied request removes only the documented root
`guard_execution_environment` field from the raw payload and places it in
the source context. When the outside input supplied that context, the verifier
requires exact equality. Locally collected context remains a product claim;
its opaque environment digest is not independently recomputed or authenticated.

The two contained PreToolUse calls require the same expected action plus the
explicit `guard_containment_receipt_only=true` field. Their own source context
is bound to each request identity. They join the contained sink's gate and
remain distinct from the three acknowledged outer hook deliveries. Cancellation
has no completed sink input receipt and receives no invented delivery credit.

For each matched pair, Rust checks the closed OMP edge envelope, policy
generation agreement, canonical event, inline payload, Rust authority label,
request/result/receipt identity and the exact normalized outer harness response.
The request ID omitted by the caller is derived from the request digest. The
copied response and receipt must contain that same derived ID. The authority
label and consistent digests do not authenticate the product's policy decision.

The identity implementation follows the pinned product's documented v3 request
and v2 intent dialects in
[`edge.rs`](../rust/crates/guard-runtime/src/edge.rs) and
[`edge_identity.rs`](../rust/crates/guard-runtime/src/edge_identity.rs).
Root event aliases and transport timestamps are excluded; nested tool arguments
remain bound. The OMP PreToolUse transport call ID is excluded only with a
nonempty session, preserving the existing retry contract. No approval or
product runtime behavior changes. Typed execution-context defaults are inserted,
and empty library-path maps are omitted exactly as the Native contract does.
This bounded diagnostic subset refuses floating-point and oversized integer
identity material instead of substituting the Python numeric dialect.

## Observed scope and validation

All 249 request frames and 248 response frames are counted. Five are matched
hook exchanges; 244 requests are explicitly classified as metadata operations
whose semantics are not verified here. A final `hook_direct_evidence_drain`
request in stream one has no copied response before the measured ending. Its
disposition remains unknown; no success, refusal or EOF is inferred. FIFO
correspondence uses the separately pinned
[`resident-client-stream` serial loop](../rust/crates/guard-runtime/src/managed_resident_client_stream.rs).
This is an explicit source assumption, with atomic-wire verification still false.

The public five-vector fixture is 43,259 bytes, SHA-256
`ba19d19e0300b52d66f79dff5f972d08a5fe7630bb969ada95b5b10ab14f59cc`.
It contains only selected synthetic hook requests/responses and their expected
outer inputs, with the original public archive and frame digests. Eight focused
tests cover all five real identities, swapped/changed receipts, nested action,
source/policy/event substitutions, retry metadata, typed-context serialization,
unsupported identity dialects and outer input/context/reauthorization changes.

The first focused run retains two failures caused by omitting Native's typed
execution-context serialization. The corrected implementation preserves the
original comparisons and passes all eight tests. A mistaken build-bin selector
also remains retained. A first local freeze attempt failed before writing an
artifact because its full stat equality changed; read-only reconciliation found
the destination absent. The final freeze checks stable content/identity fields,
source hashes and exact bytes, excluding read access time from that comparison.

The full locked/offline Mac workspace passes **623 tests**, with zero failures
or ignored tests. The retained log `native-hook-correlation-workspace-001.log`
has SHA-256 `ac9dc33f0113708f939ee0fd053d01e824136a496a20c67e7189f9a576d7ba29`.
The working source map, including all 677 Rust files, Cargo manifests/lock and
the vector fixture, has SHA-256
`57471354c0b49e79c6d469ddd105faee6407ae117d1b18ab0d971a3b81a9d9ca`.
Its base is `3c366e6926c4983892f00dca1931c28e937b2cbd`; the map binds the new
working bytes explicitly rather than claiming they existed at that base.
Formatting and warnings-denied Mac/ARM Clippy pass.

The 7,105,840-byte frozen Mac reader is SHA-256
`02c5e12a0b4faa2694ec5a715e0039fadaf3d57dd25c0e3a9aad151778f81636`.
Nine actual signed/MCP/process/hook/control/restart/wrong-pin cases pass.
The complete control output is SHA-256
`ea113422a647ff19a8e1c0895de05f879b06f899552b306fa7f5604767ae1e35`;
restart reproduces it byte for byte. The other signed/MCP/process/hook outputs
remain byte-identical to the preceding reader. Committed-source executable
binding, owned ARM execution and the 32 historical readbacks are the next checks.
The 333-record worker baseline and every earlier failure remain retained.

The public diagnostic addition is `native_stdio_snapshots.copied_hook_relations`.
The standalone stdio summary and old launch modes retain their existing shape;
the new field never promotes the original `request_semantics_verified` flag.
Metadata-operation semantics, atomic observation, physical writers, full Native
grading, outside admission, fresh twelve-role conformance and required CI remain
open. The user owns the deferred GitHub Actions checks.
