# Copied Native resident-operation reply bindings

The Rust offline verifier now checks the request ID, versioned schema and
canonical request digest for every completed resident operation in the retained
launch-v4 control that carries those fields. This is a reply-binding check, not
an independent evaluation of what the operation should have decided. It does
not authenticate atomic kernel pipe bytes, physical writers or policy state.
The migration stays at **24/62 parent exits**, and all admission and causality
flags remain false.

## Exact input and measured result

The product remains `dc3b9336308dab4892bf0c0e0f328a9c8b7efc12` and the
producer remains `77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9`. The retained
public archive `native-stdio-control-vm-results-001-success.tar` has SHA-256
`24e4ab9b915d32c5d599553a1b38a460d8355e64109d5defb5a0bc07c35e9376`.
No product or VM job ran for this check. The new reader source is based on
`cdd51700198b54823c23405f42bf0b191c99ccb4`; the exact four changed
source-file digests and reader binary digest are recorded in the workspace's
`gauntlet-rust-pr-ready-evidence-20261026/native-operation-reply-proof-001.json`.

The workspace's `gauntlet-rust-pr-ready-evidence-20261026/native-operation-reply-replay-001.json`
is 199,767 bytes, SHA-256
`85cbeab9c8aae697375356a4813a9d5c081831cbdfc2d29703eac05ce7dbb294`.
It reopens the prior public completion and archive against the prior host
public-key pin, and preserves 249 request frames, 248 response frames and five
copied hook pairs. Of the 244 operation requests, **97 completed replies**
have matching request IDs, schemas and independently recomputed digests. Three
of those are `command_capability` replies: their product-defined digest
replaces `integrity_key_b64` with null before hashing, so the digest does not
bind the signing-key bytes. The remaining **146 completed replies** are the
136 `hook_direct_evidence_drain` and ten `policy_snapshot_push` replies; their
dialects expose no request digest. One final drain has no copied response.
Its outcome remains unknown.

The verifier now refuses an unknown operation with a completed reply instead
of silently counting it as metadata. It also rejects changed IDs, digests,
request bodies and schemas
for the 15 digest-bearing dialects. The two other dialects receive structural
checks only. The product's response payloads and operation effects remain
unverified; `operation_request_semantics_verified`,
`all_request_semantics_verified`, `atomic_kernel_pipe_bytes_verified` and
`execution_eligible` remain false.

## Local validation and next proof

The focused binding tests pass three cases, including request substitution and
the deliberate signing-key exclusion. The full `gauntlet-evidence` library
passes **134 tests**. Rustfmt and Mac/ARM warnings-denied Clippy pass for the
affected crate. The new host reader accepted the retained control with the
counts above; this is local same-machine replay and supplies no independent
reviewer or new ARM execution.

The owned VM is currently stopped. Lima start found a stale `ha.pid`; its PID
does not exist. Lima's forced stop confirmed both VM processes already stopped,
but this session cannot remove stale PID/socket files under `~/.lima` because
that directory is outside its writable roots. Fresh Root feature-worker
execution and restart/recovery proof remain pending until the owned VM is
available. Full metadata semantics, atomic observation, physical effect
writers, role grading, outside admission and required CI remain separate work.
