# Rust Native MCP and provider artifact verification

Rust source `65a700765f5805c1663664c390fff10e3618a2d4` adds the offline
`--mcp-artifacts PUBLIC_USTAR SHA256` completion mode. It authenticates the
report, preparation, declaration, role and source against the prior host pin
journal, then independently checks the public MCP/provider relations for all
six deterministic diagnostic roles. The existing envelope, input-binding and
boundary modes remain compatible.

The evidence reader selects clean records or the fixed compiled catalog's
`python-cli-with-tests` / `text-injection` document. It joins strict sequential
JSON-RPC frames, pending request IDs, raw wire hashes, captured Native NDJSON,
actual SDK stdout/stderr and the shared builtin/MCP budget. The Native result
can be forwarded or an actual error withholding the injected payload; nested
JSON-encoded content is checked too. It does not infer Guard causality from
either disposition. Cancellation retains the missing SDK result.

The physical SQLite file must match the Root report's device, inode, ownership,
mode and single link. A bounded read-only in-memory deserialization checks its
header, exact schema, integrity, metadata, every physical record and journal,
and empty replay cache. No archive member becomes a filesystem path. A bounded
SQLite progress handler limits query work. The one actual `docs.read` joins
the source-selected snapshot, strict Ed25519 receipt, arguments, result and
event chain. Fixed public relay/proxy/helper bytes and source prefix must agree.

`independent_process_custody_checked`, signing-key admission, qualified-role
completion, execution eligibility and Guard causality remain false. Independent
SDK/process/peer custody, Native Bash effects, lifecycle and complete role
grading remain open. This proof closes no parent exit: the ledger stays 24/62.

## Actual archive and refusal checks

The committed-source Mac verifier is 5,098,944 bytes, SHA-256
`d13055131f918c4c7996ed4ef00eb4b53f04e0823527c4e0dcafe53cb3c95810`.
The [inert proof courier](../ci/gauntlet-rs/proofs/verify_native_mcp_artifacts_20261027.py)
passes 31 cases: six envelope regressions, six actual MCP readbacks and their
byte-identical restarts, both byte-identical older artifact modes, wrong
digest/job/role, and eight mutation archives with recomputed inventory and
outer hashes. Mutations change a database record, journal, cache or schema,
Native output, SDK stdout, database inode or required Native input. Every
refusal exits 2 with empty stdout. Original archives and host pins are unchanged.

The six archives are the existing v7 jobs `e2c701baf1475102` through `5107`:
historical runtime `f53bc490` and product `62aa7ba7` / 3.57.0. This is not fresh
current-source execution. The successful reads check 144 frontend frames,
12 physical records and six signed read receipts. All historical injection
responses are forwarded; no model resistance is claimed.

The 7,698-byte `native-mcp-artifact-proof-001.json` index has SHA-256
`e264b89b3d286cc0b1955e67b3629c29e59ffcb85121fcfd15a8a92dcfa5660a`.
It records every case and all six actual stdout hashes. The retained executable
build log hashes to
`020ca2ab91187404ce851c9f3ed5f382dccd4cd01ef1ceeab2f427b3700a1b02`.

## Mac and native ARM validation

The full Mac workspace passes 529 tests with zero failures or ignores.
`native-mcp-rust-workspace-001.log` hashes to
`62989124ec9b390f7f011044c135fb3a415a350141da089ec2c242fd566b307d`.
All-workspace/all-target/all-feature warnings-denied Clippy passes on Mac
(`c48c73e07c4a248bd5404c2e2ff10316acd6f1826a7ae814cdfb557c472273bf`)
and ARM (`65b6264b2993c890cef9e3a52dd33abfe8efb22838e9c7594eda926947eea49d`).

Owned VM `hol-gauntlet-rust-build-20261026-001` passes eight provider tests,
seven MCP-selected tests and two archive-custody tests natively under Root.
The MCP selector includes one existing test as well as the six new tests.
These 17 focused tests are not a full native workspace run. Both worker leases
are held; all 284 old worker records remain unchanged and owned product cgroups
are absent. The first proof runner expected six MCP tests and stopped after
the successful seven-test result; its files remain retained. A fresh proof
directory uses the corrected count without changing either executable.

The evidence ELF hashes to
`9a30c8bcbb40f0fc4170eca633e8485afa51b6a951402b9bfb8a2f1a037e557b`;
the host ELF hashes to
`cbd22526f2bfb4f113a246cd92ff0ca3866868ace3cd78238cb1d9212c4e8cfc`.
The 32,020,480-byte three-member input hashes to
`2c6b26c3b535a495f69e8c5d72928ac81a1216e41b50beeb588bf36b4513e8bf`.
Root hashes the held result before public handoff: the 20,480-byte ten-member
`native-mcp-arm-vm-results-002.tar` hashes to
`0f57a763f202faa6a497a68f4c61415d6024f9b119bd33abc80b96c2a94ab859`.
The [independent host reader](../ci/gauntlet-rs/proofs/verify_native_mcp_arm_20261027.py)
checks every file and exact source/ELF/log/metadata pin; its successful stdout
hashes to `d3676425a377f73e7405aa13a6c4a5a75983f55b554f6c929e5865b14c5f95c8`.
Both proof helpers pass Ruff formatting and lint. No model requests ran.

The separate [SDK/MCP process reader](gauntlet-rust-native-process-artifact-verifier.md)
now joins the six archives to outside kernel samples, preserving historical
missing observations and raw SDK bytes as unverified. Full process custody and
Native hook/Bash/lifecycle grading remain open.

The [current 3.58.0 runtime publication](gauntlet-rust-current358-runtime-proof-20261027.md)
is separately proven. Twelve fresh staging/installed roles and conformance,
independent process grading, feature audit and remaining operational/workflow/
legacy/cutover exits remain open. Required GitHub CI remains user-owned and pending.
