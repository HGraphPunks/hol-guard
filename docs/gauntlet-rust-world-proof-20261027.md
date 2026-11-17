# Rust transactional synthetic world

`gauntlet-world` implements the synthetic provider state previously owned by
`ci/gauntlet/benchmark/world.py`. It supports all seven service families,
collection/tenant/ACL checks, reads and attachments, search/projection/signed
pagination, create/update/delete, mail draft/send, document permissions,
calendar invitations and chat posts. This library has no network client,
executable selection or Guard admission authority.

The caller supplies a privately custodied SQLite connection and in-memory
Ed25519 key. The library never stores private key material. Initialization
refuses any existing schema; reopen requires the same public signing identity.
Each call uses `BEGIN IMMEDIATE` and commits state, signed chained receipt
and idempotency result together. Errors roll back all three. SQLite uses a
10-second busy bound, delete journaling and full synchronization. The pinned
rusqlite 0.40.2 [transaction contract](https://docs.rs/rusqlite/0.40.2/rusqlite/struct.Transaction.html)
documents rollback on drop and explicit commit; the dependency matches the
product workspace's pinned version. No dependency download was needed.

Original arguments retain omitted defaults. Receipt digests and signatures
use the existing strict Python-compatible canonical codec. Search separately
preserves Python's object insertion order, ASCII escaping, spaces, float
format and case folding; it does not enable a global serde JSON-order feature.
An exact integer comparison prevents large record versions from being rounded
through floating point. The receipt reader requires separately supplied public
key, count and final-hash anchors; signatures confer no Guard causality.

The fixture producer invokes the unchanged actual Python World with a public
synthetic test key. Its immutable JSON contains 153 sequential operations:
94 accepted and 59 refused. Rust matches every result or error, every
intermediate snapshot digest, receipt count and complete receipt digest,
and the final snapshot and Ed25519 signatures. It covers all families,
insertion-sensitive search, stale/signed pagination, ACLs, attachments,
permissions/owner immutability, synthetic destinations, failed writes and
idempotent replay/conflict. The fixture pins the Python source bytes and the
test checks those pins.

Five additional tests cover actual database reopen, same-key identity,
idempotent replay across restart, refusal of initialization over existing
state, rollback after an injected receipt-storage failure, independent
signature/count/anchor/tampering checks, strict original arguments and the
large-integer version regression. The public seed occurs only in test tooling
and inert fixtures; it is not a runtime key source.

The complete Mac workspace passes 460 tests across 222 targets with zero
failures or ignores. Log `rust-workspace-world-002.log` has SHA-256
`7a065eb763eb7b5a0c002d95837a3a75ba48cc44ca0b40ad1e0617ebb959f6eb`.
Warnings-denied Mac and ARM64 Clippy pass. Three static ARM64 test executables
compile. The earlier 459-test passing checkpoint is retained; initial
compiler/Clippy corrections remain in the task record.

Native execution now passes on `hol-gauntlet-rust-build-20261026-001` at
source `6f308fae66d47f4a92f2b354adf802a2c2472283`. The Root-owned static
ARM64 executables pass the 153-operation Python parity test and all five
durability/refusal tests, with no failures or ignores. Input archive
`rust-world-native-tests-input-001.tar` has SHA-256
`c02a485d6820c58ed7192b0234a128663dee6b821e0014dd7f10377050105c19`.
The nine-member results export has SHA-256
`13400d05773a96eaf09ed3561c98f13ca6e26c16275b771072400a3909851988`.
The inert `verify_rust_world_native_20261027.py` checks input ELF bytes,
source/generation pins, every result member, output hashes and exact counts.

The same reader verifies all eight contained-output bridge vectors using
the exact Linux Bun pin. They run as UID/GID10001 against the unchanged
bridge helper and an explicitly mocked controller, with zero network/model
requests and no Native execution. Receipt SHA-256 is
`73a85593dea796613b87799b7188325f70642d17aace3c749379956e11d88ed1`.
This closes the architecture-specific unit-test skip in the consolidation
report; it supplies no benchmark or Guard-causality verdict.

This is the state engine component, not an integrated MCP service or complete
legacy migration. Root socket/process custody, real MCP dispatch/catalogs,
shared operation budgets, Native MCP proxy lifecycle, independent Guard/effect
scoring, fresh conformance and remaining workflow/legacy/cutover exits stay
open. SQLite file custody still belongs to the future Root service wrapper;
the library API alone does not authenticate an arbitrary database path.
The parent checklist remains 24/62 complete. No model request or qualification
claim is made.
