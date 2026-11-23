# Upstream synchronization through ee0b44f4

Merge `86fce56549f738713da46b23427ad17bb04048a3` preserves upstream
`ee0b44f418db47862455183a3dca2c182ead3508` and published migration
history. This imports 40 newer commits, including package 3.58.0 and further
Native resident ownership of command, policy, hook and approval work.

The only conflict placed two independent additions at the same point in
`native_execution.py`. Preserve the migration's
`consume_contained_completion_native` function and upstream's
`ContainedVerdictUnavailableError` class. Both remain; the upstream
contained-verdict handling and migration completion binding still require
their matching Native tests.

The one changed Gauntlet file is `extension_adapters.py`. Its required
extensions already stay enabled in the catalog. The reviewed change sends
only requested permission controls for those extensions, preserving normal
enable controls for optional extensions and refusing an empty control set.
It prevents the runtime's `immutable_extension` refusal from invalidating a
fixture that does not need to change extension state.

The explicit source delta remains 432 files, 69 changed and 12 added. The
420-file immutable Python baseline and all historical controller/proof pins
remain unchanged.

The first merged Rust workspace run stops at the stale current-source
controller-tree assertion. Its retained log
`rust-workspace-after-ee0b44f4-001.log` hashes to
`edc6602844e57d22eab91d93041d13986507517ad6b847243b2d962b4d422050`.
Rust computes
`a6b9a563dc21f1e29684bde7c2245c789fdffeeb2587ae651cbf926426a6063d`.
The actual Python bootstrap selector, exercised with an inert transfer sink
that installs nothing, independently selects 401 files and 412 entries and
computes that same digest. The unchanged selector hashes to
`47143fac9747cc6ddc907891febe85dd571c57861203c4041c20e7000272a50d`;
the fresh installer hashes to
`623c7ce91b172edd07013eb237c8e457a3e9baeffe3c201d8305d52e2e503e4e`.
Only the explicitly current-source test pin is refreshed.

Current-source validation passes at
`3736c0999dd95777e0a54786c86102ce15888015`:

| Check | Result | Retained log SHA-256 |
| --- | --- | --- |
| Full migration workspace, all targets/features | 501 passed, no failures or ignores | `36001ab591752c38333fc5bc23f57f46a8c6bbf988dcd9317fb1881d4f935aea` |
| Workspace Clippy, all targets/features, warnings denied | Passed | `23a9b7b953ecef79c380202c993d16430f6a667c74faa5a15574687bb9fa66e5` |
| Matching Native library, CLI and compiler | Built, package 3.58.0 | `9e2a5434d0958c474bddf5b6b1d822cea4c20b0af8057b4a2e97265c5135f6ff` |
| Native PostToolUse output integration | 3 passed | `81b788b7efb2a5b5d299bc1b3fff38ac098c29bd19d4f695cca3781a009d13c6` |
| macOS pinned Native image hardening | 7 passed | `0ad169a45b76dec424963eb1c33f38b676721f8d6b1f81239dff52aa4d7245fe` |
| Native program and directory validation | All five stages passed | `71c6768872f748c1ad2be8e7e56b67f86b49b0c08138e44e64b39de889162746` |
| Native/Gauntlet Python regressions, 18 files | 453 passed, five skips explained below | `5bba04c2f621e8339ae4d3d4338a0da0fce3749d42ee1b0999cdb20448a81fd2` |
| Four real TypeScript observer cases | 4 passed separately | `285a0fcb19d88aef8d3a8bf03456688755f33b03ab786144fe993e1bc0fc4738` |

Logs and per-command result records are retained in the external
`gauntlet-rust-pr-ready-evidence-20261026` directory, with names ending
`after-ee0b44f4-002`. The Python JUnit digest is
`1c1ca9b36ceb91c9be32aaecba12b5348b8491162d3c6814eb4ad84fc3ad0ef7`.
The current Native runtime is 120,395,616 bytes, below the unchanged
128-MiB admission bound, with SHA-256
`12c6fb889fbdfd0d08ee5787eef9c09085f409f9a0f83ec5e3b764104955715f`.
The source compiler hashes to
`4e05c6bac4f684e2e9397573ba83422cffbb883729cf27fbbc7aa9106e15e9b2`.

The initial Native program attempt retained a default-auto discovery refusal
before pytest began. The corrected run explicitly selects the freshly built
binary using the supported developer `force` mode. The unchanged validator
runs inside a bound synthetic test home with a public test seed; its resident
is closed before that test home is removed. No real Guard store is read.
Its directory preparation regenerated three tracked documentation outputs;
their exact bytes and patch are retained separately before restoring their
committed contents. No generated catalog churn is included in this change.

Four Python skips were caused by Bun being absent from the validation PATH.
The unchanged cases subsequently pass with retained macOS Bun 1.3.14,
SHA-256 `e0c90ec15d33363e6b70713d56bc3b2c7585c17f40a0fe0f8fd9305901d4e233`.
The first observer-only attempt was stopped by pytest's loopback status socket
restriction before collection; its failed log is retained, and the authorized
rerun passes all four cases. The remaining local bridge skip requires the
exact pinned Linux ELF, rather than this macOS executable. Its separate
[eight-vector native VM proof](gauntlet-rust-world-proof-20261027.md)
remains historical, with no claim of fresh current-source execution.

The six completed host-pinned VM diagnostics still refer to Rust source
`f53bc490` and historical product `62aa7ba7`; they are not relabeled as
current-source conformance. Fresh candidate publication, independent Rust
grading, required CI and the other parent exits remain open. The user will
handle disabled GitHub Actions; all five exact-head jobs remain required
before merging. Parent exits stay 24/62. Model requests remain zero.
