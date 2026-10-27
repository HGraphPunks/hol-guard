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

The restarted full Rust tests/Clippy and matching package-3.58.0 Native
library, CLI/compiler and ownership/approval/delivery validation remain
pending at this checkpoint. The six completed host-pinned VM diagnostics
still refer to Rust source `f53bc490` and historical product `62aa7ba7`;
they are not relabeled as current-source conformance. Fresh candidate
publication, independent Rust grading, required CI and the other parent
exits remain open. Model requests remain zero.
