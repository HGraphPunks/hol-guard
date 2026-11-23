# Native source installation and capture proof

The separate owned VM `hol-gauntlet-rust-build-20261026-001` now has an inert
source-bound controller and an initial product archive captured directly by
Rust. No candidate has been compiled or executed by this proof; all receipts
retain `execution_eligible: false` and zero model use.

## Exact controller source

The host checked all 431 `ci/gauntlet` Git blobs at
`00791fbe35e70c623ac51bfd765edc10da7ee0b7`, totaling 4,034,879 bytes, against
the unchanged baseline-plus-delta map. The Rust host reader independently
matched that exact source and planned 400 installed files. The 4,372,480-byte
Git source tar has SHA-256
`d95ccff0816576447777372d69c9121cd01d4c083bf7406c4057c37e352494ef`;
the map has SHA-256
`3f240bf9235cdcb31c11c78b27eb9edf45b9568c68a095804c0a930806402638`.
The courier accepts only archive directories derived from those exact map
paths; its first preflight refused Git's `ci/` parent before any destination
was created. That allowlist was corrected without relaxing file checks.

Measured Rust installer and independent verifier digests are respectively
`de6f11a34f3e9d68da8eec98b98d5c52ddfe3537c76edd66397bb4a1c1ccac76`
and `119a4a1ff2aa755acdb6d8738b6f7a17b900aa8f7563f1a45629d304449a4ecc`.
Under umask 0077, wrong-tree input refused before a final or partial generation
existed. The positive call installed 400 files at
`/opt/hol-gauntlet/controller-00791fbe35e70c62`; the separate verifier observed
411 entries and 3,741,707 file bytes, matching tree digest
`9dcb5e8de575a89e2b2d27f8cc5b009ade6385251a21a050dfc8b357e717a47d`.
Replay refused and a new verifier process returned the same inventory. No
controller was executed and no Python control-plane worker was installed.

The nine-member result archive `native-controller-install-vm-results-001.tar`
is 20,480 bytes, SHA-256
`694936c12d356935389cd036c3ad69322373a28d9bf0727ce7d94608d6ddaf58`.
The host verified every manifest member and its outer hash without extraction.

## Versioned private build layout

Build integration found that initialization v1's 0755 build parent violated
the existing candidate reader's 0700 contract. Source
`c80ac788e6e6acfcf182011fa0d0d0b9340a06fe` corrects the initializer with
explicit `hol-gauntlet-native-initialization.v2` / `native-worker-layout-v2`.
A wrong executable pin and the loose existing directory both refused before
a v2 receipt; the original mode/inode and v1 receipt stayed unchanged.

An explicit operator maintenance step held both worker leases, required no
native jobs, no Python worker, no active containers and the measured empty
original directory, then retained it without replacement as
`/var/lib/hol-gauntlet/builds.native-initialization-v1-bff9ed0d`.
Its device 64769, inode 262513, original 0755 mode and empty contents remain.
Rust then created a new private 0700 build parent under umask 0077. Identical
reopen preserved the new receipt, SHA-256
`b1daa3def05615eee17d3b8fdb453b0d90b7deb500d6a676315377445ec689e0`;
the historical v1 receipt remains
`ffe3e262687ab9bb100c23e2c54dd8dccac4a193d2d7390f6de5eaf0dcd24c26`.
No directory containing jobs or history was chmodded, discarded or adopted.

## Bounded Rust source upload

The new explicit `--capture-build-source` command receives only stdin with
outside job/source/archive-length/archive-hash/executable pins. Both worker
leases cover an exclusive fixed build slot, a 180-second boottime deadline,
cancellation checks and a 256-MiB ceiling. Only exact length/hash plus EOF can
commit 0444 `source.tar.gz`. The actual downstream candidate reader then opens
the private slot and verifies the same archive before a separate private
source receipt. No guest-home path, archive extraction or source execution
is part of this operation.

The initial 3.57.0 Git working-tree archive at source `c80ac788` is 54,777,625 bytes,
SHA-256 `9e1dd5a47deebc6086ca7ed158fb88b592e3774739593e3afa166c9ad2dfb492`.
Rust captured it under job `e2c701baf1471001`, verified it with the real
candidate reader, and preserved the same bytes/receipt on replay refusal.
The source receipt SHA-256 is
`d3b91a85a8763595b5c80e3cd61abfc1d9e65028e05c356024852ec937f06233`.
Wrong generation and both competing worker leases refused before creating
their slots. Wrong digest, truncated input and extra bytes refused without
creating a committed source or receipt; rejected partials remain private and
consumed. Replaying a rejected slot preserved its original bytes.

The actual Root worker suite passes **122 tests**, with **24 existing
fixture-specific ignores** separate. New stream cases exercise binary bytes,
truncation, overflow, cancellation and an unanswered-pipe deadline. ARM64
builds and warnings-denied Clippy pass. The new implementation modules are
under 500 lines; historical guest-home capture and v1 wire requests remain
separate and unchanged.

| Artifact | SHA-256 |
| --- | --- |
| Native worker, 6,750,824 bytes | `29f5dfd5448c4bd82e0cae204e21ab395b73d31323bcb775ed6f3678ae82bf7f` |
| Actual Root test binary | `e73a97c64566ea4b332b3e44cc09fbb13a84e02c261befc20fc3d574534a048f` |
| Actual Root test log | `bcc12470929cee117a03e2e8be78321ebbeb37f8ed1b30fb1587d44d332ff480` |
| Input generation archive | `c36ef632220aa5f6e96fa714e61ed9c876735dd12bb802e2554b2e3cfe1024ef` |
| 23-member 51,200-byte result archive | `bc8146d963cddc4cb59f1d7837de8e13bf435d4d55b3a1a55a98d1056040f6ed` |

The host independently verified the outer hash and every member in
`native-source-vm-results-001.tar`, including both initialization receipts,
the retirement audit, failed partial bytes and raw refusal/result records.
Original records remain in
`/var/lib/hol-gauntlet-rust/native-source-proof-20261026-001` and source slots
under `/var/lib/hol-gauntlet/builds`. Host archives remain under
`gauntlet-rust-pr-ready-evidence-20261026`.

This command proves bounded byte custody. It does not verify the archive's
Git-object format. A subsequent builder run rejected this working-tree archive
because its required `repository.git` was absent; that consumed job and its
failure receipt remain. Fresh bare-object archives are separately checked by
the existing Rust archive/ref/Git-graph verifier before upload.

The two trusted builder bases were fetched by immutable registry digest and
matched the retained ARM64 image IDs. Rust verified those bases and wrote its
exclusive image-ID-pinned build context. The bounded trusted builder image
build passed as a separate step. The subsequent [current candidate build](gauntlet-rust-native-candidate-build-20261026.md)
uses the corrected controller and Git-object format, preserving these original
records. Artifact admission, six-plus-six independent controls/conformance and
model/campaign execution remain open.
No quota was reset or inference requested. Parent exits remain 24/62.
