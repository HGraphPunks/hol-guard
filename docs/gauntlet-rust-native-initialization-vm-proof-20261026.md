# Rust-only native initialization VM proof

This is the retained v1 initialization proof. Subsequent build integration
found that its 0755 build parent does not satisfy the candidate reader's 0700
contract. The current initializer explicitly versions that correction as v2;
this historical receipt does not establish current build readiness. Its
records remain retained; an upgrade must preserve the original empty directory.

Source `bff9ed0d1209eac5cae5ede1c5eaccf44e7d9edc` adds the explicit
`gauntlet-vm-worker --initialize-native GENERATION_SHA256` command. It creates
only fixed empty native state/build/deployment namespaces and permanent locks,
with initial-namespace Root and an exact running-executable digest. It does
not install or invoke the Python control-plane worker, dispatch/adopt jobs,
request inference or qualify a result.

The owned fresh VM `hol-gauntlet-rust-build-20261026-001` was prepared using
the [pinned native build profile](gauntlet-rust-native-build-vm-20261026.md).
Before execution, `/opt/hol-gauntlet`, `/var/lib/hol-gauntlet-rust` and
`/var/lib/hol-gauntlet` were absent. A wrong outside generation refused before
creating any of them. The positive Rust process ran under umask 0077, created
the exact 0755 public/0700 private directories and 0600 files, then retained a
generation-keyed private initialization receipt.

Both competing-owner cases refused: an outside holder of the Rust active
lease and an outside holder of the legacy worker lease. Neither modified the
receipt. A fresh identical initializer invocation returned the same canonical
bytes, with no additional worker state or native job. Root inspection found
only `native-deployments` and `worker.lock` under `/opt/hol-gauntlet`;
`worker.py` was absent. The receipt always records no dispatched job, no model
use and `execution_eligible: false`.

The actual Root ARM64 worker library passes **120 tests**, with **24 preexisting
fixture-specific ignores** reported separately. Its new isolated custody test
proves that a loose existing private directory, directory/file symlinks and a
multiply linked lock file refuse; the directory's original loose mode remains
unchanged. This proves refusal, not silent in-place repair. The focused Mac
worker library, locked ARM64 executable/test builds and warnings-denied Mac/
ARM64 Clippy pass.

The first courier preflight refused proof output beneath `/var/log`, whose
Ubuntu parent is group-writable. No input directory or initialization domain
had been created. Output moved to the verified Root-only ancestry under
`/var/lib`; the ancestry checks remained unchanged. Final inputs are at
`/usr/local/lib/hol-gauntlet-native-input-20261026-001` and proof records at
`/var/lib/hol-gauntlet-native-init-proof-20261026-001`.

| Artifact | SHA-256 |
| --- | --- |
| Worker, 6,690,216 bytes | `2d6c4bad97bb92829d83fa3240aeb26625cdc184fb1bc88743568c309d52403d` |
| Root worker test binary | `aae4748bc1d56a7930b878dead6e198dd7f5c5a84ddbe1b6cdc81cc169e0a202` |
| Outside proof adapter | `a501e072daecff345a92f537486cbf30dd683f2b33ce4e4f450043814d758249` |
| Four-file input archive | `81a0d567eb6e2906d045e089f7ee5314d2062d7929f3acb3122cb911aa87d0aa` |
| Immutable initialization receipt | `ffe3e262687ab9bb100c23e2c54dd8dccac4a193d2d7390f6de5eaf0dcd24c26` |
| Actual Root unit log | `f269ea6746b67677dbe4344fa06fc51ef883807d8e5ebc01c4590eced69c8379` |
| Nine-member 30,720-byte result archive | `5ef6079c23f2d9cfd96ab200329fc627acf0763483861fb475add2de49af00cf` |

The host retained `native-initialize-vm-results-001.tar` in the readiness
evidence directory. Its outer digest and every member's manifest hash/size
were independently verified without extraction. Original Root receipts and
proof records remain in the VM.

The VM additionally has pinned `slirp4netns=1.2.1-1build2`, required by the
candidate-build network preflight. Current-source controller/artifact
installation, builder/executor images, actual candidate compilation and
six-plus-six independent conformance remain open. This inert initialization
does not complete a parent migration exit; the ledger remains 24/62.
