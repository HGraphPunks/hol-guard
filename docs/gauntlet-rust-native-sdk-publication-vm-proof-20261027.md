# Rust Native SDK publication: owned ARM VM proof

Root Rust source `8c868cbf4184e5317a76ea5c016bfcb0c626ab14` publishes
the retained public SDK/Bun dependency pair without importing or executing
either package. This is dependency custody evidence, with no SDK run,
model request, Guard verdict, execution eligibility or completed parent exit.

The old source VM is `hol-beta-bootstrap-20261016-004`; the destination is
the owned `hol-gauntlet-rust-build-20261026-001`. The source export is readonly
and streamed to the host. The external dependency bootstrap on the destination
copies inert bytes and normalizes ownership; the actual immutable publication
and its refusal logic are Rust-owned under both permanent worker leases.

| Input or result | Exact value |
| --- | --- |
| SDK | 18.4.12; 42,321 entries; 1,053,309,967 regular-file bytes |
| Original SDK tree | `4b12e74045c56e5f387c2a82312e38a97d665a88cc52bb698e55bf52747bf0b1` |
| Root normalized SDK tree | `ad4d62276c7f7d4026411ceedc56bbd257b06cd6ffd0c9933a6ef3b91d901a3e` |
| Bun | 91,801,560 bytes; `37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086` |
| Source archive | `native-sdk-public-source-024b.tar`; 42,324 members; 1,200,394,240 bytes; `fb658d14d25a8a7c7906edd723b2d9dad54ef063661bbb773419de3a0c6df4fc` |
| Source declaration | `1f4b60186253171767bf4784145095385ea362c6af9017730cd5027b7e45bc1a` |
| Publication job | `e2c701baf1472400` |
| Root publisher | 9,126,728 bytes; `784bfa5825ca2ea4b46fc89335754ff75737fa39998320646ced4dab0f68c77e` |
| Binary input archive | `native-sdk-publisher-input-024.tar`; three members; 32,389,120 bytes; `9895834f7e447cdbec563c98933f88abd1740d97d0adc0ded7153429644b4ec1` |
| Dual canonical publication receipt | `8af6afd12aaaf4e798d18846f33e93a959ce85d73c39a3f121769c9291a8c3fc` |
| VM result archive | `native-sdk-publication-vm-results-024.tar`; 20 members; 16,947,200 bytes; `7f111ec9f762737b0dd732511daa384d159a26d69349c2adfb6a6caa1d56ad53` |

The immutable directory is
`/opt/hol-gauntlet/sdk-assets/ad4d62276c7f7d4026411ceedc56bbd257b06cd6ffd0c9933a6ef3b91d901a3e-37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086`.
Root owns the directory at mode 0755, Bun at 0555 and both receipt copies at
0600. Every file byte is unchanged. The explicit bootstrap ownership change
to UID/GID 0 and removal of ordinary group/other write bits explains the
distinct tree digest; symlink metadata remains unchanged. No original
source archive, SDK tree or older proof was replaced.

Actual Root execution refuses the wrong worker generation, wrong declaration
digest and held Rust or Python lease before target creation. Publication
passes, and the second attempt refuses its consumed slot. Independent
post-readback verifies the complete source and published inventories, exact
normalization, unchanged Bun and receipts, and absence of a partial publication.
All 54 prior worker files remain unchanged. The actual Root worker suite
passes 141 tests, with its 24 existing fixture-specific ignores reported
separately. Its log SHA-256 is
`8acc5697019c8119ac3d82fe116783db83c137f008cc7bf5827ebc385bcf808c`.

The first source-export attempt refused a canonical path-order assertion
before writing payload bytes. Its zero-byte archive and result remain
retained. The corrected attempt sorts complete relative path strings and
matches the original outside tree pin. This did not change a custody bound
or accept a failed attempt.

The committed inert host reader is
`ci/gauntlet-rs/proofs/verify_native_sdk_publication_20261027.py`. It reads
all 42,324 source members, 20 export members and three binary-input members,
checks actual SDK package identity as JSON, complete inventories, dual receipt,
refusal results, Root test count and the 54 retained worker hashes. Run:

```sh
python ci/gauntlet-rs/proofs/verify_native_sdk_publication_20261027.py --evidence-dir /absolute/path/to/evidence
```

The host result `native-sdk-publication-host-verification-024.json` reports
`sdk_imported: false`, `bun_executed: false`, `artifact_admitted: false`,
`execution_eligible: false` and `model_requests: 0`. Ruff formatting and checks
pass. Earlier source-matched Mac validation is recorded in the
[SDK transport component contract](gauntlet-rust-native-sdk-transport.md).

The Root proof directory is
`/var/lib/hol-gauntlet-rust/native-sdk-assets-proof-20261027-024`.
The host archives and reader output are retained under
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-pr-ready-evidence-20261026`.
