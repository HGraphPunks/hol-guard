# Native inert runtime publication proof, 2026-10-26

Rust publisher `c89e0008ca649c87e6e97368b72842ea08bffc6f` passes on the
owned ARM64 VM `hol-gauntlet-rust-build-20261026-001` (two CPUs, 16 GiB RAM,
48 GiB disk). It publishes the independently verified
[candidate prefix](gauntlet-rust-native-candidate-prefix-vm-proof-20261026.md)
from job `e2c701baf1471601` under its exact source path:

```text
/opt/hol-gauntlet/candidates/62aa7ba777a5a4cc0806c34ee94e9822eaa58d32/prefix
```

This is one-use inert data publication. It executes no candidate or package,
writes no deployment/admission, and grants no conformance or Guard verdict.

The frozen three-member transfer is 37,918,720 bytes, SHA-256
`c03d4bd9b4b6d946ac69e1f70e2e10d99ad8970cdb61a9a212164668c4e0b3c8`.
The new Root-owned single-link mode-0500 worker is
`47cd8c5a8b110870e0d1be2439818121a89ab2797ab60d2011ad5ca532792235`.
The original clone receipt remains outside-pinned at
`42a86cca874c40739f48019399b10c20a05f3d528c756f22efbe3833661f9433`.

Rust reads the closed clone receipt and computes the complete typed PEP
508/440 requirement proof. It takes both permanent worker leases and rechecks
source, captured candidate, separate dependency receipt/tree, interpreter and
complete prefix identity before writing. A source/job partial stays private
while descriptor-relative copying and independent tree inventories complete.
Only then does Rust publish without replacement under the immutable source
path. Canonical receipts in the source directory and original job are byte-
identical, SHA-256
`3b5ed1b9d5ea1faa395aae6526d7ec746408d376fb134ae5e6b0bc9df930f432`.

The published Root-owned 0755 prefix has the same 4,411 entries and
117,018,419 bytes as the independently reconstructed inert prefix. Its digest
is `cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637`.
All ordinary files are single-link; the three interpreter links resolve to the
fixed system Python. Complete requirement results match the earlier actual
Python source-loop oracle: 63 distributions, 23 requirements, 13 active and
satisfied, 10 inactive, with MCP 1.30.0 and CPython 3.12.3 markers.

Ten refusals pass: wrong source, version, clone receipt, prefix tree, Native
hash, interpreter version and worker generation; both busy leases; and replay.
Refusals before publication create no source/job partial or receipt. All
8,059 original files/links retain their metadata and bytes. Replay preserves
the complete published prefix and both receipts. No container remains; free
space is 40,955,621,376 bytes.

The actual Root ARM64 library passes 135 tests, with 24 preexisting fixture
ignores, log SHA-256
`b12eb1186550da5c296b068572f14052212213cc6d61bd2927df4bea66f4c11a`.
The complete Mac workspace passes 425 tests across 215 targets, with zero
failures/ignores. Mac/ARM64 warnings-denied Clippy and Rustfmt checks pass.

The host verifies all 23 members in the 3,235,840-byte export, SHA-256
`22d3eb8c01e63e01b36c63b130491049295dea0599ea4e1990da855bca17e161`.
It matches both raw receipts, every published tree row against the independently
reconstructed prefix, the complete requirement proof, refusal records and
Root test log. The [offline verifier](../ci/gauntlet-rs/proofs/verify_native_candidate_prefix_20261026.py)
supports `--publication-export` in addition to the build/prefix inputs; its
combined retained-artifact run and Ruff checks pass. It refuses Python
optimization and performs bounded, stable reads without candidate imports.

VM records remain under
`/var/lib/hol-gauntlet-rust/native-runtime-publication-proof-20261026-017`.
Host records are `native-runtime-publication-vm-results-017.tar` and
`native-runtime-publication-host-verify-017.json` in the retained evidence
directory. Earlier partials, failures, generations and Python baselines remain.

Every report stays `artifact_admitted:false`, `execution_eligible:false`,
`guard_causality_verified:false`, with zero model requests. Source-matched
independent controls, fresh conformance, qualified deployment and broader
interruption recovery remain open. The parent ledger stays 24 complete/38 open.
