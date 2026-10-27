# Native dependency input VM proof — 2026-10-26

The exact-Git host capsule and native Root capture pass on owned VM
`hol-gauntlet-rust-build-20261026-001`. No dependency installer, container,
candidate import or model request executes in this proof. All results remain
unadmitted, execution-ineligible and without verified Guard causality.

The host producer and capture worker use source
`cb97ad107bc525970194a6fea47c5784ae431da7`. Job `e2c701baf1471301` retains
source `84549fd4183ad89d82efaa041240e88ec9534040`, independently verified by
the Rust local Git producer and graph reader. Its 55,702,249-byte archive has
SHA-256 `21363432af545de03c24609b0bee78016921e0577e308f05953b51e49b58d237`.

| Input | SHA-256 |
| --- | --- |
| Native capture worker | `828dca57b7655807fbc252d54b405da2aba625f010f12328dbd4256df4525179` |
| Host capsule producer | `db6fa9046a954cf4e589fa1742db4b412023f64a1bb380526caee2ee09e6a6ba` |
| 1,551,712-byte capsule | `68c690cde61a20e4782989adedffe587b8e9d04a28463b5fbcd102a518a73ab4` |
| `pyproject.toml` | `5778df7e3e6ed909916ea8fbc7c7d854fa2a872baf1387f5395831af903e031b` |
| `uv.lock` | `ebc65d35df75fc4967cf8a9c709e3236f8c0382e936cdef5d44dea4d3559c1f8` |
| Unprivileged exporter ELF | `3a10107fcdb0d48fafcd05829967cffde39e22e2096776d005c66b4e3463c698` |
| Root capture receipt | `aa7b13f8a4d03c0b132dde0276a94b56a5aab6f6e6582149e1a56ae33c91e7e3` |

Root refuses wrong executable generation, source and either busy permanent
lease before receiving-file creation. Separate consumed jobs `1312`–`1315`
retain wrong-outer-hash, truncated, extra-byte and wrong-exporter-hash partials.
No rejected case publishes inputs. Failed-slot and successful-slot replays
refuse while preserving source archives, receipts, capsule and extracted files.
With umask 0077, committed input modes are exactly 0444/0444/0555 inside a
Root-owned 0700 directory; the private receipt is 0600 and archive 0444.
Direct Root invocation of the exporter refuses its required UID before I/O.
Final independent inspection finds no containers or native jobs.

The first actual Root library run retained 125 passes, one failure and 24
preexisting fixture ignores. The failed current-source test still expected the
builder context from before the Native-test ordering correction. Independently
evaluating the current Python `vm_build.py` identity AST gives
`721957934870b8e8a4f424e0deb72490a9771b6c50de1f44af3c18ca8dc402f0`;
the job policy bytes remain unchanged. Source `5c02d14e75b68b68dcecfab2810eda612f58ccfc`
corrects only that current-source expectation. Its separately installed ARM
test executable passes 126 tests, with the same 24 ignores. Historical baseline
fixtures and receipts are unchanged.

| Retained log | SHA-256 |
| --- | --- |
| First ARM run, including failure | `80c01908e55606e30a2237ba0c1ae9b28ea8132091035b51014bd867b807b310` |
| Corrected ARM run | `f04a832aadadc2a6c06553113006a73ff1c11101f3b420c42e0a9d7b84d1be8c` |
| Complete Mac workspace: 413 passes, 213 targets, zero failures/ignores | `3d559ddf7cc5a3b1391aa9a9bfa7f0788b3cd58075ea44c064a9e58d893cb674` |

The Root proof directory is
`/var/lib/hol-gauntlet-rust/native-dependency-input-proof-20261026-006`.
Its 36-member, 12,912,640-byte export is retained locally as
`native-dependency-capture-vm-results-006.tar`, SHA-256
`c08f28af867b520c974bedb83f790e5926c766e64c26603ee8a9e59828de5fa4`.
Independent host verification checks every member hash/size, exact capsule
contents, both library outcomes and capture/result pins; the record is
`native-dependency-capture-host-verify-006.json`. Five full source archives are
hashed on the guest and omitted from the export; their individual receipts
remain included. All original guest inputs, failed partials and logs remain.

The next work is the host prelaunch dependency intent, Root-owned bounded
container lifecycle and independent inert dependency-prefix construction.
Successful input capture establishes no package compatibility or conformance.
