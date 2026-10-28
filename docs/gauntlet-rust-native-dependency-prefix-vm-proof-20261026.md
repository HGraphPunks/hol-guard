# Native inert dependency prefix proof, 2026-10-26

The Rust stager at `c19dcfc794828a4400ca3a1104b6a3e0ee96ecff` publishes a
one-use dependency prefix from successful dependency job `e2c701baf1471402`.
That producer uses exact candidate source `62aa7ba777a5a4cc0806c34ee94e9822eaa58d32`;
its [run, outside kernel observation and cleanup](gauntlet-rust-native-dependency-run-vm-proof-20261026.md)
remain separate retained evidence. Root executes no Python or dependency code
during prefix staging.

The owned disposable VM is `hol-gauntlet-rust-build-20261026-001`, with two
CPUs, 16 GiB RAM and 48 GiB disk. The frozen transfer contains the new worker,
library test executable and manifest: 30,689,280 bytes, SHA-256
`65ff3828ecfd2671543bc6a77a36dc8debc652fb9774a6138dca6c0e657b4b16`.
Root installs a new single-link mode-0500 worker; old generations remain.

| Outside identity | SHA-256 |
| --- | --- |
| Actual stager executable | `9a37e47233d2d87b258d4913736cc894cdadcd3c001cfd0e389f937bda7e1ea5` |
| Dependency prelaunch intent | `f955c02bcd51992bf0436fc0be47572f1d31a1e88ff9d8d71c4f09f9150c2c5f` |
| Successful retained producer report | `89c3b69fb03e848348cf1028c3d8151c74ca6d532795c2c44154cce8d17a9813` |
| Captured dependency ZIP | `67a69d651acc1c4bc399c5ee587a46617230126ff70c5748a9d17651ca5f5250` |
| System `/usr/bin/python3.12` file | `6242e0e8650d7dbdebbc25e08bf4c9359ddaf65f54fcae0e57fa99395fa5357a` |

The stager takes both permanent worker leases, audits unresolved jobs and
rechecks source/input/intent/report custody. It independently reads every ZIP
member and CRC, verifies the closed manifest and framed byte digest, then
materializes ordinary files through held directory descriptors with exclusive
creation, stable metadata and byte readback. The partial stays private until
verified. Publication uses rename without replacement, followed by independent
final tree inventory and a separate canonical receipt.

The prefix contains 2,302 dependency files, one inert `pyvenv.cfg`, 343
directories and three fixed interpreter symlinks. Its 2,649 inventory entries
contain 54,452,817 ordinary-file bytes. Every dependency file matches the ZIP.
All files/directories are Root-owned, modes 0644/0755; only the three fixed
Python symlinks are accepted. No package launcher is created by this operation.

The published tree digest is
`df07ad782d2bea44d49a3ac4a84a1ae3a160d4fe96764adc4b591d4a82acebb2`.
The canonical receipt hash is
`f2c80031066ecfb3ba9d6ee28db2831bf358e88d3dc8e71450c3f100f8f09029`.
It binds source, both run pins, archive, project/lock files, original runner,
actual stager, system interpreter and actual prefix inventory.

Nine refusal cases pass: wrong intent, report, archive, interpreter and
stager; a held Rust lease; a held legacy lease; repaired aborted output; and
replay after successful publication. All 18 original input/log/archive/journal
files retain their metadata and bytes. The aborted predecessor's missing
terminal is not invented or accepted. Replay preserves the receipt and entire
published tree. Independent final readback finds no container and
41,944,391,680 bytes free.

The actual Root ARM64 library passes 129 tests, with 24 preexisting explicit
fixture ignores and zero failures. Its 16,331-byte log hashes to
`6d069d19896ed47acdfd3da2279aa3cc379eab3c6cf14681d2da5c87a0a062d9`.
The full Mac workspace passes 419 tests across 215 targets, with zero failures
or ignores. Mac/ARM64 warnings-denied worker Clippy and Rustfmt checks pass.

The host independently verifies all 29 members in the 18,984,960-byte export,
SHA-256 `49a47fbcf6bc9b3ebad40406e36349a59d706155f4d0f153f19bd519c83f76aa`.
It reconstructs the complete expected prefix inventory from ZIP bytes, fixed
configuration and fixed links, then agrees with the observed Root tree hash,
counts and bytes. The retained files are
`native-dependency-prefix-vm-results-014.tar` and
`native-dependency-prefix-host-verify-014.json` in the local evidence directory;
VM records are under
`/var/lib/hol-gauntlet-rust/native-dependency-prefix-proof-20261026-014`.

All reports remain `artifact_admitted:false`, `execution_eligible:false`,
`guard_causality_verified:false`, with zero model requests. Candidate overlay,
complete requirement verification, independent controls and fresh conformance
remain open. This proof closes a staging subproof, not its migration parent.
