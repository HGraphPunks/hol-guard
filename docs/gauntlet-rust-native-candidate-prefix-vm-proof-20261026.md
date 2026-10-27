# Current Native candidate prefix proof, 2026-10-26

Rust composition at `fc80aecdc6f4de01f29a2f52929508a27deae965` passes on the
owned two-CPU, 16-GiB, 48-GiB ARM64 VM
`hol-gauntlet-rust-build-20261026-001`. Candidate job `e2c701baf1471601`
uses exact product source `62aa7ba777a5a4cc0806c34ee94e9822eaa58d32` and the
separately [verified dependency prefix](gauntlet-rust-native-dependency-prefix-vm-proof-20261026.md)
from job `e2c701baf1471402`. Root executes no package, installer or candidate.

## Fresh source and build

The frozen Rust source producer captures a new 55,757,825-byte archive,
SHA-256 `a02196e45587cdd9a82912c76bbe435d4fb7dc974b237b24597c5ac64f594869`.
The Rust host durably binds its job, VM, source, runtime, image, controller and
worker pins before launch. Its host-pin digest is
`84e2edda817cb50027faafd6d5ece5b00fa18f786316dafcf2aa5cef0fd280df`.
The source-matched build completes in 420.22 seconds with four selected and
187 complete contained tests passing. Result hash is
`9afcea963f7a14eb2b9526d56b19b0cee00776d5258c122263f15f5a3aa59530`.

Outside kernel observation confirms actual UID/GID 65532, zero effective and
permitted capabilities, no-new-privileges, seccomp mode 2, the enforcing job
AppArmor policy, slirp networking and 12-GiB, zero-swap, 512-PID, two-CPU limits.
The container is
`5637eee6f44237714abfc88a7ec7da887f65fdcea8b79a1f0712e4b6e293abf4`.
Independent final reads confirm its container, client cgroup, machine-slice
scope and job profile absent. The Rust host result reader reconciles the
retained result; wrong-VM refusal preserves the original host pin.

Candidate ZIP SHA-256 is
`77dec4add32586606a1885d7a285f78c03e64bfe14a2877148086ddd0bf69177`.
The 24,426,588-byte wheel is byte-identical to the
[previous exact-source build](gauntlet-rust-native-candidate-build-current-20261026.md),
SHA-256 `4f29b6f76417b7172db007a64ac99f5de9c68b62078d95be5545f1fecd30c2f0`.
Its 1,705 entries decode to 62,564,815 bytes. The Native executable is
36,682,448 bytes, SHA-256
`1632de1167b167ffe05d02ab4f2cdf157d9328addfcc054ceeffef640b8b9489`.
Wrong capture hash, capture replay and wheel-stage replay refuse unchanged.

## Composition and complete requirements

The corrected worker, Root-owned mode 0500, hashes to
`11acd7f70119e504435c2a7e6a2a5ec96ec0496bad4e67b5e7aba0b92244e08f`.
Its distinct input generation has four ordinary members, 46,581,760 bytes,
SHA-256 `851757284134f1413c99362d72fde7306f61ad260738ef7bebd2a837ba122a4a`.
The dependency checker is independently pinned at
`cba6dcc8f09e584a77b365c7592971413d66c35cdc5f20c82060514b0365182f`.

Under both worker leases, Rust verifies the separate dependency receipt,
source/archive/wheel identities, complete dependency tree and system Python
hash. It clones the inert dependencies, overlays all candidate bytes, validates
the exact six-entry console declaration and writes fixed relocatable launchers.
Preflight and readback recheck custody. No Root launcher or interpreter runs.

The resulting prefix has 4,014 files, 394 directories and three fixed Python
links: 4,411 inventory entries and 117,018,419 ordinary-file bytes. Tree digest:
`cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637`.
Canonical 23-field clone receipt:
`42a86cca874c40739f48019399b10c20a05f3d528c756f22efbe3833661f9433`.
All six scripts, including the legacy aliases, preserve sibling-interpreter
relocation, isolation flags and argument bytes.

Twelve composition refusals pass: nine identity substitutions, both held
worker leases and consumed-slot replay. Wrong Native and prefix hashes also
refuse in the dependency checker. All 4,041 original files/links retain their
bytes and metadata; replay preserves the complete prefix and receipt.

Rust reads all 63 installed distributions without imports and evaluates all
23 declared requirements against outside-observed CPython 3.12.3 and actual
Linux ARM64 kernel markers: 13 active requirements pass, 10 are inactive.
MCP is 1.30.0. The host independently executes the exact source-pinned Python
staging loop over the same inert metadata and explicit target marker environment;
counts, active names and acceptance match. This is metadata compatibility,
without candidate execution or conformance.

The actual Root ARM64 library passes 133 tests, with 24 preexisting fixture
ignores, log SHA-256
`ca5e7f1479a781eaff5723afa5a277ac25757725587eefc63615d7ba225daca6`.
The historical clone fixture also passes explicitly. The corrected full Mac
workspace passes 423 tests with no failures/ignores; Mac/ARM64 Clippy pass
with warnings denied.

## Retained failure and independent reproduction

The earlier `5fa3f5f3` clone attempt on job `e2c701baf1471501` remains private
and consumed. Its reader incorrectly required 0644 instead of the staged
metadata's 0444. It writes no launcher or receipt, retaining 4,405 entries and
117,017,632 bytes under a Root-private 0700 parent. All 4,041 original files
remain unchanged. The snapshot courier's earlier refusal of two unprivileged
export files is also retained. Independent host readback verifies all 27
members of that failed-attempt export and reconstructs its complete partial
tree. The fix requires exact 0444 custody and validates declarations before
creating a prefix; it does not change existing staging modes or retry the
consumed slot.

The successful 46-member, 26,224,640-byte export has SHA-256
`861ec18d4be685b54a801900cd39309c8cfbd84e2feed217aced63838ea4ee18`.
The host verifies every member, reconstructs the entire expected prefix from
independently verified wheel/dependency bytes and six fixed launchers, and
agrees with the observed tree, counts and bytes. The reproducible offline
[verifier](../ci/gauntlet-rs/proofs/verify_native_candidate_prefix_20261026.py)
accepts `--export`, `--dependency-export`, `--source-archive` and `--repository`.
It intentionally accepts only these frozen proof generations, never grants
admission and imports no candidate. Ruff and its actual retained-artifact run
pass.

Host files are `native-candidate-prefix-vm-results-016.tar` and
`native-candidate-prefix-host-verify-016.json` in the retained evidence
directory. VM records are under
`/var/lib/hol-gauntlet-rust/native-candidate-prefix-proof-20261026-016` and
`native-current-candidate-proof-20261026-016`. Free space after cleanup and
composition is 41,203,634,176 bytes.

Every report remains `artifact_admitted:false`, `execution_eligible:false`,
`guard_causality_verified:false`, with zero model requests. One-use stable
runtime publication, independent controls, fresh conformance and deployment
admission remain separate exits. The parent ledger stays 24 complete/38 open.
