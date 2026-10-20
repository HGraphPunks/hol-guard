# Inert ARM64 asset-inventory proof

On 2026-10-20, the idle `hol-beta-bootstrap-20261016-004` Linux ARM64 VM held the pinned Gauntlet deployment for source `b4efd8171b06d0e13cbe12a077c376ecdc891fd1`. Its Root-owned config at `/opt/hol-gauntlet/candidates/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/config.json` had the outside SHA-256 pin `97dcf0337f2f98539212390d969a30c2290d3123ce99d8a3aeba7725d54f7568` and asset root `/opt`.

The Rust `gauntlet-inputs-verify` binary was cross-built with Rust 1.88 for `aarch64-unknown-linux-musl`, using the SHA-verified Zig 0.14.1 C toolchain only to build `ring`. Its local and guest SHA-256 were both `fcb4803c27c34ef64011c444078f9d8aec43653d8672527e53821203495a1639`. An unprivileged attempt failed with `Permission denied` at the private deployment files. The exact read-only command under guest Root was:

```text
sudo -n /home/construct.guest/gauntlet-inputs-verify-fcb4803c /opt/hol-gauntlet/candidates/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/config.json 97dcf0337f2f98539212390d969a30c2290d3123ce99d8a3aeba7725d54f7568 /opt --full-inert-assets
```

It exited `0`, reported schema `gauntlet-ci-runner.v7`, installed package version metadata `3.49.0`, 108 selected episodes, and `full_inert_asset_inventory_completed: true`. The pinned Python controller's read-only `load_config` plus `verify_assets` functions were then run on the same config and `/opt` tree; they exited `0` and returned the same 13 role digests and `guard_package_version: 3.49.0`. Every observed role also matched its frozen config digest:

| Role | SHA-256 |
| --- | --- |
| bun | `37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086` |
| compiler | `8376c966ec267dc797b6e4d4a83af829173f70ff10ec86f684307f30ef0529a0` |
| conformance | `e8be3025418181f686dea6a6b86482535a0bdf9bf1762522fd4aef274af4c7bd` |
| guard_prefix | `9af26c159ba48f4ab3f5b4535cd1e146b3c097560a1c4434f8703e508b5786c8` |
| model_manifest | `6f29e77f082dfb2f2be38c5199f5e5b2f084af1ed8cc95b51eeb33b8cbe3487f` |
| native | `8376c966ec267dc797b6e4d4a83af829173f70ff10ec86f684307f30ef0529a0` |
| node | `3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90` |
| policy | `71bc075d1d636134e63a9a3a2cd5d154145589716bdd2f4d0925e9e09abe1c66` |
| private_cell | `de302caa1844f877f66206468fb1579932a74f63d5584c7f468b6709c3e5665a` |
| provider_manifest | `1e852a6e4db1e778e58ed894b037210e12cead8d600d336e39cebc5df315e3c0` |
| sdk | `4b12e74045c56e5f387c2a82312e38a97d665a88cc52bb698e55bf52747bf0b1` |
| wheel | `371c0d6dae392f274e70386254bfc95696287e54b089d9ac2a09f0a92a8b2407` |
| zod_cache | `1e8c5a380e2ef272781700a00062ed39652737c7bae36f59b3897b744579ec39` |

Both readers handled inert bytes only; they did not install a worker, launch Guard, call a model, or alter a Gauntlet journal. The Rust report explicitly retained `tree_and_installed_assets_verified: false` and `execution_eligible: false`. The remaining reader exit proof is symlink-race hardening plus a complete Python/Rust accept/refuse and reason-class corpus on identical retained assets.

The Linux reader was then hardened to resolve SDK and installed-prefix symlink chains relative to the opened tree descriptor with `openat2` and `RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS`; the installed-prefix exception only accepts the same inode as a Root-owned, non-writable `/usr/bin/python3` or `/usr/bin/python3.12`. The rebuilt static verifier SHA-256 was `4748c7a8fdf65c2e6eefde95bc96599b7bfeb1a871b3f15ce5a9387d5479a1ed`, matched on both host and VM, and the exact command above with `/home/construct.guest/gauntlet-inputs-verify-4748c7a8` again exited `0` with all 13 role hashes unchanged. A separate SHA-matched Linux unit-test binary (`eb179b64d1ce9927dfc1bd54d9d7c5e4d54f10504d020c7fa65eba2a8c815e4c`) ran unprivileged in the VM: 8 tests passed, including an inside symlink chain and nested escape refusal. A concurrent mutation/race proof and the full negative parity corpus remain open; this is still read-only verification, not execution admission.

For negative parity, the reviewed one-shot [v7 asset-pin differential script](../ci/gauntlet-rs/proofs/v7_asset_negative_20261020.py) was copied to the guest's Root home and verified against SHA-256 `f2f6209ed2ae3440417c41faaf5e53b0a4b2745a44ce6e292b64f39373f1982e`. The same static Rust verifier was copied into Root-owned mode `0500` at `/root/gauntlet-inputs-verify-4748c7a8` and its SHA was rechecked. The script used the pinned controller Python at `/opt/hol-benchmark-controller-20261013/.venv/bin/python` and generated one temporary config per role under `/root/gauntlet-rust-asset-negative-20261020`, replacing only that role's claimed SHA-256 with 64 zeroes and supplying each mutated config's independently recomputed digest to both readers. The exact invocation was:

```text
sudo -n /opt/hol-benchmark-controller-20261013/.venv/bin/python /root/hol-gauntlet-rust-asset-negative-20261020.py
```

All 13 cases were refused by both readers (`cases=13 reason_stage_mismatches=0`). The script asserted the expected Python exception and Rust refusal stage for every role. The eight ordinary file roles failed their file digest pin, `guard_prefix`, `sdk` and `zod_cache` failed their tree digest pin, and `private_cell` failed the private manifest pin. Changing `native` failed earlier in both loaders because the private-cell native pin must equal the native asset pin. This establishes accept/refuse and broad reason-stage parity for altered declared digests on the retained v7 deployment. It does not cover changed file bytes, ownership/mode attacks, symlink swaps, concurrent mutation, malformed configs or older deployment versions; those remain open in the migration checklist. Neither test changed the deployed `/opt` assets or ran Guard.
