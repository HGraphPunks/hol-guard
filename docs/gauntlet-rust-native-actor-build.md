# Native product-cell actor build contract

The unprivileged Rust actor dynamically loads the pinned glibc libseccomp
library after dropping privileges. Build this executable for
`aarch64-unknown-linux-gnu`, with the ARM64 glibc loader
`/lib/ld-linux-aarch64.so.1`. Static musl is appropriate for the separate Root
worker and constructor, but cannot supply this actor's dynamic-library ABI.

On the native Ubuntu ARM64 builder, use the locked Rust 1.88 toolchain:

```sh
CARGO_PROFILE_RELEASE_DEBUG=0 CARGO_PROFILE_RELEASE_STRIP=symbols cargo +1.88.0 build --manifest-path ci/gauntlet-rs/Cargo.toml -p gauntlet-product-cell --bin gauntlet-product-cell --release --locked
```

The existing actor bound remains 2 MiB. Debug binaries exceeding that bound
are not deployable artifacts. Cross builds must target GNU with a glibc
version compatible with the pinned executor image. Root helpers and actor
are deliberately separate build artifacts; one target setting for the
whole workspace does not establish the actor ABI.

`gauntlet-native-actor-verify ACTOR OUTSIDE_SHA256` checks the bounded inert
ELF64 little-endian ARM64 executable, the exact outside byte hash and its
single glibc interpreter declaration. It executes no actor code and grants
no admission. The ARM64 CI job builds the release actor and runs this reader.
The private-cell factory repeats ELF validation before reserving an artifact
tree. The complete private-cell inventory also checks the native actor ABI.
Historical Python-actor artifact semantics are unchanged.

The fixed libseccomp path and hash, syscall filters, AppArmor, capabilities,
no-new-privileges, namespace, ownership and resource constraints are still
required. ELF metadata alone cannot prove that a live filter was installed;
outside kernel observations and the complete execution proof remain required.
