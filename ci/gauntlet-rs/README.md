# Gauntlet Rust migration

This independent Cargo workspace is the first implementation slice of the
[Gauntlet Rust migration plan](../../docs/gauntlet-rust-migration.md). It builds
Gauntlet's trusted code separately from the HOL Guard product workspace in
`rust/`; a candidate product build must never supply its own verifier.

`gauntlet-contracts` currently accepts bounded JSON byte records, rejects
duplicate keys and nonfinite values, reproduces the Python canonical JSON
bytes and SHA-256 digest, and applies the Python depth, node, byte and decimal
integer limits. It recognizes Python's UTF-8/16/32 byte-input encodings. The
golden cases and 256 deterministic float vectors were produced by
`ci/gauntlet/benchmark/json_data.py` at
[`b4efd817`](https://github.com/HGraphPunks/hol-guard/blob/b4efd8171b06d0e13cbe12a077c376ecdc891fd1/ci/gauntlet/benchmark/json_data.py)
in [Gauntlet PR #5263](https://github.com/hashgraph-online/hol-guard/pull/5263),
whose file SHA-256 is recorded in the tests. That benchmark implementation is
not yet on `main`.

Run the checks from the repository root:

```sh
cargo +1.88.0 fmt --manifest-path ci/gauntlet-rs/Cargo.toml --all --check
cargo +1.88.0 test --manifest-path ci/gauntlet-rs/Cargo.toml --locked
cargo +1.88.0 clippy --manifest-path ci/gauntlet-rs/Cargo.toml --all-targets --locked -- -D warnings
```

The next slices add typed identities and schema versions, a read-only evidence
verifier, then the Linux VM worker and host observer. The existing Python
Gauntlet, VM jobs, model provider, dashboard and optional PR gate remain the
authoritative execution path until fresh source-bound parity and recovery
checks justify a controlled cutover. This workspace does not start a job or
publish a status.
