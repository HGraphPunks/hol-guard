# Upstream synchronization through 759130ab

Merge `7a473d21cd57dc0b870e9eb2d80e31c475c4fd78` preserves upstream
`759130abeac163bcb23fa708cbb150c7e973b20a` and the published migration
history without conflicts. Upstream includes Native hook document redaction,
running-process identities, signed network bundles, approval recovery and
further Python runtime retirements.

Nine Gauntlet files changed. The review retains the two explicit Git-allow
refresh scenarios and their physical fast-forward/stash checks. Installed
acceptance contract v3 adds prompt cases, exact per-event registered argv,
declared-but-unregistered event failures and rejection of cases no harness
can replay. Intentionally unregistered prompt hooks remain explicit skips.
These additions remain part of the pending Rust legacy parity scope.

The immutable 420-file Python baseline is unchanged. The explicit delta now
records 432 Gauntlet files: 69 changed and 12 added. The new Git fixture has
an explicit Rust-port disposition. Python's actual bootstrap file selection
and Rust's source-derived plan agree on 401 installed files, 412 entries and
tree digest
`618719916d29001162f4a228c28713ee73928f9b7082f2547c85066551549a2c`.
This is a new source plan; the retained VM controller/prefix are not relabeled.

The Gauntlet Mac workspace passes all 454 tests across 218 targets with no
failures or ignores, plus warnings-denied Clippy. Log
`rust-workspace-after-759130ab-b.log` has SHA-256
`b76b61567283c0372ce4773fa906d19cca7fb1db6d3e9714c8a811f3960c6f23`.
The earlier stale 68-file changed-count assertion is retained in
`rust-workspace-after-759130ab.log`; the corrected test still checks every
tracked source byte against the reviewed map.

Matching Native runtime/compiler builds pin package 3.57.0 and merge source
`7a473d21`. Development symbol stripping produces the 119,387,696-byte
runtime, below the unchanged 128 MiB resident bound. A real isolated resident
context request succeeds. The initial omitted package-version override and
the oversized unstripped development builds remain recorded as failed
validation inputs; no product bound or approval assertion was weakened.

| Executable | SHA-256 |
| --- | --- |
| Native runtime | `939ce2dc19803cad05a981bf0fd281c19a0b10183ec1af973065ca8219901e27` |
| Command source compiler | `15c13e6639c84fd81661bf0b6752b234d316eac0941e2376608b77869b64a11c` |

The focused 14-file Native/Gauntlet suite passes 369 tests. Its one skip
requires the exact Linux Bun ELF for eight TypeScript bridge vectors. Those
vectors now pass separately on the ARM VM with the exact Bun pin as UID10001;
see the [native unit proof](gauntlet-rust-world-proof-20261027.md).
Mac Bun observer
cases and real Native Bash ownership, policy readiness, exact-action approval,
installed prompt replay and MCP/container contracts pass. Log
`native-and-gauntlet-after-759130ab-c.log` has SHA-256
`260b66a2f0e82cef11a44632826f645551977a1d413f374e34fe523ff41a2b54`;
JUnit SHA-256 is
`567bca52d2e81357f18c38fd51f73f4fed04632ad73ca08fad2eec90feb30437`.
Both earlier unsuccessful product runs are retained separately.

Fresh current-source VM candidate publication, full conformance, the five
actual final-head CI jobs and remaining migration exits stay open. The user
is handling disabled Actions separately. No inference, quota reset,
upstream PR merge or production gate activation occurred.
