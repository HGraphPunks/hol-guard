# Current 3.58.0 Rust build and inert runtime proof

Exact product and build-tool source
`9f42d9dd3574ede89d8912a85813f9d817a9de46` now has a fresh Rust-controlled
build, dependency run, complete wheel verification, compatible prefix and
one-use runtime publication on owned ARM64 VM
`hol-gauntlet-rust-build-20261026-001` (two CPUs, 16 GiB RAM, 48 GiB disk).
This supersedes the current-source build/publication gap identified after
[upstream synchronization](gauntlet-rust-upstream-sync-ee0b44f4.md).
It does not supply deterministic conformance or close a parent migration exit.

The published data path is:

```text
/opt/hol-gauntlet/candidates/9f42d9dd3574ede89d8912a85813f9d817a9de46/prefix
```

Root imports and executes no candidate or dependency during capture, staging,
composition or publication. The separate build container runs the product's
contained contract tests unprivileged. Every artifact remains unadmitted,
execution-ineligible and without verified Guard causality. Zero model requests
ran. Old source paths, failed attempts, journals and receipts remain unchanged.

## Fresh source and contained build

The Rust local-Git producer and graph reader independently bind the exact
commit and `refs/heads/local-9f42d9dd3574ede89d8912a85813f9d817a9de46`.
Candidate job `e2c701baf1475201` retains a 56,908,589-byte bare-object archive,
SHA-256 `9aa9ccab60c047d258e263fec2539f991453e538ef5845c57c991dd0199eb6cc`.
The host intent precedes Root execution; source capture remains immutable 0444.

The retained trusted builder controller generation `84549fd4` has tree digest
`681f204300c1d85327b244f9a45cf733a00a3e9ac18b56694174b8904b1f5b69`.
Its Dockerfile, AppArmor source, builder entry and artifact adapter are
byte-identical to the current source. The new job receives its own context and
policy. A request to build the already existing trusted tag refuses before
mutation; independent image/label/platform/UID inspection allows reuse of
immutable image `383e9cf215d3b8481c2b9fb67d32816ef322b7f40abc17e5a1f9a72dd728fc8a`.
No tag or old builder generation is overwritten.

The build completes in 438.51 seconds, exit zero: four selected checks and
all 187 contained-contract tests pass. The selected checks overlap the full
suite. Outside observation binds actual PID/start tick/held pidfd, Python ELF,
exact builder argv and script, UID/GID 65532, zero capabilities,
no-new-privileges, seccomp 2, separate process/mount/network namespaces,
slirp and effective 12 GiB memory, zero swap, 512 PIDs and two CPUs.
The actual attachment is a mixed `crun//&job` stack; the separate job profile
is independently observed in enforce mode. Final observation finds the
original entrypoint dead and its exact container, cgroups and profile absent.

| Current build artifact | SHA-256 |
| --- | --- |
| Host prelaunch intent | `3c84ba18fc0cc39aebe50b4c0a20c2f52f1b009be9362ec5f198b7396662dc86` |
| Root host anchor | `bda85f07eff1aa6f279942ccdc72827fa7d34aab61bfdae4c01e250662add454` |
| Retained Root build result | `56021d970cd71e1d9a6ca5ca5a0065273ec8fed2c70d64986695edcf66e3fcda` |
| 24,440,917-byte candidate ZIP | `66433a3f03d55c86bef4666f253620039a678f920e15ebcfd4675e8f1cf93303` |
| 24,691,647-byte 3.58.0 wheel | `3ade48a5c814b42a83e9a9d849071968c38a202445a1dc8d3ecf35830cc1b6dd` |
| 37,403,464-byte actual Native ELF | `b25537f38e7374348366208e1d6e4edd51446cff9853c261bde4e7253e17117e` |

Rust verifies all 1,665 wheel entries and 62,822,365 decoded bytes; their
framed digest is `f93d6bcb373c8bce154bd122e96b4876094e22090cb3fe4e2d2d5583188a90fa`.
Inert staging independently inventories 1,716 entries, tree digest
`2c3c0be8ea465c4e38358e31b99c79f2e3a5320a895b57389790f4bf63d47f13`.
Wrong capture digest, capture replay and stage replay refuse. Rust host result
reconciliation matches the result, archive, wheel, source, logs, host intent
and absent cleanup. Its initial pre-capture read refuses as required; the
post-capture read succeeds without rerunning the build.

## Fresh locked dependencies and complete requirements

Dependency job `e2c701baf1475203` independently captures the same exact commit
in a distinct 56,908,850-byte archive, SHA-256
`1138a3f23a2e43f109690abd2d2f4a9d8ac1cbd84a857e83a13ff1d2dacf2d8d`.
The current project and lock hashes are `630779e8…5df9b58f` and
`8f850a30…f47c6cc3`, different from the historical 3.57.0 input pins.
Rust produces/captures a three-member input capsule, SHA-256
`406bc995185152c3542a8cb773f785b77c91489beaa886ece1472a6b7bc8d8da`.

Under a durable host intent and the measured Root worker, the fixed
UID-65532 Rust exporter installs only locked dependency wheels in its bounded
container. The 66.34-second run exits zero. The outside observer binds its
actual ELF `a4dbe9fd4f54a6d23c34168d9c68f67407b8d09b8a932643a56b5d975da28e71`,
five exact argv arguments, both mounted input hashes, intent label, held pidfd,
kernel restrictions and effective limits. Independent final checks prove
death, container/cgroup/profile absence and unchanged prior worker records.

The host intent is `2b73c22609df1a135d497f76285275c5ed1f55227ab9026da9c1baabbb7a140b`;
the retained producer result is
`de475cf508a237b376e08cbd91f40fd2c91e96382f57d19950eab1ac6aa05ad5`.
Its 17,489,481-byte captured ZIP hashes to
`0aa4548a77aceb99b73a273fa1eef2fbdc4a946f244204d1d50dd24a32edfdcd`.
Every one of the 2,302 dependency files matches independently, totaling
54,452,716 decoded bytes. The framed file digest remains
`62b019ab339c6471c20e62890f89f9a9fae056ba86757c654cee4718f71d09ed`.

The fresh system interpreter is CPython 3.12.3, actual ELF hash
`c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960`.
The older `6242e0e8…` pin refuses before either partial or prefix creation;
the old receipt is preserved. Debug-worker refusal calls also expose roughly
38-second validation latency. A release build of the same Rust source is
separately frozen and installed; its actual worker hash is
`0837235333feac8481e2f47d374de5bacb187a2e7646f95d0cad9fd1422e645d`.
Its 12,988,688 bytes and source identity are independently pinned. The original
debug runner `4d6c104d…` still owns the retained dependency execution.

The optimized Rust stager passes five wrong-pin cases, both competing leases,
positive publication and replay. All 17 original files remain unchanged.
The fresh 2,649-entry dependency prefix has digest
`df07ad782d2bea44d49a3ac4a84a1ae3a160d4fe96764adc4b591d4a82acebb2`;
its source/interpreter-bound receipt hashes to
`5dc6f4f440a15eb530f47b6c1348121298a2d0f0f9ab4d061d192d6d977c3897`.

## Composition and immutable runtime publication

Rust clones the fresh dependencies, overlays all wheel bytes and creates six
fixed relocatable console scripts, including legacy aliases. Nine identity
substitutions and both competing leases refuse; positive composition and
replay pass. A separately pinned optimized checker passes complete metadata
validation and refuses wrong Native/prefix hashes: sixteen cases in total.
All 1,677 original files remain unchanged.

The resulting 4,371-entry prefix contains 117,275,969 ordinary-file bytes.
Its digest is `dcea26a1e1f5ba54e085daf3f5eaa5f38eb85357c4ee92fa489828d5b00ad036`;
the clone receipt hashes to
`d9a86189425854aae01ed0f044f8cdc0bac25324a2543b91048993bde37f7692`.
Rust evaluates all 23 requirements against all 63 distributions and the
actual Linux ARM64/CPython markers: 13 active and satisfied, 10 inactive,
with MCP 1.30.0. The exact source-pinned Python staging loop independently
agrees using the same inert metadata and explicit target environment.

One-use publication passes seven identity refusals, both busy leases, actual
publication and replay: eleven cases. All 5,655 original files/links remain
unchanged, as do the complete job and published trees on replay. Publication
executes no package. Both canonical receipts are byte-identical, SHA-256
`99a42a9746f9a1463b814264c49fc6e868fa2116106c38643500e07699ecaac1`.
The published tree exactly matches the independently reconstructed prefix.

## Independent reproduction and retained limits

The host verifies every member of the 104-member, 51,394,560-byte public
export `native-current358-vm-results-004.tar`, SHA-256
`ae25aaeef7168b1694cd7486ae564c6d609f84c80bac934077351ef74181f217`.
Root hashes its held archive before handing it to transport UID 501.
The [fixed-generation reader](../ci/gauntlet-rs/proofs/verify_native_current358_20261027.py)
checks outside host journals, Root results/receipts, logs, all ZIP bytes,
source blobs, four complete tree inventories, six launcher bodies, all 36
staging/composition/publication cases and Python/Rust requirement parity.
The actual readback and Ruff format/lint pass. Successful stdout is retained
as `native-current358-independent-host-readback-002.stdout`, SHA-256
`dc54840f093ec352652be00af1dd22f1b3ed32d4b33768d35b8e6a034f8068fc`.

The first dependency job `5202` succeeded but its independent observer missed
the live process because the courier encoded a NUL followed by a digit as an
octal escape. Its unavailable observation is retained and receives no kernel
credit. A corrected, independently checked argv construction runs only on
fresh `5203`. The initial host source courier's unsupported system-Python
hash API, pre-capture result refusal, stale-interpreter refusal, existing-tag
refusal and first export's incorrect five-file journal expectation all remain
retained. The corrected export requires exactly the actual four journal fields;
it does not change journals or fabricate a missing record.

All 284 old worker records retain their hashes. Current build/dependency
containers, cgroups and profiles are absent. Final free space is
29,697,196,032 bytes. Proofs reside in the retained local evidence directory
and the separate VM `native-current358-…` proof directories. Full source
archives stay in their original custody and are hashed rather than exported.

This closes fresh 3.58.0 inert publication and metadata compatibility only.
Independent Rust deterministic grading, twelve fresh staging/installed roles,
conformance/deployment admission, broader interruption recovery and feature
audit, operations, model workflows, legacy compatibility and cutover remain
open. Required CI is user-owned and pending. Parent exits remain 24/62.
