# Merged-source Native worker-budget runtime proof

Product and tooling source `dc3b9336308dab4892bf0c0e0f328a9c8b7efc12`
merges upstream `73b4826503f6ae97d2f0a3cf53d29fd00ae663f7` and preserves the
[CPU-aware Native worker budget](gauntlet-rust-native-task-pressure.md).
The fresh 3.58.0 runtime is published as inert, unadmitted data on owned VM
`hol-gauntlet-rust-build-20261026-001`:

```text
/opt/hol-gauntlet/candidates/dc3b9336308dab4892bf0c0e0f328a9c8b7efc12/prefix
```

The first source-matched traced benign control passes the real Node/npm
fixture with task peak 108 and no PID-limit rejections. Its independent
polling sampler records an assertion failure, so complete outside observation
is unavailable. A passed fixture does not close complete Native grading,
observer admission or conformance. Parent exits remain 24/62.

## Upstream synchronization and local validation

The upstream merge includes 15 commits and 253 changed files. Reviewed changes
include instruction-file risk findings, the Native CLI observer, Claude hook
consolidation, custom rules and structured output, and managed timeout
allowance. No `ci/gauntlet` file changes. The 432-file migration source map,
70 changed/12 added entries, and immutable 420-file baseline remain byte-for-byte
unchanged. The delta and parity manifest hashes remain
`57d0314f1f6a6c4b2ae7f025395d1889725eca02da4370365ae1c9d1fb159c72`
and `9c0418833bfa5795e382a4426ab327afbe630904823e49c07b2bbf6714a8ee0f`.

Exact merged-source checks pass:

- 30 focused Native tests: worker budgets, transport concurrency, actual
  launch ownership/cancellation, and runtime finding precedence.
- Native all-target warnings-denied Clippy, formatting, and matching macOS
  runtime/command-source compiler builds.
- All 585 macOS migration workspace tests, macOS/ARM warnings-denied Clippy,
  formatting, and 32 byte-identical historical control readbacks.
- 637 Native/Gauntlet Python regressions pass; one explicit Linux-Bun bridge
  skip remains visible. The macOS Bun executable does not satisfy that pin.
- All 41 focused recorder, image-generation, replay, trace-join and sampler
  tests pass natively under Root on ARM with both worker leases held.

Logs and frozen executable pins reside under `native-pressure-merged-…` and
`native-pressure-control-…` in the retained local evidence directory. These
checks do not supply the five missing current-head cloud jobs. CI remains
user-owned and pending.

## Fresh build, dependencies and inert publication

Candidate job `e2c701baf1475501` captures the exact commit in a 57,129,521-byte
bare-source archive, hash
`b51100a22e8907e355e6c34f7c82dddd49933e58585348d260d5ee03c820180d`.
The trusted builder's four source inputs remain byte-identical to controller
`84549fd4`; its immutable image is independently inspected. A fresh context
and job-specific AppArmor policy are prepared without overwriting that image.

The 426.68-second build passes four selected checks and all 187 contained
contract tests. The selected checks overlap the complete suite. Outside
kernel observation binds the real builder ELF/argv, held pidfd, UID/GID 65532,
zero capabilities, no-new-privileges, seccomp 2, separate namespaces, enforcing
job profile, slirp and effective 12-GiB/zero-swap/512-task/two-CPU limits.
Independent final readback verifies death and container/cgroup/profile absence.

| Artifact | SHA-256 |
| --- | --- |
| Host prelaunch pin | `f4993dfee3e60a9f092a2e9aa6e2f08b76926f5b5f77ef89b9f9b15bd2a1a86e` |
| Root build result | `833b0331607400a4949cf6ba51f629d28c8b8dc205641d220b8b89e7861d6e13` |
| Root host anchor | `a81646415cd691f74337b275f5d051be2893b2a0636705f24a3fe0a960061266` |
| 24,416,441-byte candidate ZIP | `6334698a6f991798214bbdd2dc9620d724f6ec7ab2c5e83feedb5a3ec93bceb3` |
| 24,667,821-byte wheel | `32f9aae2854605f39d94aeceedec17d6826a40e595d7a74543f492f33f4eb575` |
| 37,402,888-byte actual Native ELF | `bdaf053911cd278930c17e3c58b7741e23334a5156817db78780349f8635eb10` |

Rust verifies all 1,656 wheel entries and 62,745,767 decoded bytes. Wheel
staging inventories 1,706 entries, hash
`04800b680e1fc9c4f0c15002876645c92b278cb41301de5c990f5b287124eb0c`.
Capture and staging replay refuse. Host result readback reconciles the source,
host intent, retained result, archive, wheel, logs and cleanup.

Separate dependency job `e2c701baf1475503` captures the same commit in a fresh
57,130,617-byte source archive, hash
`3ed52f744d4ed944fcb7c0ac14f2d8df5729f959e6deff542b7eb9b1c01abc85`.
The source-pinned Rust exporter and locked project inputs form a 1,114,324-byte
capsule, hash `755a83d6bb45db87a764b9912ad87326cec60433b23c6113e9063a359a4d060a`.
The project and lock bytes match the older source's dependency inputs; this
does not permit borrowing its source receipt. A fresh one-use host intent and
outside kernel snapshot bind the actual exporter and mounted inputs.
The 11.23-second export completes with cleanup independently confirmed.

All 2,302 dependency files and 54,452,716 decoded bytes independently match.
The captured ZIP hashes to
`d45b3d33ca9a1f7460bf20939c6c12674ecfc68b099f7224a095b63bb4b27f24`;
the fresh source-bound dependency-prefix receipt hashes to
`897cf427c9af1b1d6895937b1cc567fccb5962d7792ec0ae39271c625d4cb5d1`.
Its complete tree remains `df07ad78…acebb2`. The measured system interpreter
remains CPython 3.12.3, ELF `c86f21d0…6cbe960`.

Rust composes the dependency prefix, every wheel file and six relocatable
console scripts. Complete requirements checking and the exact-source Python
metadata loop independently agree: 63 distributions, 23 requirements,
13 active/satisfied and ten inactive. Staging, composition and immutable
publication pass all 36 positive/refusal/lease/replay cases. No package runs
during those operations. The 4,361-entry, 117,199,371-byte published prefix
hashes to `742c7726d39dc3a73c6015329374410eb55f1d9e543539daf17f1f7d0d6e6736`;
publication receipt
`7e8ea23d84d87b807133298fdff6d4306b0823902360eb23072732dd230b73f3`
matches in both locations.

## Independent reconstruction and first control

The [fixed-generation host reader](../ci/gauntlet-rs/proofs/verify_native_pressure_runtime_20261028.py)
verifies every member of `native-pressure-vm-results-001.tar`: 86 members,
48,455,680 bytes, hash
`a73bbaf48f5cfa42c753f54f98457d06bf65a0d427ad49c49e90e8c17d273338`.
It reconstructs all wheel/dependency bytes, four complete prefix trees,
source blobs, host/Root execution records, launchers, all 36 cases and Python
requirement parity. Successful output hash is
`01c9e2dbc4651fd2631f2affda434cdf02566fcd473a89dcd41d487085c5ec19`.
All 312 prior worker records remain unchanged through inert publication.
Historical builds, prefixes, failures and receipts remain in their old custody.

Fresh traced control `e2c701baf1475601` uses this exact product/tool source,
the unchanged single-CPU/1-GiB/128-task cell and original benign fixture.
The signed controller reports `passed`, and host signature/context readback
succeeds. The actual fixture confirms Node `v22.22.2`, npm `10.9.7`, the pinned
Node ELF and the private-plane file effect. The SDK receives the exact
Native-reviewed original output. Pressure observation records 200 snapshots,
task peak 108, no pressure errors and `pids.events: max 0` throughout.

The independent polling sampler stops after 57 observations with
`AssertionError: `; its error remains present. Root process tracing separately
closes 393 created tasks with 393 actual final waits, 127 execs and 1,997
journal events. The
[fixed control reader](../ci/gauntlet-rs/proofs/verify_native_pressure_control_20261028.py)
checks the 159-member public export, passed fixture and incomplete sampler,
then delegates actual/restart/three refusal cases to frozen Rust reader
`a0439880`. Its proof hash is
`b05e0af588cc91777a9c6e7089a1cfa6d296399d6577469124f132f23c9b1409`.
The control export hashes to
`ad4c20c8a419d154a35d8fa5a5919e57a566adf8d2b4c7be2a7d86613c711c84`.

This attempt retains all 312 prior worker records and adds seven; the resulting
319-record baseline hashes to
`e4776ada639da46a179784d39df8fccda522c27e9e6166639e2ddabd8bb191a0`.
A fresh diagnostic control adds bounded sampler error tracebacks, with every
observation assertion retained. It does not reproduce the failure; its exact
cause remains unknown.

## Second source-matched control and complete artifact readback

Control `e2c701baf1475602` passes the original fixture and signed host readback
in 72.49 seconds. The outside observer records 70 kernel samples and one
controller observation without errors. Separate pressure sampling records
213 snapshots without errors, peak 108 and `pids.events: max 0`. Root tracing
closes all 392 tasks with 392 actual final waits, 127 execs and 1,930 events.
Post-cleanup bounded kernel readback finds no remaining UID-10004 product
process or thread anywhere in the owned VM.

The exact-source Rust reader passes signature-only, MCP, process, hook and
complete artifact-relation modes, an identical complete-mode restart, and
three wrong-archive/interpreter/observer refusals: nine cases. It checks all
nine gated/interpreter launches, four observed Native clients with no missing
selected client observations, three acknowledged hook inputs, three raw SDK
request/response frames, eight reconstructed output captures, both MCP
families and physical fixture/database relations. Internal Native request
bytes, actual effect writers, full Native descendant grading, observer/key
admission and independent qualification remain explicitly unverified.

The public export has 159 members and 2,979,840 bytes, hash
`31364fd5f5fbcf0ca165952e6aef04a72394255c1b756fc31d2b792fef4de8f1`.
The nine-case artifact proof hashes to
`f92816454340b1a34a18a20b5cfa9641561e1d76dd4c4ed3f282d7ba41227f7c`;
complete-mode output hashes to
`60c0eb64e13413a00c8341bc2e34100d896593bacb026d368325ee73353b5b74`.
The [second fixed-generation reader](../ci/gauntlet-rs/proofs/verify_native_pressure_complete_20261028.py)
independently checks the export, pressure and retained limits, delegates five
actual/restart/refusal trace cases to frozen Rust reader `a0439880`, and
repeats complete artifact verification with the exact-source Rust reader.
Its five-case trace proof hashes to
`7fe47b3c18ba483050f9654c9d256c914d87896da41ce9bf9c0660ccc6785895`.

All 319 prior worker records survive. The resulting 326-record baseline hashes
to `16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be`.
These passed fixtures do not erase the first sampler failure or close the
broader pressure, full-grading or conformance exits. All evidence remains
execution-ineligible and without verified Guard causality. No model request
or quota reset occurs.
