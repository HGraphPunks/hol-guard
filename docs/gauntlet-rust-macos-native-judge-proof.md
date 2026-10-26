# macOS Native fixture and CI proof

The real Gauntlet Bash-owner fixture now executes on macOS 26.6.1. Its
compiled registry keeps the Mach-O `LC_UUID` command, its exact five-line
report and deletion sentinel are checked, and the authenticated Native
operation journal must agree with the physical result.

Source `dca678a6` corrects four compiled fixture builders and makes the
consent test's current policy explicit. Source `6c6c0c71` adds a direct
`LC_UUID` assertion to the real lifecycle test so older CI images also reject
the invalid fixture. The chunk imports four upstream commits through
`main` at `f1f90ae6`.

## Failure and correction

The original fixture returned `native_bash_launch_failed_after_authorization`
with dispatch acknowledged and its operation uncertain. A separate diagnostic
checkout of `ca15e04a` traced the captured helper to dyld's
`missing LC_UUID load command` error. The helper exited by signal 6; the Bash
child returned 134, and the broker refused EOF before its next planned call.
The uncertain result was preserved.

All four positive compiled-fixture builders used `-Wl,-no_uuid`. Removing that
flag keeps the linker's UUID metadata while preserving the existing code
signing, hardened-runtime options, no-entitlement checks, captured executable
hashes and launch fencing. The original lifecycle test then passed with the
uninstrumented Native runtime. The temporary diagnostic changes remain in the
separate checkout and are absent from the migration branch.

The expanded consent suite also exposed a fixture assumption: ordinary
verified HOME writes are benign under the current Native file-write rules.
The consent variants now select `require-reapproval`, as the SDK tests do;
the quiet variants select `allow`. Every existing assertion remains, including
both approval choices, once and persistent reuse, default resolution behavior,
blocked intent, replay, integrity and physical report checks. Product policy
and approval behavior are unchanged by these fixture corrections.

## Observed local results

- All 53 Bash-owner, Native sink and delivery tests passed, with no skips,
  using Bun 1.3.14 and the uninstrumented Native runtime. The subsequent
  UUID-metadata assertion passed in the focused real lifecycle test.
- All seven macOS hardened-image tests passed, including actual valid-image
  execution and rejection of non-hardened and JIT-entitled images.
- All 51 Gauntlet CI policy tests, the complete 427-file source inventory,
  macOS/ARM64 controller-plan tests, warnings-denied ARM64 evidence/contracts
  Clippy, Rustfmt, Python Ruff and workflow YAML parsing passed.
- The matching Native runtime and source compiler were built together using
  Rust 1.88.0 and the existing CI release-test overrides: LTO disabled and 16
  codegen units. Full Native program and directory preparation/checks passed
  with program digest
  `a01ccc683e8bb415a08bbc1a9a9eec4236277a1290b5748952a9cfb07ae873d9`.

| Retained artifact | SHA-256 |
| --- | --- |
| Uninstrumented Native runtime | `c808421e178dfd7bc794d581852b2ed4ec482c7dd8fb9502609e5a9ae9ab831b` |
| Matching source compiler | `be0b5e172f47dcb9e4c02cb6e4c4c4d49248c5b0af17b2bce228b00ce5608199` |
| Separate diagnostic runtime | `50a0bcb4db396385266b0be2d7a45a419dc2e1a22b9ce204236ce69d033b7a33` |
| Diagnostic source patch | `1e13d9ce28ba399bf3b32fed140a96907ff05eaecab64aa8275311723213d12a` |
| Private diagnostic log | `b778b707740d7403e3b2936f39c0152b20e2c250a6977602fa4bf7c02d13bd24` |

Python's bootstrap selection and Rust independently agree on 396 selected
files, 407 entries and current controller digest
`9c936cb68c564ee8f9ad4d92ee3efcc58268262acb957845a16a10a5f22c1164`.
The immutable baseline remains unchanged; the reviewed delta still contains
58 changed and seven added Gauntlet files. The retained VM controller remains
the older `01ba1750…` generation.

## Incremental CI

The integration-only `macos-native-judge` job builds matching Native binaries,
prepares and checks the full current program and public directory, runs the
seven hardening tests and all three Python fixture files, and retains JUnit
results. It uses pinned Rust, Python, uv, Bun and action revisions. Its cache
namespace is separate; only the exact integration branch's successful push
can warm that branch's dependency cache. PR refs remain cache readers.

The chunk cycle now requires five current-head jobs before integration.
An explicit `workflow_dispatch` also runs all five jobs on its selected ref,
including the Native jobs whose automatic triggers are integration-specific.
The child PR records their actual results. Existing required product checks
and the passive benchmark gate retain their current ownership.

## Latest upstream and unavailable Actions

PR #3 subsequently imports upstream `d1ab7bc629f3c5bbd45459424e5b0a39be880fea`
as merge `e5f4b1205ff7958c9eb14322d3953285dd4ef2ab`. The only incoming change
seeds `test_runner_sync_payload.py` receipts relative to the real clock; its
old fixed date expired on October 23 and could fail every open PR. All ten
tests in that file passed locally with the matching Native binary after this
merge. Gauntlet and Native implementation bytes, the 427-file source map and
controller digest above are unchanged.

GitHub's dispatch API returns HTTP 422, `Actions has been disabled for this
repository`, although the repository permissions API reports enabled.
Reapplying that existing setting did not restore execution. There is no
current-head cloud result, and this child remains unmerged until all five
required jobs actually complete on its final pushed SHA.

These are source-built, synthetic local and CI fixtures. They made zero model
requests and do not establish exact-wheel real-agent qualification, fresh ARM
VM conformance, independently authenticated model usage or migration cutover.
