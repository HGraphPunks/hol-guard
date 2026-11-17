# Upstream synchronization through 785b6aaf

Merge `8208a6b52f547e29392a42693af47c7cee3a08e1` imports 35 upstream commits
through `785b6aaf39a387f52873966cee62125d5ce1c90d`, preserving published
migration history. There are no conflicts. The migration's contained-completion
adapter and upstream's contained-verdict handling remain present.

Review covers all seven changed Gauntlet files: the README, approval-row
transport, harness setup, proof checks, review fixtures, runner and scenario
catalog. The new GitHub case uses a local recording stand-in for both a
repository named `hol-guard` and a global `--hostname` option; it makes no
GitHub request. Approval rows use the Native batch scope API. The explicit
map remains 432 files, now with 70 changed and 12 added entries. The 420-file
immutable Python baseline and historical source/proof pins are unchanged.

The actual Python bootstrap selector, run with an inert transfer sink,
independently selects 401 files and 412 entries, with controller-tree digest
`5a135a5abb4f0663bbdfb6e440c085f443ac6be943ccee7afd11fbc9ba46a311`.
The Rust current-source assertion is updated to that digest. The inert
fixture generator still expected an older 400-file selection; its corrected
401-file check produces archive SHA-256
`fa650e3c649da04f3ed06107b1ed2628c6f47a3bcf6d72729312e8320592792c`.
No controller is installed by these checks. The selector and installer remain
byte-identical to the previous synchronization.

The first merged workspace attempt refuses the stale 69-file inventory
assertion; log SHA-256
`efb3c71dc55a5cfd2be832ff1075f174d2a95474f4eeb1e6dc08e841760584b4`.
The corrected test retains exact path/blob checks for every reviewed file.
At source `c6c35510fb18bbd4ca3fcf3c6717c0961fceb336`:

| Check | Result | Log SHA-256 |
| --- | --- | --- |
| Full migration workspace, all targets/features | 561 passed, no failures or ignores | `af8864c0739aa24e08948218cd53c50347082fa541a4e9aa944bca899956ca05` |
| Mac workspace Clippy, warnings denied | Passed | `ccebd0119d30b892b113f993aa2ea487da6914a127f29580096d0e5f93798a46` |
| ARM workspace Clippy, warnings denied | Passed | `fba641450a397204260c3b51dca4cccb9d9817b685c213fd08ec6c1d20991a87` |
| Matching Native library, CLI and compiler | Built, package 3.58.0 | `6fb21b705b7acc13ed62b994cb81eba09491939906f1523cdd1ae35bdfd095df` |
| Native contained-output integration | 3 passed | `70f2d3e2d6bb2798daf58b88ac7728c55435ee3a5ecf2e61a0a37bb974421350` |
| Mac pinned-image hardening | 7 passed | `ab653a720b8e0ead0d60ee3b279958fee866e81a2429c640a55c0eeada82979b` |
| Native program/public directory | All five stages passed | `9864ee8d839704e3a4999ef733bdc509d2deb0a8d63c4cb6c3fc3416ab39ad8b` |

Program validation uses a new private synthetic home and a public 32-byte
test key, with the owned resident closed afterward. Three generated public
directory outputs are retained with their committed originals and binary
patch before restoring only those generated changes. The six-member archive
has SHA-256 `d26de1ceb41c89bce4d648d7b6015dc8fe23c5a4cefee29184f83baeb6f63c89`.
No real Guard home or credential store is used.

The broader 26-file Native/Gauntlet suite initially reports 637 passes, one
failure and one explicit Linux-Bun skip. Its retained log hashes to
`29c27339c2d6c2841f03f381d394226283ef1c7b950541cde02bae6a2fcb32fa`.
The failing upstream watch-mode case finds the vulnerability text behind an
intrinsic workspace-containment floor, but the final observed response keeps
the containment reason code and omits the runtime finding identifier. A
public-field Native-edge trace reproduces it, SHA-256
`9ceafd9877078ccf7ed6c9df011acdff20bb28108be65504bc31940a462e8b87`.

Rust fix `564a7a471d7d67d59d0f01ed2a687b01d7f27467` identifies that finding
for the specific observed workspace-containment case. The intrinsic floor,
policy action and deny decision remain `sandbox-required`/`deny`; enforce
mode and intrinsic reviews retain their previous behavior. All 13 runtime
finding unit cases pass, log SHA-256
`6e1e9cb15dc7acbc8568c63a7978107bca40b40de0ffd594d43c2e7b040174fc`.
Runtime Clippy with all targets and warnings denied passes, log SHA-256
`de6aefe905145784bb9b37747775745db50f23d766a5875e660d5ec60345a60f`.
The unchanged failing integration now passes with the expected observed
identifier; its trace hashes to
`4a331813dc4c27a4a8cbfe9a5b14abd9988df9e32e3c22f8a6cb7ca6eb27c93b`.
The frozen current Native runtime has 120,681,280 bytes, below the unchanged
128-MiB admission limit, and SHA-256
`884a3321cf56d6e469f3cbc026d7e7b3875f25525e806022de48a6e7389cda8d`.
Its compiler is byte-identical to the validated compiler, SHA-256
`0d59f7b8efad7e1b04b421286f2ad863bac6ca326295d12c6a43a80debc1ac49`.

The complete 26-file regression rerun against this fix passes 638 cases with
one explicit Linux-Bun bridge skip and no failures. It covers the unchanged
watch regression, approval scopes/persistence, exact-action Always allow,
package reviews, Bash ownership/delivery and the new offline GitHub case.
Log SHA-256 is
`4ad697f853b2d8b0af9d44d83904500542609c5ca5f44af3cb5c09eb4a449ad0`;
JUnit SHA-256 is
`f67f6259e21a75f1c2d72b8aad0746a5b20369dae287a667c7c3def41e51de45`.
The Linux-Bun bridge retains its separate historical eight-case VM proof;
the Mac's four actual observer cases pass with pinned Bun 1.3.14. Both Rust
workspaces pass formatting checks. All initial failed attempts remain retained.
Fresh full-source VM candidate/conformance, independent custody/admission,
the retained intermittent 128-task failure, operational exits and all five
final-head cloud jobs remain open. CI is user-owned; no bypass or merge is
performed. Parent exits remain 24/62 and model requests remain zero.
