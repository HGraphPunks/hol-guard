# Rust Native binding artifact verification

Rust verifier source `b059a59000b4b76e282f65ffa9b56f5e5570c2d7` now
checks the retained input-binding diagnostic's public capture and physical
relations after authenticating its completion against the prior host journal.
This is one independently recomputed subset of R3. It does not complete
deterministic role grading or change the 24/62 parent-exit count.

The existing offline CLI keeps its original eight arguments and observation
schema. Appending `--input-binding-artifacts PUBLIC_USTAR SHA256` selects a
distinct artifact-observation schema. It refuses any role except
`input-binding`. The host opens every path component without following
symlinks, holds a regular single-link owner file, refuses group/world writes,
checks stable descriptor/name metadata and verifies the caller's outside
SHA-256. It reads at most 128 MiB without extracting files.

Only normalized regular USTAR members are accepted: bounded ASCII paths,
no duplicate names or link/extension records, at most 2,048 members and 32 MiB
per member, with a complete zero trailer. The archived report must match the
host-authenticated report digest and diagnostic. Preparation and declaration
bytes must match the pinned context; the runtime prefix must name the pinned
product source. An archive cannot choose a different job, role or signing key.

The Rust evidence library checks every indexed file digest and length,
the complete supervisor-event hash chain, unique capture filenames and actual
stdout/stderr bytes. It reconstructs the nine malformed requests exactly,
including the deliberately duplicated JSON field. Every handoff's byte/hash,
UID/GID and fixed request path bind to the complete Native argv. Each distinct
capture must return 126 with an authorization refusal, empty stdout, no
capture/cleanup error and no trap effect. The retained trap bytes and physical
inode/owner/mode must match their original observation.

The separate forbidden-command relation requires the fixed synthetic seed,
actual unguarded deletion, a reseeded marker with different held file/directory
inodes, an actual captured deny/block decision, and a subsequent Native
authorization refusal. Captures must occur in order. The final marker must
retain its exact bytes, original inode and owner/mode, and single link. A
planner failure, captured allow decision, reordered hook or substituted
same-byte marker refuses.

The request wire and live custody observations remain signed Root-controller
measurements. This subset does not independently observe hook stdin or live
request descriptors, recompute outside kernel/SDK/MCP observations, score the
other five roles, admit signing keys for qualification, or prove full Guard
causality. Its output explicitly retains
`independent_process_custody_checked:false`, qualification/eligibility false
and zero model requests. The historical product is not relabeled as current.

## Retained actual evidence

The executable is retained outside the repository as
`native-binding-artifact-verifier-001`, 2,428,400 bytes, SHA-256
`13e5a3eb4e3bb0a96af10d3b3237099a13abdddd4e878da3e6643793ed90ccab`.
It reads actual v7 job `e2c701baf1475103`, Rust runtime source
`f53bc490`, historical product `62aa7ba7` / 3.57.0, and archive
`native-host-keyed-vm-results-001-input-binding.tar`, SHA-256
`5b9eb3ca04063bfb535dbc09f133ee8fb1409fa3b897964c46b8da2963aece94`.
The existing host journal and all original artifacts remain unchanged.

The inert
`ci/gauntlet-rs/proofs/verify_native_binding_artifacts_20261027.py`
courier executes only the offline Rust verifier. Fourteen cases pass:
six historical envelope regressions, actual artifact verification, identical
restart readback and six refusals. The refusals cover a wrong digest,
cross-job archive, wrong role, replaced physical marker inode, broken hash
chain and altered captured stderr. The latter three use separate synthetic
mutation archives with recomputed inventory/outside digests; originals are
never modified. Every refusal exits 2 with empty stdout.

The actual and restart stdout are byte-identical, SHA-256
`04d4625ea7d591e81326d6ee23a6eef455547e4ffaf98f81a9160e3d8e8694ce`.
The 4,049-byte proof index `native-binding-artifact-proof-001.json` hashes to
`03004a1af4f335b641d844f2d533b4a30523c2491b15f7aed1a85ddf55da83d8`.
The earlier signature-only executable is separately retained as
`native-host-keyed-offline-verifier-001`, with its original
`c8036050…50cfc844` digest.

## Local validation and remaining work

The complete macOS workspace passes 510 tests over 217 targets, with no
failures or ignores. Log `native-binding-rust-workspace-003.log` hashes to
`8a685c9156b32039f0014b4480bba64169cc437de99e549c9fa983d280bc727a`.
All-target/all-feature warnings-denied Clippy passes; its log hashes to
`08cdb8db9bc8e2d6c27ed1d750e038f3a582afce4e0326767049491a046824d6`.
Seven new evidence tests cover hostile semantic mutations, with two more
host tests covering archive/path custody. The strengthened broken-chain test
also passes after recomputing its manifest; its separate log hashes to
`9329a58c1d6d3c40d4db809a4de9bb21a0faa83183efcd705153ee79e7b422af`.
The proof courier passes Ruff format and lint.

The first compile failed only at a test helper's nonexistent tar API;
the failed log is retained. The subsequent run passed the new tests but
encountered transient `Busy` during the existing parallel observer fixture's
immutable configuration setup. That setup now uses the existing bounded
`Busy` retry; uncertain commits and real failures are still final, and all
observer assertions remain. Both failed attempts remain retained under
`native-binding-rust-tests-001/002.log`.

Linux ARM validation also passes at source
`788eeeed49a7ade424705ac965a52a80c49869f9`, whose Rust implementation is
unchanged from `b059a590`. All-target/all-feature warnings-denied ARM Clippy
passes; log SHA-256 is
`b2a3431b99bda0b071b2640d373267647f9447e33f6827dbbbbd1b7110aab2dd`.
Two pinned static test executables run through held descriptors under Root
on the owned VM: all seven new evidence tests and both archive/path tests pass,
with no failures or ignores. Both worker leases remain held, all 284 old
worker files match their prior hashes, and owned product cgroups remain absent.
These are the nine new tests, rather than a claim to a full native workspace run.

Input `native-binding-arm-input-001.tar` is 28,006,400 bytes, SHA-256
`5baa8c5a4c744f070c842eb31be4bd1353d5cf72a96bab02c691b98e7fe5bbe3`.
The eight-member public result export
`native-binding-arm-vm-results-001.tar` is 20,480 bytes, SHA-256
`eeea76abf06c59534e4cd3aac0e493f7c4d2fc99c641bc4e645907363614fccc`.
Only seven fixed Root-owned unit-proof files are exported, with an index.
The exporter hashes its held archive descriptor before handing that public
archive to UID 501. The inert
`verify_native_binding_arm_20261027.py` reader checks both archives, exact
ELF/source pins, each result/log and every public-file digest and metadata.
Its retained stdout hashes to
`23ab058d6e83c1bdf746164ae706e85fb3a6da8054d6f93e3c6a96c34bd9fb23`.
No private Guard data, SDK home or model use is involved.

Independent Rust process/SDK/MCP and other-role grading, fresh
3.58.0 candidate publication and twelve fresh staging/installed controls,
operational/workflow/legacy completion, required CI and cutover remain open.
The user will handle disabled GitHub Actions. No parent exit is closed.
