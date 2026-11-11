# Rust Native hook and captured-output artifact verification

Implementation `72f49ab8f5210880b90f69d46eeb42751d82717c` adds completion mode
`--hook-artifacts PUBLIC_USTAR SHA256 INTERPRETER_SHA256 OBSERVER_SHA256`.
It composes the [process verifier](gauntlet-rust-native-process-artifact-verifier.md)
with actual Root-captured Native hook bytes, exact payloads and contained
results. Existing envelope and artifact modes remain byte-compatible.

Rust selects the fixed prompt, Root session, actual SDK command and complete
execution environment. It reconstructs canonical prompt/Pre/Post payloads,
matches ordered capture handles and exact Native argv, checks stdout/stderr
digests, and normalizes actual Native output. It joins the contained request
file and its physical handoff to the actual Native argv and captured result,
then recomputes the SDK-delivered content, error and Post output digest.
The role-selected forbidden Pre probe must also match its actual capture.
Timeout preserves exit 124. Cancellation preserves the missing result and
Post; its process termination is not yet graded by this reader.

New executions sign a Root journal checkpoint in the Native plane: event
count, raw length, tail digest and physical file identity/custody. The hook
reader checks this checkpoint and requires complete versioned stdin receipts.
It recomputes expected canonical input plus newline, acknowledged bytes,
close state, handle and argv joins. Missing, duplicate, reordered, partial,
wrong-handle or changed input refuses. A historical signed report without
the feature/checkpoint must contain no new receipt events; rehashing invented
events into an old public journal cannot grant delivery credit. Root also
refuses a replaced journal inode and a poisoned/partial append.

## Historical readback and limits

The six original v7 archives use runtime `f53bc490` and product `62aa7ba7`
/ 3.57.0. Rust checks 19 actual hook captures and five captured results.
All six lack input receipts and signed journal checkpoints, so input-delivery
credit stays zero. The explicit interpreter/observer digests remain readback
pins. Native process custody, physical effect causality, cancellation lifecycle,
outside key admission, full role qualification and Guard causality remain
false. Fresh actual execution of the new receipt and raw SDK wire producers
remains open. The current 3.58 runtime build is separate from these old jobs.

The frozen committed-source Mac verifier is 5,658,816 bytes, SHA-256
`e08140b1869502f92f64ef1bc64dd5f394cadced52f1c5e9775eb8ec7b93f4ed`.
The [archive courier](../ci/gauntlet-rs/proofs/verify_native_hook_artifacts_20261027.py)
passes 43 cases: six actual readbacks and six restarts, six envelope,
six MCP and six process regressions, both older artifact regressions and
eleven refusals. Changed prompt/Pre/Post capture records, invented historical
input bindings/terminals, missing captures and wrong archive/job/role or
interpreter/observer pins refuse with exit 2 and empty stdout. Host pin
journals and original archives remain unchanged. The 10,315-byte proof index
hashes to `ad90843d05257efb5c78189952e4b548373ab908b9e3983258ac833607481a36`.

## Mac and native ARM validation

The Mac workspace passes 547 tests with zero failures or ignores, log SHA-256
`2ec9f76ac813e1ba979dcfb9066edf2488c83a307f7cbe3312b592307474bc40`.
Warnings-denied all-workspace/all-target/all-feature Clippy passes on Mac
(`c2e553aa79df8462f88202c95c9b7064aec57cf3259ecc214932311c9ceea0fc`)
and final ARM source
(`0464afa3d957e0e2b7c7b04b33a55b3da02a87e1c5827725923bccdc704c1c68`).
The Mac run precedes two Linux-only journal-test layout/fixture fixes; no
Mac runtime code changed in those fixes.

All eleven focused tests pass natively under Root on owned VM
`hol-gauntlet-rust-build-20261026-001`: five input readers, two hook readers,
two journal-custody tests and two archive tests. Both worker leases are held,
all 284 retained worker records are unchanged, and owned product cgroups are
absent. This is a focused native proof, not a full native workspace run.

The three ARM ELF digests are
`eb7efef6ebe3f79ff438c1fee00e6d3ac0bda74f6b5c198b626dd238b0959c43`
(evidence),
`0605a72bcd0c1b1ced39cd708b75629a5b5d9fb5c472889636dc0e4543c1fec6`
(Root journal) and
`8fb355cc7a5b0b24dccd6b57f3b9195f4320724af0a7d59cc352092b0d48f891`
(host archive). The 41,984,000-byte four-member input hashes to
`28a88c0f1c638a7ff18e60120707581913de175e1bd989c14566281e4eb70891`.
Root hashes the held output before public handoff. The 20,480-byte twelve-member
export hashes to
`ba53115f8ae13645381f4762ec4faab502fc1c4fbd187c77640f3dd3b6e83c26`.
The [fixed-generation host reader](../ci/gauntlet-rs/proofs/verify_native_hook_arm_20261027.py)
checks all source/ELF/log/metadata pins and public members. Its successful
stdout hashes to
`d9800f7ab34afccf5c02b387709666463e0f7d087189b70554feda46cdcf5048`.
Both proof helpers pass Ruff formatting and lint. No model requests ran.

Retained failures include the Mac lease fixture's immediate reacquisition
during a concurrent fork/CLOEXEC window, ARM test-module placement caught by
Clippy and the initial Root journal tests under writable `/tmp` ancestry.
The lease fixture now waits at most two seconds only for `LeaseBusy` after
release; production acquisition remains nonblocking. Root tests use `/run`.
The failed proof and logs remain retained; no custody rule was relaxed.

Parent exits remain 24/62. Full Native process/effect/lifecycle grading,
admitted outside custody, twelve fresh current-source staging/installed roles,
conformance and other migration phases remain open. Required CI is user-owned
and pending.
