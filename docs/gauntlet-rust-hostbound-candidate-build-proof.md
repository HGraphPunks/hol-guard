# Host-bound candidate builds

## Historical local 3.49.0

The host-bound runner and result reader came from `7bd496e5`; the read-only prelaunch readiness check came from `d7e8d110`. This is a **shadow build**, with `artifact_admitted:false` and `execution_eligible:false` throughout. It did not stage or install Guard, run conformance or model inference, publish observer state, or enable the PR gate.

The first one-use job, `c6891bca61e59c95`, durably recorded its Mac host pin but stopped before a candidate container or host anchor existed. The missing prerequisite was the job-specific `Builder.apparmor`. That job remains consumed. The new Root-only readiness binary, SHA-256 `587ee52f6f70a9d530a175d811cc1f81205ab1cf688af642edb098fc80656c93`, rejected this incomplete job with `PolicyMismatch` before any new host pin was written. Its Mac caller also requires an exact canonical, matching readiness response before recording a pin. Targeted macOS tests cover the fixed VM argv, wrong policy, low disk, invalid binary pin and journal absence; the full host crate and warnings-denied host Clippy passed. The ARM64 readiness binary was built from the locked workspace, installed Root:Root mode 0500/nlink 1, and independently rehashed in the VM.

Fresh job `6446059453be1a15` used local 3.49.0 commit `76c31929833b5571d25a56d9783e24a0997d5422` and 45,439,546-byte source archive SHA-256 `bedd98ab7da8ca728484799e1ef6b13c854f7fcbb31a17ebdcc469c4c772af43`. The separately installed controller root `/opt/hol-gauntlet/controller-18d31910a8cefbd6` had tree digest `33c98333891743e6976bee9a123365fe7fe95dcf1bf9b65ee39a59fb41043c68`. Rust captured the source into a fresh Root slot, verified both local ARM64 base images, wrote the one-use builder image context and job-specific AppArmor policy SHA-256 `4aaa2cc5cbeb4e4e6578bb8927542be9ac344134f5db96a3c224b51a90489594`, and verified source-bound image ID `sha256:39a6e74e48b2619189e191b5f5038ce0e27fba1cb57177d713e2077e64c7bb29`. The readiness probe observed 12,916,948,992 free disk bytes before launch. The guest runner and result reader had outside binary SHA-256 pins `2f7330d46e41bf0f2b064e443752755293c15a1129c5d8d0bce7bfc80ab517a5` and `861ca5acaf4e797bdf3d5abf7a4a77cad07941a35e69e75c61a51ca389aaa3ee`.

The Mac wrote one private 0600 pin journal entry before spawning Lima. Its SHA-256 was `2400f4d8092424f46d49589d8a29970aa2c4400608e7dd130ba1588f122db388`; the Root guest wrote host anchor SHA-256 `da5f826cc926216dc13839335c1fe1c932a490d7cc81106c667634209a142943` before the candidate Podman run. The VM's 2-vCPU/16-GiB/48-GiB configuration held the fixed 12-GiB candidate container. The product build completed the release Rust compile in 6m 58s, built the wheel, and passed 4 selected Python tests plus 186 product contract tests. The bounded candidate run exited zero; independent Podman and cgroup reads found no remaining candidate container, job AppArmor profile or candidate cgroup. The canonical Root result SHA-256 was `6e8be6ee673f6c0f803ad5725180c794cb41955a7d4a2ffd7c9d6f221d57e220`.

The first read-only host result probe correctly refused the uncaptured export. A separate one-use Root capture copied the 20,274,622-byte unprivileged export into mode-0444 `candidate.zip`; its SHA-256 was `5283c839fc0e035f5b475d6837c9dc8bbe0f1e44e4fad7530a3cb48d9e854b14`. The host-bound reader then succeeded, checking the host journal, exact guest anchor bytes, result, captured source, stdout/stderr, exported and captured archive, wheel declaration, and cleanup. A separate inert wheel reader decoded all 1,727 entries and 53,396,514 uncompressed bytes, matched wheel SHA-256 `f3acbcd0476e1ecc3d119f29e56c9c1bd22401e76c5d83c8cb8255d214eab496`, and hashed the 29,732,624-byte native executable to `533d72c30de62b460556c7330067e1078b353b094ee2fc3f1edf0f6d6af83eed`. Both readers reported the artifact unadmitted.

This demonstrates a full host-pinned source build and retained-result reconciliation for one historical local commit. It does not independently review the source/controller/compiler pins, authenticate a signed deterministic worker verdict, stage an installed prefix, execute the six controls, or run a model-backed feature campaign. The current Rust host pin is an execution-intent record, not an admission decision. The archive-fixture fix at `aabdbd7d` passed the isolated Linux `contracts`, `macos-host` and `arm64-binaries` checks on [run 39590546631](https://github.com/hashgraph-online/hol-guard/actions/runs/39590546631). The product-wide rollup on that head had one Windows packaged-daemon failure and a pending benchmark-candidate job when inspected; the final-head CI exit remains open. The separate [release-tag proof](gauntlet-rust-release-tag-build-proof.md) covers the subsequent v3.48.0 source-ref correction and live build.

## Current 3.59.0 timeout and container cleanup

On November 6, job `b937d2e04a16c85f` captured exact product source
`83f079b5c4a45cc7aa01849189ad80e0c674386a`, archive SHA-256
`5d7ca00197896145d0ad07650a70acea1dc5f2eabdebec92367f79c321a8f8c8`.
The new 409-file controller has digest `e81a214c…`; prior generations remain
intact. Outside observation binds the actual Root supervisor, UID-65532 builder,
entry script, source/version/tag, source archive, enforced job profile, separate
namespaces, seccomp, 12-GiB/zero-swap/512-PID/two-CPU limits and held pidfds.

After 2,093 host seconds, the call is uncertain and its dispatch stays consumed.
The supervisor/client are gone while the exact container remains active. This
matches the 2,100-second timeout path: it killed the client cgroup but supplied
a no-op candidate-container drain callback. No OOM event was observed. The
container later disappears without a retained Root result or export. Under
all three leases, outside checks find its original processes and cgroups gone;
an operator removes only the remaining profile. No workload signal, fabricated
exit or replay is supplied. The attempt remains unknown and unqualified.

Rust now precreates a container with a request-binding label, verifies and
durably retains its full ID before starting the attached client, and reopens
that identity before removal. Shared validation checks full CID, exact job name,
immutable image, UID and binding. Both client cleanup and create/receipt failure
paths drain the verified container before the enforced profile can be removed.
The frozen Python run-vector reader is unchanged. Candidate release LTO now has
a fixed 7,200-second budget; host transport adds 120 seconds for teardown.
Dependency and feature deadlines stay 2,100 and 14,400 seconds.

The exact patch from base `dd621e614` has SHA-256
`ecefc9a2e32ed2b8fc2d37e472de1be9d97c8ebeafad6f5cd9fdd9bb6d38628d`
over `git diff --binary dd621e614 -- ci/gauntlet-rs`. Its ARM test ELF is
`69c6dacdefb579b00e8cda25e3e472ead9d65d8c7df9ad5bb48e42dc8b8d5ca8`.
An explicit Root probe starts only inert `/bin/sleep` as UID/GID 65532, with
zero capabilities, no-new-privileges, the enforced job policy, no network,
configured 128-MiB/zero-swap/16-PID/one-CPU limits and a 100-ms supervision timeout.
It refuses a foreign binding without changing the receipt, then proves actual
container/cgroup removal and original-init death. The profile is removed after
cleanup; repeat drain preserves the receipt. These fixture limits do not replace
the production limits observed above. Outside checks under all three leases
confirm complete absence and unchanged metadata for all 333 older worker records,
without reading their private bytes. All 656 Mac tests, Rustfmt and Mac/ARM
warnings-denied Clippy pass. No crate, Cargo target, codebase file or dependency is added.

Evidence is retained outside Git in `gauntlet-rust-pr-ready-evidence-20261026`:

| Receipt | SHA-256 |
| --- | --- |
| `native-current359-build-host-state-20261106-001/outside-kernel-003.json` | `610799559fb177c633c249a645b69e86a48e81992bf78f4330a4947d1d2b9d38` |
| Same directory, `run-command-002.json` | `08fc8015c97fe59f537a4e9412c84923b8f622cca0cb92289217ca7b44f0c96d` |
| Same directory, `operator-quiescence-001.json` | `3d8ef67a60ff181fc121f3317508d87d5075a62da1687e548a2ce320a5955db3` |
| `candidate-timeout-20261106-root-timeout-001.json` | `b1331b5bc58f83d229bf7dbdc52887e663235ddab9b0f7939f087d133506ddfc` |
| `candidate-timeout-20261106-outside-completion-001.json` | `a050007c64624270355b697e84930895d5f38f76f3b923cead162a6e3ff3aa9c` |
| `candidate-timeout-20261106-mac-all-001.log` | `d2d3daebc08297bc0ed389490212a017a9162d75c6573299acf81d04a2fd99f2` |

The first outside completion check named the image-builder group instead of
the candidate-client group. Its original receipt remains retained; it alone
does not independently establish client-group absence. A follow-up test captures
the actual client path from the supervisor and asserts that exact path is gone.
Test-only patch `fe5f5641…` over `8bb6d1b5f` compiles to ELF
`05c08242cfe31d25dc339b61a79193e270c5a2d22c41b90299531408d4bbbbf1`.
The explicit Root case and ARM warnings-denied Clippy pass. Its command receipt,
`candidate-timeout-20261106-root-timeout-002.json`, hashes to
`043724ac93bd3a8c9c1e3a299e9a67d601570f4b9394455aa59932e23f02bef3`;
the corrected independent outside receipt,
`candidate-timeout-20261106-outside-completion-002.json`, hashes to
`a173553923130ebca0c06fbc4dbc0d279becdd5250454643d3b39063ab059c45`.
It checks the actual candidate-client group, all container/conmon groups,
original-init death, profile absence and all 333 prior records' unchanged metadata.
The production code is unchanged by this follow-up.

The physical probe closes handled-timeout cleanup only. Fresh full candidate
build/publication, crash recovery, conformance and admission remain open. Every
result stays ineligible, with zero model requests/tokens and no causality claim.

## Source-matched 3.59.0 dependencies

Fresh dependency job `5ea8b3c2907df614` independently captures the same exact
`83f079b5c` product source, archive `8ce7383a…`, and a three-member input capsule.
Outside observation binds the actual Rust exporter ELF, five argv elements,
mounted project/lock bytes, prelaunch intent, held pidfd, enforced profile,
namespaces and effective production resource limits. The 36.34-second run exits
zero and retains an ineligible producer result. Under four leases, independent
checks verify cleanup and unchanged metadata for all 333 prior worker records;
they also verify the actual candidate-client paths for both earlier probe jobs.

Rust stages 2,290 inert files under the pinned system interpreter. Independent
host reconstruction reuses five bounded helpers from the existing 3.58 verifier;
it imports no candidate or dependency. All 2,633 tree entries and 51,318,689 file
bytes match, digest
`ae59b1bbf115f41cab193c47e5f47caf1abef701a03c4a4e041370e63fd2f30e`.
There are 61 distributions, including MCP 1.30.0. The source-bound prefix receipt
is `416ee68d0db6f6c75e3c7146d928291e8ee694336671f8ce34114d470ec416a3`.

Evidence lives in external `native-current359-dependency-host-state-20261106-001`:
`outside-kernel-001.json` hashes to
`2b7979aca179f6fd2f043cd82a3f94f070b9e9256430839f9254075ad876f217`;
`outside-completion-001.json` to
`7e6209469c91353b49d7d56ceeea87849bb23073cac2b514b90c4a72e4fcb115`;
the six-member `inert-prefix-export-001.tar` to
`db6966fb1875b542c0c94ce900f27520edfdb0a6e87667ada8c236aee918f07f`;
and `independent-prefix-readback-001.json` to
`21504a167f59075bde699836321dd13e082cfe636030525ab859fae394b6c98b`.
Private intents, nonces and keys are excluded from the export. Candidate wheel
composition and publication remain open, with no artifact admission, qualification,
causality or model use claimed.
