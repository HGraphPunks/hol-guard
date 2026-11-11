# Current-source native candidate build

The separate owned 2-vCPU/16-GiB/48-GiB VM
`hol-gauntlet-rust-build-20261026-001` built the 3.57.0 candidate from exact
commit `84549fd4183ad89d82efaa041240e88ec9534040`. Fresh job
`e2c701baf1471201` exited zero in 410.3 seconds, including the 6m14s Native
release compile, four selected tests and the complete 187-test contained
contract suite. The four selected tests overlap that suite; they are not 191
distinct tests. This is an unadmitted build and inert-staging proof, with
`artifact_admitted: false`, `execution_eligible: false` and zero model use.

## Preserved attempts and correction

Job `e2c701baf1471001` received the original Git working-tree archive. The
builder requires a bare `repository.git`, so it failed before compilation.
Job `e2c701baf1471101` received a separately Rust-verified bare-object archive
but exposed the old adapter running Native-dependent tests before compiling
Native. Both failed jobs, source bytes, logs, host intents and failure results
remain unchanged and consumed. Both fully cleaned up.

Commit `84549fd4` moves the same checks after installation, actual native
hash/provenance verification and explicit matching runtime selection. Seventeen
existing Python tests pass. Independently recomputed Python/Rust source plans
match the new 400-file/411-entry controller digest
`681f204300c1d85327b244f9a45cf733a00a3e9ac18b56694174b8904b1f5b69`.
Its new immutable controller is `/opt/hol-gauntlet/controller-84549fd4183ad89d`;
the original controller remains. The 420-file baseline is unchanged; the
431-file delta now records 68 changed and 11 added files.

The successful build's 55,710,484-byte Git-object archive has SHA-256
`66dadb3f34d0a5667979bf813eb470f5c5278918048b14783436a224b2a84601`.
Rust independently verified its exact local ref/commit/graph before upload,
then the pinned native worker captured it under both permanent leases.
This particular archive was constructed by an explicit proof courier. The
subsequent [Rust producer](gauntlet-rust-local-source-producer.md) replaces
that step for future local captures; this build is not relabeled retroactively.

## Prelaunch custody and isolation

Host code `afbff8e15e15012a9019243629eff19870481b3b` writes a v4 intent binding
the exact Lima executable and selected VM before launching the pinned Root
runner. It does not replace the historical VM default. The outside host pin
SHA-256 is `dc7ea54de5df5d961ab9ab368350b3b702c09227c0f3a13e27806cd1a68f2c96`;
the guest pre-run anchor is
`624117a2ccdba230a83140ce5982b0d7b08555862689133f010642d69f5f4701`.
Read-only reconciliation through the historical VM refused before a probe;
the correct VM matched the unchanged intent, anchor, source, logs, captured
archive and final cleanup.

Rust built the trusted builder image from the exact controller bytes and
previously measured immutable base IDs. Image
`sha256:383e9cf215d3b8481c2b9fb67d32816ef322b7f40abc17e5a1f9a72dd728fc8a`
has source context `721957934870b8e8a4f424e0deb72490a9771b6c50de1f44af3c18ca8dc402f0`.
Independent reads matched image platform/user/labels and bounded log hashes.
The job policy SHA-256 is
`f1fe376406eee9d8b64a08b118b7cb2f8e414ae656abc57b8e9ff680d0659516`.

Live kernel and Podman reads observed UID/GID 65532, zero effective/permitted
capabilities, no-new-privileges, seccomp mode 2, slirp4netns and limits of
12 GiB, 512 PIDs and two CPUs. Ubuntu reports the actual stacked AppArmor label
as `crun//&hol-gauntlet-build-e2c701baf1471201 (mixed)`; the kernel separately
reports the job profile in **enforce** mode and the distribution `crun` profile
unconfined. The first outside observer expected an unstacked label and refused
before writing a record. Its corrected observer checks both actual kernel
profile modes; no policy or isolation setting changed.

Final independent checks found no containers, job AppArmor profiles,
candidate/builder cgroups or matching original client PID/start tuples for
all three jobs. Available disk was 43,675,418,624 bytes. No history, failed
artifact, image or quota journal was removed to obtain headroom.

## Captured artifact and inert staging

The canonical successful result is
`96f529cf3fab3bb6396b135c863aa748f93fe90c37b00caf4c44c936cf853788`.
Rust copied the dormant unprivileged export once to Root-owned mode 0444,
refused a wrong digest before capture, and preserved it on replay refusal.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| Captured candidate ZIP | 24,176,541 | `295eac484b653311ba286023bab786eb62a25cea7dd477e94252a79156aebc41` |
| Nested 3.57.0 wheel | 24,436,106 | `0bbda185bfa50d3fdc98e9fe44ae95cff5010851287005cdf58a02f0f3e7c8cb` |
| Actual ARM64 Native executable | 36,616,912 | `18f84feb7d6277c583b6df238f543735de05ec0990a7a4f4849b70f0f2ae5d8f` |
| Framed complete wheel entry bytes | 62,621,495 decoded | `55f207ef26fffe8cbda941ff55660d941af65bf015f176eed66a0397f7dc0e79` |

Both Rust and the exact-commit Python inert reader decoded all **1,722** entries
and matched metadata, native manifest and actual executable bytes. The current
completion module is present; no wheel capability is reported missing. Rust
materialized 1,773 inert file/directory entries with tree digest
`eaf64d9650cb2baee78af19bde691e85201774cc64f9ead83cba56c4bc26ab5b`,
verified its readback and refused replay. No candidate was imported as Root.
Original source, result, anchor and log hashes remained unchanged throughout.

The 56-member `native-build-vm-results-003.tar` is 24,309,760 bytes, SHA-256
`5e08ed05aab71b3d946cbc467684a4084db44bd2fbec7971b5c66324212e32a5`.
The host verified every member and the outside archive hash without extraction,
then recomputed the wheel inventory through pinned Python and a separate ZIP
byte walk. Root records remain under `/var/lib/hol-gauntlet/builds` and the
named `native-*-proof-20261026-*` directories; host archives and outside pin
journals remain in `gauntlet-rust-pr-ready-evidence-20261026`.

This does not establish independently approved production provenance, a
compatible installed dependency prefix, current-source six-plus-six controls,
Guard causality, conformance, qualified worker admission, inference or cutover.
The retained dependency prefix has MCP 1.28.1 while this candidate requires
at least 1.30.0; it cannot be silently reused. Parent exits remain 24/62.
