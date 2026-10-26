# Passive Rust observer and native VM telemetry

Code commit `6271f09b3c4564110229a46a36e48fef80bfa384` adds a functioning
Rust observer in the independent `rust-host-v1` namespace. It serves its own
loopback dashboard, resolves the exact v3.48.0/v3.49.0 tags, preserves their
first source pins, samples host resources and invokes a native ARM64 VM
telemetry executable. The observer never dispatches a benchmark, starts a
provider, publishes GitHub status or changes a merge rule.

This is preparation on `codex/gauntlet-rust-host-lifecycle-prep-20261022`.
It descends from incremental PR #3 while that PR's GitHub Actions checks are
unavailable. It has not completed the required five-job child-PR cycle.
No parent migration exit is closed by this operational subproof.

## Implementation and boundaries

`gauntlet-host up` owns the observer lease and optional dashboard socket in
one foreground process. `configure` creates an immutable, private configuration
envelope; subsequent starts require its outside SHA-256. `status` without that
pin reports current private lifecycle metadata; pinned `status` reads the public
snapshot. `doctor` performs one read-only sample without taking the observer
lease, publishing files or queuing work. `hold`, `resume` and `down` use the
independent permanent transaction lock. `agent --config-sha256` runs the same
observer without an HTTP listener. Reconcile, repair, history import and
authoritative worker admission remain separate work.

The configuration reader rejects duplicate JSON keys, loose permissions,
symlinks, a different namespace/repository, changed bytes, PR discovery,
additional releases, GitHub artifact builds and arbitrary prepare commands.
Source and telemetry samplers run independently of the heartbeat and HTTP
loop. Every Git/Lima probe has bounded output, a deadline and cancellation;
its owned process group is stopped before its leader is reaped. On macOS,
an `EPERM` from killing an already-exited group is accepted only after a kernel
process-group inventory proves that no other member remains.

The new fixed VM command is a Rust executable under a full-digest filename.
It reads kernel resource data as the ordinary guest user. Its response has
exactly ten versioned fields. This path uses no Python interpreter. The older
Python-compatible telemetry plan remains available for historical parity.
The installation below verifies the executable's bytes and Root ownership;
the telemetry response itself is an operational observation, not a signed
worker attestation or evidence of benchmark correctness.

Public files contain an explicit allowlist of operational fields. They omit
private configuration and deployment pins. Missing, stale, future or wrong-VM
data is unavailable. Moved tags retain the original job and display an error.
The snapshot identifies GitHub connectivity as `release-source-only`; it does
not claim GitHub Actions or required-gate readiness. All execution,
qualification and production-CI eligibility fields remain false.

## Tests

- macOS Rust 1.88: 141 host/dashboard tests passed, with zero failures or skips.
- Linux ARM64 Rust 1.88: 28 lifecycle, process, observer and telemetry tests
  passed, plus two owned-probe cancellation/descendant tests.
- Rustfmt and warnings-denied all-target/all-feature Clippy passed for host
  and dashboard on macOS and ARM64. Both source inventory checks passed.
- Real subprocess tests exercise HTTP instance identity, exact-tag queueing,
  hold/resume/down, occupied-port refusal before checkpoint mutation, private
  configuration refusal, source immutability, stale/future telemetry, an
  operator umask of 077, read-only doctor and SIGTERM during slow Git probes.

The full macOS test output is retained as
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-observer-proof-20261022/macos-host-dashboard-tests.txt`
(SHA-256 `5d0e34512b85e348f64f24dcea65f5eb79e3b5b5a490459d5b73b3f6720c6d7b`).
An initial ARM64 link failed because the dedicated Docker target volume ran
out of disk. Clearing only generated migration build caches and rebuilding
with debug information/incremental output disabled resolved it. Retained
proofs and VM job evidence were preserved.

## Live host/VM result

The retained proof directory is
`/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-observer-proof-20261022`.

| Item | Observed identity |
| --- | --- |
| Mac executable | `gauntlet-host-macos-arm64`, 3,967,632 bytes, SHA-256 `1d2b9f69ec543fc46adb4468d08939835cf9266e16404f8b0c14b3f6d013e361` |
| VM executable | `gauntlet-vm-telemetry-linux-arm64`, 671,736 bytes, SHA-256 `a795236ed3cb2efb04371f13a8660c9976bb9ddeb0ce2e3c1628eeb9d181b3ce` |
| Installed VM path | `/opt/hol-gauntlet/gauntlet-vm-telemetry-a795236ed3cb2efb04371f13a8660c9976bb9ddeb0ce2e3c1628eeb9d181b3ce`, Root:Root, mode 0555, matching SHA-256 |
| New instance | `ca7ed1d05f8f04aa5e658e2c7c5178a3`, port 8794 |
| Configuration | `69505ad9acc075a18de3d6904a5d35c9494a5c85a34441069326ac55954f5b36` |
| Existing dashboard | `82640901df6605bf42cb4b85ed740b34`, port 8791, remained online |
| VM | `hol-beta-bootstrap-20261016-004`, Running, aarch64, 2 CPUs, 16 GiB RAM, 48 GiB virtual disk |

The actual VM sample reported 16,733,863,936 memory bytes and a
48,803,864,576-byte root filesystem with 8,792,686,592 free bytes. An independent
`/proc/meminfo` read confirmed `MemTotal: 16341664 kB`; available memory varied
normally between samples. Root filesystem free space is only about 195 MiB
above the configured 8-GiB floor. The probe installation consumed approximately
1.3 MiB including its guest inbox copy; no candidate build was started.

Both live Git lookups succeeded:

- `v3.48.0` → `3864097f2e4fe623e403c1a948d9882f34c78690`, job `a75f874a9a2a56b1`.
- `v3.49.0` → `e3f9e7eb4e0cc7b1987780a62697e8bb221ae050`, job `0e8671c23e1265b9`.

`live-snapshot.v1.json` has SHA-256
`db5e51a9683efc547454920bc21860681f9e416fb8dd08078813982dab499ccd`.
It showed an online Rust collector, running VM, connected exact-tag source,
two queued jobs and held admissions. It also reported that the Rust worker
is unqualified and its reviewed deployment is unavailable.

`down` committed a stop request. The foreground process exited zero; its
port closed, its kernel lease released and the public collector became stopped.
Both queued tuples and the held flag survived. The original port-8791 instance
remained online. `operator-cycle.v1.json` records this result with SHA-256
`7da9a32bede09bce67549dc1b68c4bb7d7ec3d48349c9e48ee1ef66e43e6d0d3`.
Restarting from the same configuration pin retained the instance and both jobs.
The stopped public record samples the lease before its final release; use the
private lifecycle status for a fresh kernel-lease observation.

## Commands for this retained installation

The private parent and immutable configuration already exist. Start the
observer and dashboard together with one command:

```sh
/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-observer-proof-20261022/gauntlet-host-macos-arm64 up --state-parent /Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-observer-proof-20261022/state --config-sha256 69505ad9acc075a18de3d6904a5d35c9494a5c85a34441069326ac55954f5b36 --port 8794
```

Open `http://127.0.0.1:8794`. A duplicate start refuses ownership or the port.
Stop only this Rust observer with:

```sh
/Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-observer-proof-20261022/gauntlet-host-macos-arm64 down --state-parent /Users/construct/Documents/projects/hol-guard-refinement/gauntlet-rust-observer-proof-20261022/state
```

This is an isolated passive deployment. The authoritative Python observer,
its jobs, the existing dashboard and retained provider quota are not adopted
by these commands. Zero VM benchmark jobs and zero model requests occurred.
Rust worker qualification, independent scoring, actual inference, reviewed
production artifacts and controlled cutover remain required.

## Subsequent upstream synchronization

The preparation branch also incorporates upstream `main` through
`c5202d11d4859c1e3a70f33937317cfe9821b121`. Its 17 intervening commits
merged without conflicts. The two Gauntlet changes add the sourced-toolchain
approval case and its realistic init-file fixture. The immutable baseline
remains unchanged; the explicit map still covers 427 files, 58 changed and
seven added. Python and Rust independently agree on the resulting controller
plan: 396 files, 407 entries, digest
`a81e82a241bb9755fa72ca77f01cebbfb75839faa4d70324a9f27ede32276e48`.
That controller generation is not installed into the VM by this proof.

The merged Native library/CLI compiled, matching release executables rebuilt,
and all generated projection/directory checks passed. The targeted approval,
ownership, CI-policy and real macOS Bash judge run passed 193 tests; four
TypeScript observer cases initially skipped because Bun was missing, then
passed after installing SHA-verified official Bun 1.3.14 in the private proof
tools directory. Five Linux-only timeout tests remain explicit macOS skips.
The two JUnit reports are `merged-main-native-judge.xml` (SHA-256
`ab2d53c96701a8db02458ace448739a3e6443f1845477be144925d8535a4c4c4`)
and `merged-main-native-observer-bun.xml`. The live observer continues using
its retained `6271f09b` executable; this synchronization does not silently
replace its bytes or upgrade any retained VM deployment/provider allowance.
