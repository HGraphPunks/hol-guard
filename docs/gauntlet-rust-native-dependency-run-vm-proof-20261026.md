# Native dependency run and recovery proof — 2026-10-26

Rust now produces current locked dependencies under a prelaunch host intent
and a measured Root supervisor on owned VM `hol-gauntlet-rust-build-20261026-001`.
The resulting ZIPs are inert data. No candidate/dependency import as Root,
Guard verdict, conformance, artifact admission or model request is claimed.
Parent migration exits remain 24/62 complete.

The host journal binds the exact VM/transport, source and archive, input capsule
and capture generation/receipt, exporter, controller, base/builder images,
policy/runtime helpers, runner and a fresh nonce before execution. Source
archives come from the Rust exact-Git producer and independent graph reader;
capsules come from the exact committed ordinary project/lock blobs and a
separately pinned static ARM64 exporter. Root receives both through its bounded
native capture operations and independently reads back their immutable bytes.

| Measured component | SHA-256 |
| --- | --- |
| Current runner/recovery worker, source `62aa7ba777a5a4cc0806c34ee94e9822eaa58d32` | `71873edfbe82c89bc00b7c84d72a857ab48c5b3b9d4f378d3c6104f6d28fc9fb` |
| Host dependency caller, source `6c7da5bdf92de710a628dd608a8c198b1216f637` | `ba374cc5b0771e118f432228d79320886bca946f13cf1e0faffc41e0ff0f669e` |
| Current host local Git producer | `93056da86f62e45e46d97edd0c5fb75852801ceb47646c24833040d5eb4304a5` |
| Current host capsule producer | `71171120f8c397a30e2a369d40787f1927f10de0924d09789377856171fd7a08` |
| Actual unprivileged exporter | `3a10107fcdb0d48fafcd05829967cffde39e22e2096776d005c66b4e3463c698` |
| Pinned builder image | `383e9cf215d3b8481c2b9fb67d32816ef322b7f40abc17e5a1f9a72dd728fc8a` |

The current host binaries have unchanged source bytes at the later runner
commit. The retained 400-file/411-entry controller generation remains
`681f204300c1d85327b244f9a45cf733a00a3e9ac18b56694174b8904b1f5b69`.
Its separate installed path names the earlier `84549fd4` revision; no historical
controller or baseline is overwritten. The current source includes upstream
`9dd2fefb`; project/lock hashes remain `5778df7e…` and `ebc65d35…` respectively.

The first job, `e2c701baf1471301`, installs all 62 locked packages and captures
17,489,481 bytes, hash `a6a25abbbead6dbf5510534474c0da9bc36c423ff374b21ce7dad3917a75f642`.
Its older supervisor omits the mandatory running marker, so terminal publication
refuses. Original inputs, output and started marker remain. The new quiescent
repair checks outside host-derived intent/reservation pins, both permanent
leases and the separate dependency lease, immutable inputs and exact CID,
then independently proves all resources absent. Five wrong-pin/competing-lease
cases refuse before a repair write. The positive receipt records `aborted`,
null running-marker hash and null exit code, with no execution credit; replay
preserves the exact receipt. Its SHA-256 is
`c9d3bec5e4b04f15bc4857a582911a0dda33e92884b90eb23a79f1de18b9563c`.
No running marker, report or terminal is fabricated for that old job.

| Fresh current-source job | Source archive | Captured dependency ZIP | Retained result |
| --- | --- | --- | --- |
| `e2c701baf1471401` | 55,757,651 bytes; `eabb339333f93c2ce31178694eccaef800a41b98fd8041ffc4bf5b30f899bd2e` | 17,489,480 bytes; `7ffb455ff4e2d481f96e41271cb9a62f6e907a650a7970efda0c705fdea4bc64` | `a0f30794873a1c1c5c754fa7406c11b7f8b368ffd8b9035229256994eff5bcaf` |
| `e2c701baf1471402` | 55,757,602 bytes; `ff09bf61b54e119983c895dd898a402b9cc1bbeae92b9427dd12e12adfdffef4` | 17,489,479 bytes; `67a69d651acc1c4bc399c5ee587a46617230126ff70c5748a9d17651ca5f5250` | `89c3b69fb03e848348cf1028c3d8151c74ca6d532795c2c44154cce8d17a9813` |

Both jobs use exact source `62aa7ba7`, exit zero and retain durable observed
Podman PID/start-tick/cgroup identities plus matching reports/terminals. The
terminal remains `invalid-evidence`. The second run also verifies admission
after both a repaired and a completed predecessor. Its host intent hash is
`f955c02bcd51992bf0436fc0be47572f1d31a1e88ff9d8d71c4f09f9150c2c5f`.

Independent observation hashes the actual `/proc/PID/exe` exporter, binds its
unchanged start ticks and CID/host intent, and verifies UID/GID 65532, zero
effective/permitted capabilities, no-new-privileges, seccomp 2, slirp and job
AppArmor enforcement. The actual attachment is a mixed `crun//&job` stack;
the job profile is independently loaded in enforce mode. Reading all non-root
cgroup ancestors verifies effective 12 GiB memory, zero swap, 512 PIDs and two
CPUs. Earlier observers of the parent scope and absent root limit files remain
recorded as unavailable. The initial installer-mode refusal also remains;
the worker's exact required Root-only 0500 check was preserved.

Wrong source, capsule, image, runtime or actual executable, both busy permanent
leases and guest replay all refuse without changing current inputs, source,
logs, archives or journals. Host replay refuses before spawning the guest.
Independent final checks find every exact container name/CID, client/container
cgroup and job profile absent, with 42,438,676,480 bytes free.

Actual Root ARM64 tests pass 126 cases, with 24 preexisting fixture ignores;
the full Mac workspace at `6c7da5bd` passes 416 tests across 215 targets with zero
failures/ignores. Mac/ARM64 Clippy passes with warnings denied. The first
sandboxed Mac interop attempt and all failed VM attempts remain retained.

The 80-member, 59,340,800-byte host export
`native-dependency-run-vm-results-012.tar` has SHA-256
`fffdca6417d8d9c550362dab68346323771b76a29843fa5bd7f8567ed607a063`.
Host readback verifies every member hash/size, original host intents, retained
result/marker bindings and every ZIP entry/CRC. All three archives contain
2,302 ordinary files, 54,452,716 decoded bytes and 62 distribution metadata
records including MCP 1.30.0. Their independently recomputed framed file digest
is `62b019ab339c6471c20e62890f89f9a9fae056ba86757c654cee4718f71d09ed`.
The record is `native-dependency-run-host-verify-012.json`. All guest originals
remain under the separate `008`, `010`, `011` and `012` proof directories.

Next are a bounded Rust ZIP reader, inert dependency-prefix construction and
complete candidate requirement validation. Broader dependency interruption
recovery, current-source controls/conformance and execution admission remain open.
