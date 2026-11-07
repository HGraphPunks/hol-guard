# Separate native build VM

`hol-gauntlet-rust-build-20261026-001` is a new owned disposable VM created
from [the native v1 profile](../ci/gauntlet-rs/profiles/native-vm-v1.yaml).
It has 2 vCPU, 16 GiB memory and a 48-GiB disk, using the existing pinned
Ubuntu 24.04 ARM64 image digest
`7df0201546f75b8bcc1044594c806c35749421ad3c9bc1be2a3ab806cfae39cc`.
Actual kernel is `6.8.0-134-generic`; filesystem total is 48,803,864,576 bytes.
Available bytes after provisioning are 46,554,120,192, above the unchanged
12-GiB candidate-build starting floor. The older evidence VM, its disk,
images, jobs, quota and history remain intact.

Effective Lima configuration has no host mounts, no forwarded SSH agent or
user SSH public keys, no propagated proxy environment, and explicit all-port
ignore rules for IPv4 and IPv6. The initial template's default guest address
covered loopback only; the VM was stopped, both explicit rules applied, and
restarted before provisioning. Lima then reported TCP/UDP forwarding disabled
except its necessary SSH management connection.

Signed Ubuntu package metadata was refreshed in this fresh VM. Exact packages
installed from its configured distribution repositories are:

| Package | Version |
| --- | --- |
| Podman | `4.9.3+ds1-1ubuntu0.2` |
| uidmap | `1:4.13+dfsg1-4ubuntu3.2` |
| AppArmor | `4.0.1really4.0.1-0ubuntu0.24.04.9` |
| libseccomp2 | `2.5.5-1ubuntu3.1` |
| ca-certificates | `20260816ubuntu0.24.04.1` |
| mount, libmount1, util-linux | `2.39.3-9ubuntu6.6` |
| slirp4netns (added before candidate build) | `1.2.1-1build2` |

The latter update matches the existing `ubuntu2404-controller-v1` idmap
profile. Both helper digests were checked directly; no constructor pin or
acceptance rule was relaxed. AppArmor reports enabled.

| Helper | SHA-256 |
| --- | --- |
| `/usr/bin/podman` | `f93ee492920150e229b9b41729bfe675073a4df0569ee5d570a8106b5a64506a` |
| `/usr/bin/mount` | `a4e2960330ff237a185306d9d92df1fc69ee77d8abe9d3282f662f54e13f01f4` |
| `/usr/lib/aarch64-linux-gnu/libmount.so.1.1.0` | `cfa453687fb8eee3c6f8e06de6ab2c1f9dfc59b94d05477593fae99fe7fe1e6d` |

Two Root-private package logs remain in the VM's `/var/log`:
`hol-gauntlet-native-provision-20261026-001.log`, SHA-256
`23a3b9534b361f6750a827f6e665a3f682869cb0fa4fce49527b3a98cf1f5ab1`,
and `hol-gauntlet-native-idmap-provision-20261026-001.log`, SHA-256
`5ea0bc21ba178555fb08d2fef351ae09c2e2f1dc06b9b523bdcfa90c7c7906be`.

The [Rust initializer](gauntlet-rust-native-initialization-vm-proof-20261026.md)
subsequently created native storage and both permanent worker locks without
installing a Python control-plane worker or dispatching a job.
Its explicit [v2 layout and source capture](gauntlet-rust-native-source-vm-proof-20261026.md)
correct the historical v1 build-parent mode while preserving the old directory
and receipt.

Rust has installed source-bound inert controller generations and built a
source-pinned builder image here. Two attempted candidate builds failed and
cleaned up: the first received a working-tree archive; the second exposed a
Native-dependent test running before Native was compiled. Their immutable
records remain. A [corrected build](gauntlet-rust-native-candidate-build-20261026.md)
passes with a fresh job/controller, complete wheel verification and inert
staging. Compatible dependencies, reviewed execution artifacts and six-plus-six
conformance are still required. No inference or quota reset has
occurred.
