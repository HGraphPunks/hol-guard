# Current Native candidate build, 2026-10-26

This proof supplements the retained [earlier 3.57.0 build](gauntlet-rust-native-candidate-build-20261026.md).
It does not relabel that build or its 1,722-entry wheel. The new job
`e2c701baf1471501` uses exact product source
`62aa7ba777a5a4cc0806c34ee94e9822eaa58d32`, incorporating upstream Native
changes through `9dd2fefbacd4a7e9855ccebd2516e98c9b8d1590`. Its wheel has
1,705 entries because upstream removed 17 Python files.

The owned disposable VM is `hol-gauntlet-rust-build-20261026-001`: Linux
ARM64, two CPUs, 16 GiB RAM and 48 GiB disk. Candidate helpers were built
from `aeaa62b04713f6178b191f6528a28faa1b0ccf95` outside the candidate source.
Root installs and checks them as single-link mode-0500 files:

| Helper | SHA-256 |
| --- | --- |
| Build supervisor | `17aa4b23b203701c5283a143549a5d61b5a732491c2d78ff60379417eb32b56e` |
| Build readiness | `a21bf198dfb63d2a4c4098fce1efb433f5b6005fd30cbd6a9380b8ac4445494e` |
| Result reader | `522486ff28d4afe5613006ac2f73ff2d2ed26cd786208732fbe38e37392f0fd3` |

The Mac source producer captures a fresh 55,757,148-byte archive with SHA-256
`7cc1b336cdd2a8a1edec6a8c56f3dd41f1557c13648c7f3318a26e18da45be0e`.
Its one-use v4 host build pin is
`1d49cf9550f44975de50fd3f24bb2303e63715ad325ad60db8297d43ce8ba8c9`.
The actual build finishes in 420.75 seconds with exit 0: four selected and
187 full contained tests pass. Report SHA-256 is
`b9ec5b8c4afc11622ea1fa0d54b051180f0fe365296dfad91d734db9cb114c85`.

An outside kernel observer checks the actual entrypoint's UID/GID 65532,
zero capabilities, no-new-privileges, seccomp mode 2, job AppArmor enforcement,
slirp networking and effective 12-GiB memory, zero-swap, 512-PID and two-CPU
limits. The exact container is
`a4761355ded969936e816d02d10dcc1029be19fb353f60958d9187af683a474b`.
After completion, independent readback finds the container, client cgroup,
machine-slice container scope and job profile absent. Free space is
42,100,002,816 bytes. A separate host result read reconciles the retained
record; a wrong VM is refused before a guest probe, preserving the host pin.

The previously measured Root capture/staging tools handle the candidate as
inert data. They execute no candidate or package code. Wrong-hash capture,
capture replay and stage replay all refuse; six original files remain
unchanged.

| Retained data | Bytes | SHA-256 |
| --- | ---: | --- |
| Candidate ZIP | 24,169,955 | `f3a7f0d04e0e918b22aa341036a3cf8fe8402555426805d3d8b3660e95dc6989` |
| Wheel | 24,426,588 | `4f29b6f76417b7172db007a64ac99f5de9c68b62078d95be5545f1fecd30c2f0` |
| Native executable | 36,682,448 | `1632de1167b167ffe05d02ab4f2cdf157d9328addfcc054ceeffef640b8b9489` |
| Export tar | 24,227,840 | `39a039b57284deee0bab5fa1cec3265ed4a4f6939c6ad0c447fe00ff82ac72cd` |

The wheel decodes to 62,564,815 bytes. Its framed entry digest is
`386a5fca7880da49c1a18b8ecda229ca68d2a0c786bb7736c3b2acd7457dcf6b`;
the Root inert-wheel inventory has 1,756 entries and digest
`47ddfffaa1f96259978a3d15ecf9f5e17037283a86d79dba941783e56b45a17d`.
Independent host readback checks all 22 export members, every decoded wheel
byte, the actual source-pinned Python wheel oracle and the Native executable.
The host verification is `native-current-candidate-host-verify-013.json` in
the retained evidence directory; VM records are under
`/var/lib/hol-gauntlet-rust/native-current-candidate-proof-20261026-013`.

Every result remains `artifact_admitted:false`, `execution_eligible:false`,
with zero model requests. Build success and inert readback establish neither
fresh conformance nor a Guard verdict. A compatible dependency prefix,
independent controls, installed identity and live workflow qualification
remain separate requirements.
