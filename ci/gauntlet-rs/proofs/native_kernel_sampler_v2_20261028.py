"""Versioned read-only VM proof sampler; no runtime, verdict or admission authority."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path

KNOWN_NATIVE = {
    "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960",
    "86d29b8438b21521cdbcd97d60255a3ad4a2f7d63170a3d4ec3d2fdae7a8d401",
    "b25537f38e7374348366208e1d6e4edd51446cff9853c261bde4e7253e17117e",
    "3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90",
}


class NativeMcpKernelSampler:
    def __init__(self, job_id, stop, source_sha256):
        if not re.fullmatch("[0-9a-f]{16}", job_id) or not re.fullmatch("[0-9a-f]{64}", source_sha256):
            raise ValueError("exact job and outside sampler source pins required")
        self.job_id, self.stop, self.source_sha256 = job_id, stop, source_sha256
        self.observations, self.errors, self.seen = [], [], set()

    def observe(self):
        while not self.stop.is_set():
            group = Path("/sys/fs/cgroup/holgauntletrust" + self.job_id + ".slice")
            try:
                units = list(group.iterdir()) if group.exists() else []
                for unit in units:
                    if not unit.is_dir() or not re.fullmatch(
                        r"(?:hol-product-cell-[0-9a-f]{32}\.service|libpod-[0-9a-f]{64}\.scope)", unit.name
                    ):
                        continue
                    for task in [unit, unit / "container"]:
                        if not task.is_dir():
                            continue
                        for raw_pid in (task / "cgroup.procs").read_text().split():
                            try:
                                self._sample(int(raw_pid), unit, task)
                            except (FileNotFoundError, ProcessLookupError):
                                continue
            except (FileNotFoundError, ProcessLookupError):
                pass
            except Exception as error:
                self.errors.append(type(error).__name__ + ": " + str(error))
                return
            self.stop.wait(0.02)

    def _sample(self, pid, unit, task):
        process = Path("/proc") / str(pid)
        start = int((process / "stat").read_text().rsplit(") ", 1)[1].split()[19])
        status = {
            k: v.strip()
            for line in (process / "status").read_text().splitlines()
            if ":" in line
            for k, v in [line.split(":", 1)]
        }
        if status.get("Uid") not in [
            "10004\t10004\t10004\t10004",
            "10001\t10001\t10001\t10001",
            "10005\t10005\t10005\t10005",
        ]:
            return
        if status.get("Seccomp") != "2":
            return
        pidfd = os.pidfd_open(pid, 0)
        try:
            descriptor = os.open(process / "exe", os.O_RDONLY | os.O_CLOEXEC)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 128 * 1024**2:
                    return
                with (process / "cmdline").open("rb") as command:
                    argv = command.read(32769)
                assert 0 < len(argv) <= 32768 and argv.endswith(b"\0")
                argv_sha256 = hashlib.sha256(argv).hexdigest()
                view = None
                if ("hol-gauntlet-native-detached-" + "timeout-" + self.job_id).encode() in argv or (
                    "hol-gauntlet-native-detached-" + "cancel-" + self.job_id
                ).encode() in argv:
                    directory = os.open(process / "cwd", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                    try:
                        s = os.fstat(directory)
                        view = {
                            "cwd": os.readlink(process / "cwd"),
                            "directory": {
                                "device": s.st_dev,
                                "inode": s.st_ino,
                                "uid": s.st_uid,
                                "gid": s.st_gid,
                                "mode": stat.S_IMODE(s.st_mode),
                            },
                            "files": {},
                        }
                        for name in ["detached-ready.json", "detached-ready.pending", "late-detached-effect.txt"]:
                            try:
                                fd = os.open(
                                    name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory
                                )
                            except FileNotFoundError:
                                view["files"][name] = None
                                continue
                            try:
                                f = os.fstat(fd)
                                assert stat.S_ISREG(f.st_mode) and f.st_size <= 4096
                                contents = os.read(fd, 4097)
                                assert len(contents) == f.st_size
                                view["files"][name] = {
                                    "device": f.st_dev,
                                    "inode": f.st_ino,
                                    "uid": f.st_uid,
                                    "gid": f.st_gid,
                                    "mode": stat.S_IMODE(f.st_mode),
                                    "links": f.st_nlink,
                                    "sha256": hashlib.sha256(contents).hexdigest(),
                                    "utf8": contents.decode("utf-8"),
                                }
                            finally:
                                os.close(fd)
                    finally:
                        os.close(directory)
                stamp = (
                    pid,
                    start,
                    before.st_dev,
                    before.st_ino,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                    argv_sha256,
                    json.dumps(view, sort_keys=True),
                )
                if stamp in self.seen:
                    return
                raw = stream.read(128 * 1024**2 + 1)
                after = os.fstat(stream.fileno())

                def fields(s):
                    return (
                        s.st_dev,
                        s.st_ino,
                        s.st_mode,
                        s.st_uid,
                        s.st_gid,
                        s.st_size,
                        s.st_mtime_ns,
                        s.st_ctime_ns,
                    )

                assert fields(before) == fields(after) and len(raw) == before.st_size
            executable = hashlib.sha256(raw).hexdigest()
            if status["Uid"].startswith("10004") and executable not in KNOWN_NATIVE:
                return
            actual = (process / "cgroup").read_text().strip()
            assert actual == "0::/" + str(task.relative_to("/sys/fs/cgroup"))
            assert int((process / "stat").read_text().rsplit(") ", 1)[1].split()[19]) == start
            label = (process / "attr/current").read_text().strip()
            if unit.name.startswith("hol-product-cell-"):
                assert label == unit.name.removesuffix(".service") + " (enforce)"
            namespaces = {
                n: (process / "ns" / n).stat().st_ino for n in ["cgroup", "ipc", "mnt", "net", "pid", "user", "uts"]
            }
            limits = {n: (task / n).read_text().strip() for n in ["memory.max", "pids.max", "cpu.max"]}
            if len(self.observations) >= 2048:
                raise ValueError("kernel observation limit 2048 exhausted")
            self.observations.append(
                {
                    "synthetic_lifecycle_view": view,
                    "pid": pid,
                    "parent_pid": int(status["PPid"]),
                    "namespace_pids": [int(n) for n in status["NSpid"].split()],
                    "start_ticks": start,
                    "pidfd_held": True,
                    "executable_sha256": executable,
                    "executable_device": before.st_dev,
                    "executable_inode": before.st_ino,
                    "argv_sha256": argv_sha256,
                    "argv_utf8": argv.decode("utf-8"),
                    "cgroup": actual[3:],
                    "lsm_label": label,
                    "namespaces": namespaces,
                    "limits": limits,
                    "status": {
                        k: status[k]
                        for k in [
                            "Uid",
                            "Gid",
                            "Groups",
                            "CapAmb",
                            "CapBnd",
                            "CapEff",
                            "CapInh",
                            "CapPrm",
                            "NoNewPrivs",
                            "Seccomp",
                            "Seccomp_filters",
                        ]
                    },
                }
            )
            self.seen.add(stamp)
        finally:
            os.close(pidfd)

    def result(self):
        return {
            "schema": "hol-gauntlet-outside-native-mcp-kernel.v2",
            "collection_limits": {"observations": 2048, "argv_bytes": 32768, "executable_bytes": 134217728},
            "observer_sha256": self.source_sha256,
            "deduplication": "pid-start-executable-inode-and-argv-v1",
            "observations": self.observations,
            "errors": self.errors,
            "execution_eligible": False,
            "guard_causality_verified": False,
        }
