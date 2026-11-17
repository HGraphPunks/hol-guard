"""Exercise the Rust constructor with the retained, independently checked VM apparatus.

Only the Root constructor launch is substituted. The original collector still
checks the actual actor, gates, idmap, AppArmor, streams and terminal cleanup.
This is an apparatus diagnostic, not full Rust supervisor ownership or a verdict.
No model/provider action is performed.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess

NAMESPACES = ["/usr/bin/unshare", "--mount", "--pid", "--net", "--ipc", "--uts",
              "--cgroup", "--fork", "--kill-child=KILL"]


def read_driver(path):
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("literal diagnostic driver path required")
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("Root driver ancestry required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size <= 128 * 1024):
            raise ValueError("bounded immutable Root diagnostic required")
        raw = stream.read(128 * 1024 + 1)
        after = os.fstat(stream.fileno())
        visible = path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(other, key)
                                          for key in fields for other in (after, visible)):
            raise ValueError("diagnostic source changed during read")
        return raw


def constructor_tail(argv):
    """Recognize one fixed old constructor, with its namespace floor intact."""
    if not isinstance(argv, list) or argv.count("/usr/bin/unshare") != 1:
        return None
    index = argv.index("/usr/bin/unshare")
    tail = argv[index + len(NAMESPACES):]
    if (argv[index:index + len(NAMESPACES)] != NAMESPACES or len(tail) != 13
            or tail[:4] != ["/usr/bin/python3", "-I", "-B", "-c"]
            or "from ci.gauntlet.benchmark.product_vm_rootfs import construct;" not in tail[4]
            or not tail[4].endswith("expected_artifact_manifest_digest=sys.argv[8])")):
        return None
    return index, tail


@contextlib.contextmanager
def native_constructor(base, binary, expected, records):
    original = subprocess.Popen

    def replace_argv(argv):
        found = constructor_tail(argv)
        if found is None:
            return argv
        if records:
            raise ValueError("exactly one native constructor per fresh VM proof required")
        index, tail = found
        if base.sha256(base.read_root(binary, 16 * 1024**2)) != expected:
            raise ValueError("native Root constructor differs from outside binary pin")
        stage = Path(tail[6])
        declaration = {
            "schema": "hol-gauntlet-product-rootfs.v1",
            "stage": str(stage),
            "initializer_sha256": tail[7],
            "artifact_manifest_sha256": tail[12],
            "system_spec_sha256": tail[9],
            "task_spec_sha256": tail[11],
            "runtime_spec_sha256": base.sha256(base.read_root(stage / "runtime.json", 8192)),
            "idmap_runtime": tail[10],
            "state": "persistent-v1",
            "network_profile": "private-loopback-v1" if tail[8] else "unix-only-v1",
            "parent_network_namespace": tail[8] or None,
        }
        base.save(stage / "native-rootfs.v1.json", declaration)
        raw = base.read_root(stage / "native-rootfs.v1.json", 8192)
        digest = base.sha256(raw)
        records.append({"constructor_sha256": expected, "declaration_sha256": digest,
                        "declaration": declaration, "namespaces": NAMESPACES[1:]})
        replacement = [*argv[:index], *NAMESPACES, str(binary), str(stage / "native-rootfs.v1.json"), digest]
        return replacement

    class NativePopen(original):
        # Preserve Popen's class/generic interface for imported libraries.
        def __init__(self, args, *arguments, **options):
            super().__init__(replace_argv(args), *arguments, **options)

    subprocess.Popen = NativePopen
    try:
        yield
    finally:
        subprocess.Popen = original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("driver", "driver-sha256", "constructor", "constructor-sha256"):
        parser.add_argument("--" + name, required=True)
    for name in ("controller-source", "controller-tree-sha256", "verifier-sha256",
                 "artifact-manifest-sha256", "actor-sha256", "legacy-config-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--case", choices=("success", "timeout", "cancel"), default="success")
    args = parser.parse_args()
    driver = Path(args.driver)
    # This loader runs only an explicitly outside-pinned diagnostic script.
    # Deployment and full input custody are checked again by that script.
    raw = read_driver(driver)
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != args.driver_sha256:
        raise ValueError("VM diagnostic driver differs from outside source pin")
    spec = importlib.util.spec_from_file_location("native_vm_driver", driver)
    base = importlib.util.module_from_spec(spec)
    # Execute the checked bytes, never reopen a path through the import loader.
    exec(compile(raw, str(driver), "exec"), base.__dict__)
    if base.read_root(driver, 128 * 1024) != raw:
        raise ValueError("VM diagnostic driver changed while loading")
    records = []
    with base.worker_leases():
        try:
            with native_constructor(base, Path(args.constructor), args.constructor_sha256, records):
                base.execute(args)
            if len(records) != 1:
                raise ValueError("the proof did not execute one native Root constructor")
        finally:
            output = Path(args.output)
            if output.is_dir():
                base.save(output / "native-rootfs-proof.json", {
                    "schema": "hol-gauntlet-native-rootfs-vm-proof.v1",
                    "driver_sha256": args.driver_sha256,
                    "constructor_sha256": args.constructor_sha256,
                    "launches": records,
                    "model_requests": 0,
                    "execution_eligible": False,
                    "rust_supervisor_owned": False,
                })


if __name__ == "__main__":
    main()
