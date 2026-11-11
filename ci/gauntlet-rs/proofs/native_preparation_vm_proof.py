"""Outside VM test of Rust-owned cell staging/image/supervisor; zero inference.

Python prepares only the outside declaration and physical test task. It never
imports the old factory, acquires the successful case's image or starts a cell.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import traceback
import types

HELPERS = ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/aa-exec",
           "/usr/bin/unshare", "/usr/sbin/apparmor_parser")


def run(args, base):
    read, save = base.read_root, base.save
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    directory = Path(args.inputs)
    for name, pin in (("gauntlet-cell-rootfs", args.constructor_sha256),
                      ("gauntlet-native-cell-proof", args.proof_sha256)):
        if sha(read(directory / name, 16 * 1024**2)) != pin:
            raise ValueError("Rust executable differs from outside pin")
    podman = Path("/usr/bin/podman")
    if sha(read(podman, 128 * 1024**2)) != args.podman_sha256:
        raise ValueError("Podman differs from outside pin")
    verifier = Path("/opt/hol-gauntlet") / ("native-cell-input-" + args.controller_source[:16]) / "gauntlet-controller-install-verify-shadow"
    if sha(read(verifier, 16 * 1024**2)) != args.verifier_sha256:
        raise ValueError("controller verifier differs from outside pin")

    def verify():
        completed = subprocess.run([str(verifier), args.controller_source, args.controller_tree_sha256],
                                   capture_output=True, check=True, timeout=30)
        return json.loads(completed.stdout)

    def image(*arguments):
        if sha(read(podman, 128 * 1024**2)) != args.podman_sha256:
            raise ValueError("outside Podman pin changed")
        completed = subprocess.run([str(podman), "image", *arguments], capture_output=True,
            check=True, timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"})
        if len(completed.stdout) > 1024**2 or len(completed.stderr) > 65536:
            raise ValueError("outside image inventory byte bound")
        return completed.stdout

    legacy = Path("/opt/hol-gauntlet/rust-shadow-candidates/b70d59e2681c4a3f/provisional-66703091ba2f7815-8ef7a22ac7a4d01b.json")
    raw = read(legacy, 1024**2)
    if sha(raw) != args.legacy_config_sha256:
        raise ValueError("retained config differs from outside pin")
    config = json.loads(raw)
    output = Path(args.output)
    base.trusted_parents(output)
    output.mkdir(mode=0o700)
    workspace = output / "workspace"
    workspace.mkdir(mode=0o700)
    os.chown(workspace, 10001, 10001)
    metadata = workspace.lstat()
    prefix = Path("/opt") / config["assets"]["guard_prefix"]["path"]
    image_id = config["runtime"]["guard_executor_image_id"]
    if re.fullmatch(r"sha256:[0-9a-f]{64}", image_id) is None:
        raise ValueError("exact retained image identity required")

    def mounts():
        rows = json.loads(image("mount", "--format", "json"))
        return [row for row in rows if row["id"].removeprefix("sha256:") == image_id[7:]]

    if mounts():
        raise ValueError("preexisting external image lease; refusing this test")
    stage = output / "cell"
    declaration = {"schema": "hol-gauntlet-cell-preparation.v1", "stage": str(stage),
        "artifacts": str(legacy.parent / "cell-artifacts-rust-v2"),
        "artifact_manifest_sha256": args.artifact_manifest_sha256,
        "initializer_sha256": config["runtime"]["private_cell"]["initializer_sha256"],
        "runtime_prefix": str(prefix), "runtime_tree_digest": config["runtime"]["private_cell"]["runtime_tree_digest"],
        "image_id": image_id, "podman_sha256": args.podman_sha256,
        "task_mounts": {"schema": "product-cell-task-mounts.v1", "workspace": {
            "source": str(workspace), "destination": "/runtime/home/project", "custody_root": str(output),
            "device": metadata.st_dev, "inode": metadata.st_ino, "mode": metadata.st_mode & 0o7777}, "providers": []},
        "launch": {"schema": "hol-gauntlet-cell-supervisor.v1", "constructor": str(directory / "gauntlet-cell-rootfs"),
            "constructor_sha256": args.constructor_sha256, "wall_seconds": 180, "cpu_profile": "single-core-v1",
            "job_slice": None, "host_helpers": {name: sha(read(Path(name), 16 * 1024**2)) for name in HELPERS}}}
    if args.case == "wrong-pin":
        declaration["launch"]["constructor_sha256"] = "0" * 64
    path = output / "native-cell-preparation.v1.json"
    save(path, declaration)
    digest = sha(read(path, 49152))
    result = {"schema": "hol-gauntlet-rust-preparation-parent.v1", "status": "failed", "case": args.case,
        "controller_before": verify(), "model_requests": 0, "execution_eligible": False,
        "preparation_declaration_sha256": digest, "rust_image_lease_owned": args.case not in {"wrong-pin", "borrowed-image"}}
    borrowed = False
    try:
        prior_mount = None
        if args.case == "borrowed-image":
            borrowed = True
            prior_mount = image("mount", image_id).decode().strip()
            if len(mounts()) != 1:
                raise ValueError("outside test image mount unavailable")
        command = [str(directory / "gauntlet-native-cell-proof"), str(path), digest,
                   args.case if args.case in {"success", "timeout", "cancel"} else "success", "--prepared"]
        completed = subprocess.run(command, capture_output=True, timeout=150)
        save(output / "rust-process.json", {"returncode": completed.returncode,
            "stdout": completed.stdout.decode(errors="replace"), "stderr": completed.stderr.decode(errors="replace")})
        if args.case in {"wrong-pin", "borrowed-image"}:
            expected = "outside digest" if args.case == "wrong-pin" else "image already mounted"
            if completed.returncode != 2 or expected not in completed.stderr.decode(errors="replace"):
                raise ValueError("Rust preparation did not refuse the injected boundary violation")
            if (stage / "native-supervisor-events.v1.jsonl").exists():
                raise ValueError("refused preparation launched a supervisor")
            if args.case == "wrong-pin" and stage.exists():
                raise ValueError("wrong executable pin mutated the cell stage")
            if borrowed:
                rows = mounts()
                if len(rows) != 1 or rows[0]["mountpoint"] != prior_mount:
                    raise ValueError("Rust borrowed or unmounted another owner's image")
                result["borrowed_mount_untouched"] = True
        else:
            report = json.loads(completed.stdout)
            if (completed.returncode or report.get("status") != "passed" or report.get("rust_image_lease_owned") is not True
                    or report.get("rust_supervisor_owned") is not True or report.get("cell_cleanup_complete") is not True
                    or report.get("preparation_declaration_sha256") != digest):
                raise ValueError("Rust-owned preparation proof failed")
            result["rust_report"] = report
            if args.case == "replay":
                before = read(stage / "native-supervisor-events.v1.jsonl", 64 * 1024**2)
                replay = subprocess.run(command, capture_output=True, timeout=60)
                save(output / "replay-process.json", {"returncode": replay.returncode,
                     "stdout": replay.stdout.decode(errors="replace"), "stderr": replay.stderr.decode(errors="replace")})
                if replay.returncode != 2 or read(stage / "native-supervisor-events.v1.jsonl", 64 * 1024**2) != before:
                    raise ValueError("one-use preparation replay was not refused without mutation")
                result["replay_refused"] = True
        result["status"] = "passed"
    except BaseException:
        result["traceback"] = traceback.format_exc()
        raise
    finally:
        try:
            # Only the intentionally borrowed-image negative has an outside owner.
            # A failed ordinary case is retained as unknown; no intervention hides it.
            if borrowed:
                image("unmount", image_id)
                result["outside_negative_fixture_unmounted"] = True
            result["image_cleanup_complete"] = not mounts()
            active = Path("/var/lib/hol-gauntlet-rust/cell-image-leases") / (image_id[7:] + ".active.json")
            result["active_image_lease_absent"] = not active.exists()
            journal = stage / "native-supervisor-events.v1.jsonl"
            if journal.exists():
                first = json.loads(read(journal, 64 * 1024**2).splitlines()[0])
                profile = first["data"]["profile"]
                if re.fullmatch(r"hol-product-cell-[0-9a-f]{32}", profile) is None:
                    raise ValueError("invalid owned supervisor profile")
                result["cgroup_absent"] = not (Path("/sys/fs/cgroup/system.slice") / (profile + ".service")).exists()
                with Path("/sys/kernel/security/apparmor/profiles").open("rb") as stream:
                    raw = stream.read(1024**2 + 1)
                if len(raw) > 1024**2:
                    raise ValueError("outside AppArmor inventory bound")
                result["apparmor_absent"] = all(row.split()[0] != profile for row in raw.decode().splitlines())
                with Path("/proc/self/mountinfo").open("rb") as stream:
                    raw = stream.read(2 * 1024**2 + 1)
                if len(raw) > 2 * 1024**2:
                    raise ValueError("outside mount inventory bound")
                encoded = str(stage / "rootfs").replace("\\", "\\134").replace(" ", "\\040")
                result["rootfs_mount_absent"] = all(row.split()[4] != encoded for row in raw.decode().splitlines())
                if not all(result[key] for key in ("cgroup_absent", "apparmor_absent", "rootfs_mount_absent")):
                    raise ValueError("outside collector found surviving Rust cell resources")
            result["controller_after"] = verify()
            if not result["image_cleanup_complete"] or not result["active_image_lease_absent"]:
                raise ValueError("Rust image cleanup unresolved; retain mount/lease and refuse new work")
        except BaseException:
            result["status"] = "failed"
            result["cleanup_traceback"] = traceback.format_exc()
            raise
        finally:
            save(output / "result.json", result)
    print(json.dumps({key: result[key] for key in ("case", "status", "model_requests", "execution_eligible", "image_cleanup_complete")}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inputs", "driver", "driver-sha256", "constructor-sha256", "proof-sha256", "controller-source",
                 "controller-tree-sha256", "verifier-sha256", "legacy-config-sha256", "artifact-manifest-sha256",
                 "podman-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--case", choices=("success", "timeout", "cancel", "wrong-pin", "replay", "borrowed-image"), required=True)
    args = parser.parse_args()
    # Use the existing outside reader/worker-lock adapter, pinned before execution.
    path = Path(args.driver)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("literal diagnostic driver path required")
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != args.driver_sha256:
        raise ValueError("outside diagnostic adapter pin differs")
    base = types.ModuleType("pinned_native_driver")
    exec(compile(raw, str(path), "exec"), base.__dict__)
    if base.read_root(path, 128 * 1024) != raw:
        raise ValueError("adapter metadata or bytes changed")
    with base.worker_leases():
        run(args, base)


if __name__ == "__main__":
    main()
