"""Outside zero-model proof of native worker leases, process and terminal state.

This adapter supplies fixture/declaration bytes and reads results. The Rust
worker owns both worker locks, reservation, controller, cell and image cleanup.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import traceback
import types

HELPERS = ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/aa-exec",
           "/usr/bin/unshare", "/usr/sbin/apparmor_parser")


def run(args, base):
    read, save = base.read_root, base.save
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    directory = Path(args.inputs)
    for name, pin in (("gauntlet-cell-rootfs", args.constructor_sha256), ("gauntlet-vm-worker", args.worker_sha256)):
        if sha(read(directory / name, 128 * 1024**2)) != pin:
            raise ValueError("Rust worker/constructor differs from outside pin")
    verifier = Path("/opt/hol-gauntlet") / ("native-cell-input-" + args.controller_source[:16]) / "gauntlet-controller-install-verify-shadow"
    if sha(read(verifier, 16 * 1024**2)) != args.verifier_sha256:
        raise ValueError("outside controller verifier differs")

    def verify():
        completed = subprocess.run([str(verifier), args.controller_source, args.controller_tree_sha256],
                                   capture_output=True, check=True, timeout=30)
        return json.loads(completed.stdout)

    legacy = Path("/opt/hol-gauntlet/rust-shadow-candidates/b70d59e2681c4a3f/provisional-66703091ba2f7815-8ef7a22ac7a4d01b.json")
    raw = read(legacy, 1024**2)
    if sha(raw) != args.legacy_config_sha256:
        raise ValueError("outside retained configuration differs")
    config = json.loads(raw)
    if sha(read(Path("/usr/bin/podman"), 128 * 1024**2)) != args.podman_sha256:
        raise ValueError("outside Podman differs")
    if re.fullmatch(r"[0-9a-f]{16}", args.job_id) is None:
        raise ValueError("exact fresh job ID required")
    output = Path(args.output)
    base.trusted_parents(output)
    output.mkdir(mode=0o700)
    job = Path("/var/lib/hol-gauntlet-rust/native-jobs") / args.job_id
    deployments = Path("/opt/hol-gauntlet/native-deployments")
    for parent in (job.parent, deployments):
        if not parent.exists():
            base.trusted_parents(parent)
            parent.mkdir(mode=0o700)
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("private Root native fixture parent required")
    base.trusted_parents(job)
    job.mkdir(mode=0o700)
    workspace = job / "workspace"
    workspace.mkdir(mode=0o700)
    os.chown(workspace, 10001, 10001)
    metadata = workspace.lstat()
    prefix = Path("/opt") / config["assets"]["guard_prefix"]["path"]
    preparation = {"schema": "hol-gauntlet-cell-preparation.v1", "stage": str(job / "cell"),
        "artifacts": str(legacy.parent / "cell-artifacts-rust-v2"), "artifact_manifest_sha256": args.artifact_manifest_sha256,
        "initializer_sha256": config["runtime"]["private_cell"]["initializer_sha256"], "runtime_prefix": str(prefix),
        "runtime_tree_digest": config["runtime"]["private_cell"]["runtime_tree_digest"],
        "image_id": config["runtime"]["guard_executor_image_id"], "podman_sha256": args.podman_sha256,
        "task_mounts": {"schema": "product-cell-task-mounts.v1", "workspace": {"source": str(workspace),
            "destination": "/runtime/home/project", "custody_root": str(job), "device": metadata.st_dev,
            "inode": metadata.st_ino, "mode": metadata.st_mode & 0o7777}, "providers": []},
        "launch": {"schema": "hol-gauntlet-cell-supervisor.v1", "constructor": str(directory / "gauntlet-cell-rootfs"),
            "constructor_sha256": args.constructor_sha256, "wall_seconds": 180, "cpu_profile": "single-core-v1",
            "job_slice": "holgauntletrust" + args.job_id + ".slice",
            "host_helpers": {name: sha(read(Path(name), 16 * 1024**2)) for name in HELPERS}}}
    path = job / "preparation.v1.json"
    save(path, preparation)
    declaration = {"schema": "hol-gauntlet-native-worker-job.v1", "profile": "native-apparatus-v1",
        "source_sha": config["runtime"]["guard_source_sha"], "job_id": args.job_id,
        "worker_generation": args.worker_sha256, "preparation_sha256": sha(read(path, 49152)),
        "case": args.case if args.case in {"success", "timeout", "cancel"} else "success"}
    raw = (json.dumps(declaration, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = sha(raw)
    deployment = deployments / (digest + ".json")
    with deployment.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    deployment.chmod(0o400)
    request = {"schema": "hol-gauntlet-worker-request.v1", "action": "run", "source_sha": declaration["source_sha"],
               "job_id": args.job_id, "deployment_digest": digest}
    save(output / "request.json", request)
    state = Path("/var/lib/hol-gauntlet-rust/worker-state")
    result = {"schema": "hol-gauntlet-native-worker-vm-proof.v1", "case": args.case, "status": "failed",
        "job_id": args.job_id, "deployment_digest": digest, "worker_sha256": args.worker_sha256,
        "controller_before": verify(), "model_requests": 0, "execution_eligible": False,
        "outside_pin_provenance_verified": False}

    def invoke(action="run", generation=None):
        wire = {**request, "action": action}
        if action != "run":
            # v1 query frames carry no deployment field; the outside CLI pin
            # remains mandatory and binds the read-only retained response.
            wire.pop("deployment_digest")
        return subprocess.run([str(directory / "gauntlet-vm-worker"), declaration["source_sha"], digest,
            generation or args.worker_sha256], input=(json.dumps(wire, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            capture_output=True, timeout=360)

    def retain(name, completed):
        save(output / name, {"returncode": completed.returncode, "stdout": completed.stdout.decode(errors="replace"),
                             "stderr": completed.stderr.decode(errors="replace")})

    try:
        if args.case == "lease-busy":
            lock = state / "active.lock"
            base.trusted_parents(lock)
            fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o077:
                    raise ValueError("outside lease fixture unsafe")
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                completed = invoke()
            finally:
                os.close(fd)
        else:
            completed = invoke(generation="0" * 64 if args.case == "wrong-generation" else None)
        retain("rust-process.json", completed)
        if args.case in {"lease-busy", "wrong-generation"}:
            expected = "another worker holds the active lease" if args.case == "lease-busy" else "running Root binary differs from outside digest or mode"
            if (completed.returncode != 2 or expected not in completed.stderr.decode(errors="replace")
                    or (state / (args.job_id + ".started.json")).exists()):
                raise ValueError("native worker failed to refuse before reservation")
            result["admission_refused_before_reservation"] = True
        else:
            response = json.loads(completed.stdout)
            if completed.returncode or response.get("state") != "terminal" or response.get("status") != "invalid-evidence":
                raise ValueError("native worker did not retain an ineligible terminal")
            report_raw = read(state / (args.job_id + ".report.json"), 16 * 1024**2)
            if sha(report_raw) != response["report_sha256"]:
                raise ValueError("outside terminal/report bytes differ")
            report = json.loads(report_raw)
            if (report["execution_eligible"] is not False or report["guard_causality_verified"] is not False
                    or report["model_requests"] != 0 or report["status"] != "invalid-evidence"
                    or report["worker_generation"] != args.worker_sha256 or report["job_id"] != args.job_id
                    or report["controller_report"]["status"] != "passed"
                    or report["controller_report"]["case"] != declaration["case"]
                    or report["controller_report"]["rust_image_lease_owned"] is not True):
                raise ValueError("native apparatus was falsely qualified or failed")
            save(output / "retained-terminal.json", json.loads(read(state / (args.job_id + ".terminal.json"), 2048)))
            save(output / "retained-report.json", report)
            result.update(report_sha256=response["report_sha256"], apparatus_completed=True)
            reopened = invoke("reconcile")
            retain("reconcile-process.json", reopened)
            if reopened.returncode or json.loads(reopened.stdout).get("report_sha256") != response["report_sha256"]:
                raise ValueError("restart reconciliation lost the terminal pin")
            if args.case == "replay":
                replay = invoke()
                retain("replay-process.json", replay)
                if (replay.returncode != 2 or "job ID was already reserved" not in replay.stderr.decode(errors="replace")
                        or read(state / (args.job_id + ".report.json"), 16 * 1024**2) != report_raw):
                    raise ValueError("native worker replay mutated or reexecuted the job")
                result["replay_refused"] = True
        result["status"] = "passed"
    except BaseException:
        result["traceback"] = traceback.format_exc()
        raise
    finally:
        try:
            result["controller_cgroup_absent"] = not (Path("/sys/fs/cgroup/system.slice") / ("hol-gauntlet-rust-job-" + args.job_id)).exists()
            result["product_slice_absent"] = not (Path("/sys/fs/cgroup") / ("holgauntletrust" + args.job_id + ".slice")).exists()
            image_id = preparation["image_id"]
            rows = json.loads(subprocess.run(["/usr/bin/podman", "image", "mount", "--format", "json"],
                capture_output=True, check=True, timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}).stdout)
            result["image_unmounted"] = not any(row["id"].removeprefix("sha256:") == image_id[7:] for row in rows)
            result["image_active_pointer_absent"] = not (Path("/var/lib/hol-gauntlet-rust/cell-image-leases") / (image_id[7:] + ".active.json")).exists()
            retained = output / "retained-report.json"
            if retained.exists():
                profile = json.loads(read(retained, 16 * 1024**2))["controller_report"]["actor"]["lsm_label"].split()[0]
                if re.fullmatch(r"hol-product-cell-[0-9a-f]{32}", profile) is None:
                    raise ValueError("unexpected owned worker cell profile")
                with Path("/sys/kernel/security/apparmor/profiles").open("rb") as stream:
                    raw = stream.read(1024**2 + 1)
                if len(raw) > 1024**2:
                    raise ValueError("outside AppArmor inventory bound")
                result["apparmor_absent"] = all(row.split()[0] != profile for row in raw.decode().splitlines())
                if not result["apparmor_absent"]:
                    raise ValueError("worker left its AppArmor profile loaded")
            result["controller_after"] = verify()
            if not all(result[key] for key in ("controller_cgroup_absent", "product_slice_absent", "image_unmounted", "image_active_pointer_absent")):
                raise ValueError("outside worker cleanup check failed; retain unknown state")
        except BaseException:
            result["status"] = "failed"
            result["cleanup_traceback"] = traceback.format_exc()
            raise
        finally:
            save(output / "result.json", result)
    print(json.dumps({key: result[key] for key in ("case", "status", "job_id", "model_requests", "execution_eligible")}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inputs", "driver", "driver-sha256", "constructor-sha256", "worker-sha256", "controller-source",
                 "controller-tree-sha256", "verifier-sha256", "legacy-config-sha256", "artifact-manifest-sha256",
                 "podman-sha256", "output", "job-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--case", choices=("success", "timeout", "cancel", "wrong-generation", "lease-busy", "replay"), required=True)
    args = parser.parse_args()
    path = Path(args.driver)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("literal diagnostic driver required")
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != args.driver_sha256:
        raise ValueError("outside diagnostic adapter pin differs")
    base = types.ModuleType("pinned_native_driver")
    exec(compile(raw, str(path), "exec"), base.__dict__)
    if base.read_root(path, 128 * 1024) != raw:
        raise ValueError("adapter metadata or bytes changed")
    run(args, base)


if __name__ == "__main__":
    main()
