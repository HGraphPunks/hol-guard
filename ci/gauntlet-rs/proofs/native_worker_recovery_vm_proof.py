"""Outside readback of Rust recovery for one retained failed apparatus job.

This adapter never stops a service or releases an image itself. It preserves
the original failure and verifies that Rust records no execution credit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import traceback
import types


def run(args, base):
    read, save = base.read_root, base.save
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    worker = Path(args.worker)
    if sha(read(worker, 128 * 1024**2)) != args.worker_sha256:
        raise ValueError("repair executable differs from outside pin")
    output = Path(args.output)
    base.trusted_parents(output)
    output.mkdir(mode=0o700)
    state = Path("/var/lib/hol-gauntlet-rust/worker-state")
    job = Path("/var/lib/hol-gauntlet-rust/native-jobs") / args.job_id
    paths = [state / (args.job_id + suffix) for suffix in
             (".started.json", ".running.json", ".native.stdout", ".native.stderr")]
    paths += [job / "cell" / name for name in ("native-image-events.v1.jsonl",
              "native-supervisor-events.v1.jsonl", "native-rootfs.v1.json", "native-supervisor.v1.json")]
    def retained(path):
        # A controller that failed before reporting legitimately has no stdout.
        # Preserve descriptor custody and metadata checks for empty streams too.
        base.trusted_parents(path)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            first = os.fstat(stream.fileno())
            if (not stat.S_ISREG(first.st_mode) or first.st_uid != 0 or first.st_gid != 0
                    or first.st_nlink != 1 or first.st_mode & 0o022 or first.st_size > 16 * 1024**2):
                raise ValueError("bounded retained Root stream required")
            raw = stream.read(16 * 1024**2 + 1)
            after = os.fstat(stream.fileno())
            fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if len(raw) != first.st_size or any(getattr(first, k) != getattr(other, k) for k in fields for other in (after, path.lstat())):
                raise ValueError("retained Root stream changed")
            return raw

    before = {str(path): sha(retained(path)) for path in paths}
    if before[str(paths[0])] != args.started_sha256:
        raise ValueError("original started marker differs from outside pin")
    preparation = json.loads(read(job / "preparation.v1.json", 49152))
    active = Path("/var/lib/hol-gauntlet-rust/cell-image-leases") / (preparation["image_id"][7:] + ".active.json")
    pointer_before = sha(read(active, 4096))
    result = {"schema": "hol-gauntlet-native-recovery-vm-proof.v1", "status": "failed",
              "job_id": args.job_id, "worker_sha256": args.worker_sha256,
              "original_worker_generation": args.original_generation,
              "model_requests": 0, "execution_eligible": False, "retained_before": before}

    def invoke(started, generation):
        return subprocess.run([str(worker), "--repair-native", args.source_sha,
            args.deployment_digest, args.original_generation, args.job_id, started, generation],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=150)

    def retain(name, completed):
        save(output / name, {"returncode": completed.returncode,
             "stdout": completed.stdout.decode(errors="replace"), "stderr": completed.stderr.decode(errors="replace")})

    try:
        for name, started, generation in (("wrong-started.json", "0" * 64, args.worker_sha256),
                                         ("wrong-worker.json", args.started_sha256, "0" * 64)):
            completed = invoke(started, generation)
            retain(name, completed)
            if completed.returncode != 2 or sha(read(active, 4096)) != pointer_before:
                raise ValueError("wrong recovery pin mutated the lease or was accepted")
        completed = invoke(args.started_sha256, args.worker_sha256)
        retain("repair-process.json", completed)
        if completed.returncode:
            raise ValueError("Rust quiescent recovery failed")
        receipt_raw = read(state / (args.job_id + ".native-repair.json"), 8192)
        receipt = json.loads(receipt_raw)
        if (receipt["status"] != "aborted" or receipt["exit_code"] is not None
                or receipt["execution_eligible"] is not False or receipt["guard_causality_verified"] is not False
                or receipt["model_requests"] != 0 or receipt["repair_generation"] != args.worker_sha256
                or receipt["started_marker_sha256"] != args.started_sha256
                or receipt["cleanup"]["active_pointer_sha256"] != pointer_before
                or json.loads(completed.stdout) != receipt):
            raise ValueError("recovery fabricated execution credit or lost its bindings")
        save(output / "retained-repair.json", receipt)
        reopened = invoke(args.started_sha256, args.worker_sha256)
        retain("reopened-process.json", reopened)
        if reopened.returncode or json.loads(reopened.stdout) != receipt or read(state / (args.job_id + ".native-repair.json"), 8192) != receipt_raw:
            raise ValueError("recovery restart changed the immutable receipt")
        after = {str(path): sha(retained(path)) for path in paths}
        if before != after:
            raise ValueError("recovery rewrote failed-job evidence")
        if any((state / (args.job_id + suffix)).exists() for suffix in (".terminal.json", ".report.json")):
            raise ValueError("recovery fabricated an ordinary terminal")
        rows = json.loads(subprocess.run(["/usr/bin/podman", "image", "mount", "--format", "json"],
            capture_output=True, check=True, timeout=60, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root"}).stdout)
        if active.exists() or any(row["id"].removeprefix("sha256:") == preparation["image_id"][7:] for row in rows):
            raise ValueError("recovery left the image mounted or active")
        result.update(status="passed", retained_after=after, original_failure_preserved=True,
                      ordinary_terminal_absent=True, image_unmounted=True, active_pointer_absent=True,
                      repair_receipt_sha256=sha(receipt_raw))
    except BaseException:
        result["traceback"] = traceback.format_exc()
        raise
    finally:
        save(output / "result.json", result)
    print(json.dumps({key: result[key] for key in ("status", "job_id", "model_requests", "execution_eligible")}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("worker", "worker-sha256", "driver", "driver-sha256", "source-sha", "deployment-digest",
                 "original-generation", "started-sha256", "job-id", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    path = Path(args.driver)
    raw = path.read_bytes()
    if len(raw) > 128 * 1024 or hashlib.sha256(raw).hexdigest() != args.driver_sha256:
        raise ValueError("outside diagnostic adapter pin differs")
    base = types.ModuleType("pinned_native_driver")
    exec(compile(raw, str(path), "exec"), base.__dict__)
    if base.read_root(path, 128 * 1024) != raw:
        raise ValueError("adapter metadata changed")
    run(args, base)


if __name__ == "__main__":
    main()
