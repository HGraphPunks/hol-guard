"""Verify Rust-only fixed-layout initialization on a fresh owned VM.

The outside adapter supplies no layout or Root command to the initializer.
It checks custody, immutable receipts and both competing worker leases.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import traceback


def read_root(path, limit):
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("immutable Root input ancestry required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > limit):
            raise ValueError("bounded Root input required")
        raw = stream.read(limit + 1)
        fields = ("st_dev", "st_ino", "st_uid", "st_gid", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, k) != getattr(other, k) for k in fields for other in (os.fstat(stream.fileno()), path.lstat())):
            raise ValueError("Root input changed")
        return raw


def save(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inputs", "worker-sha256", "worker-tests-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    inputs, output = Path(args.inputs), Path(args.output)
    worker = inputs / "gauntlet-vm-worker"
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    for path, pin in ((worker, args.worker_sha256), (inputs / "worker-tests", args.worker_tests_sha256)):
        if sha(read_root(path, 128 * 1024**2)) != pin:
            raise ValueError("outside initialization executable pin differs")
    output.mkdir(mode=0o700)
    roots = [Path(p) for p in ("/opt/hol-gauntlet", "/var/lib/hol-gauntlet-rust", "/var/lib/hol-gauntlet")]
    result = {"schema": "hol-gauntlet-native-initialize-vm-proof.v1", "status": "failed",
              "worker_sha256": args.worker_sha256, "model_requests": 0, "execution_eligible": False}

    def invoke(pin, name):
        completed = subprocess.run([str(worker), "--initialize-native", pin], stdin=subprocess.DEVNULL,
            capture_output=True, timeout=30, preexec_fn=lambda: os.umask(0o077))
        save(output / name, {"returncode": completed.returncode, "stdout": completed.stdout.decode(errors="replace"),
                            "stderr": completed.stderr.decode(errors="replace")})
        return completed

    try:
        if any(p.exists() or p.is_symlink() for p in roots):
            raise ValueError("fresh initialization domains required; preserve existing state")
        wrong = invoke("0" * 64, "wrong-pin.json")
        if (wrong.returncode != 2 or b"running Root binary differs" not in wrong.stderr
                or any(p.exists() for p in roots)):
            raise ValueError("wrong generation mutated initialization domains")
        positive = invoke(args.worker_sha256, "initialize.json")
        expected = {"schema": "hol-gauntlet-native-initialization.v2", "worker_generation": args.worker_sha256,
                    "layout": "native-worker-layout-v2", "job_dispatched": False, "execution_eligible": False, "model_requests": 0}
        if positive.returncode or json.loads(positive.stdout) != expected:
            raise ValueError("native initialization failed or claimed execution")
        root = roots[1]
        directories = {str(roots[0]): 0o755, str(root): 0o700, str(roots[2]): 0o755,
            str(roots[2] / "builds"): 0o700, str(roots[0] / "native-deployments"): 0o700,
            **{str(root / name): 0o700 for name in ("worker-state", "native-jobs", "cell-image-leases", "native-initialization")}}
        for name, mode in directories.items():
            info = Path(name).lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o7777 != mode:
                raise ValueError("initializer directory custody/mode differs under 0077")
        receipt = root / "native-initialization" / (args.worker_sha256 + ".json")
        original = read_root(receipt, 2048)
        if original != json.dumps(expected, sort_keys=True, separators=(",", ":")).encode():
            raise ValueError("initialization receipt differs from response")
        for path in (receipt, roots[0] / "worker.lock", root / "worker-state/active.lock"):
            if path.lstat().st_mode & 0o7777 != 0o600:
                raise ValueError("initialization file mode differs")
            checked = read_root(path, 2048)
            if path != receipt and checked:
                raise ValueError("initialization lock contains unexpected bytes")
        for path, name, diagnostic in ((root / "worker-state/active.lock", "rust-lease-busy.json", b"another worker holds the active lease"),
                           (roots[0] / "worker.lock", "legacy-lease-busy.json", b"Rust or Python worker lease unavailable")):
            fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                refused = invoke(args.worker_sha256, name)
                if refused.returncode != 2 or diagnostic not in refused.stderr or read_root(receipt, 2048) != original:
                    raise ValueError("initializer borrowed another worker lease or rewrote its receipt")
            finally:
                os.close(fd)
        reopened = invoke(args.worker_sha256, "reopened.json")
        if reopened.returncode or json.loads(reopened.stdout) != expected or read_root(receipt, 2048) != original:
            raise ValueError("initialization restart changed its receipt")
        if list((root / "native-jobs").iterdir()) or {p.name for p in (root / "worker-state").iterdir()} != {"active.lock"}:
            raise ValueError("initializer dispatched or adopted a job")
        fd = os.open(output / "worker-tests.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as log:
            tested = subprocess.run([str(inputs / "worker-tests")], stdout=log, stderr=subprocess.STDOUT, timeout=180)
        if tested.returncode:
            raise ValueError("actual Root worker library tests failed")
        result.update(status="passed", wrong_pin_before_mutation=True, both_competing_leases_refused=True,
                      directory_modes={name: oct(mode) for name, mode in directories.items()},
                      receipt_sha256=sha(original), immutable_reopen=True, job_dispatched=False,
                      worker_tests_log_sha256=sha(read_root(output / "worker-tests.log", 1024**2)))
    except BaseException:
        result["traceback"] = traceback.format_exc()
        raise
    finally:
        save(output / "result.json", result)
    print(json.dumps({key: result[key] for key in ("status", "model_requests", "execution_eligible", "job_dispatched")}, sort_keys=True))


if __name__ == "__main__":
    main()
