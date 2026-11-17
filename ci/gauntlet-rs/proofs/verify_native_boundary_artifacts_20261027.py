"""Inert courier for the Rust boundary verifier over retained public evidence."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

SOURCE = "cec21c2c4ddc2ce9d179334ba069376bd49bd2ec"
BINARY = "5918fa2e4ebfa80ab8f6203adb0b9d1bf5755582c6b1af4a7348a6729f35dc42"
ARCHIVE = "f6f838f80636da3a73afe36ca4272f6113fc8c2c82b449d0c26f114f88842670"
ROLES = ["success", "input-binding", "injection", "boundary", "timeout", "cancel"]


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, raw):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def mutation(directory, index, kind, files):
    files = dict(files)
    manifest = json.loads(files["results.sha256.json"])
    if kind == "canary-inode":
        manifest["filesystem"]["combined/product-guard-canary.txt"]["inode"] += 1
    elif kind == "timeout-row":
        name = "combined/workspace/boundary-negatives.json"
        report = json.loads(files[name])
        report["rows"][6]["errno"] = 110
        files[name] = canonical(report)
    else:
        assert kind == "missing-sdk-positive"
        control = json.loads(files["combined/worker/report.json"])["controller_report"]
        pin = control["measurements"]["sdk_boundary_canary_positive"]["stdout_sha256"]
        selected = [
            name
            for name, raw in files.items()
            if name.startswith("combined/sdk-processes/") and name.endswith(".stdout") and sha(raw) == pin
        ]
        assert len(selected) == 1
        files[selected[0]] = b"synthetic hostile capture\n"
    for name, raw in files.items():
        if name != "results.sha256.json":
            manifest["files"][name] = {"bytes": len(raw), "sha256": sha(raw)}
    files["results.sha256.json"] = canonical(manifest)
    path = directory / f"native-boundary-artifact-mutation-{index}-{kind}.tar"
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.mode, entry.uid, entry.gid, entry.mtime = 0o600, 0, 0, 0
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        stream.flush()
        os.fsync(stream.fileno())
    return path, sha(path.read_bytes())


def verify(directory, index):
    binary = directory / "native-boundary-artifact-verifier-001"
    assert sha(binary.read_bytes()) == BINARY
    metadata = json.loads((directory / "native-boundary-rust-cli-build-001.json").read_bytes())
    assert metadata["source_commit"] == SOURCE and metadata["binary_sha256"] == BINARY
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    cases = []

    def run(name, role, expected, archive=None, pin=None, option="--boundary-artifacts"):
        job = jobs[role]
        argv = [
            str(binary),
            str(directory / "native-host-keyed-host-pins-001"),
            str(directory / f"native-host-keyed-completion-001-{role}-valid.json"),
            job["source_sha"],
            job["job_id"],
            job["deployment_sha256"],
            job["worker_generation"],
            job["preparation_sha256"],
            role,
        ]
        if archive is not None:
            argv.extend([option, str(archive), pin])
        result = subprocess.run(argv, capture_output=True, timeout=30)
        prefix = directory / f"native-boundary-artifact-proof-{index}-{name}"
        save(prefix.with_suffix(".stdout"), result.stdout)
        save(prefix.with_suffix(".stderr"), result.stderr)
        row = {
            "case": name,
            "returncode": result.returncode,
            "stdout_sha256": sha(result.stdout),
            "stderr_sha256": sha(result.stderr),
        }
        save(prefix.with_suffix(".json"), canonical(row))
        cases.append(row)
        assert result.returncode == expected, result.stderr.decode()
        if expected:
            assert not result.stdout
            return None
        value = json.loads(result.stdout)
        assert value["execution_eligible"] is value["guard_causality_verified"] is False
        return value

    for role in ROLES:
        run("envelope-" + role, role, 0)
    original = directory / "native-host-keyed-vm-results-001-boundary.tar"
    assert sha(original.read_bytes()) == ARCHIVE
    actual = run("actual-boundary", "boundary", 0, original, ARCHIVE)
    facts = actual["boundary_artifacts"]["relations"]
    assert facts["physical_canaries_preserved"] == 3 and facts["path_refusals"] == 6
    assert facts["network_refusals"] == 2 and facts["child_kernel_claims_authenticated"] is False
    assert run("restart-boundary", "boundary", 0, original, ARCHIVE) == actual
    binding = directory / "native-host-keyed-vm-results-001-input-binding.tar"
    run(
        "input-binding-regression",
        "input-binding",
        0,
        binding,
        sha(binding.read_bytes()),
        option="--input-binding-artifacts",
    )
    assert cases[-1]["stdout_sha256"] == "04d4625ea7d591e81326d6ee23a6eef455547e4ffaf98f81a9160e3d8e8694ce"
    run("wrong-digest", "boundary", 2, original, "0" * 64)
    run("cross-job-archive", "boundary", 2, binding, sha(binding.read_bytes()))
    run("wrong-role", "input-binding", 2, original, ARCHIVE)
    with tarfile.open(original, mode="r:") as archive:
        files = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
    for kind in ["canary-inode", "timeout-row", "missing-sdk-positive"]:
        path, pin = mutation(directory, index, kind, files)
        run(kind, "boundary", 2, path, pin)
    result = {
        "schema": "hol-gauntlet-native-boundary-artifact-verifier-proof.v1",
        "verifier_source_commit": SOURCE,
        "verifier_sha256": BINARY,
        "historical_runtime_source": "f53bc490f7483ad41a781d62dc4d0d2c6a47c6a9",
        "historical_product_source": jobs["boundary"]["source_sha"],
        "archive_sha256": ARCHIVE,
        "cases": cases,
        "relations": facts,
        "fresh_current_source_execution": False,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    save(directory / f"native-boundary-artifact-proof-{index}.json", canonical(result))
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3 or not re.fullmatch(r"[0-9]{3}", sys.argv[2]):
        raise SystemExit("usage: verify_native_boundary_artifacts_20261027.py EVIDENCE_DIRECTORY ATTEMPT_INDEX")
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))
