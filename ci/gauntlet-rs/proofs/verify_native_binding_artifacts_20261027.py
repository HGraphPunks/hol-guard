"""Inert courier: exercise the Rust verifier on retained public VM evidence."""

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

SOURCE = "b059a59000b4b76e282f65ffa9b56f5e5570c2d7"
BINARY = "13e5a3eb4e3bb0a96af10d3b3237099a13abdddd4e878da3e6643793ed90ccab"
ARCHIVE = "5b9eb3ca04063bfb535dbc09f133ee8fb1409fa3b897964c46b8da2963aece94"
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


def mutated_archive(directory, index, kind, files):
    files = dict(files)
    manifest = json.loads(files["results.sha256.json"])
    if kind == "marker-inode":
        manifest["filesystem"]["combined/workspace/forbidden-command-target/synthetic-marker.txt"]["inode"] += 1
    else:
        journal = "combined/cell/native-supervisor-events.v1.jsonl"
        events = [json.loads(row) for row in files[journal].splitlines()]
        if kind == "broken-chain":
            events[1]["previous_sha256"] = "0" * 64
        else:
            assert kind == "changed-capture"
            record = next(r["data"] for r in reversed(events) if r["kind"] == "capture-terminal")
            pin = record["files"]["stderr"]
            name = "combined/cell/" + pin["file"]
            assert files[name].startswith(b"contained_run_authorization_failed:")
            files[name] = b"changed-capture: synthetic hostile bytes\n"
            pin.update(bytes=len(files[name]), sha256=sha(files[name]))
            previous = "0" * 64
            for row in events:
                row["previous_sha256"] = previous
                previous = sha(canonical(row))
        files[journal] = b"".join(canonical(row) + b"\n" for row in events)
        for name, raw in files.items():
            if name != "results.sha256.json":
                manifest["files"][name] = {"bytes": len(raw), "sha256": sha(raw)}
    files["results.sha256.json"] = canonical(manifest)
    path = directory / f"native-binding-artifact-mutation-{index}-{kind}.tar"
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, raw in sorted(files.items()):
                member = tarfile.TarInfo(name)
                member.mode, member.uid, member.gid, member.mtime = 0o600, 0, 0, 0
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
        stream.flush()
        os.fsync(stream.fileno())
    return path, sha(path.read_bytes())


def verify(directory, index):
    binary = directory / "native-binding-artifact-verifier-001"
    assert sha(binary.read_bytes()) == BINARY
    metadata = json.loads((directory / "native-binding-rust-cli-build-001.json").read_bytes())
    assert metadata["source_commit"] == SOURCE and metadata["binary_sha256"] == BINARY
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    rows = []

    def run(name, role, expected, archive=None, pin=None):
        job = jobs[role]
        command = [
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
            command.extend(["--input-binding-artifacts", str(archive), pin])
        result = subprocess.run(command, capture_output=True, timeout=30)
        prefix = directory / f"native-binding-artifact-proof-{index}-{name}"
        save(prefix.with_suffix(".stdout"), result.stdout)
        save(prefix.with_suffix(".stderr"), result.stderr)
        row = {
            "case": name,
            "returncode": result.returncode,
            "stdout_sha256": sha(result.stdout),
            "stderr_sha256": sha(result.stderr),
        }
        rows.append(row)
        save(prefix.with_suffix(".json"), canonical(row))
        assert result.returncode == expected, result.stderr.decode()
        if expected:
            assert not result.stdout
            return None
        value = json.loads(result.stdout)
        assert value["execution_eligible"] is value["guard_causality_verified"] is False
        return value

    for role in ROLES:
        run("envelope-" + role, role, 0)
    archive = directory / "native-host-keyed-vm-results-001-input-binding.tar"
    assert sha(archive.read_bytes()) == ARCHIVE
    first = run("actual-binding", "input-binding", 0, archive, ARCHIVE)
    assert first["binding_artifacts"]["relations"]["native_request_refusals"] == 9
    assert first["binding_artifacts"]["relations"]["forbidden_authorization_control_verified"]
    assert run("restart-binding", "input-binding", 0, archive, ARCHIVE) == first
    run("wrong-digest", "input-binding", 2, archive, "0" * 64)
    other = directory / "native-host-keyed-vm-results-001-success.tar"
    run("cross-job-archive", "input-binding", 2, other, sha(other.read_bytes()))
    run("wrong-role", "success", 2, other, sha(other.read_bytes()))
    with tarfile.open(archive, mode="r:") as source:
        files = {member.name: source.extractfile(member).read() for member in source.getmembers()}
    for kind in ["marker-inode", "broken-chain", "changed-capture"]:
        path, pin = mutated_archive(directory, index, kind, files)
        run(kind, "input-binding", 2, path, pin)
    result = {
        "schema": "hol-gauntlet-native-binding-artifact-verifier-proof.v1",
        "verifier_source_commit": SOURCE,
        "verifier_sha256": BINARY,
        "historical_runtime_source": "f53bc490f7483ad41a781d62dc4d0d2c6a47c6a9",
        "historical_product_source": jobs["input-binding"]["source_sha"],
        "archive_sha256": ARCHIVE,
        "cases": rows,
        "relations": first["binding_artifacts"]["relations"],
        "fresh_current_source_execution": False,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    save(directory / f"native-binding-artifact-proof-{index}.json", canonical(result))
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3 or not re.fullmatch(r"[0-9]{3}", sys.argv[2]):
        raise SystemExit("usage: verify_native_binding_artifacts_20261027.py EVIDENCE_DIRECTORY ATTEMPT_INDEX")
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))
