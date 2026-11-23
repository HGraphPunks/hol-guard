"""Retain current Rust readback of all immutable legacy Native control modes."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from verify_native_control_artifacts_20261027 import PROOFS
from verify_native_mcp_artifacts_20261027 import ARCHIVES, LEGACY
from verify_native_process_artifacts_20261027 import INTERPRETER, OBSERVER

SOURCE = "c3c8fa5d3cadc3121967895ca97cb5aadd70283b"
VERIFIER = "6bd81d83d456edecb00953792161557ec96b40484dfae3d31b2c4fa4e1f79daa"
CONTROL = "72242b0d6a4120677fb5de5bcd3eb8c57d838cb5cb868d5435c34fbe343f7f18"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(directory, index):
    assert index.isdigit() and len(index) == 3
    exe = directory / "native-launch-verifier-001"
    assert sha(exe.read_bytes()) == VERIFIER
    prior = {}
    for mode, pin in {**PROOFS, "control": CONTROL}.items():
        number = "002" if mode == "hook" else "001"
        raw = (directory / ("native-" + mode + "-artifact-proof-" + number + ".json")).read_bytes()
        assert sha(raw) == pin
        prior[mode] = json.loads(raw)
    envelopes = {r["case"]: r for r in prior["mcp"]["cases"]}
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    journal = directory / "native-host-keyed-host-pins-001"
    before = {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    cases = []

    def arguments(role):
        p = jobs[role]
        return [
            str(exe),
            str(journal),
            str(directory / ("native-host-keyed-completion-001-" + role + "-valid.json")),
            p["source_sha"],
            p["job_id"],
            p["deployment_sha256"],
            p["worker_generation"],
            p["preparation_sha256"],
            role,
        ]

    def run(name, args, expected):
        result = subprocess.run(args, capture_output=True, timeout=60)
        stem = "native-launch-legacy-proof-" + index + "-" + name
        for suffix, raw in [("stdout", result.stdout), ("stderr", result.stderr)]:
            with (directory / (stem + "." + suffix)).open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        row = dict(
            case=name, returncode=result.returncode, stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr)
        )
        cases.append(row)
        assert result.returncode == 0 and not result.stderr, row
        assert row["stdout_sha256"] == expected, row
        value = json.loads(result.stdout)
        assert value["execution_eligible"] is value["guard_causality_verified"] is False
        assert value["model_requests"] == 0
        return value

    for role, digest in ARCHIVES.items():
        archive = directory / ("native-host-keyed-vm-results-001-" + role + ".tar")
        assert sha(archive.read_bytes()) == digest
        run("envelope-" + role, arguments(role), envelopes["envelope-" + role]["stdout_sha256"])
        for mode in ["mcp", "process", "hook", "control"]:
            args = [*arguments(role), "--" + mode + "-artifacts", str(archive), digest]
            if mode != "mcp":
                args += [INTERPRETER, OBSERVER]
            value = run(mode + "-" + role, args, prior[mode]["actual_readback_sha256"][role])
            if mode == "process":
                relation = value["process_artifacts"]["relations"]
                assert relation["interpreter_prelaunch_pinned"] is False
                assert "launch_provenance" not in relation
        if role in LEGACY:
            option, expected = LEGACY[role]
            run("older-" + role, [*arguments(role), option, str(archive), digest], expected)
    assert {p.name: sha(p.read_bytes()) for p in journal.iterdir()} == before
    assert len(cases) == 32
    output = dict(
        schema="hol-gauntlet-native-launch-legacy-proof.v1",
        source_commit=SOURCE,
        verifier_sha256=VERIFIER,
        cases=cases,
        unchanged_legacy_readbacks=32,
        historical_prelaunch_credit_added=False,
        public_host_pin_records_unchanged=True,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )
    raw = json.dumps(output, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    path = directory / ("native-launch-legacy-proof-" + index + ".json")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(
        json.dumps(
            dict(
                proof_sha256=sha(raw),
                cases=len(cases),
                source_commit=SOURCE,
                execution_eligible=False,
                model_requests=0,
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    assert len(sys.argv) == 3
    verify(Path(sys.argv[1]), sys.argv[2])
