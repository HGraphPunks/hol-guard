"""Inert reconciliation of the fixed public ARM copied-hook readback."""

import hashlib
import io
import json
import re
import tarfile
from pathlib import PurePosixPath

SOURCE = "3ea621aa7e2cc2985ce5e31fe6ae9017a2aefdb0"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(evidence, mac_output):
    raw = (evidence / "native-hook-correlation-vm-results-001.tar").read_bytes()
    assert len(raw) == 8110080 and sha(raw) == "a7c4cbc4a7edbf58b560cdc89cd3e23954275d1075b333df44b518b973958fde"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        members = stream.getmembers()
        assert len(members) == 42
        for member in members:
            path = PurePosixPath(member.name)
            assert member.isfile() and member.name not in files and not path.is_absolute() and ".." not in path.parts
            assert member.uid == member.gid == member.mtime == 0 and member.mode == 0o600
            assert 0 <= member.size <= 8 * 1024**2
            data = stream.extractfile(member).read(member.size + 1)
            assert len(data) == member.size
            files[member.name] = data
    index = json.loads(files["results.sha256.json"])
    assert index["schema"] == "hol-gauntlet-copied-native-hook-arm-public-export.v1"
    assert set(index["files"]) == set(files) - {"results.sha256.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
    expected_metadata = {name for name in files if name.startswith(("input/", "proof/"))}
    assert len(expected_metadata) == 39 and set(index["filesystem"]) == expected_metadata
    for metadata in index["filesystem"].values():
        assert metadata["uid"] == metadata["gid"] == 0 and metadata["links"] == 1 and metadata["mode"] == 0o600
        assert metadata["device"] > 0 and metadata["inode"] > 0
    assert files["input/control.tar"] == (evidence / "native-stdio-control-vm-results-001-success.tar").read_bytes()
    assert files["input/expected-control.json"] == mac_output
    assert (
        files["input/host-pin.json"]
        == (evidence / "native-stdio-control-host-pins-001/e2c701baf1475701.controller-key-pin.json").read_bytes()
    )
    assert sha(files["input/host-pin.json"]) == "06197f1a24dffb1f45e8ee166340d1d1af43bb8f40d06ff44c6a7ea74f3c9dc6"
    assert (
        files["input/completion.json"]
        == (evidence / "native-stdio-control-completion-001-success-valid.json").read_bytes()
    )
    transfer = json.loads(files["input/transfer.json"])
    installation = json.loads(files["proof/installation.json"])
    assert installation["files"] == transfer["files"]
    for name in ["completion.json", "host-pin.json", "job.json", "expected-control.json"]:
        assert transfer["files"][name] == dict(bytes=len(files["input/" + name]), sha256=sha(files["input/" + name]))
    tools = json.loads(files["tools.json"])
    expected_tools = {
        "control-reader": (8918472, "12ed96ac6544a98f95de409032f931ffd74efd465c22ecba0d8390cf392335ff"),
        "evidence-tests": (23385616, "512c7060c1582986f21d0c17fc41f5a70ac3673f14a6817dc114c0275db31599"),
    }
    assert set(tools) == set(expected_tools)
    for name, (count, pin) in expected_tools.items():
        assert tools[name] == dict(bytes=count, sha256=pin, uid=0, gid=0, mode=0o500, links=1)
        assert transfer["files"][name] == dict(bytes=count, sha256=pin)
    summary = json.loads(files["proof/summary.json"])
    assert summary["passed_cases"] == 10 and summary["focused_tests"] == 14 and summary["artifact_cases"] == 9
    assert summary["mac_control_output_identical"] is True
    assert summary["control_stdout_sha256"] == sha(mac_output)
    assert (summary["copied_hook_pairs"], summary["outer_hooks"], summary["contained_reauthorizations"]) == (5, 3, 2)
    assert summary["unanswered_metadata_requests"] == 1
    rows = {row["case"]: row for row in summary["cases"]}
    assert len(rows) == len(summary["cases"]) == 10
    for name, row in rows.items():
        assert json.loads(files["proof/" + name + ".json"]) == row
        assert row["returncode"] == row["expected_returncode"]
        for kind in ["stdout", "stderr"]:
            assert sha(files["proof/" + name + "." + kind]) == row[kind + "_sha256"]
    assert re.findall(
        rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", files["proof/focused-tests.stdout"]
    ) == [(b"14", b"0", b"0")]
    mac = json.loads((evidence / "native-hook-correlation-artifacts-working-proof-001.json").read_bytes())
    assert len(mac["cases"]) == 9 and mac["passed"] is True
    assert mac["verifier_sha256"] == "02c5e12a0b4faa2694ec5a715e0039fadaf3d57dd25c0e3a9aad151778f81636"
    for expected in mac["cases"]:
        row = rows[expected["case"]]
        for key in ["returncode", "expected_returncode", "stdout_sha256", "stderr_sha256"]:
            assert row[key] == expected[key]
    assert files["proof/control.stdout"] == files["proof/control-restart.stdout"] == mac_output
    baseline = files["proof/final-worker-hashes.json"]
    assert len(json.loads(baseline)) == 333
    assert sha(baseline) == "f7e44a5879bfbd8bd19097fc5b81927dfe93103b8db330813266bf25ad327a9d"
    final = json.loads(files["final.json"])
    for value in [transfer, installation, summary, final]:
        assert value["reader_source_commit"] == SOURCE
        assert value["tool_source_commit"] == "77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9"
        assert value["product_source_commit"] == "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
        assert value["public_host_pin_fixture"] is True
        assert value["execution_eligible"] is value["guard_causality_verified"] is False
        assert value["model_requests"] == 0
    for value in [summary, final]:
        assert value["both_worker_leases_held"] is True and value["worker_files_preserved"] == 333
        assert value["fresh_product_execution"] is False
    return dict(
        public_members=42, focused_tests=14, artifact_cases=9, mac_output_identical=True, worker_files_preserved=333
    )
