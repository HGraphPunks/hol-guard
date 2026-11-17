"""Verify the fixed public ARM replay of the actual launch-v4 Native control."""

import hashlib
import io
import json
import tarfile
from pathlib import PurePosixPath


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(evidence, live_files, mac_output):
    raw = (evidence / "native-stdio-live-readback-vm-results-001.tar").read_bytes()
    assert len(raw) == 8089600 and sha(raw) == "9702468e978356a5acef1fa3e4d89e7ed44fe33408cd5e0fa323aadb4e20da9b"
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as stream:
        members = stream.getmembers()
        assert len(members) == 39
        for member in members:
            path = PurePosixPath(member.name)
            assert member.isfile() and member.name not in files and not path.is_absolute() and ".." not in path.parts
            assert (
                member.uid == member.gid == member.mtime == 0
                and member.mode == 0o600
                and 0 <= member.size <= 8 * 1024 * 1024
            )
            data = stream.extractfile(member).read(member.size + 1)
            assert len(data) == member.size
            files[member.name] = data
    index = json.loads(files["results.sha256.json"])
    assert set(index["files"]) == set(files) - {"results.sha256.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
    for name, metadata in index["filesystem"].items():
        assert (
            name in files
            and metadata["uid"] == metadata["gid"] == 0
            and metadata["links"] == 1
            and metadata["mode"] == 0o600
        )
    assert files["input/control.tar"] == (evidence / "native-stdio-control-vm-results-001-success.tar").read_bytes()
    assert (
        files["input/completion.json"]
        == (evidence / "native-stdio-control-completion-001-success-valid.json").read_bytes()
    )
    assert (
        files["input/host-pin.json"]
        == (evidence / "native-stdio-control-host-pins-001/e2c701baf1475701.controller-key-pin.json").read_bytes()
    )
    assert sha(files["input/host-pin.json"]) == "06197f1a24dffb1f45e8ee166340d1d1af43bb8f40d06ff44c6a7ea74f3c9dc6"
    assert files["input/expected-control.json"] == mac_output
    transfer = json.loads(files["input/transfer.json"])
    installation = json.loads(files["proof/installation.json"])
    assert transfer["files"] == installation["files"]
    for name, pin in transfer["files"].items():
        assert pin == dict(bytes=len(files["input/" + name]), sha256=sha(files["input/" + name]))
    tool = json.loads(files["tools.json"])["control_reader"]
    assert tool == dict(
        bytes=8770376,
        sha256="ffacdf72c0794ec938021ce69286b9aa5a3a7989000c35f448ba670ee88ce8a3",
        uid=0,
        gid=0,
        mode=0o500,
        links=1,
    )
    summary = json.loads(files["proof/summary.json"])
    assert summary["passed_cases"] == 9 and summary["mac_control_output_identical"] is True
    assert (summary["native_streams"], summary["native_frames"], summary["native_bytes"]) == (12, 497, 382274)
    assert (
        summary["control_stdout_sha256"]
        == sha(mac_output)
        == "97fbecbaec0ad7772b1c49e129366b384be069b23f0294611931318a5e277d94"
    )
    rows = {row["case"]: row for row in summary["cases"]}
    assert len(rows) == len(summary["cases"]) == 9
    mac = json.loads((evidence / "native-stdio-control-artifacts-proof-001.json").read_bytes())
    assert len(mac["cases"]) == 9 and mac["source_commit"] == "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
    assert mac["verifier_sha256"] == "4e4de9d24934efc04a706c0a761ad808bbe6ecd66e64e709c84cd42e3fda0ddf"
    host_tools = json.loads((evidence / "native-stdio-control-host-executables-001.json").read_bytes())
    job_inputs = json.loads((evidence / "native-stdio-control-job-inputs-001.json").read_bytes())
    assert host_tools["source_commit"] == job_inputs["tool_source_commit"] == "77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9"
    for expected in mac["cases"]:
        name = expected["case"]
        row = rows[name]
        assert (
            row["returncode"] == row["expected_returncode"] == expected["returncode"] == expected["expected_returncode"]
        )
        assert json.loads(files["proof/" + name + ".json"]) == row
        for kind in ["stdout", "stderr"]:
            data = files["proof/" + name + "." + kind]
            assert sha(data) == row[kind + "_sha256"] == expected[kind + "_sha256"]
    assert files["proof/control.stdout"] == files["proof/control-restart.stdout"] == mac_output
    assert files["proof/final-worker-hashes.json"] == live_files["proof/final-worker-hashes.json"]
    assert (
        sha(files["proof/final-worker-hashes.json"])
        == "f7e44a5879bfbd8bd19097fc5b81927dfe93103b8db330813266bf25ad327a9d"
    )
    final = json.loads(files["final.json"])
    for value in [transfer, installation, summary, final]:
        assert value["reader_source_commit"] == "bd262dcad72278b58ae1059866a217acf366c90b"
        assert value["tool_source_commit"] == "77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9"
        assert value["product_source_commit"] == "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
        assert value["public_host_pin_fixture"] is True
        assert (
            value["execution_eligible"] is value["guard_causality_verified"] is False and value["model_requests"] == 0
        )
    assert summary["both_worker_leases_held"] is final["both_worker_leases_held"] is True
    assert summary["worker_files_preserved"] == final["worker_files_preserved"] == 333
    assert summary["fresh_product_execution"] is final["fresh_product_execution"] is False
    return dict(
        public_members=39,
        passed_cases=9,
        mac_control_output_identical=True,
        native_streams=12,
        native_frames=497,
        native_bytes=382274,
        worker_files_preserved=333,
        public_host_pin_fixture=True,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )
