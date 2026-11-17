"""Read back the fixed owned-VM Rust reader execution; no runtime authority."""

import hashlib
import io
import json
import os
import re
import sys
import tarfile
from pathlib import Path

from verify_native_process_events_20261027 import VM_SOURCE, archive

ARCHIVE_SHA256 = "1f8ccafb3259fa9d0f5ea213791862dc1bd49c654844b144c988d3ca6a9df0b5"
READER_SOURCE = "a04398800cc99e617e96766a508a7bdebbbefc2f"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(evidence):
    raw = (evidence / "native-trace-reader-vm-results-001.tar").read_bytes()
    assert len(raw) == 153600 and sha(raw) == ARCHIVE_SHA256
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        members = tar.getmembers()
        assert len(members) == 96
        files = {}
        for member in members:
            assert member.isfile() and member.name not in files
            assert member.mode == 0o600 and member.uid == member.gid == member.mtime == 0
            assert 0 <= member.size <= 1024**2
            data = tar.extractfile(member).read(member.size + 1)
            assert len(data) == member.size
            files[member.name] = data
    index = json.loads(files["results.sha256.json"])
    assert index["schema"] == "hol-gauntlet-process-reader-export.v1"
    assert set(index["files"]) == set(files) - {"results.sha256.json"}
    assert index["execution_eligible"] is False and index["model_requests"] == 0
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
        metadata = index["filesystem"][name]
        assert metadata["uid"] == metadata["gid"] == 0
        assert metadata["mode"] == 0o600 and metadata["links"] == 1
    summary = json.loads(files["proof/summary.json"])
    assert summary["reader_source_commit"] == READER_SOURCE
    assert summary["fixture_source_commit"] == VM_SOURCE
    assert summary["unit_returncode"] == 0 and summary["unit_tests_passed"] == 6
    assert summary["unit_log_sha256"] == sha(files["proof/units.log"])
    assert re.findall(
        rb"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", files["proof/units.log"]
    ) == [(b"ok", b"6", b"0", b"0")]
    for key in [
        "all_input_files_unchanged",
        "all_original_root_journals_unchanged",
        "both_worker_leases_held",
        "passed",
    ]:
        assert summary[key] is True
    assert summary["worker_files_preserved"] == 298
    assert summary["execution_eligible"] is False and summary["guard_causality_verified"] is False
    assert summary["model_requests"] == 0
    transfer = json.loads(files["proof/transfer.json"])
    assert transfer["source_commit"] == READER_SOURCE
    manifest = json.loads((evidence / "native-trace-reader-artifacts-001.json").read_bytes())
    assert manifest["source_commit"] == READER_SOURCE
    for guest, host in [("verifier", "arm-verifier"), ("evidence-tests", "evidence-tests")]:
        pin = manifest["files"][host]
        data = Path(pin["path"]).read_bytes()
        assert len(data) == pin["bytes"] and sha(data) == pin["sha256"]
        assert transfer["files"][guest] == dict(bytes=len(data), sha256=sha(data))
    receipt = json.loads(files["proof/installation.json"])
    assert receipt["files"] == transfer["files"]
    assert receipt["input_archive_sha256"] == "2e2c6504f70911b212fda4b645ca0291b4644e75cc91f992897f878bead49140"
    plan = json.loads(files["proof/cases.json"])
    host_proof = (evidence / "native-trace-readback-proof-001.json").read_bytes()
    assert plan["host_proof_sha256"] == sha(host_proof)
    host_proof = json.loads(host_proof)
    assert plan["bindings"] == host_proof["bindings"]
    assert len(plan["cases"]) == len(summary["cases"]) == len(host_proof["cases"]) == 30
    original_count = 0
    for planned, actual, host in zip(plan["cases"], summary["cases"], host_proof["cases"], strict=True):
        assert planned["case"] == actual["case"] == host["case"]
        assert actual["passed"] is True
        stem = actual["stem"]
        assert re.fullmatch(r"case-[0-9]{3}", stem)
        assert actual == json.loads(files["proof/" + stem + ".json"])
        for stream in ["stdout", "stderr"]:
            assert actual[stream + "_sha256"] == host[stream + "_sha256"] == sha(files["proof/" + stem + "." + stream])
        assert actual["returncode"] == host["returncode"]
        assert actual["original_root_journal"] is host["accepted"]
        original_count += actual["original_root_journal"]
    assert original_count == 8
    fixtures, _ = archive(evidence, "002")
    for binding in plan["bindings"].values():
        assert sha(fixtures[binding["journal_member"]]) == binding["journal_sha256"]
        assert sha(fixtures[binding["checkpoint_member"]]) == binding["checkpoint_sha256"]
    report = dict(
        schema="hol-gauntlet-process-reader-arm-readback.v1",
        reader_source_commit=READER_SOURCE,
        fixture_source_commit=VM_SOURCE,
        archive_sha256=ARCHIVE_SHA256,
        members=96,
        unit_tests_passed=6,
        cli_cases_passed=30,
        original_root_journal_readbacks=8,
        mac_matching_cases=30,
        refusal_cases=22,
        worker_records_preserved=298,
        process_custody_authenticated=False,
        all_native_descendants_verified=False,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )
    with (evidence / "native-trace-reader-arm-readback-001.json").open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(json.dumps(report, sort_keys=True, separators=(",", ":")).encode())
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
