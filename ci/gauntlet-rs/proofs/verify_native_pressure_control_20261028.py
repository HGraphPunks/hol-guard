"""Inert public-evidence courier. Rust owns process-history replay/refusal."""

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

PRODUCER = "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
READER = "a04398800cc99e617e96766a508a7bdebbbefc2f"
ARCHIVE = "ad4c20c8a419d154a35d8fa5a5919e57a566adf8d2b4c7be2a7d86613c711c84"
WORKER = "3f4aae30a57f08908c28f209f212b6dafc132eaaf7f2d6c6b7c62a11675d249e"
IMAGE = "dc3b9336308dab4892bf0c0e0f328a9c8b7efc12"
JOURNAL = "combined/cell/native-process-events.v1.jsonl"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def save(path, raw):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prove(evidence):
    archive = (evidence / "native-pressure-control-vm-results-001-success.tar").read_bytes()
    assert len(archive) == 2908160 and sha(archive) == ARCHIVE
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        assert len(members) == 159
        files = {}
        for member in members:
            assert member.isfile() and member.name not in files
            assert member.uid == member.gid == member.mtime == 0 and member.mode == 0o600
            assert 0 <= member.size <= 16 * 1024**2
            files[member.name] = tar.extractfile(member).read(member.size + 1)
            assert len(files[member.name]) == member.size
    index = json.loads(files["results.sha256.json"])
    assert index["schema"] == "hol-gauntlet-native-host-keyed-export.v1"
    assert index["execution_eligible"] is False and index["model_requests"] == 0
    assert set(index["files"]) == set(index["filesystem"]) == set(files) - {"results.sha256.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
    report = json.loads(files["combined/worker/report.json"])
    assert report["job_id"] == "e2c701baf1475601"
    assert report["source_sha"] == IMAGE and report["worker_generation"] == WORKER
    assert report["status"] == "invalid-evidence"
    signed = report["controller_signature_verification"]
    assert signed["signature_verified"] is True and signed["reported_status"] == "passed"
    controller = report["controller_report"]
    assert controller["status"] == "passed" and controller["execution_eligible"] is False
    plane = controller["plane"]
    assert plane["schema"] == "hol-gauntlet-native-hook-plane.v2"
    assert plane["cleanup_complete"] is True and plane["process_events"]["available"] is True
    checkpoint = plane["process_events"]["checkpoint"]
    for field, value in index["filesystem"][JOURNAL].items():
        assert checkpoint["journal"][field] == value
    assert checkpoint["created_tasks"] == checkpoint["final_waits"] == 393
    assert checkpoint["exec_retirements"] == 0 and checkpoint["execs"] == 127
    assert checkpoint["journal"]["events"] == 1997
    events = [json.loads(line) for line in files["combined/cell/native-supervisor-events.v1.jsonl"].splitlines()]
    closed = [row for row in events if row["kind"] == "process-events-closed"]
    assert len(closed) == 1 and closed[0]["data"] == plane["process_events"]
    outside = json.loads(files["proof/outside-summary.json"])
    assert outside["prior_worker_files_preserved"] == 312 and outside["final_worker_files"] == 319
    assert outside["kernel_errors"] == ["AssertionError: "] and outside["kernel_observations"] == 57
    assert outside["root_errors"] == [] and outside["host_null_identity_unchanged"] is True
    baseline = files["proof/final-worker-hashes.json"]
    assert sha(baseline) == "e4776ada639da46a179784d39df8fccda522c27e9e6166639e2ddabd8bb191a0"
    kernel = json.loads(files["proof/outside-kernel.json"])
    assert kernel["schema"] == "hol-gauntlet-outside-native-mcp-kernel.v2"
    assert kernel["errors"] == ["AssertionError: "] and len(kernel["observations"]) == 57
    assert kernel["collection_limits"] == dict(observations=2048, argv_bytes=32768, executable_bytes=134217728)
    assert controller["error"] is None
    result = controller["requests"][1]["response"]["result"]
    assert result["exit_code"] == 0 and "Ran 1 test in " in result["stderr"] and result["stderr"].endswith("OK\n")
    post = controller["requests"][2]["response"]
    assert post["product_response"]["reviewed_output_sha256"] == post["contained_output"]["output_sha256"]
    assert post["product_response"]["model_output_action"] == "allow_original"
    pressure = json.loads(files["proof/outside-task-pressure.json"])
    assert pressure["errors"] == [] and len(pressure["samples"]) == 200
    assert max(int(s["counts"]["pids.peak"]) for s in pressure["samples"]) == 108
    assert {s["counts"]["pids.events"] for s in pressure["samples"]} == {"max 0"}
    node = json.loads(files["combined/workspace/node-runtime-control.json"])
    assert node == dict(
        node_version="v22.22.2",
        npm_version="10.9.7",
        node_sha256="3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90",
        node_is_symlink=False,
    )
    units = json.loads(files["unit/summary.json"])
    assert units["source_commit"] == PRODUCER and units["passed"] is True and units["unit_tests_passed"] == 41
    manifest = json.loads((evidence / "native-trace-reader-artifacts-001.json").read_bytes())
    assert manifest["source_commit"] == READER
    pin = manifest["files"]["mac-verifier"]
    verifier = Path(pin["path"])
    assert verifier.parent == evidence
    raw = verifier.read_bytes()
    assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]
    directory = evidence / "native-pressure-control-trace-readback-inputs-001"
    directory.mkdir(mode=0o700)
    calls = []

    def run(label, raw, checkpoint, accepted, journal_pin=None):
        stem = directory / f"case-{len(calls):03d}"
        journal, checkpoint_file = stem.with_suffix(".jsonl"), stem.with_suffix(".json")
        checkpoint_raw = canonical(checkpoint)
        save(journal, raw)
        save(checkpoint_file, checkpoint_raw)
        result = subprocess.run(
            [str(verifier), str(journal), journal_pin or sha(raw), str(checkpoint_file), sha(checkpoint_raw)],
            capture_output=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin"},
        )
        save(stem.with_suffix(".stdout"), result.stdout)
        save(stem.with_suffix(".stderr"), result.stderr)
        row = dict(
            case=label,
            accepted=accepted,
            returncode=result.returncode,
            journal_sha256=sha(raw),
            checkpoint_sha256=sha(checkpoint_raw),
            stdout_sha256=sha(result.stdout),
            stderr_sha256=sha(result.stderr),
        )
        calls.append(row)
        assert result.returncode == (0 if accepted else 2), row
        if not accepted:
            assert not result.stdout and b"Native process events unavailable:" in result.stderr
            return None
        assert not result.stderr
        output = json.loads(result.stdout)
        assert output["complete_task_relation_verified"] is True
        assert output["created_tasks"] == output["final_waits"] == 393
        assert output["execs"] == 127 and output["exec_retirements"] == 0
        assert output["journal_events"] == 1997 and output["journal_sha256"] == sha(raw)
        for field in [
            "process_custody_authenticated",
            "all_native_descendants_verified",
            "execution_eligible",
            "guard_causality_verified",
        ]:
            assert output[field] is False
        assert output["model_requests"] == 0
        return result.stdout

    journal = files[JOURNAL]
    first = run("actual-passed-control-unavailable-sampler", journal, checkpoint, True)
    assert run("unchanged-restart", journal, checkpoint, True) == first
    run("wrong-outside-journal-pin", journal, checkpoint, False, "0" * 64)
    run("truncated-journal", journal[:-1], checkpoint, False)
    changed = copy.deepcopy(checkpoint)
    changed["final_waits"] -= 1
    run("false-final-wait-count", journal, changed, False)
    proof = dict(
        schema="hol-gauntlet-native-pressure-control-trace-readback.v1",
        producer_source=PRODUCER,
        reader_source=READER,
        product_image_source=IMAGE,
        archive_sha256=ARCHIVE,
        archive_members=159,
        archive_index_verified=True,
        retained_control_status="passed",
        retained_worker_status="invalid-evidence",
        process_checkpoint_metadata_matches_export=True,
        cases=calls,
        passed=True,
        worker_files_preserved=319,
        old_worker_files_preserved=312,
        execution_eligible=False,
        guard_causality_verified=False,
        outside_observer_admitted=False,
        outside_sampler_complete=False,
        task_peak=108,
        pid_limit_rejections=0,
        model_requests=0,
    )
    output = canonical(proof) + b"\n"
    destination = evidence / "native-pressure-control-trace-readback-proof-001.json"
    save(destination, output)
    print(json.dumps(dict(proof=str(destination), sha256=sha(output), cases=len(calls), passed=True)))


if __name__ == "__main__":
    prove(Path(sys.argv[1]))
