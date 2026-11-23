"""Fixed public-evidence courier; Rust owns Native frame and hook verification."""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from native_copied_hooks_arm_proof_20261028 import SOURCE
from native_copied_hooks_arm_proof_20261028 import verify as verify_arm

ARCHIVE = "24e4ab9b915d32c5d599553a1b38a460d8355e64109d5defb5a0bc07c35e9376"
CONTROL = "ea113422a647ff19a8e1c0895de05f879b06f899552b306fa7f5604767ae1e35"
FIXTURE = "ci/gauntlet-rs/crates/gauntlet-evidence/tests/fixtures/native_stdio_hook_vectors.v1.json"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def save(path, raw):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def source_blobs(evidence):
    working = (evidence / "native-hook-correlation-workspace-001.source.json").read_bytes()
    committed = (evidence / "native-hook-correlation-mac-reader-003.source.json").read_bytes()
    assert sha(working) == "57471354c0b49e79c6d469ddd105faee6407ae117d1b18ab0d971a3b81a9d9ca"
    assert sha(committed) == "fbbd694222149c39ec6e23891b921663835b1736564963f69119905a003e9b59"
    before, after = json.loads(working), json.loads(committed)
    assert before["files"] == after["files"] and after["head"] == SOURCE
    pins = after["files"]
    assert len(pins) == 691 and sum(path.endswith(".rs") for path in pins) == 677
    query = "".join(SOURCE + ":" + path + "\n" for path in pins).encode()
    repo = Path(__file__).resolve().parents[3]
    raw = subprocess.check_output(["git", "cat-file", "--batch"], cwd=repo, input=query, timeout=60)
    assert len(raw) <= 16 * 1024**2
    offset = 0
    fixture = None
    for path, pin in pins.items():
        assert path.startswith("ci/gauntlet-rs/") and ".." not in Path(path).parts
        end = raw.index(b"\n", offset)
        header = raw[offset:end].decode().split()
        assert len(header) == 3 and header[1] == "blob"
        count = int(header[2])
        data = raw[end + 1 : end + 1 + count]
        assert len(data) == count and sha(data) == pin
        offset = end + 1 + count
        assert raw[offset : offset + 1] == b"\n"
        offset += 1
        if path == FIXTURE:
            fixture = data
    assert offset == len(raw) and fixture is not None
    assert len(fixture) == 43259 and sha(fixture) == "ba19d19e0300b52d66f79dff5f972d08a5fe7630bb969ada95b5b10ab14f59cc"
    return json.loads(fixture)


def validation(evidence):
    pins = {
        "workspace-001": "ac9dc33f0113708f939ee0fd053d01e824136a496a20c67e7189f9a576d7ba29",
        "focused-002": "79c69c3848334a713b754598d8d7e90dc32e6006e1be1b2956f6f39e86c096a6",
        "mac-clippy-001": "501225c0d81a1d6df069a072884061f8543fe2b284dfdc4d40155df6d35642c5",
        "arm-clippy-001": "547c969241f7b490a34b84950a819cc069590e1465aa278b7814024c92ac8934",
    }
    for name, pin in pins.items():
        raw = (evidence / ("native-hook-correlation-" + name + ".log")).read_bytes()
        assert sha(raw) == pin
        result = json.loads((evidence / ("native-hook-correlation-" + name + ".result.json")).read_bytes())
        assert result["returncode"] == 0 and result["log_sha256"] == pin
        assert result["source_file_sha256"] == "57471354c0b49e79c6d469ddd105faee6407ae117d1b18ab0d971a3b81a9d9ca"
        if name.startswith(("workspace", "focused")):
            rows = re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", raw)
            counts = [sum(int(row[n]) for row in rows) for n in range(3)]
            assert counts == ([623, 0, 0] if name.startswith("workspace") else [8, 0, 0])
    legacy = (evidence / "native-hook-correlation-legacy-proof-001.json").read_bytes()
    assert sha(legacy) == "8ab9ebc64121f8058aede12e446cec2d640e9e6deda3063e9347f176ff32d2f4"
    prior = json.loads(legacy)
    assert prior["source_commit"] == SOURCE and prior["unchanged_legacy_readbacks"] == 32
    assert prior["public_host_pin_records_unchanged"] is True and prior["historical_prelaunch_credit_added"] is False
    for row in prior["cases"]:
        assert row["returncode"] == 0
        for kind in ["stdout", "stderr"]:
            raw = (evidence / ("native-hook-correlation-legacy-proof-001-" + row["case"] + "." + kind)).read_bytes()
            assert sha(raw) == row[kind + "_sha256"]
    failed = (evidence / "native-hook-correlation-focused-tests-001.log").read_bytes()
    assert sha(failed) == "62d662d262cfebcd8f57a9c0d374cccc99d8dc1cd172d506e0a5b254f0d24e93"
    assert b"5 passed; 2 failed; 0 ignored" in failed
    assert sha((evidence / "native-hook-correlation-mac-reader-001.log").read_bytes()) == (
        "82cab60fea304df6feeecc3c0aebd292064378d198fd6dffbab70fddb824e15a"
    )


def prove(evidence, run_index):
    assert len(run_index) == 3 and run_index.isdigit()
    vectors = source_blobs(evidence)
    validation(evidence)
    tools = json.loads((evidence / "native-hook-correlation-tools-001.json").read_bytes())
    assert tools["source_commit"] == SOURCE and tools["working_and_committed_mac_bytes_identical"] is True
    verifier = evidence / "native-hook-correlation-mac-reader-001"
    raw = verifier.read_bytes()
    assert len(raw) == 7105840 and sha(raw) == "02c5e12a0b4faa2694ec5a715e0039fadaf3d57dd25c0e3a9aad151778f81636"
    assert tools["files"]["mac-reader"]["sha256"] == sha(raw)
    archive = evidence / "native-stdio-control-vm-results-001-success.tar"
    assert archive.stat().st_size == 7004160 and sha(archive.read_bytes()) == ARCHIVE
    job = json.loads((evidence / "native-stdio-control-job-inputs-001.json").read_bytes())["jobs"]["success"]
    args = [
        str(verifier),
        str(evidence / "native-stdio-control-host-pins-001"),
        str(evidence / "native-stdio-control-completion-001-success-valid.json"),
        job["source_sha"],
        job["job_id"],
        job["deployment_sha256"],
        job["worker_generation"],
        job["preparation_sha256"],
        "success",
        "--control-artifacts",
        str(archive),
        ARCHIVE,
        "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960",
        "318f3f5b592bb863c6d902c4bd23285d9855a4619ddde0a3bbc5da303c325eb9",
    ]
    destination = evidence / ("native-hook-correlation-independent-readback-" + run_index)
    destination.mkdir(mode=0o700)
    calls = []

    def execute(label, argv, expected):
        result = subprocess.run(argv, capture_output=True, timeout=60)
        assert len(result.stdout) <= 16 * 1024**2 and len(result.stderr) <= 8192
        save(destination / (label + ".stdout"), result.stdout)
        save(destination / (label + ".stderr"), result.stderr)
        row = dict(
            case=label,
            returncode=result.returncode,
            expected_returncode=expected,
            stdout_sha256=sha(result.stdout),
            stderr_sha256=sha(result.stderr),
        )
        calls.append(row)
        assert result.returncode == expected, (row, result.stderr.decode())
        if expected == 0:
            assert not result.stderr
        else:
            assert not result.stdout and result.stderr
        return result.stdout

    output = execute("actual", args, 0)
    assert sha(output) == CONTROL and execute("restart", args, 0) == output
    for label, position in [("archive", 11), ("interpreter", 12), ("observer", 13)]:
        trial = list(args)
        trial[position] = "0" * 64
        execute("wrong-" + label, trial, 2)
    clients = json.loads(output)["control_artifacts"]["relations"]["native_clients"]
    snapshots = clients["native_stdio_snapshots"]
    relations = snapshots["copied_hook_relations"]
    assert (relations["request_frames"], relations["response_frames"], relations["copied_hook_pairs_checked"]) == (
        249,
        248,
        5,
    )
    assert (relations["outer_hooks_joined"], relations["contained_reauthorizations_checked"]) == (3, 2)
    assert len(relations["unanswered_requests"]) == 1
    assert relations["unanswered_requests"][0]["operation"] == "hook_direct_evidence_drain"
    assert relations["all_request_semantics_verified"] is relations["atomic_kernel_pipe_bytes_verified"] is False
    assert vectors["product_source"] == job["source_sha"] and vectors["producer_source"] == job["tool_source_commit"]
    assert vectors["public_archive_sha256"] == ARCHIVE and len(vectors["vectors"]) == 5
    streams = {row["stream"]: row for row in snapshots["streams"]}
    for vector in vectors["vectors"]:
        stream = streams[vector["stream"]]
        for direction, label in [("read", "request"), ("written", "response")]:
            frame = stream[direction]["frames"][vector["frame_index"]]
            assert frame["sha256"] == vector[label + "_frame_sha256"]
            assert frame["canonical_json_sha256"] == sha(canonical(vector[label]))
    arm = verify_arm(evidence, output)
    proof = dict(
        schema="hol-gauntlet-copied-native-hook-proof.v1",
        reader_source_commit=SOURCE,
        producer_source_commit=job["tool_source_commit"],
        product_source_commit=job["source_sha"],
        committed_files_verified=691,
        rust_files_verified=677,
        mac_tests=623,
        focused_mac_tests=8,
        unchanged_legacy_readbacks=32,
        cases=calls,
        arm_readback=arm,
        copied_hook_pairs=5,
        outer_hooks=3,
        contained_reauthorizations=2,
        unanswered_metadata_requests=1,
        fixture_frames_match_actual_rust_replay=True,
        passed=True,
        worker_files_preserved=333,
        all_request_semantics_verified=False,
        atomic_kernel_pipe_bytes_verified=False,
        outside_observer_admitted=False,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )
    encoded = canonical(proof) + b"\n"
    path = evidence / ("native-hook-correlation-proof-" + run_index + ".json")
    save(path, encoded)
    print(json.dumps(dict(proof=str(path), sha256=sha(encoded), passed=True, cases=len(calls))))


if __name__ == "__main__":
    prove(Path(sys.argv[1]), sys.argv[2])
