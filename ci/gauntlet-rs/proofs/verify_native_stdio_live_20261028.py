"""Inert public-evidence courier. Rust owns process-history replay/refusal."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

from native_stdio_live_arm_proof_20261028 import verify as verify_arm

PRODUCER = "77e7b7e7f9e4c5fada74ae2ff2e2a612214f90b9"
READER = "bd262dcad72278b58ae1059866a217acf366c90b"
ARCHIVE = "24e4ab9b915d32c5d599553a1b38a460d8355e64109d5defb5a0bc07c35e9376"
WORKER = "6d2b067e9ac3c7ec6236d3e445e59e5789305b7ea748b67166e0f4a048c29446"
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


def prove(evidence, run_index):
    assert len(run_index) == 3 and run_index.isdigit()
    archive = (evidence / "native-stdio-control-vm-results-001-success.tar").read_bytes()
    assert len(archive) == 7004160 and sha(archive) == ARCHIVE
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        members = tar.getmembers()
        assert len(members) == 147
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
    assert report["job_id"] == "e2c701baf1475701"
    assert report["source_sha"] == IMAGE and report["worker_generation"] == WORKER
    assert report["status"] == "invalid-evidence"
    signed = report["controller_signature_verification"]
    assert signed["signature_verified"] is True and signed["reported_status"] == "passed"
    controller = report["controller_report"]
    assert controller["status"] == "passed" and controller["execution_eligible"] is False
    plane = controller["plane"]
    assert plane["schema"] == "hol-gauntlet-native-hook-plane.v3"
    assert plane["cleanup_complete"] is True and plane["process_events"]["available"] is True
    checkpoint = plane["process_events"]["checkpoint"]
    for field, value in index["filesystem"][JOURNAL].items():
        assert checkpoint["journal"][field] == value
    assert checkpoint["created_tasks"] == checkpoint["final_waits"] == 460
    assert checkpoint["exec_retirements"] == 0 and checkpoint["execs"] == 154
    assert checkpoint["journal"]["events"] == 2268
    events = [json.loads(line) for line in files["combined/cell/native-supervisor-events.v1.jsonl"].splitlines()]
    closed = [row for row in events if row["kind"] == "process-events-closed"]
    assert len(closed) == 1 and closed[0]["data"] == plane["process_events"]
    outside = json.loads(files["proof/outside-summary.json"])
    assert outside["prior_worker_files_preserved"] == 326 and outside["final_worker_files"] == 333
    assert outside["kernel_errors"] == [] and outside["kernel_observations"] == 127
    assert outside["root_errors"] == [] and outside["host_null_identity_unchanged"] is True
    baseline = files["proof/final-worker-hashes.json"]
    assert sha(baseline) == "f7e44a5879bfbd8bd19097fc5b81927dfe93103b8db330813266bf25ad327a9d"
    kernel = json.loads(files["proof/outside-kernel.json"])
    assert kernel["schema"] == "hol-gauntlet-outside-native-mcp-kernel.v2"
    assert kernel["errors"] == [] and len(kernel["observations"]) == 127
    assert kernel["collection_limits"] == dict(observations=2048, argv_bytes=32768, executable_bytes=134217728)
    assert controller["error"] is None
    launch = json.loads(files["combined/preparation.v1.json"])["launch"]
    assert launch["wall_seconds"] == 180 and launch["cpu_profile"] == "single-core-v1"
    assert launch["native_runtime_sha256"] == controller["guard_pins"]["native_sha256"]
    result = controller["requests"][1]["response"]["result"]
    assert result["exit_code"] == 0 and "Ran 1 test in " in result["stderr"] and result["stderr"].endswith("OK\n")
    post = controller["requests"][2]["response"]
    assert post["product_response"]["reviewed_output_sha256"] == post["contained_output"]["output_sha256"]
    assert post["product_response"]["model_output_action"] == "allow_original"
    pressure = json.loads(files["proof/outside-task-pressure.json"])
    assert pressure["errors"] == [] and len(pressure["samples"]) == 772
    assert max(int(s["counts"]["pids.peak"]) for s in pressure["samples"]) == 112
    assert {s["counts"]["pids.events"] for s in pressure["samples"]} == {"max 0"}
    node = json.loads(files["combined/workspace/node-runtime-control.json"])
    assert node == dict(
        node_version="v22.22.2",
        npm_version="10.9.7",
        node_sha256="3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90",
        node_is_symlink=False,
    )
    assert json.loads(files["combined/preparation.v1.json"])["launch"]["schema"] == "hol-gauntlet-cell-supervisor.v4"
    io_checkpoint = checkpoint["native_stdio"]
    assert checkpoint["schema"] == "hol-gauntlet-native-process-events.v2"
    assert io_checkpoint["counts"] == dict(streams=12, closed_streams=12, calls=529, syscall_stops=111945, bytes=382274)
    for field, value in index["filesystem"]["combined/cell/native-stdio-events.v1.jsonl"].items():
        assert io_checkpoint["journal"][field] == value
    assert io_checkpoint["declaration"]["atomic_kernel_pipe_bytes_verified"] is False
    assert (
        sha(files["proof/prior-worker-hashes.json"])
        == "16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be"
    )
    prior = json.loads(files["proof/prior-worker-hashes.json"])
    final = json.loads(baseline)
    assert len(prior) == 326 and len(final) == 333 and all(final[name] == pin for name, pin in prior.items())
    assert set(final) - set(prior) == {
        report["job_id"] + "." + suffix
        for suffix in [
            "started.json",
            "running.json",
            "terminal.json",
            "report.json",
            "controller-key.json",
            "native.stdout",
            "native.stderr",
        ]
    }
    directory = evidence / ("native-stdio-control-independent-readback-" + run_index)
    directory.mkdir(mode=0o700)
    calls = []
    host = evidence / "native-stdio-control-verifier-001"
    host_raw = host.read_bytes()
    assert (
        len(host_raw) == 6971424 and sha(host_raw) == "4e4de9d24934efc04a706c0a761ad808bbe6ecd66e64e709c84cd42e3fda0ddf"
    )
    pins = json.loads((evidence / "native-stdio-control-job-inputs-001.json").read_bytes())["jobs"]["success"]
    argv = [
        str(host),
        str(evidence / "native-stdio-control-host-pins-001"),
        str(evidence / "native-stdio-control-completion-001-success-valid.json"),
        IMAGE,
        pins["job_id"],
        pins["deployment_sha256"],
        WORKER,
        pins["preparation_sha256"],
        "success",
        "--control-artifacts",
        str(evidence / "native-stdio-control-vm-results-001-success.tar"),
        ARCHIVE,
        "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960",
        "318f3f5b592bb863c6d902c4bd23285d9855a4619ddde0a3bbc5da303c325eb9",
    ]

    def execute(label, args, expected):
        actual = subprocess.run(args, capture_output=True, timeout=60)
        save(directory / (label + ".stdout"), actual.stdout)
        save(directory / (label + ".stderr"), actual.stderr)
        row = dict(
            case=label,
            returncode=actual.returncode,
            expected_returncode=expected,
            stdout_sha256=sha(actual.stdout),
            stderr_sha256=sha(actual.stderr),
        )
        calls.append(row)
        assert actual.returncode == expected, (row, actual.stderr.decode())
        if expected == 0:
            assert not actual.stderr
        else:
            assert not actual.stdout and actual.stderr
        return actual

    actual = execute("actual", argv, 0)
    assert actual.stdout == (evidence / "native-stdio-control-artifacts-001-control.stdout").read_bytes()
    assert sha(actual.stdout) == "97fbecbaec0ad7772b1c49e129366b384be069b23f0294611931318a5e277d94"
    assert execute("restart", argv, 0).stdout == actual.stdout
    for label, position in [("archive", 11), ("interpreter", 12), ("observer", 13)]:
        trial = list(argv)
        trial[position] = "0" * 64
        execute("wrong-" + label, trial, 2)
    relations = json.loads(actual.stdout)["control_artifacts"]["relations"]
    assert relations["product_launches"]["prefix_python_launches_checked"] == 15
    assert relations["native_clients"]["installed_runtime_clients_checked"] == 8
    assert relations["native_clients"]["missing_internal_client_observations"] == []
    assert relations["hooks"]["hook_input_deliveries_checked"] == 3
    assert relations["hooks"]["process_relations"]["raw_sdk_requests_checked"] == 3
    assert relations["capture_streams"]["captures_checked"] == 14
    assert relations["qualified_role_complete"] is relations["guard_causality_verified"] is False

    snapshots = relations["native_clients"]["native_stdio_snapshots"]
    assert snapshots["counts"] == io_checkpoint["counts"] and snapshots["complete_frames"] == 497
    assert snapshots["request_semantics_verified"] is snapshots["atomic_kernel_pipe_bytes_verified"] is False
    assert len(snapshots["streams"]) == 12
    assert all(row["read"]["status"] == row["written"]["status"] == "complete" for row in snapshots["streams"])
    arm = verify_arm(evidence, files, actual.stdout)
    proof = dict(
        schema="hol-gauntlet-native-stdio-live-control-proof.v1",
        producer_source=PRODUCER,
        reader_source=READER,
        product_image_source=IMAGE,
        archive_sha256=ARCHIVE,
        archive_members=147,
        archive_index_verified=True,
        retained_control_status="passed",
        retained_worker_status="invalid-evidence",
        process_checkpoint_metadata_matches_export=True,
        cases=calls,
        passed=True,
        worker_files_preserved=333,
        old_worker_files_preserved=326,
        native_streams=12,
        native_frames=497,
        native_bytes=382274,
        arm_readback=arm,
        execution_eligible=False,
        guard_causality_verified=False,
        outside_observer_admitted=False,
        outside_sampler_complete=True,
        task_peak=112,
        pid_limit_rejections=0,
        model_requests=0,
    )
    output = canonical(proof) + b"\n"
    destination = evidence / ("native-stdio-control-live-proof-" + run_index + ".json")
    save(destination, output)
    print(json.dumps(dict(proof=str(destination), sha256=sha(output), cases=len(calls), passed=True)))


if __name__ == "__main__":
    prove(Path(sys.argv[1]), sys.argv[2])
