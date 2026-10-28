"""Courier for current Rust launch-v2 readback; preserve the earlier failed run."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

SOURCE = "c3c8fa5d3cadc3121967895ca97cb5aadd70283b"
PRODUCT = "9f42d9dd3574ede89d8912a85813f9d817a9de46"
VERIFIER = "6bd81d83d456edecb00953792161557ec96b40484dfae3d31b2c4fa4e1f79daa"
ARCHIVE = "69b8b88dda38161235d97d2b463cce763eb4202cb6711da5bd149280a04d032f"
FAILED = "4522753e3a697a66e4847d2ca06d6e5413143292f4efa2903001ef493e08a8f9"
EXPECTED = {
    "envelope": "6f696689b42b13f2fd15058df5b0487953c4cba18fea53bc9b265f4af17f1f55",
    "mcp": "309a71f417a6c0c42f49b6e57a1bf69461eb12c1142a43bce6737820cac664de",
    "process": "ae4a6ea6056e437987aa7c9f6e2589a1aab4f139a3d45fec82b59a34314b6232",
    "hook": "87ed85f5fe9c81a5e9ddd65ba82ea0db982c7109f7a2abdd88a4c5d739d7a303",
    "control": "519c90497307e99862de6b34a90da85f362fec6a1bb27d935a085ee4b59c48ea",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(directory, index):
    assert index.isdigit() and len(index) == 3
    exe = directory / "native-launch-verifier-001"
    assert sha(exe.read_bytes()) == VERIFIER
    jobs = {
        n: json.loads((directory / ("native-launch-job-inputs-" + n + ".json")).read_bytes())["jobs"]["success"]
        for n in ["001", "002"]
    }
    observer = json.loads((directory / "native-launch-observer-002.json").read_bytes())
    assert sha((directory / "native-launch-observer-002.py").read_bytes()) == observer["observer_sha256"]
    for p in jobs.values():
        assert p["source_commit"] == SOURCE and p["source_sha"] == PRODUCT
    archives = {}
    for n, pin in [("001", FAILED), ("002", ARCHIVE)]:
        path = directory / ("native-launch-vm-results-" + n + "-success.tar")
        assert sha(path.read_bytes()) == pin
        archives[n] = path
    before = {
        n: {p.name: sha(p.read_bytes()) for p in (directory / ("native-launch-host-pins-" + n)).iterdir()} for n in jobs
    }
    stem = "native-launch-live-proof-" + index

    def save(name, raw):
        with (directory / (stem + "-" + name)).open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    cases = []

    def arguments(n):
        p = jobs[n]
        return [
            str(exe),
            str(directory / ("native-launch-host-pins-" + n)),
            str(directory / ("native-launch-completion-" + n + "-success-valid.json")),
            p["source_sha"],
            p["job_id"],
            p["deployment_sha256"],
            p["worker_generation"],
            p["preparation_sha256"],
            "success",
        ]

    def artifacts(path, digest):
        return [
            *arguments("002"),
            "--control-artifacts",
            str(path),
            digest,
            observer["interpreter_sha256"],
            observer["observer_sha256"],
        ]

    def run(name, args, code):
        result = subprocess.run(args, capture_output=True, timeout=60)
        save(name + ".stdout", result.stdout)
        save(name + ".stderr", result.stderr)
        row = dict(
            case=name, returncode=result.returncode, stdout_sha256=sha(result.stdout), stderr_sha256=sha(result.stderr)
        )
        cases.append(row)
        assert result.returncode == code, (row, result.stdout.decode(), result.stderr.decode())
        if code == 2:
            assert not result.stdout and result.stderr
        else:
            assert not result.stderr
            value = json.loads(result.stdout)
            assert value["execution_eligible"] is value["guard_causality_verified"] is False
            assert value["model_requests"] == 0
        return result.stdout

    actual = {}
    for mode, expected in EXPECTED.items():
        args = arguments("002")
        if mode != "envelope":
            args += ["--" + mode + "-artifacts", str(archives["002"]), ARCHIVE]
        if mode in ["process", "hook", "control"]:
            args += [observer["interpreter_sha256"], observer["observer_sha256"]]
        raw = run("actual-" + mode, args, 0)
        assert sha(raw) == expected
        actual[mode] = json.loads(raw)
    assert sha(run("restart-control", artifacts(archives["002"], ARCHIVE), 0)) == EXPECTED["control"]
    process = actual["process"]["process_artifacts"]["relations"]
    launch = process["launch_provenance"]
    assert process["raw_sdk_request_bytes_checked"] and process["raw_sdk_requests_checked"] == 3
    assert process["sdk_and_mcp_processes_checked"] == 8
    assert launch["interpreter_prelaunch_pinned"] and launch["outside_observer_prelaunch_declared"]
    assert launch["observer_execution_authenticated"] is launch["outside_signing_key_admitted"] is False
    hook = actual["hook"]["hook_artifacts"]["relations"]
    assert hook["journal_report_binding_checked"] and hook["hook_input_deliveries_checked"] == 3
    relation = actual["control"]["control_artifacts"]["relations"]
    assert relation["product_launches"]["prefix_python_launches_checked"] == 9
    assert relation["product_launches"]["interpreter_prelaunch_pinned"]
    assert relation["capture_streams"]["captures_checked"] == 8
    assert relation["native_clients"]["installed_runtime_clients_checked"] == 5
    for field in [
        "qualified_role_complete",
        "all_native_runtime_descendants_graded",
        "outside_signing_key_admitted",
        "outside_child_death_observed",
    ]:
        assert relation[field] is False
    failed = json.loads(run("earlier-failed-envelope", arguments("001"), 0))
    assert failed["readback"]["reported_status"] == "failed"
    first = json.loads((directory / "native-launch-observer-001.json").read_bytes())
    run(
        "earlier-failure-cannot-pass-control",
        [
            *arguments("001"),
            "--control-artifacts",
            str(archives["001"]),
            FAILED,
            first["interpreter_sha256"],
            first["observer_sha256"],
        ],
        2,
    )
    for position, name in [(-3, "wrong-archive"), (-2, "wrong-interpreter"), (-1, "wrong-observer")]:
        args = artifacts(archives["002"], ARCHIVE)
        args[position] = "0" * 64
        run(name, args, 2)
    args = artifacts(archives["002"], ARCHIVE)
    args[8] = "boundary"
    run("wrong-role", args, 2)
    run("cross-job-failed-archive", artifacts(archives["001"], FAILED), 2)

    with tarfile.open(archives["002"], "r:") as archive:
        originals = {m.name: archive.extractfile(m).read() for m in archive.getmembers()}
    target = directory / (stem + "-mutations")
    target.mkdir(mode=0o700)

    def mutate(name, change):
        files = dict(originals)
        change(files)
        inventory = json.loads(files["results.sha256.json"])
        inventory["files"] = {
            n: dict(bytes=len(r), sha256=sha(r)) for n, r in files.items() if n != "results.sha256.json"
        }
        files["results.sha256.json"] = canonical(inventory)
        path = target / (name + ".tar")
        with path.open("xb") as output, tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for member, raw in sorted(files.items()):
                info = tarfile.TarInfo(member)
                info.mode = 0o600
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        run(name, artifacts(path, sha(path.read_bytes())), 2)

    def journal_change(change):
        def apply(files):
            name = "combined/cell/native-supervisor-events.v1.jsonl"
            rows = [json.loads(line) for line in files[name].splitlines()]
            change(rows)
            previous, lines = "0" * 64, []
            for sequence, row in enumerate(rows):
                row["sequence"], row["previous_sha256"] = sequence, previous
                raw = canonical(row)
                previous = sha(raw)
                lines.append(raw + b"\n")
            files[name] = b"".join(lines)

        return apply

    mutate("changed-prelaunch-interpreter", journal_change(lambda rows: rows[1]["data"].update(sha256="0" * 64)))
    mutate("late-interpreter-pin", journal_change(lambda rows: rows.insert(2, rows.pop(1))))
    mutate(
        "missing-input-terminal",
        journal_change(
            lambda rows: rows.pop(next(i for i, r in enumerate(rows) if r["kind"] == "capture-input-terminal"))
        ),
    )
    mutate(
        "changed-input-bound",
        journal_change(
            lambda rows: next(r for r in rows if r["kind"] == "capture-input-bound")["data"].update(bytes=1)
        ),
    )

    def changed_report(files):
        name = "combined/worker/report.json"
        value = json.loads(files[name])
        value["controller_report"]["requests"][0]["request_wire_utf8"] += " "
        files[name] = canonical(value)

    mutate("changed-signed-sdk-wire", changed_report)

    def changed_outside(files):
        name = "proof/outside-kernel.json"
        value = json.loads(files[name])
        value["observer_sha256"] = "0" * 64
        files[name] = canonical(value)

    mutate("changed-outside-observer", changed_outside)
    mutate(
        "changed-physical-effect",
        lambda files: files.update({"combined/workspace/native-contained.txt": b"changed effect"}),
    )
    units = json.loads(originals["unit/summary.json"])
    assert units["source_commit"] == SOURCE and units["unit_tests_passed"] == 7
    assert units["worker_files_preserved"] == 284 and units["both_worker_leases_held"]
    for row in units["cases"]:
        raw = originals["unit/" + row["case"] + ".log"]
        assert sha(raw) == row["log_sha256"] and row["returncode"] == 0
    prior = json.loads(originals["proof/prior-worker-hashes.json"])
    final = json.loads(originals["proof/final-worker-hashes.json"])
    assert len(prior) == 291 and len(final) == 298
    assert all(final[name] == pin for name, pin in prior.items())
    pressure = json.loads(originals["proof/outside-task-pressure.json"])
    assert pressure["errors"] == [] and len(pressure["samples"]) == 160
    peak = max(int(row["counts"]["pids.peak"]) for row in pressure["samples"])
    sampled_peak = max(int(row["counts"]["pids.current"]) for row in pressure["samples"])
    assert peak == 126 and sampled_peak == 122
    assert all(row["counts"]["pids.max"] == "128" for row in pressure["samples"])
    assert all(row["counts"]["pids.events"] == "max 0" for row in pressure["samples"])
    assert {
        n: {p.name: sha(p.read_bytes()) for p in (directory / ("native-launch-host-pins-" + n)).iterdir()} for n in jobs
    } == before
    assert len(cases) == 20 and sum(row["returncode"] == 2 for row in cases) == 13
    result = dict(
        schema="hol-gauntlet-native-launch-live-proof.v1",
        source_commit=SOURCE,
        product_source_commit=PRODUCT,
        verifier_sha256=VERIFIER,
        archive_sha256=ARCHIVE,
        failed_archive_sha256=FAILED,
        cases=cases,
        arm_tests_passed=7,
        actual_readback_sha256=EXPECTED,
        interpreter_prelaunch_pinned=True,
        raw_sdk_requests_checked=3,
        hook_input_deliveries_checked=3,
        journal_report_binding_checked=True,
        earlier_task_limit_failure_retained=True,
        task_pressure_issue_resolved=False,
        sampled_pids_peak=sampled_peak,
        kernel_retained_pids_peak=peak,
        pids_limit=128,
        observer_execution_authenticated=False,
        outside_signing_key_admitted=False,
        current_source_full_conformance=False,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )
    raw = canonical(result) + b"\n"
    with (directory / (stem + ".json")).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(
        json.dumps(
            dict(
                proof_sha256=sha(raw),
                cases=len(cases),
                refusals=13,
                arm_tests=7,
                source_commit=SOURCE,
                execution_eligible=False,
                model_requests=0,
            )
        )
    )


if __name__ == "__main__":
    assert len(sys.argv) == 3
    verify(Path(sys.argv[1]), sys.argv[2])
