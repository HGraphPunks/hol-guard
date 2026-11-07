#!/usr/bin/env python3
"""Verify retained Rust SDK failures and scoped repairs without executing them."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import verify_native_current_worker_20261026 as v
from verify_native_sdk_transport_attempts_20261027 import verify_025, verify_027, verify_028


def verify_029(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-029.tar",
        "6e2ac9913c65c68a31d1afc45eccca2f41069c1b6357800bf3f459f030572d14",
        101,
    )
    old = v.exported(
        base / "native-sdk-transport-vm-results-028.tar",
        "ee7646a50e47859d550f1ee831d34c12155fd7b3c381c82c7fd8ac07ad6aa002",
        63,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-029.tar",
        "eb669b61ec6823bf130403f8e414039373d85e28fea41dcfcdb2f21e53e82395",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "a506de2ec11f621787efa91d0625b07545122425"
    assert set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"]
        assert len(raw) == transfer["files"][name]["bytes"]
    assert v.parse(data["input/transfer.json"]) == transfer
    generation = v.sha(inputs["gauntlet-vm-worker"])
    assert generation == "8e9c4d0489be56d51e339938d3e7445e718767b000e10d49a2d14f30ecc3ac35"
    proof = v.parse(data["proof/proof.json"])
    jobs = v.parse(data["proof/native-sdk-jobs.json"])
    assert len(proof["worker_hashes"]) == proof["worker_files"] == 82
    assert len(jobs["prior_worker_hashes"]) == proof["prior_worker_files_preserved"] == 76
    assert all(proof["worker_hashes"][n] == h for n, h in jobs["prior_worker_hashes"].items())
    for prefix, job in [("retained_failed_job", "e2c701baf1472501"), ("retained_created_failure", "e2c701baf1472801")]:
        for suffix in ["started.json", "running.json", "native.stdout", "native.stderr", "native-repair.json"]:
            assert v.sha(data[prefix + "/worker/" + suffix]) == proof["worker_hashes"][job + "." + suffix]
        assert job + ".terminal.json" not in proof["worker_hashes"]
        assert job + ".report.json" not in proof["worker_hashes"]
    for suffix in ["started.json", "running.json", "native.stdout", "native.stderr"]:
        assert data["retained_created_failure/worker/" + suffix] == old["sdk_transport/worker/" + suffix]
    intent_raw = data["retained_created_failure/sdk-created-repair-intent.v1.json"]
    receipt_raw = data["retained_created_failure/sdk-created-repair.v1.json"]
    intent, receipt = v.parse(intent_raw), v.parse(receipt_raw)
    assert v.sha(intent_raw) == "b7ae2e005e8b02f05ee183c0ef31d30accfef59434c3763554577cc95ada0297"
    assert v.sha(receipt_raw) == "080760c7cc9dbd504194e2fba57deb6a26cf27cfe3a729cd9e116c6b888a6433"
    inspection = v.parse(old["sdk_transport/sdk-processes/004.stdout"])[0]
    assert receipt["intent_sha256"] == v.sha(intent_raw)
    assert intent["container_id"] == receipt["container_id"] == inspection["Id"]
    assert intent["creation_sha256"] == v.sha(old["sdk_transport/sdk-processes/003.stdout"])
    assert intent["inspection_sha256"] == v.sha(old["sdk_transport/sdk-processes/004.stdout"])
    assert intent["started_marker_sha256"] == v.sha(old["sdk_transport/worker/started.json"])
    assert intent["repair_generation"] == generation
    assert intent["quiescent"]["image_history"] == "already-closed-v1"
    assert receipt["status"] == "removed-never-started"
    assert all(
        receipt[k] is False
        for k in ["process_signalled", "image_adopted", "job_terminal_written", "execution_eligible"]
    )
    assert receipt["sdk_agent_absent"] is receipt["sdk_profile_absent"] is True
    created_proof = v.parse(data["proof/created-repair-proof.json"])
    old_failure = v.parse(old["proof/failed-attempt.json"])
    expected_old = {**old_failure["prior_worker_hashes"], **old_failure["original_worker_hashes"]}
    assert created_proof["original_worker_hashes"] == expected_old
    assert len(expected_old) == created_proof["original_worker_files_preserved"] == 75
    assert all(proof["worker_hashes"][n] == h for n, h in expected_old.items())
    assert created_proof["native_unknown_job_still_retained"] and created_proof["reopen_exact"]
    for operation in ["created-repair", "repair"]:
        result = v.parse(data["proof/" + operation + ".json"])
        reopened = v.parse(data["proof/" + operation + "-reopen.json"])
        assert result["returncode"] == reopened["returncode"] == 0
        assert result["stdout"] == reopened["stdout"] and result["stderr"] == reopened["stderr"] == ""
        for name, raw in data.items():
            if name.startswith("proof/" + operation + "-") and ("wrong-" in name or "lease-busy" in name):
                assert v.parse(raw)["returncode"] == 2
    assert v.parse(v.parse(data["proof/created-repair.json"])["stdout"]) == receipt
    repair_raw = data["retained_created_failure/worker/native-repair.json"]
    repair = v.parse(repair_raw)
    assert v.sha(repair_raw) == "9cc45ffc6492a61c357487b24bd32771b99a88e4dc35f5fa3ac141a5bff9b433"
    assert v.parse(v.parse(data["proof/repair.json"])["stdout"]) == repair
    assert repair["schema"] == "hol-gauntlet-native-worker-repair.v2"
    assert repair["status"] == "aborted" and repair["exit_code"] is None
    assert repair["started_marker_sha256"] == intent["started_marker_sha256"]
    assert repair["running_marker_sha256"] == v.sha(old["sdk_transport/worker/running.json"])
    assert repair["repair_generation"] == generation
    assert repair["worker_generation"] == intent["worker_generation"]
    assert repair["cleanup"]["quiescent"] == intent["quiescent"]
    assert repair["cleanup"]["sdk_agent_absent"] is repair["cleanup"]["sdk_profile_absent"] is True
    assert not repair["execution_eligible"] and not repair["guard_causality_verified"]
    job = jobs["records"]["sdk_transport"]
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-029.json")
    assert v.sha(prelaunch_raw) == "34a04995bd049e3f4eae8d8e75be0dcf548b8947d035cf7bf072c7cf3b534e0d"
    assert v.parse(prelaunch_raw)["records"] == jobs["records"]
    assert v.sha(data["sdk_transport/preparation.v1.json"]) == job["preparation_sha256"]
    assert v.sha(data["sdk_transport/declaration.json"]) == job["deployment_sha256"]
    report_raw = data["sdk_transport/worker/report.json"]
    report = v.parse(report_raw)
    assert v.sha(report_raw) == "0dc0f637d39f3cf2733993b2a1e05bfe7c0922e84f45a9af1bf188a143774f56"
    terminal = v.parse(data["sdk_transport/worker/terminal.json"])
    assert terminal["report_sha256"] == v.sha(report_raw)
    for suffix in ["started.json", "running.json", "report.json", "terminal.json", "native.stdout", "native.stderr"]:
        assert v.sha(data["sdk_transport/worker/" + suffix]) == proof["worker_hashes"][job["job_id"] + "." + suffix]
    assert report["status"] == terminal["status"] == "invalid-evidence"
    assert report["exit_code"] == terminal["exit_code"] == 2
    assert report["worker_generation"] == generation and report["job_id"] == job["job_id"]
    assert all(
        report[k] is True
        for k in [
            "controller_cgroup_drained",
            "product_slice_absent",
            "image_lease_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
        ]
    )
    controller = v.parse(data["sdk_transport/worker/native.stdout"])
    assert report["controller_report"] == controller
    assert controller["error"] == "SDK container ID/cgroup relation differs"
    assert controller["status"] == "failed" and not controller["sdk_exercised"]
    assert controller["requests"] == controller["plane"]["executions"] == []
    assert all(
        controller[k] is True
        for k in [
            "cell_cleanup_complete",
            "agent_cleanup_complete",
            "sdk_cleanup_complete",
            "prefix_unchanged",
            "sdk_assets_unchanged",
            "public_helpers_unchanged",
        ]
    )
    for value in [proof, report, controller]:
        assert value["execution_eligible"] is value["guard_causality_verified"] is False
        assert value["model_requests"] == 0
    for name, pin in transfer["public_helpers"].items():
        assert v.sha(data["sdk_transport/public/" + name]) == pin["sha256"]
    events = v.chain(data["sdk_transport/cell/native-supervisor-events.v1.jsonl"])
    v.chain(data["sdk_transport/cell/native-image-events.v1.jsonl"])
    assert events[-2]["kind"] == "terminal-cleanup" and events[-2]["data"]["failures"] == []
    assert events[-1]["kind"] == "rust-image-cleanup"
    for row in events:
        if row["kind"] == "capture-terminal":
            for pin in row["data"]["files"].values():
                raw = data["sdk_transport/cell/" + pin["file"]]
                assert v.sha(raw) == pin["sha256"] and len(raw) == pin["bytes"]
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == [] and len(kernel["observations"]) == 16
    assert all(o["pidfd_held"] and o["status"]["Seccomp"] == "2" for o in kernel["observations"])
    for action in ["replay", "reconcile"]:
        result = v.parse(data["proof/worker-sdk_transport-" + action + ".json"])
        if action == "replay":
            assert result["returncode"] == 2
        else:
            value = v.parse(result["stdout"])
            assert result["returncode"] == 0 and value["state"] == "terminal"
            assert value["report_sha256"] == v.sha(report_raw) and value["exit_code"] == 2
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "150", "0", "24"]]
    assert tests["gauntlet-rootfs-tests"]["results"] == [["ok", "1", "0", "0"], ["ok", "30", "0", "0"]]
    for name, result in tests.items():
        assert result["returncode"] == 0 and v.sha(data["proof/" + name + ".log"]) == result["sha256"]
    return {
        "schema": "hol-gauntlet-host-native-sdk-recovery.v1",
        "source_commit": transfer["source_commit"],
        "export_members_verified": 101,
        "input_members_verified": 5,
        "worker_files_preserved": 82,
        "original_failure_preserved": True,
        "created_metadata_repair_sha256": v.sha(receipt_raw),
        "native_abort_repair_sha256": v.sha(repair_raw),
        "no_fabricated_terminal_or_exit": True,
        "sdk_exercised": False,
        "guard_causality_verified": False,
        "execution_eligible": False,
        "model_requests": 0,
    }


def verify_030(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-030.tar",
        "7ac9557ca0a4082d621269efad32db1ff39cc26430f20b13ed6b17324925e3c2",
        84,
    )
    prior = v.exported(
        base / "native-sdk-transport-vm-results-029.tar",
        "6e2ac9913c65c68a31d1afc45eccca2f41069c1b6357800bf3f459f030572d14",
        101,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-030.tar",
        "de1bc1538091b4e5c0c5b6c4d1ca319947971b1da779f1be53719f46fe192e1d",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "2213e73f80ccf61d8d7be3a2b7b9cedbf924af12"
    assert v.parse(data["input/transfer.json"]) == transfer
    assert set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"]
        assert len(raw) == transfer["files"][name]["bytes"]
    jobs, proof = v.parse(data["proof/native-sdk-jobs.json"]), v.parse(data["proof/proof.json"])
    assert jobs["prior_worker_hashes"] == v.parse(prior["proof/proof.json"])["worker_hashes"]
    assert len(jobs["prior_worker_hashes"]) == 82
    assert len(proof["worker_hashes"]) == proof["worker_files"] == 88
    assert all(proof["worker_hashes"][n] == h for n, h in jobs["prior_worker_hashes"].items())
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-030.json")
    assert v.sha(prelaunch_raw) == "1ffc2339f4df604a3a72045c291118b9f782c09d69a2f840d8d2a02ae57bbf16"
    prelaunch = v.parse(prelaunch_raw)
    assert prelaunch["records"] == jobs["records"] and prelaunch["prior_worker_hashes"] == jobs["prior_worker_hashes"]
    job = jobs["records"]["sdk_transport"]
    assert job["worker_generation"] == prelaunch["worker_generation"] == v.sha(inputs["gauntlet-vm-worker"])
    assert v.sha(data["sdk_transport/preparation.v1.json"]) == job["preparation_sha256"]
    assert v.sha(data["sdk_transport/declaration.json"]) == job["deployment_sha256"]
    report_raw = data["sdk_transport/worker/report.json"]
    assert v.sha(report_raw) == "7891f067e3101215a08989b1ffa8d91bb664088e534f90fe8b989a7a2ceb18b3"
    report, terminal = v.parse(report_raw), v.parse(data["sdk_transport/worker/terminal.json"])
    assert terminal["report_sha256"] == v.sha(report_raw)
    assert report["exit_code"] == terminal["exit_code"] == 2
    assert report["status"] == terminal["status"] == "invalid-evidence"
    assert all(
        report[k] is True
        for k in [
            "controller_cgroup_drained",
            "product_slice_absent",
            "image_lease_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
        ]
    )
    controller = v.parse(data["sdk_transport/worker/native.stdout"])
    assert controller == report["controller_report"] and controller["status"] == "failed"
    assert controller["error"] == "SDK named unconfined template label differs"
    assert not controller["sdk_exercised"] and controller["requests"] == controller["plane"]["executions"] == []
    assert all(
        controller[k] is True
        for k in [
            "cell_cleanup_complete",
            "agent_cleanup_complete",
            "sdk_cleanup_complete",
            "prefix_unchanged",
            "sdk_assets_unchanged",
            "public_helpers_unchanged",
        ]
    )
    for value in [report, controller, proof]:
        assert (
            not value["execution_eligible"] and not value["guard_causality_verified"] and value["model_requests"] == 0
        )
    for suffix in ["started.json", "running.json", "report.json", "terminal.json", "native.stdout", "native.stderr"]:
        assert v.sha(data["sdk_transport/worker/" + suffix]) == proof["worker_hashes"][job["job_id"] + "." + suffix]
    agent = controller["agent"]
    cid = agent["container_id"]
    assert cid == "2a5b6d6cc1fb0d999420372ce357f237b9ff0e26f96e8e0ce756e5363943f891"
    assert agent["kernel"]["cgroup"] == "/holgauntletrust" + job["job_id"] + ".slice/libpod-" + cid + ".scope/container"
    assert agent["kernel"]["limits"] == {
        "memory.max": "2147483648",
        "pids.max": "256",
        "cpu.max": "200000 100000",
        "cpuset.cpus.effective": "0-1",
    }
    assert agent["inspection"]["State"]["Pid"] == agent["kernel"]["pid"]
    assert agent["inspection"]["State"]["Running"] is True and agent["cleanup_complete"] is True
    for name, pin in transfer["public_helpers"].items():
        assert v.sha(data["sdk_transport/public/" + name]) == pin["sha256"]
    for name in ["native-supervisor-events.v1.jsonl", "native-image-events.v1.jsonl"]:
        rows = v.chain(data["sdk_transport/cell/" + name])
        if name.startswith("native-supervisor"):
            assert rows[-2]["kind"] == "terminal-cleanup" and rows[-2]["data"]["failures"] == []
            assert rows[-1]["kind"] == "rust-image-cleanup"
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == [] and len(kernel["observations"]) == 16
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "151", "0", "24"]]
    for name, result in tests.items():
        assert result["returncode"] == 0 and v.sha(data["proof/" + name + ".log"]) == result["sha256"]
    for action in ["replay", "reconcile"]:
        result = v.parse(data["proof/worker-sdk_transport-" + action + ".json"])
        if action == "replay":
            assert result["returncode"] == 2
        else:
            value = v.parse(result["stdout"])
            assert result["returncode"] == 0 and value["state"] == "terminal"
            assert value["report_sha256"] == v.sha(report_raw) and value["exit_code"] == 2
    return {
        "schema": "hol-gauntlet-host-native-sdk-cgroup-label-refusal.v1",
        "export_members_verified": 84,
        "input_members_verified": 5,
        "source_commit": transfer["source_commit"],
        "worker_files_preserved": 88,
        "exact_cgroup_leaf_observed": True,
        "actual_process_label_not_retained": True,
        "sdk_exercised": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path, help="directory containing the fixed retained exports and inputs")
    parser.add_argument("--output", type=Path, help="exclusively create the verification report")
    args = parser.parse_args()
    result = {
        n: verify(args.evidence)
        for n, verify in [
            ("025", verify_025),
            ("027", verify_027),
            ("028", verify_028),
            ("029", verify_029),
            ("030", verify_030),
        ]
    }
    raw = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()
