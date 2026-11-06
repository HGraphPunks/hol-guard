#!/usr/bin/env python3
"""Verify the retained SDK success with a failed timestamp-custody predicate."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import native_sdk_readback_20261027 as sdk
import verify_native_current_worker_20261026 as v


def verify_recovery(data, previous):
    failure = v.parse(previous["proof/failed-attempt.json"])
    proof = v.parse(data["proof/repair-proof.json"])
    assert (
        proof["all_prior_worker_hashes"] == failure["worker_hashes"]
        and proof["all_prior_worker_files_preserved"] == 104
    )
    assert proof["original_worker_hashes"] == failure["original_worker_hashes"]
    for suffix in ["started.json", "running.json", "native.stdout", "native.stderr"]:
        assert data["retained_startup_failure/worker/" + suffix] == previous["sdk_transport/worker/" + suffix]
    raw = data["retained_startup_failure/worker/native-repair.json"]
    assert v.sha(raw) == proof["receipt_sha256"] == "9f5ae3f9fd0839efd3e32f0b6ee4a28b14823f150cdc7d95611d446c09e303d6"
    repair = v.parse(raw)
    assert repair["schema"] == "hol-gauntlet-native-worker-repair.v2"
    assert repair["status"] == "aborted" and repair["exit_code"] is None
    assert repair["job_id"] == failure["job_id"] == "e2c701baf1473301"
    assert repair["started_marker_sha256"] == v.sha(previous["sdk_transport/worker/started.json"])
    assert repair["running_marker_sha256"] == v.sha(previous["sdk_transport/worker/running.json"])
    assert repair["cleanup"]["active_pointer_sha256"] == failure["image_active_sha256"]
    assert repair["cleanup"]["quiescent"]["image_history"] == "recovered-pending-v1"
    assert repair["cleanup"]["sdk_agent_absent"] and repair["cleanup"]["sdk_profile_absent"]
    assert not repair["execution_eligible"] and not repair["guard_causality_verified"] and repair["model_requests"] == 0
    for n in ["repair.json", "repair-reopen.json"]:
        result = v.parse(data["proof/" + n])
        assert result["returncode"] == 0 and result["stderr"] == "" and result["stdout"].encode() == raw + b"\n"
    for n in ["wrong-generation", "wrong-started", "rust-lease-busy", "legacy-lease-busy"]:
        assert v.parse(data["proof/repair-" + n + ".json"])["returncode"] == 2
    intent_raw = data["retained_startup_failure/device-null-restore-intent.v1.json"]
    restored_raw = data["retained_startup_failure/device-null-restore.v1.json"]
    assert v.sha(restored_raw) == "87d4ad1580b7ece73c04c2d329dbf6fd13a4e72c22f0b303744944108e5b877e"
    intent, restored = v.parse(intent_raw), v.parse(restored_raw)
    assert restored["intent_sha256"] == v.sha(intent_raw)
    assert intent["before"] == restored["before"] == failure["device_null"]
    assert restored["after"] == {**failure["device_null"], "uid": 0, "gid": 0}
    assert restored["original_worker_files_preserved"] == 104 and restored["job_still_unknown"]
    recovery = [raw for n, raw in data.items() if n.startswith("retained_startup_failure/cell/native-recovery-")]
    assert len(recovery) == 1
    rows = v.chain(recovery[0])
    assert [r["kind"] for r in rows] == ["recovery-quiescent", "recovery-image-unmount-pending", "recovery-cleanup"]
    assert rows[1]["data"]["active_pointer_sha256"] == failure["image_active_sha256"]
    assert rows[2]["data"]["image_unmounted"] and rows[2]["data"]["active_pointer_absent"]
    assert rows[2]["data"]["execution_eligible"] is False
    return {
        "pending_repair_receipt_sha256": v.sha(raw),
        "device_restoration_receipt_sha256": v.sha(restored_raw),
        "original_unknown_bytes_preserved": True,
        "no_fabricated_terminal_or_exit": True,
    }


def verify(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-034.tar",
        "b85d2c58faff9dbcf00d7e190d3efa26ce8cf30d884c7c7e8f0a3f5256f03deb",
        126,
    )
    previous = v.exported(
        base / "native-sdk-transport-vm-results-033.tar",
        "4147456101102a92411b4a7516e28e50bde2974365b31e773c58f3bbb615496f",
        36,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-034.tar",
        "a329a5f28713ad1fd609d5c9f9f0bfdc87a1ddcaa500c8f8262e3e39ce005bfb",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "5c09afa28ba6fa8ef93a2dfeeaf4c297d3bac5f4"
    assert v.parse(data["input/transfer.json"]) == transfer and set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
    recovery = verify_recovery(data, previous)
    jobs, proof = v.parse(data["proof/native-sdk-jobs.json"]), v.parse(data["proof/proof.json"])
    failed = v.parse(previous["proof/failed-attempt.json"])
    expected = {
        **failed["worker_hashes"],
        "e2c701baf1473301.native-repair.json": recovery["pending_repair_receipt_sha256"],
    }
    assert jobs["prior_worker_hashes"] == expected and len(expected) == 105
    assert len(proof["worker_hashes"]) == proof["worker_files"] == 117
    assert all(proof["worker_hashes"][n] == h for n, h in expected.items())
    assert (
        "e2c701baf1473301.terminal.json" not in proof["worker_hashes"]
        and "e2c701baf1473301.report.json" not in proof["worker_hashes"]
    )
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-034.json")
    assert v.sha(prelaunch_raw) == "261afb13e9e68f8b6887227d16313892f1f715ba5a9e8f03abd0138d230dfcfe"
    prelaunch = v.parse(prelaunch_raw)
    assert prelaunch["records"] == jobs["records"] and prelaunch["prior_worker_hashes"] == expected
    assert prelaunch["worker_generation"] == v.sha(inputs["gauntlet-vm-worker"])
    assert prelaunch["fixture"]["sha256"] == v.sha(data["sdk_transport/fixture/test_control.py"])
    primary = sdk.worker(
        data,
        "sdk_transport",
        jobs["records"]["sdk_transport"],
        proof["worker_hashes"],
        2,
        "1b5a50ed7387ebe89626c28762146c59175dfe06b98aa3b97c9b3bb69fd1c7cf",
    )
    negative = sdk.worker(
        data,
        "wrong_sdk_publication",
        jobs["records"]["wrong_sdk_publication"],
        proof["worker_hashes"],
        2,
        "14ee7b8f2b029f52b8c7ad1001d4f16be5b85c7b0f644c66d6edf17213fb4292",
    )
    assert negative["controller_report"] is None
    controller = primary["controller_report"]
    exchange = sdk.sdk_exchange(data, transfer, controller, require_outside_bun=False)
    assert exchange["outside_bun_executable_observed"] is False
    assert (
        controller["error"] == "SDK runtime changed the held host null-device inode"
        and controller["status"] == "failed"
    )
    assert controller["cleanup_errors"] == [controller["error"]] and not controller["host_null_unchanged"]
    final_device = v.parse(data["proof/outside-final-device.json"])
    for n in ["device", "inode", "uid", "gid", "mode"]:
        assert final_device[n] == controller["host_null_before"][n]
    assert final_device["uid"] == final_device["gid"] == 0
    assert any(final_device[n] != controller["host_null_before"][n] for n in ["ctime_seconds", "ctime_nanoseconds"])
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "155", "0", "24"]]
    assert tests["gauntlet-rootfs-tests"]["results"] == [["ok", "1", "0", "0"], ["ok", "31", "0", "0"]]
    for name, check in tests.items():
        assert check["returncode"] == 0 and v.sha(data["proof/" + name + ".log"]) == check["sha256"]
    for role in jobs["records"]:
        for action in ["replay", "reconcile"]:
            result = v.parse(data["proof/worker-" + role + "-" + action + ".json"])
            if action == "replay":
                assert result["returncode"] == 2
            else:
                value = v.parse(result["stdout"])
                assert result["returncode"] == 0 and value["state"] == "terminal" and value["exit_code"] == 2
                assert value["report_sha256"] == proof["cases"][role]["report_sha256"]
    assert not proof["execution_eligible"] and not proof["guard_causality_verified"] and proof["model_requests"] == 0
    return {
        "schema": "hol-gauntlet-host-native-sdk-benign-timestamp-refusal.v1",
        **recovery,
        **exchange,
        "export_members_verified": 126,
        "input_members_verified": 5,
        "worker_files_preserved": 117,
        "benign_native_command_passed": True,
        "full_diagnostic_passed": False,
        "host_device_identity_preserved": True,
        "timestamp_predicate_refused": True,
        "wrong_publication_refused": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify(args.evidence), sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()
