#!/usr/bin/env python3
"""Read the unknown SDK startup before any scoped repair; never execute it."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import verify_native_current_worker_20261026 as v


def verify_failure(base):
    d = v.exported(
        base / "native-sdk-transport-vm-results-033.tar",
        "4147456101102a92411b4a7516e28e50bde2974365b31e773c58f3bbb615496f",
        36,
    )
    old = v.exported(
        base / "native-sdk-transport-vm-results-032.tar",
        "3ff026ef1ca0389ea5d33ae3c8856768ea8d3dd2ea2bdd9961c992044e974695",
        98,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-033.tar",
        "d690acfb186e36fcbea316b2416315725c16e635abe15e49323ad7ed9af38930",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "be71fe9c71e4258064a754034dcfb0081c5159fc"
    for n, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][n]["sha256"] and len(raw) == transfer["files"][n]["bytes"]
    assert v.parse(d["input/transfer.json"]) == transfer
    failure = v.parse(d["proof/failed-attempt.json"])
    jobs = v.parse(d["proof/native-sdk-jobs.json"])
    job = jobs["records"]["sdk_transport"]
    assert (
        failure["prior_worker_hashes"]
        == jobs["prior_worker_hashes"]
        == v.parse(old["proof/proof.json"])["worker_hashes"]
    )
    assert (
        len(failure["worker_hashes"]) == failure["worker_files"] == 104 and len(failure["prior_worker_hashes"]) == 100
    )
    assert (
        failure["unknown_job_retained"]
        and failure["terminal_absent"]
        and failure["controller_report_absent"]
        and failure["exit_code"] is None
    )
    for n, h in failure["original_worker_hashes"].items():
        assert v.sha(d["sdk_transport/worker/" + n.split(".", 1)[1]]) == h
    assert all(failure["worker_hashes"][n] == h for n, h in failure["prior_worker_hashes"].items())
    assert v.sha(d["sdk_transport/image-active.json"]) == failure["image_active_sha256"]
    assert v.parse(d["sdk_transport/image-active.json"])["stage"] == job["preparation"]["stage"]
    assert (
        failure["device_null"]["uid"] == failure["device_null"]["gid"] == 10001
        and failure["device_null"]["rdev"] == [1, 3]
        and failure["device_null"]["mode"] == 0o666
    )
    rows = v.chain(d["sdk_transport/cell/native-supervisor-events.v1.jsonl"])
    assert any(
        r["kind"] == "cell-stderr"
        and r["data"]["data"] == "gauntlet-cell-rootfs: fixed safe character device required\n"
        for r in rows
    )
    assert (
        rows[-1]["kind"] == "terminal-cleanup"
        and rows[-1]["data"]["failures"]
        and rows[-1]["data"]["cgroup_absent"]
        and rows[-1]["data"]["rootfs_mount_absent"]
    )
    image = v.chain(d["sdk_transport/cell/native-image-events.v1.jsonl"])
    assert len(image) == 4 and image[-1]["kind"] == "image-cell-launch-pending"
    raw = v.stable(base / "native-sdk-transport-host-prelaunch-033.json")
    assert v.sha(raw) == "e42ce79236539c7f6f169e1ce80b70c50709a170652d91ce96a232ea99413d1d"
    pre = v.parse(raw)
    assert pre["records"] == jobs["records"] and pre["fixture"]["sha256"] == v.sha(
        d["sdk_transport/fixture/test_control.py"]
    )
    assert (
        v.sha(d["sdk_transport/preparation.v1.json"]) == job["preparation_sha256"]
        and v.sha(d["sdk_transport/declaration.json"]) == job["deployment_sha256"]
    )
    tests = v.parse(d["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "155", "0", "24"]]
    for n, t in tests.items():
        assert t["returncode"] == 0 and v.sha(d["proof/" + n + ".log"]) == t["sha256"]
    out = {
        "schema": "hol-gauntlet-host-native-sdk-startup-failure.v1",
        "job_id": job["job_id"],
        "source_commit": transfer["source_commit"],
        "export_members_verified": 36,
        "input_members_verified": 5,
        "started_marker_sha256": v.sha(d["sdk_transport/worker/started.json"]),
        "original_worker_hashes": failure["original_worker_hashes"],
        "image_active_sha256": failure["image_active_sha256"],
        "device_null": failure["device_null"],
        "worker_files_preserved": 104,
        "unknown_job": True,
        "sdk_exercised": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify_failure(args.evidence), sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()
