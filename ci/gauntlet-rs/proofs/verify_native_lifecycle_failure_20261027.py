"""Preserve the genuine timeout that lacked independently joined readiness."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import native_sdk_readback_20261027 as sdk
from verify_native_mcp_transport_20261027 import archive, ineligible, parse, sha

ATTEMPTS = {
    "006": {
        "export": ("5de76f155752e62d3655b75329ee30076c7d248e06cd4e4923d43274974f4652", 1034240),
        "input": "a95132642bd3719c58e8a39b14b5d9d952815bfdc66a88aad8931b1e1b7f4caf",
        "source": "f01deadbe43e31e41f4a6f93c540dbe31b2b8f0d",
        "courier": "d32dc02e03658f51f285e9470387ae2e27b4f8f68444e1f1c8f5fa80799becca",
        "report": "cd3ae78714048cca7af33152f6f1de94ec92c8d733bb3dd08fc3d01b6bab6e0f",
        "files": 197,
        "samples": 66,
    },
    "007": {
        "export": ("7cd42eacaa06e10abe6ad2b7fcd7f94c9c340f579a65d706c87fbfe4f09d1a22", 1024000),
        "input": "45ba8bc552207ede979eeb28ebdb635543d49fac66429adef11fc9b12c2c7cc8",
        "source": "5dea4ffb0e25c07e18ff071e57add86e6d9a00fd",
        "courier": "7c081cb4a10041703695f33cade0b91597000a19fb9d692e438a23813e053667",
        "report": "0b4594a992c27fcba9510e04f0106d75184639b49956efad33d445c22d232bdb",
        "files": 203,
        "samples": 65,
    },
    "007-cancel": {
        "export": ("fa24d43d9f778e392b92ba43201ef641e7d7e0f1fa779b4e8db9fc07a4a4b8ff", 1003520),
        "members": 132,
        "input_attempt": "007",
        "role": "cancel",
        "observer": "002",
        "input": "45ba8bc552207ede979eeb28ebdb635543d49fac66429adef11fc9b12c2c7cc8",
        "source": "5dea4ffb0e25c07e18ff071e57add86e6d9a00fd",
        "courier": "3ca81e1dd278b8c188aae6151fdad3a94c76ac99d507158fb9e45a8e7cf22234",
        "report": "ad1692c65f9a6e3da38d94e9b4af01552908e593b601f0bd2ec7b329b6300b3d",
        "files": 209,
        "samples": 67,
    },
}


def verify(directory, attempt="006"):
    pins = ATTEMPTS[attempt]
    number, role = pins.get("input_attempt", attempt), pins.get("role", "timeout")
    data = archive(
        directory / f"native-role-controls-vm-results-{number}-{role}.tar",
        *pins["export"],
        pins.get("members", 138),
    )
    inputs = archive(
        directory / f"native-role-controls-input-{number}.tar",
        pins["input"],
        65863680,
        5,
    )
    transfer = parse(inputs.pop("transfer.json"))
    assert transfer == parse(data["input/transfer.json"])
    assert transfer["source_commit"] == pins["source"]
    for name, raw in inputs.items():
        assert transfer["files"][name] == {"bytes": len(raw), "sha256": sha(raw)}
        assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0"
    prelaunch = parse((directory / f"native-role-controls-prelaunch-{number}-{role}.json").read_bytes())
    assert prelaunch["courier_sha256"] == sha(
        (directory / f"native-role-controls-proof-courier-{number}-{role}.py").read_bytes()
    )
    assert prelaunch["courier_sha256"] == pins["courier"]
    observer = pins.get("observer", "001")
    assert prelaunch["observer_sha256"] == sha(
        (directory / f"native-role-lifecycle-observer-{observer}.py").read_bytes()
    )
    pin = prelaunch["pins"]
    assert pin == parse(data[f"proof/job-{role}.json"]) and pin["worker_generation"] == sha(
        inputs["gauntlet-vm-worker"]
    )
    hashes, prior = (parse(data["proof/" + n + ".json"]) for n in ["final-worker-hashes", "prior-worker-hashes"])
    assert len(hashes) == pins["files"] and len(prior) == pins["files"] - 6
    assert all(hashes[n] == h for n, h in prior.items())
    report = sdk.worker(data, "combined", pin, hashes, 2, pins["report"])
    control = report["controller_report"]
    ineligible(control)
    assert control["status"] == "failed" and control["control_role"] == role
    assert control["qualified_role_complete"] is False
    lifecycle = control["router"]["lifecycle"]
    assert lifecycle["capture_exit_code"] == 124 and lifecycle["capture_error"] is None
    assert lifecycle["ready"] is lifecycle["detached_child"] is lifecycle["detached_child_dead"] is None
    assert lifecycle["late_effect_absent"] is None and lifecycle["status"] == "failed"
    assert lifecycle["error"] == "actual detached child was not observed before control termination"
    assert "sdk" not in control["measurements"] and control["effect"] is None
    assert all(
        report[k]
        for k in [
            "product_slice_absent",
            "image_lease_absent",
            "sdk_agent_absent",
            "sdk_profile_absent",
            "mcp_agent_absent",
            "mcp_profile_absent",
        ]
    )
    physical = parse(data["combined/physical-lifecycle-absence.json"])
    assert physical["absent"] == ["detached-ready.json", "detached-ready.pending", "late-detached-effect.txt"]
    samples = parse(data["proof/outside-kernel.json"])
    assert samples["errors"] == [] and len(samples["observations"]) == pins["samples"]
    assert samples["observer_sha256"] == prelaunch["observer_sha256"]
    children = [r for r in samples["observations"] if f"hol-gauntlet-native-detached-{role}-" in r["argv_utf8"]]
    assert (
        len(children) == 1
        and children[0]["executable_sha256"] == "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960"
    )
    assert children[0]["namespace_pids"][-1] == 4 and children[0]["pidfd_held"]
    if observer == "002":
        view = children[0]["synthetic_lifecycle_view"]
        assert view["cwd"] == "/runtime/home/project" and view["directory"]["uid"] == 10004
        ready = view["files"]["detached-ready.json"]
        assert ready["uid"] == ready["gid"] == 10004 and ready["mode"] == 0o600 and ready["links"] == 1
        assert ready["sha256"] == sha(ready["utf8"].encode())
        assert parse(ready["utf8"].encode()) == {
            "schema": "hol-gauntlet-native-detached-ready.v1",
            "role": role,
            "token": f"hol-gauntlet-native-detached-{role}-{pin['job_id']}",
            "pid": 4,
            "sid": 4,
            "pgrp": 4,
        }
        assert view["files"]["detached-ready.pending"] is view["files"]["late-detached-effect.txt"] is None
    assert parse(data["proof/worker-tests.json"])["results"] == [["ok", "179", "0", "24"]]
    assert parse(data["proof/rootfs-tests.json"])["results"] == [["ok", "1", "0", "0"], ["ok", "36", "0", "0"]]
    replay = parse(data["proof/fast-replay-summary.json"])
    assert replay["worker_files_unchanged"] == pins["files"] and replay["reconcile_original_terminal"]
    return {
        "schema": "hol-gauntlet-native-lifecycle-failure-readback.v1",
        "job_id": pin["job_id"],
        "actual_timeout_exit": 124,
        "outside_child_start_observed": True,
        "published_readiness_observed": False,
        "outside_overlay_readiness_observed": True if observer == "002" else None,
        "failure_preserved": True,
        "worker_files_preserved": pins["files"],
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        raise SystemExit("usage: verify_native_lifecycle_failure_20261027.py EVIDENCE_DIRECTORY [006|007|007-cancel]")
    print(json.dumps(verify(Path(sys.argv[1]), *sys.argv[2:]), sort_keys=True))
