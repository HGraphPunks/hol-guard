#!/usr/bin/env python3
"""Read fixed SDK startup failures; no runtime execution or admission."""

from __future__ import annotations

import verify_native_current_worker_20261026 as v


def verify_025(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-025.tar",
        "d3825a288cd282ca7e5882bb2b15ded274ff0551340ba3a5c0a042aa72df14ac",
        44,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-025.tar",
        "da346939ce6aab56f566b8ec4f34a4432775f7433ca84abc0300acd713f7ba02",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "c62ca717e89bcd4d3281df6398a05044f7f2c26a"
    assert set(inputs) == set(transfer["files"])
    for name, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][name]["sha256"] and len(raw) == transfer["files"][name]["bytes"]
    assert v.parse(data["input/transfer.json"]) == transfer
    failure = v.parse(data["proof/failed-attempt.json"])
    assert (
        failure["sdk_exercised"] is False
        and failure["unknown_job_retained"]
        and failure["terminal_absent"]
        and failure["model_requests"] == 0
    )
    assert set(failure["original_worker_hashes"]) == {
        "e2c701baf1472501." + s for s in ["started.json", "running.json", "native.stdout", "native.stderr"]
    }
    for name, pin in failure["original_worker_hashes"].items():
        assert v.sha(data["sdk_transport/worker/" + name.split(".", 1)[1]]) == pin
    controller = v.parse(data["sdk_transport/worker/native.stdout"])
    assert (
        controller["status"] == "failed"
        and controller["error"] == "unsafe SDK Root helper"
        and controller["sdk_exercised"] is False
    )
    assert controller["cell_cleanup_complete"] and controller["prefix_unchanged"] and controller["sdk_assets_unchanged"]
    assert controller["guard_causality_verified"] is False and controller["execution_eligible"] is False
    assert data["sdk_transport/worker/native.stderr"] == b"native worker unavailable: unsafe SDK Root helper\n"
    assert v.parse(data["proof/worker-sdk-transport.json"])["returncode"] == 2
    jobs = v.parse(data["proof/native-sdk-jobs.json"])
    job = jobs["records"]["sdk_transport"]
    jobid = job["job_id"]
    assert v.sha(data["sdk_transport/preparation.v1.json"]) == job["preparation_sha256"]
    assert v.sha(data["sdk_transport/declaration.json"]) == job["deployment_sha256"]
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-025.json")
    assert v.sha(prelaunch_raw) == "46017425917be2a044ed1de1d553a025c4fe1b494d5d7a159ae55a94d9e2c360"
    prelaunch = v.parse(prelaunch_raw)
    assert prelaunch["records"] == jobs["records"] and prelaunch["worker_generation"] == job["worker_generation"]
    for name, pin in transfer["public_helpers"].items():
        raw = data["sdk_transport/public/" + name]
        assert len(raw) == pin["bytes"] and v.sha(raw) == pin["sha256"]
    prior = v.exported(
        base / "native-hook-transport-vm-results-023.tar",
        "01c1a8d8f6f354367439e8afdc48ae13a3b3a1a69f031a57e559ceb1883f76a6",
        56,
    )
    p = v.parse(prior["proof/proof.json"])
    expected = {**p["prior_worker_hashes"], **p["original_worker_hashes"]}
    assert len(expected) == 54 and expected == failure["prior_worker_hashes"] == jobs["prior_worker_hashes"]
    for suffix in ["wrong-generation", "wrong-source", "rust-lease-busy", "legacy-lease-busy"]:
        assert v.parse(data["proof/worker-" + suffix + ".json"])["returncode"] == 2
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == []
    assert kernel["observations"] and all(
        r["executable_sha256"] != transfer["sdk"]["bun_sha256"] for r in kernel["observations"]
    )
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "147", "0", "24"]]
    assert tests["gauntlet-rootfs-tests"]["results"] == [["ok", "1", "0", "0"], ["ok", "29", "0", "0"]]
    for name, result in tests.items():
        assert v.sha(data["proof/" + name + ".log"]) == result["sha256"]
    out = {
        "schema": "hol-gauntlet-host-native-sdk-failed-attempt.v1",
        "source_commit": transfer["source_commit"],
        "members_verified": 44,
        "input_members_verified": 5,
        "failed_job": jobid,
        "outside_kernel_samples": len(kernel["observations"]),
        "prior_worker_files_preserved": 54,
        "started_marker_sha256": v.sha(data["sdk_transport/worker/started.json"]),
        "original_worker_hashes": failure["original_worker_hashes"],
        "unknown_job": True,
        "sdk_exercised": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    return out


def verify_027(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-027.tar",
        "4000f12ed0e911013559eb2fc07e8865f22071e65874d8e8ec1e1bb665b92a0b",
        83,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-027.tar",
        "042624d57a1ea8a2700b4103f5890cd4ed684387ca1a1e363d0005e8d73906a9",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "3415db61f1536f1f7753f390bdde2f6af07b21a1"
    for n, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][n]["sha256"] and len(raw) == transfer["files"][n]["bytes"]
    assert v.parse(data["input/transfer.json"]) == transfer
    prior = v.exported(
        base / "native-sdk-transport-vm-results-025.tar",
        "d3825a288cd282ca7e5882bb2b15ded274ff0551340ba3a5c0a042aa72df14ac",
        44,
    )
    failed = v.parse(prior["proof/failed-attempt.json"])
    for n, pin in failed["original_worker_hashes"].items():
        assert v.sha(data["retained_failed_job/worker/" + n.split(".", 1)[1]]) == pin
    receipt_raw = data["retained_failed_job/worker/native-repair.json"]
    receipt = v.parse(receipt_raw)
    assert v.sha(
        receipt_raw
    ) == "618f53fbe80328d268bcd37f5e8a153f11b25286301ad6b7e00950160643e30e" and receipt_raw == v.canonical(receipt)
    assert (
        receipt["schema"] == "hol-gauntlet-native-worker-repair.v2"
        and receipt["status"] == "aborted"
        and receipt["exit_code"] is None
    )
    assert receipt["repair_generation"] == transfer["files"]["gauntlet-vm-worker"]["sha256"]
    assert receipt["started_marker_sha256"] == v.sha(prior["sdk_transport/worker/started.json"])
    assert receipt["running_marker_sha256"] == v.sha(prior["sdk_transport/worker/running.json"])
    assert receipt["preparation_sha256"] == v.sha(prior["sdk_transport/preparation.v1.json"])
    assert (
        receipt["model_requests"] == 0 and not receipt["execution_eligible"] and not receipt["guard_causality_verified"]
    )
    assert receipt["cleanup"]["sdk_agent_absent"] and receipt["cleanup"]["sdk_profile_absent"]
    q = receipt["cleanup"]["quiescent"]
    assert q["image_history"] == "already-closed-v1"
    assert q["image_events_sha256"] == v.sha(prior["sdk_transport/cell/native-image-events.v1.jsonl"])
    assert q["supervisor_events_sha256"] == v.sha(prior["sdk_transport/cell/native-supervisor-events.v1.jsonl"])
    assert q["runtime_tree_digest"] == v.TREE
    for suffix in ["wrong-generation", "wrong-started", "rust-lease-busy", "legacy-lease-busy"]:
        assert v.parse(data["proof/repair-" + suffix + ".json"])["returncode"] == 2
    for name in ["repair.json", "repair-reopen.json"]:
        r = v.parse(data["proof/" + name])
        assert r["returncode"] == 0 and r["stdout"].encode() == receipt_raw + b"\n"
    assert v.parse(data["prior_repair_attempt/repair.json"])["returncode"] == 2
    jobs = v.parse(data["proof/native-sdk-jobs.json"])
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-027.json")
    assert v.sha(prelaunch_raw) == "f910c1714cb320f3853cd5a6b3125a2f20134338fe4bd2509364703a2a5d5c94"
    assert v.parse(prelaunch_raw)["records"] == jobs["records"]
    proof = v.parse(data["proof/proof.json"])
    assert len(proof["worker_hashes"]) == 71
    expected = {
        **failed["prior_worker_hashes"],
        **failed["original_worker_hashes"],
        "e2c701baf1472501.native-repair.json": v.sha(receipt_raw),
    }
    assert len(expected) == 59 and jobs["prior_worker_hashes"] == expected
    assert all(proof["worker_hashes"][n] == h for n, h in expected.items())
    for role, pin in jobs["records"].items():
        stem = role + "/worker/"
        job = pin["job_id"]
        for suffix in [
            "started.json",
            "running.json",
            "report.json",
            "terminal.json",
            "native.stdout",
            "native.stderr",
        ]:
            assert v.sha(data[stem + suffix]) == proof["worker_hashes"][job + "." + suffix]
        report = v.parse(data[stem + "report.json"])
        terminal = v.parse(data[stem + "terminal.json"])
        assert (
            report["schema"] == "hol-gauntlet-native-worker-report.v3"
            and report["status"] == "invalid-evidence"
            and report["exit_code"] == 2
        )
        assert (
            report["sdk_agent_absent"]
            and report["sdk_profile_absent"]
            and not report["execution_eligible"]
            and report["model_requests"] == 0
        )
        assert terminal["report_sha256"] == v.sha(data[stem + "report.json"])
        assert (
            v.sha(data[role + "/preparation.v1.json"]) == pin["preparation_sha256"]
            and v.sha(data[role + "/declaration.json"]) == pin["deployment_sha256"]
        )
        if role == "sdk_transport":
            c = report["controller_report"]
            assert c["error"] == "SDK enforcing profile not observed" and c["status"] == "failed"
            assert (
                c["sdk_exercised"] is False
                and c["cell_cleanup_complete"]
                and c["prefix_unchanged"]
                and c["sdk_assets_unchanged"]
            )
            for name, h in transfer["public_helpers"].items():
                assert v.sha(data[role + "/public/" + name]) == h["sha256"]
            assert b"flags=(unconfined)" in data[role + "/agent.apparmor"]
            events = v.chain(data[role + "/cell/native-supervisor-events.v1.jsonl"])
            assert (
                events[-2]["kind"] == "terminal-cleanup"
                and events[-2]["data"]["failures"] == []
                and events[-1]["kind"] == "rust-image-cleanup"
            )
        else:
            assert role == "wrong_sdk_publication" and report["controller_report"] is None
        assert v.parse(data["proof/worker-" + role + "-replay.json"])["returncode"] == 2
        result = v.parse(data["proof/worker-" + role + "-reconcile.json"])
        assert result["returncode"] == 0 and v.parse(result["stdout"])["report_sha256"] == v.sha(
            data[stem + "report.json"]
        )
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "148", "0", "24"]]
    assert tests["gauntlet-rootfs-tests"]["results"] == [["ok", "1", "0", "0"], ["ok", "30", "0", "0"]]
    for name, r in tests.items():
        assert v.sha(data["proof/" + name + ".log"]) == r["sha256"]
    kernel = v.parse(data["proof/outside-kernel.json"])
    assert kernel["errors"] == [] and len(kernel["observations"]) == 15
    out = {
        "schema": "hol-gauntlet-host-native-sdk-repair-and-mode-refusal.v1",
        "source_commit": transfer["source_commit"],
        "export_members_verified": 83,
        "input_members_verified": 5,
        "repair_receipt_sha256": v.sha(receipt_raw),
        "original_failure_preserved": True,
        "worker_files_preserved": 71,
        "prior_worker_files_preserved": 59,
        "primary_status": "failed",
        "primary_reason": "SDK enforcing profile not observed",
        "wrong_sdk_publication_refused": True,
        "sdk_exercised": False,
        "model_requests": 0,
        "guard_causality_verified": False,
        "execution_eligible": False,
    }
    return out


def verify_028(base):
    data = v.exported(
        base / "native-sdk-transport-vm-results-028.tar",
        "ee7646a50e47859d550f1ee831d34c12155fd7b3c381c82c7fd8ac07ad6aa002",
        63,
    )
    inputs = v.archive(
        base / "native-sdk-transport-input-028.tar",
        "505b80be9772c958794911cd78939fd019be15f76ecf18b53ebed00c9f6bbde3",
        5,
    )
    transfer = v.parse(inputs.pop("transfer.json"))
    assert transfer["source_commit"] == "9e71be64ef89508794b8df64beb0904473049582"
    for n, raw in inputs.items():
        assert v.sha(raw) == transfer["files"][n]["sha256"] and len(raw) == transfer["files"][n]["bytes"]
    assert v.parse(data["input/transfer.json"]) == transfer
    failure = v.parse(data["proof/failed-attempt.json"])
    assert failure["worker_files"] == 75 and failure["never_started"] and failure["unknown_job_retained"]
    assert failure["container_id"] == "66712fa7af29a4df3e00330dd9400c8c1cd96f3693e652be8c2ff9e748303d06"
    prior = v.exported(
        base / "native-sdk-transport-vm-results-027.tar",
        "4000f12ed0e911013559eb2fc07e8865f22071e65874d8e8ec1e1bb665b92a0b",
        83,
    )
    assert (
        failure["prior_worker_hashes"] == v.parse(prior["proof/proof.json"])["worker_hashes"]
        and len(failure["prior_worker_hashes"]) == 71
    )
    for n, pin in failure["original_worker_hashes"].items():
        assert v.sha(data["sdk_transport/worker/" + n.split(".", 1)[1]]) == pin
    started = v.sha(data["sdk_transport/worker/started.json"])
    assert started == "31657a23c98737bf2d1a3ff29b1d6e574f4c97a485b872d00d61190039d95a9c"
    created = data["sdk_transport/sdk-processes/003.stdout"]
    captured = data["sdk_transport/sdk-processes/004.stdout"]
    assert (
        created == failure["container_id"].encode() + b"\n"
        and v.sha(created) == "a6bad3f7f8a2bfe47120637d042f518e919e7b598e532f5f38a6c6b1a8515a03"
    )
    assert v.sha(captured) == "35e994980e28768d91dcec205977dad23db1ab74f695c03184405b9f900f831e"
    value = v.parse(captured)[0]
    assert (
        value["Id"] == failure["container_id"]
        and value["State"]["Status"] == "created"
        and value["State"]["Pid"] == 0
        and value["State"]["Running"] is False
    )
    assert value["State"]["StartedAt"] == value["State"]["FinishedAt"] == "0001-01-01T00:00:00Z"
    assert (
        value["Config"]["Labels"]["hol.gauntlet.sdk.job"] == failure["job_id"]
        and value["Config"]["User"] == "10001:10001"
    )
    assert value["BoundingCaps"] is None and value["EffectiveCaps"] is None and value["HostConfig"]["CapAdd"] == []
    assert len(value["HostConfig"]["CapDrop"]) == len(set(value["HostConfig"]["CapDrop"])) == 11
    assert set(value["HostConfig"]["CapDrop"]) == set(
        [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT",
        ]
    )
    assert value["HostConfig"]["ReadonlyRootfs"] and value["HostConfig"]["NetworkMode"] == "none"
    assert (
        value["HostConfig"]["Memory"] == 2147483648
        and value["HostConfig"]["PidsLimit"] == 256
        and value["HostConfig"]["NanoCpus"] == 2000000000
    )
    controller = v.parse(data["sdk_transport/worker/native.stdout"])
    assert controller["status"] == "failed" and controller["error"].startswith(
        "SDK must drop every capability; SDK cleanup uncertain"
    )
    assert (
        not controller["sdk_exercised"]
        and controller["cell_cleanup_complete"]
        and controller["prefix_unchanged"]
        and controller["sdk_assets_unchanged"]
    )
    assert (
        not controller["execution_eligible"]
        and not controller["guard_causality_verified"]
        and controller["model_requests"] == 0
    )
    jobs = v.parse(data["proof/native-sdk-jobs.json"])
    pin = jobs["records"]["sdk_transport"]
    assert (
        v.sha(data["sdk_transport/preparation.v1.json"]) == pin["preparation_sha256"]
        and v.sha(data["sdk_transport/declaration.json"]) == pin["deployment_sha256"]
    )
    prelaunch_raw = v.stable(base / "native-sdk-transport-host-prelaunch-028.json")
    assert v.sha(prelaunch_raw) == "35a8cefea827064aa5cf1c384bafcfaae556e59f071fc82b01869dbe9eadd14e"
    assert v.parse(prelaunch_raw)["records"] == jobs["records"]
    for name, p in transfer["public_helpers"].items():
        assert v.sha(data["sdk_transport/sdk-public/" + name]) == p["sha256"]
    events = v.chain(data["sdk_transport/cell/native-supervisor-events.v1.jsonl"])
    assert (
        events[-2]["kind"] == "terminal-cleanup"
        and events[-2]["data"]["failures"] == []
        and events[-1]["kind"] == "rust-image-cleanup"
    )
    tests = v.parse(data["proof/root-tests.json"])
    assert tests["gauntlet-worker-tests"]["results"] == [["ok", "149", "0", "24"]]
    assert tests["gauntlet-rootfs-tests"]["results"] == [["ok", "1", "0", "0"], ["ok", "30", "0", "0"]]
    for n, r in tests.items():
        assert v.sha(data["proof/" + n + ".log"]) == r["sha256"]
    out = {
        "schema": "hol-gauntlet-host-native-sdk-created-failure.v1",
        "source_commit": transfer["source_commit"],
        "export_members_verified": 63,
        "input_members_verified": 5,
        "job_id": failure["job_id"],
        "started_marker_sha256": started,
        "original_worker_hashes": failure["original_worker_hashes"],
        "container_id": failure["container_id"],
        "creation_sha256": v.sha(created),
        "inspection_sha256": v.sha(captured),
        "worker_files_preserved": 75,
        "prior_worker_files_preserved": 71,
        "never_started": True,
        "unknown_job": True,
        "sdk_exercised": False,
        "guard_causality_verified": False,
        "execution_eligible": False,
        "model_requests": 0,
    }
    return out
