#!/usr/bin/env python3
"""Read the retained 021-023 Native transport attempts; never execute or admit them."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from verify_native_current_worker_20261026 import archive, canonical, chain, exported, parse, sha, stable

SOURCE = "62aa7ba777a5a4cc0806c34ee94e9822eaa58d32"
ACTOR = "86d29b8438b21521cdbcd97d60255a3ad4a2f7d63170a3d4ec3d2fdae7a8d401"
NATIVE = "1632de1167b167ffe05d02ab4f2cdf157d9328addfcc054ceeffef640b8b9489"
TREE = "cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637"
MANIFEST = "ef1233cb348ad3b6de236510532391c41b9b14e0b2ffdcc5568e8fdcf2f88968"
READY = {
    "ready": True,
    "native_required": True,
    "native_route": "native_resident",
    "workspace_acknowledged": True,
    "worker_ready": True,
}
GROUPS = {
    "021": {
        "source": "e1eb0a1a567078d44ec57fd4bb852a897aa79ae6",
        "generation": "bb152f5daf8d308029945c10612ac749a2bd28ec37fe888a85b76a8512fbe1fe",
        "input": "d930654c77b63a8ef81382eef8880193409f5f9486a85fe599dbf8456bc51c3a",
        "export": "cd3ee0eaf1c21a79396e21773b3c568abea7b6cb04668545e45aa431759bf098",
        "members": 103,
        "host": "be5b8136ead827335ec39c4180c44c93d11c073a32012dbc263132425730e943",
        "jobs": {
            "hook_transport": (
                "e2c701baf1472101",
                2,
                "7d1375965821c807cf5b31da8c67bd10166e38ccf092f1e6fe039f91e892f401",
            ),
            "apparatus_success": (
                "e2c701baf1472102",
                0,
                "5acde75e9d8664164cfc8802841bfb12d01ec99edcabecd459b6a29c3b04504d",
            ),
            "wrong_native": ("e2c701baf1472103", 2, "bf902bdaa92285a35cc2848184e0a8f73410b8e6c181edde00d33b274925e663"),
        },
    },
    "022": {
        "source": "119f51b46e340069ee532417178d18bb01bcf361",
        "generation": "4ad1258498560141b8f76162a0568c5efd9d23ada498d9c160298dfe55abec96",
        "input": "fc1a05d45047a8158696b553ca3be049d0b9171a156593320a3c1d0a7547fc92",
        "export": "0b19b236be6cb9589480d62222418070e325265f103c49efd8e12cd50ed4a5c6",
        "members": 51,
        "host": "e4885061552999222d36436595796d00e540a84086850e33ad4e506b5286081e",
        "jobs": {
            "hook_transport": (
                "e2c701baf1472201",
                2,
                "c5ee8ebfebda35c529351a2b750253aaf7481f0897be1988369cde44288db147",
            )
        },
    },
    "023": {
        "source": "6b901e2a8770bafacfb60186dc8eda28523ac540",
        "generation": "c832f31fafa5351c3480baf6c731a9494e65354a4c2815f970cd92c2bf2c1dbf",
        "input": "abb29244ebeca7708517cafc00a5fc5fa617d58e5d8df5c96cb5072205aab47d",
        "export": "01c1a8d8f6f354367439e8afdc48ae13a3b3a1a69f031a57e559ceb1883f76a6",
        "members": 56,
        "host": "32b99f31106f2ac1a8c2a68911aa0fd91ac45e8144df654594853a9970a23a42",
        "jobs": {
            "hook_transport": (
                "e2c701baf1472301",
                0,
                "3b3853391d228be0715da9bfca74958b2dfc4561b544fda44e8e8d90f1dfdf9f",
            )
        },
    },
}


def read_cell(data, case):
    prefix = case + "/cell/"
    assert sha(data[prefix + "cell-artifact-manifest.json"]) == MANIFEST
    rows = chain(data[prefix + "native-supervisor-events.v1.jsonl"])
    images = chain(data[prefix + "native-image-events.v1.jsonl"])
    assert any(r["kind"] == "image-cleanup" and r["data"]["owned_mount_absent"] is True for r in images)
    assert any(
        r["kind"] == "terminal-cleanup"
        and r["data"] == {"cgroup_absent": True, "failures": [], "rootfs_mount_absent": True}
        for r in rows
    )
    assert any(
        r["kind"] == "rust-image-cleanup" and r["data"] == {"active_lease_removed": True, "image_mount_absent": True}
        for r in rows
    )
    captures = []
    for row in rows:
        if row["kind"] != "capture-terminal":
            continue
        record = row["data"]
        streams = {}
        for stream, pin in record["files"].items():
            raw = data[prefix + pin["file"]]
            assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]
            streams[stream] = raw
        captures.append((record, streams))
    return captures


def outside(data):
    value = parse(data["proof/outside-kernel.json"])
    assert value["errors"] == [] and 1 <= len(value["observations"]) <= 64
    images = set()
    for row in value["observations"]:
        assert row["pidfd_held"] is True and row["pid"] > 0 and row["start_ticks"] > 0
        assert row["limits"] == {"memory.max": "1073741824", "pids.max": "128", "cpu.max": "100000 100000"}
        status = row["status"]
        assert status["Uid"] == status["Gid"] == "10004\t10004\t10004\t10004"
        assert status["Groups"] == "" and status["NoNewPrivs"] == "1"
        assert status["Seccomp"] == status["Seccomp_filters"] == "2"
        assert all(status[k] == "0000000000000000" for k in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
        assert row["lsm_label"].endswith(" (enforce)") and len(row["namespaces"]) == 7
        images.add(row["executable_sha256"])
    assert images == {ACTOR, NATIVE}
    return len(value["observations"])


def worker(data, case, pin, generation):
    job, exit_code, report_pin = pin
    prefix = case + "/worker/"
    report = parse(data[prefix + "report.json"])
    started_raw = data[prefix + "started.json"]
    started = parse(started_raw)
    running = parse(data[prefix + "running.json"])
    terminal = parse(data[prefix + "terminal.json"])
    assert sha(data[prefix + "report.json"]) == report_pin
    for row in [report, started, running, terminal]:
        assert row["source_sha"] == SOURCE and row["job_id"] == job and row["worker_generation"] == generation
    for row in [report, running, terminal]:
        assert row["started_marker_sha256"] == sha(started_raw)
        assert row["deployment_digest"] == started["deployment_digest"]
    declaration = parse(data[case + "/declaration.json"])
    assert sha(data[case + "/declaration.json"]) == started["deployment_digest"]
    assert sha(data[case + "/preparation.v1.json"]) == declaration["preparation_sha256"] == report["preparation_sha256"]
    assert report["controller"] == {"pid": running["pid"], "start_ticks": running["process_start_ticks"]}
    assert terminal["pid"] == running["pid"] and terminal["process_start_ticks"] == running["process_start_ticks"]
    assert report["status"] == terminal["status"] == "invalid-evidence"
    assert report["exit_code"] == terminal["exit_code"] == exit_code and terminal["report_sha256"] == report_pin
    assert all(report[k] is True for k in ["controller_cgroup_drained", "product_slice_absent", "image_lease_absent"])
    assert report["execution_eligible"] is report["guard_causality_verified"] is False and report["model_requests"] == 0
    for stream in ["stdout", "stderr"]:
        assert sha(data[prefix + "native." + stream]) == report["controller_" + stream + "_sha256"]
    control = parse(data[prefix + "native.stdout"])
    assert control == report["controller_report"] and control["cell_cleanup_complete"] is True
    actor = control["actor"]
    assert actor["executable_sha256"] == ACTOR and actor["argv"] == ["/public/gauntlet-product-cell", "actor"]
    assert actor["network"]["interfaces"] == ["lo"]
    assert actor["status"]["Seccomp"] == actor["status"]["Seccomp_filters"] == "2"
    for action in ["replay", "reconcile"]:
        response = parse(data["proof/worker-" + case + "-" + action + ".json"])
        assert response["returncode"] == (2 if action == "replay" else 0)
        if action == "reconcile":
            value = parse(response["stdout"])
            assert (
                value["state"] == "terminal"
                and value["report_sha256"] == report_pin
                and value["exit_code"] == exit_code
            )
    return control, read_cell(data, case)


def passed_transport(control, captures, data):
    assert control["status"] == "passed" and control["error"] is None and control["effect_error"] is None
    measurements = control["measurements"]
    assert measurements["prompt"]["decision"] == "allow"
    pre = measurements["pre"]
    assert pre["decision"] == "deny" and pre["policy_action"] == "sandbox-required"
    assert pre["required_execution_profile"] == "workspace-contained-v1"
    assert measurements["post"]["decision"] == "allow" and all(measurements["replay_refusals"].values())
    plane = control["plane"]
    assert len(plane["hooks"]) == 3 and len(plane["executions"]) == 1
    prompt, before, after = plane["hooks"]
    assert [r["hook_event_name"] for r in plane["hooks"]] == ["UserPromptSubmit", "PreToolUse", "PostToolUse"]
    assert prompt["response"] == measurements["prompt"] and before["response"] == pre
    assert after["response"] == measurements["post"]
    for row in plane["hooks"]:
        assert row["payload_digest"] == sha(canonical(row["payload"])) and row["normalization_error"] is None
        assert any(
            sha(streams["stdout"]) == row["stdout_sha256"]
            and sha(streams["stderr"]) == row["stderr_sha256"]
            and capture["returncode"] == row["returncode"]
            for capture, streams in captures
        )
    active = {
        "HOME": "/product/home",
        "LANG": "C.UTF-8",
        "MALLOC_ARENA_MAX": "2",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    env = before["payload"]["guard_execution_environment"]
    assert env["environment_digest"] == sha(canonical(active)) and env["environment_names"] == sorted(active)
    assert env["path"] == active["PATH"] and env["home"] == active["HOME"]
    sink = measurements["sink"]
    assert (
        sink == plane["executions"][0] and sink["exit_code"] == 0 and sink["payload_digest"] == before["payload_digest"]
    )
    packet = {
        "schema": "guard-contained-test-request.v1",
        "workspace": "/runtime/home/project",
        "payload": before["payload"],
    }
    assert sink["request_sha256"] == sha(canonical(packet))
    for stream in ["stdout", "stderr"]:
        assert sha(sink[stream].encode()) == sink[stream + "_sha256"]
    assert any(
        capture["returncode"] == 0 and streams == {"stdout": sink["stdout"].encode(), "stderr": sink["stderr"].encode()}
        for capture, streams in captures
    )
    text = f"Exit code: 0\nSTDOUT:\n{sink['stdout']}\nSTDERR:\n{sink['stderr']}"
    output = measurements["captured_output"]
    assert output == {
        "schema": "controller-contained-output.v1",
        "is_error": False,
        "tool_response": [{"type": "text", "text": text}],
        "result_digest": sha(canonical(sink)),
        "output_sha256": sha(text.encode()),
    }
    post = after["payload"]
    assert post["tool_input"] == before["payload"]["tool_input"] and post["tool_response"] == output["tool_response"]
    assert post["is_error"] is False and after["response"]["reviewed_output_sha256"] == output["output_sha256"]
    handoffs = [row for row in plane["observations"] if row["kind"] == "native-contained-request-handoff"]
    assert len(handoffs) == 1 and handoffs[0]["cleanup_complete"] is True
    assert handoffs[0]["request"]["sha256"] == sink["request_sha256"]
    assert data["hook_transport/effect.bin"] == b"private plane effect"
    assert control["effect"]["sha256"] == sha(data["hook_transport/effect.bin"])
    assert control["effect"]["uid"] == control["effect"]["gid"] == 10001 and control["effect"]["bytes"] == 20
    node = parse(data["hook_transport/node-runtime-control.json"])
    assert node["node_version"] == "v22.22.2" and node["npm_version"] == "10.9.7" and node["node_is_symlink"] is False
    assert node["node_sha256"] == "3159f9115ab4be7d318b7c28e946837a4dceb7f2b3c43232aa2f2e3852550b90"


def verify(root):
    publication = exported(
        root / "native-runtime-publication-vm-results-017.tar",
        "22d3eb8c01e63e01b36c63b130491049295dea0599ea4e1990da855bca17e161",
        23,
    )
    previous = exported(
        root / "native-current-worker-vm-results-019.tar",
        "a31d0ec9eccc8d80c5e4c696103b8fc6d7afa22b4c3ed500e27b87e77a6f9610",
        117,
    )
    prior_hashes = parse(previous["proof/proof.json"])["original_worker_hashes"]
    assert len(prior_hashes) == 24
    results = {}
    for label, group in GROUPS.items():
        data = exported(root / f"native-hook-transport-vm-results-{label}.tar", group["export"], group["members"])
        inputs = archive(root / f"native-hook-transport-input-{label}.tar", group["input"], 11)
        transfer = parse(inputs["transfer.json"])
        assert transfer["source_commit"] == group["source"] and data["input/transfer.json"] == inputs["transfer.json"]
        for name, pin in transfer["files"].items():
            assert len(inputs[name]) == pin["bytes"] and sha(inputs[name]) == pin["sha256"]
        assert (
            sha(inputs["gauntlet-vm-worker"]) == group["generation"] and sha(inputs["gauntlet-product-cell"]) == ACTOR
        )
        prelaunch_raw = stable(root / f"native-hook-transport-host-prelaunch-{label}.json")
        assert sha(prelaunch_raw) == group["host"]
        host = parse(prelaunch_raw)
        assert host["rust_source_commit"] == group["source"] and host["input_archive_sha256"] == group["input"]
        assert host["jobs"] == parse(data["proof/native-hook-jobs.json"])["records"]
        assert host["job_execution_requested"] is host["controller_signing_key_pinned"] is False
        proof = parse(data["proof/proof.json"])
        assert proof["source_commit"] == group["source"] and proof["prior_worker_hashes"] == prior_hashes
        tests = parse(data["proof/root-library-results.json"])
        assert tests["status"] == "passed"
        for name, result in tests["results"].items():
            log = data["proof/" + name + ".log"]
            assert result["returncode"] == 0 and sha(log) == result["sha256"] and len(log) == result["bytes"]
        assert b"136 passed; 0 failed; 24 ignored" in data["proof/gauntlet-worker-tests.log"]
        tree = parse(data["proof/published-prefix-post-tree.json"])
        assert tree == parse(publication["proof/published-prefix-tree.json"])
        assert len(tree["rows"]) == 4412 and tree["bytes"] == 117018419 and sha(canonical(tree["rows"])) == TREE
        assert data["runtime/native-runtime.v1.json"] == publication["runtime/native-runtime.v1.json"]
        group_results = {}
        for case, pin in group["jobs"].items():
            control, captures = worker(data, case, pin, group["generation"])
            job, exit_code, report_pin = pin
            for suffix in [
                "started.json",
                "running.json",
                "report.json",
                "terminal.json",
                "native.stdout",
                "native.stderr",
            ]:
                assert proof["original_worker_hashes"][job + "." + suffix] == sha(data[case + "/worker/" + suffix])
            if case == "apparatus_success":
                assert control["status"] == "passed" and control["native_daemon_started"] is True
                assert data[case + "/effect.bin"] == b"Rust supervisor released\n"
            else:
                assert control["prefix_unchanged"] is True and control["sdk_exercised"] is False
                assert control["guard_causality_verified"] is False and control["artifact_admitted"] is False
                if case == "wrong_native":
                    assert control["error"] == "installed metadata differs from outside pins"
                    assert not captures and not control["plane"]["hooks"] and not control["plane"]["executions"]
                elif label == "021":
                    assert control["error"] == "Native workspace readiness adapter failed"
                    assert any(
                        c["returncode"] == 69
                        and parse(s["stdout"]) == {"ready": False, "reason_code": "invalid_workspace"}
                        for c, s in captures
                        if s["stdout"].startswith(b"{")
                    )
                    assert not control["plane"]["hooks"] and not control["plane"]["executions"]
                elif label == "022":
                    assert control["error"] == "Native response does not supply an unused contained route"
                    assert any(
                        c["returncode"] == 0 and parse(s["stdout"]) == READY
                        for c, s in captures
                        if s["stdout"].startswith(b"{")
                    )
                    assert control["measurements"]["pre"]["reason_code"] == "native_pre_tool_unavailable"
                    assert control["plane"]["hooks"][1]["payload"]["guard_execution_environment"] == {}
                    assert not control["plane"]["executions"]
                else:
                    passed_transport(control, captures, data)
            group_results[case] = {"job_id": job, "report_sha256": report_pin, "controller_exit_code": exit_code}
        assert len(proof["original_worker_hashes"]) == len(group["jobs"]) * 6
        prior_hashes = {**prior_hashes, **proof["original_worker_hashes"]}
        cleanup = parse(data["proof/outside-final-cleanup.json"])
        assert (
            cleanup["containers"] == cleanup["mounted_images"] == [] and cleanup["exact_image_pointer_absent"] is True
        )
        results[label] = {
            "cases": group_results,
            "outside_process_samples": outside(data),
            "export_members_verified": group["members"],
            "input_members_verified": 11,
        }
    assert len(prior_hashes) == 54
    return {
        "schema": "hol-gauntlet-host-native-hook-transport-verification.v1",
        "groups": results,
        "earlier_worker_files_preserved": 48,
        "unchanged_prefix_entries_excluding_root": 4411,
        "prefix_tree_sha256": TREE,
        "failed_attempts_retained": True,
        "sdk_exercised": False,
        "product_claims_authenticated": False,
        "controller_signing_key_pinned": False,
        "guard_causality_verified": False,
        "artifact_admitted": False,
        "execution_eligible": False,
        "model_requests": 0,
    }


def main():
    if not __debug__:
        raise SystemExit("run this retained proof reader without Python optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw = json.dumps(verify(args.evidence_dir), sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()
