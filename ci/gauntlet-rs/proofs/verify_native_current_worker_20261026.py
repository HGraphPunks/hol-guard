#!/usr/bin/env python3
"""Read the retained current Native apparatus proof; never execute or admit it."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import stat
import struct
import tarfile
from pathlib import Path

SOURCE = "62aa7ba777a5a4cc0806c34ee94e9822eaa58d32"
RUST_SOURCE = "c3a75ccd632164d6ab83f260905680add1f8b368"
GENERATION = "b5cc9abd683d1cd475eb1c84a8b8157e090da2c0b9f6b1299d7203fd0f65ec95"
ACTOR = "d772b65b17dc0b1605ec9f53a53a9aa36554a2b9ec8313b1348dd86d3c935fb8"
INITIALIZER = "06b04ba359e4e0e0173aeb4015447b972ed8f8ac1f2a1ba10637502cd43c8568"
TREE = "cd092b3c0658a3aee2b436b3e4f3639627f244190ef255e1e3463487b6621637"
MANIFEST = "64fa2a14251571ecf28e89fd71b9fad19bb98d384a4966f60a71c44a08ba4fee"
JOBS = {
    "success": ("e2c701baf1471901", "3811b3850014643bf93f252f41ba3d10e3f943d2ad4107ba8c07f6e4ec6f2634"),
    "timeout": ("e2c701baf1471902", "aa4914c1898ad3e1736039a7a60f4f63f22e7dc50d620227f3a7359f3f61f4bb"),
    "cancel": ("e2c701baf1471903", "8582852bbcbd746e3b5e46fe38f59bbd7a541e6586c163cab44e9eac38c856f0"),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def unique(pairs):
    value = {}
    for key, child in pairs:
        assert key not in value, "duplicate JSON key"
        value[key] = child
    return value


def parse(raw):
    def reject_constant(_):
        raise ValueError("nonfinite JSON")

    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject_constant)


def stable(path, maximum=128 * 1024**2):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum
        raw = stream.read(maximum + 1)

        def key(s):
            return (
                s.st_dev,
                s.st_ino,
                s.st_mode,
                s.st_uid,
                s.st_gid,
                s.st_nlink,
                s.st_size,
                s.st_mtime_ns,
                s.st_ctime_ns,
            )

        assert key(before) == key(os.fstat(stream.fileno())) == key(path.lstat())
        assert len(raw) == before.st_size
    return raw


def archive(path, digest, count):
    raw = stable(path)
    assert sha(raw) == digest
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as source:
        members = source.getmembers()
        assert len(members) == count and len({m.name for m in members}) == count
        assert all(
            m.isfile() and 0 <= m.size <= 32 * 1024**2 and not m.name.startswith("/") and ".." not in m.name.split("/")
            for m in members
        )
        return {m.name: source.extractfile(m).read() for m in members}


def exported(path, digest, count):
    data = archive(path, digest, count)
    manifest = parse(data.pop("results.sha256.json"))
    assert set(data) == set(manifest["files"])
    for name, pin in manifest["files"].items():
        assert len(data[name]) == pin["bytes"] and sha(data[name]) == pin["sha256"]
        assert "controller-key" not in name and "/state/" not in name
    return data


def chain(raw):
    rows = [parse(line) for line in raw.splitlines()]
    previous = "0" * 64
    assert 1 <= len(rows) <= 10000
    for index, row in enumerate(rows):
        assert row["sequence"] == index and row["previous_sha256"] == previous
        previous = sha(canonical(row))
    return rows


def actor_identity(actor):
    assert actor["executable_sha256"] == ACTOR
    assert actor["argv"] == ["/public/gauntlet-product-cell", "actor"]
    status = actor["status"]
    assert all(status[k] == "0000000000000000" for k in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"])
    assert status["Uid"] == status["Gid"] == "10004\t10004\t10004\t10004"
    assert status["Groups"] == "" and status["NoNewPrivs"] == "1"
    assert status["Seccomp"] == status["Seccomp_filters"] == "2"
    assert actor["lsm_label"].endswith(" (enforce)")
    assert actor["network"]["interfaces"] == ["lo"]
    assert len(actor["network"]["ipv4_routes"].splitlines()) == 1


def verify_case(data, case):
    job, report_pin = JOBS[case]
    prefix = case + "/worker/"
    report_raw = data[prefix + "report.json"]
    report = parse(report_raw)
    started_raw = data[prefix + "started.json"]
    started = parse(started_raw)
    running = parse(data[prefix + "running.json"])
    terminal = parse(data[prefix + "terminal.json"])
    assert sha(report_raw) == report_pin
    for value in [report, started, running, terminal]:
        assert value["source_sha"] == SOURCE and value["job_id"] == job and value["worker_generation"] == GENERATION
    for value in [report, running, terminal]:
        assert value["started_marker_sha256"] == sha(started_raw)
        assert value["deployment_digest"] == started["deployment_digest"]
    assert sha(data[case + "/declaration.json"]) == started["deployment_digest"]
    assert sha(data[case + "/preparation.v1.json"]) == report["preparation_sha256"]
    assert report["controller"] == {"pid": running["pid"], "start_ticks": running["process_start_ticks"]}
    assert terminal["pid"] == running["pid"] and terminal["process_start_ticks"] == running["process_start_ticks"]
    assert terminal["report_sha256"] == report_pin and report["exit_code"] == terminal["exit_code"] == 0
    assert report["status"] == terminal["status"] == "invalid-evidence"
    assert all(report[k] is True for k in ["controller_cgroup_drained", "product_slice_absent", "image_lease_absent"])
    assert (
        report["execution_eligible"] is False
        and report["guard_causality_verified"] is False
        and report["model_requests"] == 0
    )
    assert sha(data[prefix + "native.stdout"]) == report["controller_stdout_sha256"]
    assert data[prefix + "native.stderr"] == b"" and sha(b"") == report["controller_stderr_sha256"]
    control = parse(data[prefix + "native.stdout"])
    assert report["controller_report"] == control
    assert control["case"] == case and control["status"] == "passed"
    assert all(
        control[k] is True
        for k in ["native_daemon_started", "cell_cleanup_complete", "rust_image_lease_owned", "rust_supervisor_owned"]
    )
    assert control["error"] is None and control["cleanup_error"] is None
    actor_identity(control["actor"])
    assert data[case + "/effect.bin"] == b"Rust supervisor released\n"
    assert sha(data[case + "/cell/cell-artifact-manifest.json"]) == MANIFEST
    rows = chain(data[case + "/cell/native-supervisor-events.v1.jsonl"])
    image = chain(data[case + "/cell/native-image-events.v1.jsonl"])
    assert any(r["kind"] == "image-cleanup" and r["data"]["owned_mount_absent"] is True for r in image)
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
        if row["kind"] == "capture-terminal":
            capture = {}
            for stream, pin in row["data"]["files"].items():
                raw = data[case + "/cell/" + pin["file"]]
                assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]
                capture[stream] = raw
            captures.append((row["data"], capture))
    assert any(
        c["returncode"] == 0 and parse(raw["stdout"]).get("running") is True
        for c, raw in captures
        if raw["stdout"].startswith(b"{")
    )
    if case == "success":
        assert any(
            c["returncode"] == 0
            and raw == {"stdout": b"Rust supervisor binary stdin\x00\xff\n", "stderr": b"Rust stderr\n"}
            for c, raw in captures
        )
    else:
        assert any(c["returncode"] is None and case.replace("timeout", "deadline") in c["error"] for c, _ in captures)
        observed = parse(data["proof/outside-" + case + ".json"])
        assert observed["errors"] == [] and len(observed["observations"]) == 1
        outside = observed["observations"][0]
        assert outside["pidfd_held"] is True
        assert all(outside[k] == control["actor"][k] for k in ["pid", "start_ticks", "executable_sha256", "cgroup"])
        assert outside["limits"] == {"memory.max": "1073741824", "pids.max": "128", "cpu.max": "100000 100000"}
        assert outside["status"]["Seccomp"] == outside["status"]["Seccomp_filters"] == "2"
        assert all(
            outside["namespaces"][k] != outside["outside_namespaces"][k] for k in outside["namespaces"] if k != "user"
        )
    for action in ["replay-v3", "reconcile-v3"]:
        response = parse(data["proof/worker-" + case + "-" + action + ".json"])
        if action.startswith("replay"):
            assert response["returncode"] == 2
        else:
            value = parse(response["stdout"])
            assert response["returncode"] == 0 and value["report_sha256"] == report_pin and value["state"] == "terminal"
    return {"job_id": job, "report_sha256": report_pin, "controller_exit_code": 0}


def verify(args):
    data = exported(args.export, "a31d0ec9eccc8d80c5e4c696103b8fc6d7afa22b4c3ed500e27b87e77a6f9610", 117)
    prior = exported(args.runtime_publication, "22d3eb8c01e63e01b36c63b130491049295dea0599ea4e1990da855bca17e161", 23)
    failed = exported(args.failed_attempt, "ea46f25d92e877aeaa9c0ae0ccb96bc612459dbc1986e6e5feb46cea251b5a6b", 24)
    inputs = archive(args.input, "03f5e9705e896bf2d4be22923018fe0facab558b429005aae5716e00dddc9d6e", 10)
    transfer = parse(inputs["transfer.json"])
    assert transfer["source_commit"] == RUST_SOURCE and transfer["actor_target"] == "aarch64-unknown-linux-gnu"
    for name, pin in transfer["files"].items():
        assert len(inputs[name]) == pin["bytes"] and sha(inputs[name]) == pin["sha256"]
    assert (
        sha(inputs["gauntlet-vm-worker"]) == GENERATION
        and sha(inputs["gauntlet-product-cell"]) == ACTOR
        and sha(inputs["initializer"]) == INITIALIZER
    )
    actor = inputs["gauntlet-product-cell"]
    assert actor[:7] == b"\x7fELF\x02\x01\x01" and actor[18:20] == b"\xb7\x00" and len(actor) <= 2 * 1024**2
    start = struct.unpack_from("<Q", actor, 32)[0]
    size, count = struct.unpack_from("<HH", actor, 54)
    assert size == 56 and 1 <= count <= 128
    interpreters = []
    for n in range(count):
        offset = start + n * size
        if struct.unpack_from("<I", actor, offset)[0] == 3:
            position, length = (
                struct.unpack_from("<Q", actor, offset + 8)[0],
                struct.unpack_from("<Q", actor, offset + 32)[0],
            )
            interpreters.append(actor[position : position + length])
    assert interpreters == [b"/lib/ld-linux-aarch64.so.1\0"]
    assert data["input/transfer.json"] == inputs["transfer.json"]
    tree = parse(data["proof/published-prefix-post-tree.json"])
    assert tree == parse(prior["proof/published-prefix-tree.json"])
    assert len(tree["rows"]) == 4412 and tree["bytes"] == 117018419 and sha(canonical(tree["rows"])) == TREE
    assert data["runtime/native-runtime.v1.json"] == prior["runtime/native-runtime.v1.json"]
    proof = parse(data["proof/proof.json"])
    assert proof["source_commit"] == RUST_SOURCE and proof["published_prefix_entries"] == 4411
    for suffix in ["started.json", "running.json", "report.json", "terminal.json", "native.stdout", "native.stderr"]:
        key = "e2c701baf1471801." + suffix
        assert proof["original_worker_hashes"][key] == sha(failed["worker/" + key])
    cases = {name: verify_case(data, name) for name in JOBS}
    cleanup = parse(data["proof/outside-final-cleanup.json"])
    assert cleanup["containers"] == cleanup["mounted_images"] == [] and cleanup["exact_image_pointer_absent"] is True
    assert b"135 passed; 0 failed; 24 ignored" in data["proof/gauntlet-worker-tests.log"]
    assert b"59 passed; 0 failed; 0 ignored" in data["proof/gauntlet-evidence-tests-portable.log"]
    assert b"23 passed; 0 failed; 0 ignored" in data["proof/gauntlet-rootfs-tests.log"]
    assert b"57 passed; 2 failed; 0 ignored" in data["proof/gauntlet-evidence-tests.log"]
    for name in [
        "actor-wrong-hash",
        "actor-static-abi",
        "artifacts-static-abi",
        "artifacts-wrong-map",
        "artifacts-replay",
        "worker-wrong-generation",
        "worker-wrong-source",
        "worker-rust-lease-busy",
        "worker-legacy-lease-busy",
    ]:
        assert parse(data["proof/" + name + ".json"])["returncode"] == 2
    assert parse(data["proof/worker-cancel-reconcile.json"])["returncode"] == 2
    return {
        "schema": "hol-gauntlet-host-current-native-worker-verification.v1",
        "all_117_export_members_verified": True,
        "all_10_input_members_verified": True,
        "cases": cases,
        "unchanged_prefix_entries_excluding_root": 4411,
        "prefix_tree_sha256": TREE,
        "live_outside_kernel_cases": ["timeout", "cancel"],
        "failed_attempt_and_adapter_errors_retained": True,
        "root_worker_tests_passed": 135,
        "root_worker_fixture_ignores": 24,
        "root_evidence_tests_passed": 59,
        "rootfs_tests_passed": 23,
        "rootfs_subprocess_tests_passed": 1,
        "artifact_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


def main():
    if not __debug__:
        raise SystemExit("run this proof reader without Python optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["export", "input", "runtime-publication", "failed-attempt"]:
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args)
    raw = json.dumps(result, sort_keys=True, indent=2) + "\n"
    if args.output:
        with args.output.open("x") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")


if __name__ == "__main__":
    main()
