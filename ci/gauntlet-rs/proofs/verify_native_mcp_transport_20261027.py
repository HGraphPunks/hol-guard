"""Independent public-artifact readback; never admit a benchmark or Guard verdict."""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import sys
import tarfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    value = {}
    for key, item in pairs:
        assert key not in value, key
        value[key] = item
    return value


def parse(raw):
    return json.loads(
        raw, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value))
    )


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def digest(value) -> str:
    return sha(canonical(value))


def archive(path: Path, pin: str, size: int, count: int) -> dict[str, bytes]:
    raw = path.read_bytes()
    assert len(raw) == size and sha(raw) == pin, path.name
    with tarfile.open(path, mode="r:") as tar:
        members = tar.getmembers()
        assert len(members) == count and len({m.name for m in members}) == count
        assert all(
            m.isfile() and not m.name.startswith("/") and ".." not in Path(m.name).parts and 0 <= m.size <= 32 * 1024**2
            for m in members
        )
        files = {m.name: tar.extractfile(m).read() for m in members}
    if "results.sha256.json" in files:
        index = parse(files["results.sha256.json"])
        assert set(index["files"]) == set(files) - {"results.sha256.json"}
        for name, pin in index["files"].items():
            assert pin == {"bytes": len(files[name]), "sha256": sha(files[name])}, name
    return files


def ineligible(value):
    assert value["execution_eligible"] is False and value["model_requests"] == 0
    if "guard_causality_verified" in value:
        assert value["guard_causality_verified"] is False


def lines(raw: bytes):
    assert raw.endswith(b"\n")
    return [parse(line) for line in raw.splitlines()]


def observed_process(process, samples, expected_argv):
    identity = process["identity"]
    assert process["held_executable_and_argv_verified"] is True
    assert process["socket_peer_bound"] is True
    assert process["execution_eligible"] is False
    assert process["guard_causality_verified"] is False
    matches = [
        sample
        for sample in samples
        if sample["pid"] == identity["pid"]
        and sample["start_ticks"] == identity["start_ticks"]
        and sample["argv_sha256"] == process["argv_sha256"]
        and sample["executable_sha256"] == process["executable_sha256"]
    ]
    assert matches, identity["pid"]
    for sample in matches:
        assert sample["argv_utf8"].split("\0") == [*expected_argv, ""]
        assert sha(sample["argv_utf8"].encode()) == sample["argv_sha256"]
        assert sample["pidfd_held"] and sample["cgroup"] == identity["cgroup"]
        assert sample["lsm_label"] == identity["lsm_label"]
        assert sample["lsm_label"].startswith("crun//&hol-gauntlet-mcp-")
        assert sample["lsm_label"].endswith(" (unconfined)")
        assert sample["limits"] == {"cpu.max": "100000 100000", "memory.max": "1073741824", "pids.max": "256"}
        for name, inode in sample["namespaces"].items():
            assert int(identity["namespaces"][name].split(":")[1]) == inode
        status = sample["status"]
        assert status["Uid"].split() == status["Gid"].split() == ["10005"] * 4
        assert status["Groups"].split() in ([], ["10005"])
        assert status["NoNewPrivs"] == "1" and status["Seccomp"] == "2"
        assert int(status["Seccomp_filters"]) > 0
        assert all(status[name] == "0000000000000000" for name in ("CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"))


def verify(directory: Path):
    data = archive(
        directory / "native-mcp-transport-vm-results-003.tar",
        "3a2b7b83c99b75549d6d68d51ad74e5162f1cb8e350c5765eccee9bd7a6e1420",
        512000,
        95,
    )
    assert not any("mcp-guard" in name or "mcp-home" in name for name in data)
    first = archive(
        directory / "native-mcp-pre-controller-failure-001.tar",
        "d4888d33f62473c133203d33246bed71031bff1aba294bc007e177c3aff1254f",
        30720,
        16,
    )
    inputs = []
    for number, pin, size, count in [
        (1, "6da999767fb1a03226c9177ed618ce6e185a4e342fd956c6c8bc5df9fff20b10", 54814720, 4),
        (2, "311444478c9cfee9dcad7cc9e489959c9fedf23839d44e631fecf61d2d3397c4", 27596800, 3),
    ]:
        files = archive(directory / f"native-mcp-transport-input-{number:03d}.tar", pin, size, count)
        transfer = parse(files["transfer.json"])
        assert files["transfer.json"] == data[f"input/transfer-{number}.json"]
        for name, info in transfer["files"].items():
            assert len(files[name]) == info["bytes"] and sha(files[name]) == info["sha256"]
            assert files[name][:4] == b"\x7fELF" and files[name][18:20] == b"\xb7\x00"
        inputs.append(transfer)
    assert inputs[1]["source_commit"] == "eafefd5bbf0d84ccf7761fb51e1ec8f518b0b455"
    worker = inputs[1]["files"]["gauntlet-vm-worker"]["sha256"]
    prelaunch = parse((directory / "native-mcp-transport-host-prelaunch-003.json").read_bytes())
    courier = directory / "native-mcp-transport-proof-courier-003.py"
    assert sha(courier.read_bytes()) == prelaunch["courier_sha256"]
    assert prelaunch["workspace_uid"] == prelaunch["workspace_gid"] == 10001
    pins = prelaunch["pins"]["mcp"]
    assert pins == parse(data["proof3/job-mcp.json"])
    assert pins["worker_generation"] == worker
    assert sha(data["job/preparation.v1.json"]) == pins["preparation_sha256"]
    assert sha(data[f"deployments/{pins['deployment_sha256']}.json"]) == pins["deployment_sha256"]
    assert parse(data[f"deployments/{pins['deployment_sha256']}.json"]) == pins["declaration"]
    audit = parse((directory / "native-mcp-transport-host-prelaunch-002.json").read_bytes())["systemd_audit"]
    assert "systemd 255.4-1ubuntu8.18 install ok installed" in audit["installed"]
    for helper in audit["pins"]:
        assert helper["package_md5_matches"] is True
        assert pins["preparation"]["launch"]["host_helpers"][helper["path"]] == helper["sha256"]
    work = Path(__file__).resolve().parents[3]
    for exported, source in [
        ("service_relay.py", "ci/gauntlet/benchmark/service_relay.py"),
        ("native_mcp_proxy_v1.py", "ci/gauntlet-rs/adapters/native_mcp_proxy_v1.py.txt"),
        ("native_mcp_identity_v1.py", "ci/gauntlet-rs/adapters/native_mcp_identity_v1.py.txt"),
    ]:
        assert data["job/mcp-public/" + exported] == (work / source).read_bytes()
    assert data["job/mcp-public/mcp.json"] == b"{}\n"
    assert parse(data["job/mcp-public/prefix.json"]) == {"prefix": pins["preparation"]["runtime_prefix"]}

    # The refused original reservation stays consumed; no invented exit/terminal.
    job36 = "e2c701baf1473601"
    started = f"state/{job36}.started.json"
    assert data[started] == first[started]
    assert sha(data[started]) == "26dc7efc4fe80b70eeb06b1400e84ae61211471d74572c9a47b6fbeb99ab06ba"
    repair_raw = data[f"state/{job36}.native-startup-repair.json"]
    assert sha(repair_raw) == "76a173e773536f060673017f5fe8dd2d061d2d67a6ac5a4f25c80a3008f41da0"
    repair = parse(repair_raw)
    ineligible(repair)
    assert repair["status"] == "aborted" and repair["controller_state"] == "never-released"
    assert repair["exit_code"] is None and repair["started_marker_sha256"] == sha(data[started])
    assert repair["repair_generation"] == worker
    assert all(value is True for name, value in repair["cleanup"].items() if name != "untouched")
    assert repair["cleanup"]["untouched"]["workspace_empty"] is True
    assert (
        parse(data["proof2/startup-repair.json"])["stdout"]
        == parse(data["proof2/startup-repair-replay.json"])["stdout"]
    )
    for name in ("wrong-marker", "rust-lease-busy", "legacy-lease-busy"):
        assert parse(data[f"proof2/startup-repair-{name}.json"])["returncode"] == 2
    bad = parse(data["proof2/worker-wrong-helper.json"])
    assert bad["returncode"] == 2 and "/usr/bin/systemctl differs from outside digest" in bad["stderr"]
    failed = parse(data["state/e2c701baf1473701.report.json"])
    ineligible(failed)
    assert failed["exit_code"] == 2 and failed["controller_report"] is None
    assert data["state/e2c701baf1473701.native.stdout"] == b""
    assert (
        data["state/e2c701baf1473701.native.stderr"]
        == b"native worker unavailable: native fixture physical workspace differs from outside pins\n"
    )
    prior = parse(data["proof3/prior-worker-hashes.json"])
    assert len(prior) == 137
    assert all(prior[name] == pin for name, pin in inputs[0]["prior_worker_hashes"].items())
    for name, pin in prior.items():
        if f"state/{name}" in data:
            assert sha(data[f"state/{name}"]) == pin

    job = pins["job_id"]
    report_raw = data[f"state/{job}.report.json"]
    assert sha(report_raw) == "38d6c240e339efaa2ee977d7c20d97f83f1d0d831062101b7dee96dabaae280a"
    report = parse(report_raw)
    ineligible(report)
    assert report["schema"] == "hol-gauntlet-native-worker-report.v4"
    assert report["status"] == "invalid-evidence" and report["exit_code"] == 0
    for name in (
        "controller_cgroup_drained",
        "product_slice_absent",
        "image_lease_absent",
        "mcp_agent_absent",
        "mcp_profile_absent",
    ):
        assert report[name] is True
    assert report["worker_generation"] == worker and report["deployment_digest"] == pins["deployment_sha256"]
    assert report["started_marker_sha256"] == sha(data[f"state/{job}.started.json"])
    assert report["controller_stdout_sha256"] == sha(data[f"state/{job}.native.stdout"])
    assert report["controller_stderr_sha256"] == sha(data[f"state/{job}.native.stderr"])
    assert data[f"state/{job}.native.stderr"] == b""
    control = report["controller_report"]
    assert parse(data[f"state/{job}.native.stdout"]) == control
    ineligible(control)
    assert control["status"] == "passed" and control["error"] is None
    assert control["sdk_exercised"] is False and control["cleanup_errors"] == []
    for name in (
        "client_cleanup_complete",
        "agent_cleanup_complete",
        "cell_cleanup_complete",
        "prefix_unchanged",
        "host_null_identity_unchanged",
    ):
        assert control[name] is True
    assert control["upstream_operation_count"] == 2
    before, after = parse(data["proof3/outside-device-before.json"]), parse(data["proof3/outside-device-after.json"])
    assert after.pop("identity_unchanged") is True and before == after
    assert before["uid"] == before["gid"] == 0 and before["mode"] == 0o666
    assert (before["major"], before["minor"]) == (1, 3)

    samples = parse(data["proof3/outside-kernel.json"])
    assert samples["errors"] == [] and len(samples["observations"]) == 20
    assert samples["observer_sha256"] == prelaunch["observer_sha256"]
    prefix = pins["preparation"]["runtime_prefix"]
    records = {row["id"]: row for row in control["initial"]["records"]}
    sessions = {row["family"]: row for row in control["upstream_sessions"]}
    assert set(sessions) == {"docs", "mail"}
    calls = []
    for measurement, log in zip(control["measurements"][1:], ["011", "013"], strict=True):
        family = measurement["exchange"]["family"]
        process = measurement["native_proxy"]
        candidates = [
            s
            for s in samples["observations"]
            if s["pid"] == process["identity"]["pid"] and s["argv_sha256"] == process["argv_sha256"]
        ]
        assert candidates
        argv = candidates[0]["argv_utf8"].split("\0")[:-1]
        payload = {
            "args": ["<path>", "--socket", "<path>"],
            "command": "python3",
            "harness": "omp",
            "name": family,
            "source_scope": "project",
            "transport": "stdio",
        }
        identifier = "mcp_server:omp:project:" + family + ":" + sha(json.dumps(payload, sort_keys=True).encode())[:20]
        assert argv == [
            prefix + "/bin/python",
            "-I",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "omp-mcp-proxy",
            "--guard-home",
            "/product/guard",
            "--server-name",
            family,
            "--server-id",
            identifier,
            "--source-scope",
            "project",
            "--config-path",
            "/product/public/mcp.json",
            "--transport",
            "stdio",
            "--command",
            "/usr/bin/python3",
            "--home",
            "/product/home",
            "--workspace",
            "/product/home/project",
            "--arg=/product/public/service_relay.py",
            "--arg=--socket",
            f"--arg=/upstream/{family}.sock",
        ]
        observed_process(process, samples["observations"], argv)
        assert measurement["relay_proxy_ancestry_verified"] is False
        assert measurement["completion"]["exit_code"] == 0
        assert measurement["completion"]["client"]["host_client_reaped"] is True
        assert measurement["completion"]["client"]["stderr_complete"] is True
        assert measurement["completion"]["client"]["product_process_drained"] is False
        session = sessions[family]
        assert session["status"] == "closed" and session["operations"] == 1
        assert session["shutdown_observation"] is None and session["sdk_builtin_budget_composed"] is False
        observed_process(
            session["peer"],
            samples["observations"],
            ["/usr/bin/python3.12", "/product/public/service_relay.py", "--socket", f"/upstream/{family}.sock"],
        )
        frames = session["frames"]
        assert [row["sequence"] for row in frames] == list(range(1, 8))
        for row in frames:
            assert sha(row["wire_utf8"].encode()) == row["sha256"]
            assert parse(row["wire_utf8"]) == row["frame"]
        requests = [row["frame"] for row in frames if row["direction"] == "request"]
        responses = [row["frame"] for row in frames if row["direction"] == "response"]
        client_in = lines(data[f"job/mcp-processes/{log}.mcp-input"])
        client_out = lines(data[f"job/mcp-processes/{log}.mcp-output"])
        assert len(client_in) == 4 and len(client_out) == 3
        assert client_in == requests
        assert all(row["written"] is True for row in frames if row["direction"] == "response")
        call = next(row for row in requests if row.get("method") == "tools/call")
        assert call["params"]["name"] == family + ".read"
        returned = parse(client_out[-1]["result"]["content"][0]["text"])
        assert returned == measurement["exchange"]["record"] == records[call["params"]["arguments"]["record_id"]]
        assert responses[-1]["result"]["structuredContent"] == returned
        calls.append(call)

    world = control["world"]
    ineligible(world)
    assert world["uid"] == world["gid"] == 0 and world["mode"] == 0o600
    assert world["agent_mounts_verified"] is False
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(world["public_key"], validate=True))
    receipts = control["receipts"]
    assert len(receipts) == 2
    previous = "0" * 64
    for sequence, (envelope, call) in enumerate(zip(receipts, calls, strict=True), 1):
        event = envelope["event"]
        assert event["sequence"] == sequence and event["previous_hash"] == previous
        assert event["request_id"] == call["id"] and event["operation"] == call["params"]["name"]
        assert event["effect"] == "read" and event["status"] == "ok" and event["before"] is None
        args = call["params"]["arguments"]
        assert event["raw_args_digest"] == digest(args)
        assert event["args_digest"] == digest({"operation": event["operation"], "args": args, "actor": "fixture-actor"})
        assert event["after"] == records[args["record_id"]]
        assert event["result_digest"] == digest(event["after"])
        key.verify(base64.b64decode(envelope["signature"], validate=True), canonical(event))
        previous = digest(envelope)
    connection = sqlite3.connect(":memory:")
    connection.deserialize(data["job/mcp-world.db"])
    connection.execute("PRAGMA trusted_schema=OFF")
    assert connection.execute("PRAGMA quick_check").fetchall() == [("ok",)]
    assert {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")} == {
        "meta",
        "records",
        "journal",
        "cached",
    }
    meta = parse(connection.execute("SELECT value FROM meta WHERE id=1").fetchone()[0])
    assert set(meta) == {"actor_id", "producer", "provider_scope", "schema"}
    assert meta["producer"] == world["public_key"]
    physical_records = {name: parse(raw) for name, raw in connection.execute("SELECT id,value FROM records")}
    assert physical_records == records
    assert [parse(row[0]) for row in connection.execute("SELECT value FROM journal ORDER BY sequence")] == receipts
    assert connection.execute("SELECT count(*) FROM cached").fetchone()[0] == 0
    connection.close()
    public_meta = {name: value for name, value in meta.items() if name != "producer"}
    assert control["final"] == control["initial"] == {**public_meta, "records": control["initial"]["records"]}
    assert control["sockets"]["socket_namespace_retired"] is True
    assert control["sockets"]["accepted_streams_drained"] is False
    assert control["sockets"]["peer_authenticated"] is False
    for row in control["sockets"]["directories"]:
        assert row["uid"] == 0 and row["mode"] == 0o710
        assert all(socket["retired"] and socket["inode_held"] and not socket["listening"] for socket in row["sockets"])
    return {
        "schema": "hol-gauntlet-native-mcp-host-readback.v1",
        "job_id": job,
        "source_commit": inputs[1]["source_commit"],
        "report_sha256": sha(report_raw),
        "archives_verified": True,
        "upstream_frames": 14,
        "provider_receipts": 2,
        "physical_sqlite_records": 2,
        "kernel_samples": 20,
        "prior_worker_files_preserved": 137,
        "self_generated_receipt_signatures_verified": True,
        "outside_signing_key_admitted": False,
        "sdk_exercised": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_native_mcp_transport_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
