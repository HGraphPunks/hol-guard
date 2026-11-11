"""Exercise the frozen Rust artifact reader on public evidence and mutations."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

SOURCE = "65a700765f5805c1663664c390fff10e3618a2d4"
VERIFIER = "d13055131f918c4c7996ed4ef00eb4b53f04e0823527c4e0dcafe53cb3c95810"
ARCHIVES = {
    "success": "0c455bb6a6d18766ceca8773ad4ed7b8c1a931863d5dc45d6bbfba25d8afed30",
    "input-binding": "5b9eb3ca04063bfb535dbc09f133ee8fb1409fa3b897964c46b8da2963aece94",
    "injection": "86e4cb80869229a39e42a4f2d1fc599016bda2dc5d2bde07eed051b56205a652",
    "boundary": "f6f838f80636da3a73afe36ca4272f6113fc8c2c82b449d0c26f114f88842670",
    "timeout": "08f5980f79304782597357a473fb541ae824ecbac0fcdfd2e8c096938f49a39d",
    "cancel": "247c6c2b808746acbc1b2fba383accb981b0958e0a0c4e18d5a5b17964b3cf5d",
}
LEGACY = {
    "input-binding": ("--input-binding-artifacts", "04d4625ea7d591e81326d6ee23a6eef455547e4ffaf98f81a9160e3d8e8694ce"),
    "boundary": ("--boundary-artifacts", "f2fc5fffffc210b9cda9f96cafc45c8e25d0d96bb0167d48d7258274b7ee75a0"),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(directory, index):
    assert index.isdigit() and len(index) == 3
    exe = directory / "native-mcp-artifact-verifier-001"
    assert sha(exe.read_bytes()) == VERIFIER
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    before = {p.name: sha(p.read_bytes()) for p in (directory / "native-host-keyed-host-pins-001").iterdir()}
    records = []

    def arguments(role):
        p = jobs[role]
        return [
            str(exe),
            str(directory / "native-host-keyed-host-pins-001"),
            str(directory / ("native-host-keyed-completion-001-" + role + "-valid.json")),
            p["source_sha"],
            p["job_id"],
            p["deployment_sha256"],
            p["worker_generation"],
            p["preparation_sha256"],
            role,
        ]

    def archive(role):
        path = directory / ("native-host-keyed-vm-results-001-" + role + ".tar")
        assert sha(path.read_bytes()) == ARCHIVES[role]
        return str(path), ARCHIVES[role]

    def run(name, args, code):
        actual = subprocess.run(args, capture_output=True, timeout=60)
        stem = "native-mcp-artifact-proof-" + index + "-" + name
        for suffix, raw in [("stdout", actual.stdout), ("stderr", actual.stderr)]:
            with (directory / (stem + "." + suffix)).open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        record = {
            "case": name,
            "returncode": actual.returncode,
            "stdout_sha256": sha(actual.stdout),
            "stderr_sha256": sha(actual.stderr),
        }
        records.append(record)
        if actual.returncode != code:
            raise AssertionError((name, actual.returncode, actual.stdout.decode(), actual.stderr.decode()))
        if code == 2:
            assert not actual.stdout and actual.stderr
        return actual.stdout

    originals = {}
    for role in ARCHIVES:
        path, pin = archive(role)
        run("envelope-" + role, arguments(role), 0)
        raw = run("actual-" + role, [*arguments(role), "--mcp-artifacts", path, pin], 0)
        assert run("restart-" + role, [*arguments(role), "--mcp-artifacts", path, pin], 0) == raw
        relation = json.loads(raw)["mcp_artifacts"]["relations"]
        assert relation["captured_frames_checked"] == 24 and relation["families_checked"] == 2
        assert relation["source_selected_inputs_checked"] is True
        assert relation["independent_process_custody_checked"] is False
        assert relation["actual_native_read_disposition"] == "forwarded"
        world = relation["provider_world"]
        assert world["signed_read_receipts_checked"] == 1
        assert world["physical_database"]["physical_records_checked"] == 2
        assert world["physical_database"]["cached_rows"] == 0
        assert world["physical_database"]["read_only_memory_database"] is True
        for value in [relation, world, world["physical_database"]]:
            assert value["execution_eligible"] is value["guard_causality_verified"] is False
            assert value["model_requests"] == 0
        originals[role] = sha(raw)
    for role, (option, pin) in LEGACY.items():
        path, digest = archive(role)
        raw = run("regression-" + role, [*arguments(role), option, path, digest], 0)
        assert sha(raw) == pin
    path, pin = archive("success")
    run("wrong-digest", [*arguments("success"), "--mcp-artifacts", path, "0" * 64], 2)
    other, digest = archive("boundary")
    run("cross-job", [*arguments("success"), "--mcp-artifacts", other, digest], 2)
    wrong = arguments("success")
    wrong[-1] = "boundary"
    run("wrong-role", [*wrong, "--mcp-artifacts", path, pin], 2)
    with tarfile.open(path, "r:") as source:
        original = {m.name: source.extractfile(m).read() for m in source.getmembers()}
    target = directory / ("native-mcp-artifact-mutations-" + index)
    target.mkdir(mode=0o700)

    def mutated(name, change):
        files = dict(original)
        inventory = json.loads(files["results.sha256.json"])
        change(files, inventory)
        inventory["files"] = {
            n: {"bytes": len(r), "sha256": sha(r)} for n, r in files.items() if n != "results.sha256.json"
        }
        inventory["filesystem"] = {n: v for n, v in inventory["filesystem"].items() if n in files}
        files["results.sha256.json"] = canonical(inventory)
        output = target / (name + ".tar")
        with (
            output.open("xb") as stream,
            tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive,
        ):
            for member, raw in sorted(files.items()):
                info = tarfile.TarInfo(member)
                info.mode = 0o600
                info.uid = info.gid = info.mtime = 0
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))
        run(name, [*arguments("success"), "--mcp-artifacts", str(output), sha(output.read_bytes())], 2)

    def database(sql):
        def change(files, _):
            connection = sqlite3.connect(":memory:")
            connection.deserialize(files["combined/mcp-world.db"])
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(sql)
            connection.commit()
            files["combined/mcp-world.db"] = connection.serialize()
            connection.close()

        return change

    for name, sql in [
        ("changed-record", "UPDATE records SET value='{}' WHERE id='developer-spec'"),
        ("changed-journal", "UPDATE journal SET value='{}'"),
        ("active-cache", "INSERT INTO cached VALUES('replay','digest','{}')"),
        ("extra-schema", "CREATE VIEW unexpected AS SELECT value FROM records"),
    ]:
        mutated(name, database(sql))

    def output(files, _):
        name = "combined/mcp-processes/011.mcp-output"
        rows = [json.loads(line) for line in files[name].splitlines()]
        rows[-1]["result"] = {"content": [{"type": "text", "text": "substituted response"}]}
        files[name] = b"".join(canonical(row) + b"\n" for row in rows)

    mutated("changed-native-output", output)

    def sdk_output(files, _):
        control = json.loads(files["combined/worker/report.json"])["controller_report"]
        pin = control["measurements"]["sdk"]["stdout_sha256"]
        names = [
            n
            for n, r in files.items()
            if n.startswith("combined/sdk-processes/") and n.endswith(".stdout") and sha(r) == pin
        ]
        assert len(names) == 1
        value = json.loads(files[names[0]])
        value["uid"] = 0
        files[names[0]] = canonical(value) + b"\n"

    mutated("changed-sdk-output", sdk_output)

    def inode(_, inventory):
        inventory["filesystem"]["combined/mcp-world.db"]["inode"] += 1

    mutated("changed-world-inode", inode)
    mutated("missing-native-input", lambda files, _: files.pop("combined/mcp-processes/011.mcp-input"))
    assert before == {p.name: sha(p.read_bytes()) for p in (directory / "native-host-keyed-host-pins-001").iterdir()}
    assert len(records) == 31
    result = {
        "schema": "hol-gauntlet-native-mcp-artifact-verifier-proof.v1",
        "verifier_source_commit": SOURCE,
        "verifier_sha256": VERIFIER,
        "historical_runtime_source": "f53bc490f7483ad41a781d62dc4d0d2c6a47c6a9",
        "historical_product_source": "62aa7ba777a5a4cc0806c34ee94e9822eaa58d32",
        "cases": records,
        "actual_readback_sha256": originals,
        "unique_mcp_frames": 144,
        "unique_physical_records": 12,
        "unique_signed_read_receipts": 6,
        "host_pin_journal_unchanged": True,
        "fresh_current_source_execution": False,
        "independent_process_custody_checked": False,
        "qualified_role_complete": False,
        "outside_signing_key_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    with (directory / ("native-mcp-artifact-proof-" + index + ".json")).open("xb") as stream:
        stream.write(canonical(result) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return result


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 3:
        raise SystemExit("usage (assertions enabled): verify_native_mcp_artifacts_20261027.py EVIDENCE_DIRECTORY INDEX")
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))
