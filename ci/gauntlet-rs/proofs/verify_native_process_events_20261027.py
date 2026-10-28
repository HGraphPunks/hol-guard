"""Inert courier for the Rust reader; it owns no runtime or verdict authority."""

import copy
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path

VM_SOURCE = "0259fa9018e9e6a9578e3f9a6fc9f61ce20a3570"
PINS = {
    "001": "c0e683cb0624d0a0658a6776a6a573214b337aa975064f4d62a63b2a8cd46cb9",
    "002": "bdf0ae50e8875c1367c3623e4f7a7c3fdc14da3ff25955cf38d6141a312cb64e",
}
EXPECTED = {
    "fork-tree": (5, 5, 0, 1),
    "group-stop": (2, 2, 0, 0),
    "rapid-exit": (65, 65, 0, 0),
    "thread-exec": (2, 1, 1, 1),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def save(path, raw):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def archive(evidence, attempt):
    raw = (evidence / f"native-trace-vm-results-{attempt}.tar").read_bytes()
    assert len(raw) == 163840 and sha(raw) == PINS[attempt]
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
        members = tar.getmembers()
        assert len(members) == (15 if attempt == "001" else 19)
        files = {}
        for member in members:
            assert member.isfile() and member.name not in files
            assert member.uid == member.gid == member.mtime == 0 and member.mode == 0o600
            assert 0 <= member.size <= 16 * 1024**2
            files[member.name] = tar.extractfile(member).read(member.size + 1)
            assert len(files[member.name]) == member.size
    index = json.loads(files["results.sha256.json"])
    assert index["schema"] == "hol-gauntlet-native-process-events-export.v1"
    assert index["execution_eligible"] is False and index["model_requests"] == 0
    assert index["worker_files_preserved"] == 298 and index["both_worker_leases_held"] is True
    assert set(index["files"]) == set(files) - {"results.sha256.json"}
    for name, pin in index["files"].items():
        assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
        metadata = index["filesystem"][name]
        assert metadata["uid"] == metadata["gid"] == 0
        assert metadata["mode"] == 0o600 and metadata["links"] == 1
    return files, index


def rechain(rows, checkpoint):
    previous = "0" * 64
    parts = []
    for sequence, row in enumerate(rows):
        row = dict(row, sequence=sequence, previous_sha256=previous)
        raw = canonical(row)
        previous = sha(raw)
        parts.append(raw + b"\n")
    raw = b"".join(parts)
    checkpoint = copy.deepcopy(checkpoint)
    checkpoint["journal"].update(events=len(rows), bytes=len(raw), tail_sha256=previous)
    return raw, canonical(checkpoint)


def prove(evidence):
    manifest = json.loads((evidence / "native-trace-reader-artifacts-001.json").read_bytes())
    assert manifest["source_commit"].startswith("a0439880")
    assert len(manifest["source_commit"]) == 40
    for pin in manifest["files"].values():
        path = Path(pin["path"])
        assert path.parent == evidence
        raw = path.read_bytes()
        assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"]
    verifier = Path(manifest["files"]["mac-verifier"]["path"])
    files, index = archive(evidence, "002")
    failed, _ = archive(evidence, "001")
    summary = json.loads(files["proof/summary.json"])
    assert summary["source_commit"] == VM_SOURCE and summary["passed"] is True
    assert summary["fixture_only"] is True and summary["fresh_product_execution"] is False
    assert [r["results"] for r in summary["cases"]] == [
        [["ok", "6", "0", "0"]],
        [["ok", "3", "0", "0"]],
        [["ok", "1", "0", "0"]],
    ]
    for case in summary["cases"]:
        assert case["returncode"] == 0
        assert sha(files["proof/" + case["case"] + ".log"]) == case["log_sha256"]
        assert case["executable_sha256"] == "ff72932a23882d4ea950a8bc8c23d7cc141a330c3a3f6638cbb5b707e34fad81"
    transfer = json.loads(files["proof/transfer.json"])
    assert transfer["source_commit"] == VM_SOURCE
    assert (
        transfer["files"]["trace-fixture"]["sha256"]
        == "af615c1906d3cd76cc8714e6409e30676efe61b90b65a820b8555401e650537a"
    )
    assert json.loads(failed["proof/summary.json"])["passed"] is False
    directory = evidence / "native-trace-readback-inputs-001"
    directory.mkdir(mode=0o700)
    calls, bindings, originals = [], {}, {}

    def run(label, raw, checkpoint, accepted, journal_pin=None, checkpoint_pin=None):
        stem = f"case-{len(calls):03d}"
        journal = directory / (stem + ".jsonl")
        pin_file = directory / (stem + ".json")
        save(journal, raw)
        save(pin_file, checkpoint)
        result = subprocess.run(
            [str(verifier), str(journal), journal_pin or sha(raw), str(pin_file), checkpoint_pin or sha(checkpoint)],
            capture_output=True,
            timeout=15,
            env={"PATH": "/usr/bin:/bin"},
        )
        row = dict(
            case=label,
            returncode=result.returncode,
            journal_sha256=sha(raw),
            checkpoint_sha256=sha(checkpoint),
            stdout_sha256=sha(result.stdout),
            stderr_sha256=sha(result.stderr),
            accepted=accepted,
        )
        save(directory / (stem + ".stdout"), result.stdout)
        save(directory / (stem + ".stderr"), result.stderr)
        calls.append(row)
        assert result.returncode == (0 if accepted else 2), (label, result.stderr.decode())
        if accepted:
            value = json.loads(result.stdout)
            assert value["complete_task_relation_verified"] is True
            for key in [
                "process_custody_authenticated",
                "all_native_descendants_verified",
                "execution_eligible",
                "guard_causality_verified",
            ]:
                assert value[key] is False
            assert value["model_requests"] == 0
            return value, result.stdout
        assert not result.stdout and b"Native process events unavailable" in result.stderr
        return None

    for mode, counts in EXPECTED.items():
        names = [
            name
            for name in files
            if re.fullmatch(r"proof/fixtures/" + mode + r"-[a-f0-9]{32}/native-process-events.v1.jsonl", name)
        ]
        assert len(names) == 1
        name = names[0]
        checkpoint_name = name.rsplit("/", 1)[0] + "/result.json"
        raw, checkpoint = files[name], files[checkpoint_name]
        value, output = run(mode, raw, checkpoint, True)
        assert tuple(value[k] for k in ["created_tasks", "final_waits", "exec_retirements", "execs"]) == counts
        assert run(mode + "-restart", raw, checkpoint, True)[1] == output
        physical = index["filesystem"][name]
        expected_pin = json.loads(checkpoint)["journal"]
        for field in ["device", "inode", "uid", "gid", "mode", "links"]:
            assert expected_pin[field] == physical[field]
        bindings[mode] = dict(
            journal_member=name,
            checkpoint_member=checkpoint_name,
            journal_sha256=sha(raw),
            checkpoint_sha256=sha(checkpoint),
            readback=value,
        )
        originals[mode] = (raw, json.loads(checkpoint))

    def mutate(label, mode, action):
        raw, checkpoint = originals[mode]
        rows = [json.loads(line) for line in raw.splitlines()]
        action(rows, checkpoint)
        run(label, *rechain(rows, checkpoint), False)

    def first(rows, kind):
        return next(row for row in rows if row["kind"] == kind)["data"]

    mutate("parent-substitution", "fork-tree", lambda rows, _: first(rows, "kernel-creation").update(parent_id=999))
    mutate(
        "missing-kernel-creation",
        "fork-tree",
        lambda rows, _: rows.remove(next(r for r in rows if r["kind"] == "kernel-creation")),
    )
    mutate(
        "missing-descendant-final",
        "fork-tree",
        lambda rows, _: rows.remove(next(r for r in rows if r["kind"] == "task-final-wait" and r["data"]["id"] != 0)),
    )
    mutate(
        "early-exit-is-not-death",
        "fork-tree",
        lambda rows, _: first(rows, "task-exit-stop").update(death_observed=True),
    )
    mutate("changed-generation", "fork-tree", lambda rows, _: first(rows, "task-created")["task"].update(start_ticks=1))
    mutate("false-total", "fork-tree", lambda rows, _: first(rows, "trace-complete").update(final_waits=999))
    mutate(
        "changed-argv",
        "fork-tree",
        lambda rows, _: first(rows, "task-exec")["image"].update(argv_base64="Y2hhbmdlZAA="),
    )
    mutate(
        "changed-cgroup",
        "fork-tree",
        lambda rows, _: first(rows, "task-exec")["image"]["task"].update(cgroup="/system.slice/other.service"),
    )
    mutate(
        "cross-tracer",
        "fork-tree",
        lambda rows, _: first(rows, "task-exec")["image"]["task"]["status"].update(TracerPid="1"),
    )
    mutate(
        "invented-leader-final",
        "thread-exec",
        lambda rows, _: first(rows, "task-exec")["retired"][0].update(final_wait_observed=True),
    )
    mutate("wrong-exec-caller", "thread-exec", lambda rows, _: first(rows, "task-exec").update(old_tid=1))
    mutate(
        "false-eligibility", "group-stop", lambda rows, _: first(rows, "trace-complete").update(execution_eligible=True)
    )
    mutate("event-after-completion", "group-stop", lambda rows, _: rows.append(copy.deepcopy(rows[-2])))
    for field, changed in [("available", False), ("uid", 10004), ("links", 2), ("bytes", 1), ("tail_sha256", "0" * 64)]:
        raw, checkpoint = originals["group-stop"]
        checkpoint = copy.deepcopy(checkpoint)
        checkpoint["journal"][field] = changed
        run("checkpoint-" + field, raw, canonical(checkpoint), False)
    raw, checkpoint = originals["group-stop"]
    run("truncated-tail", raw[:-1], canonical(checkpoint), False)
    run("wrong-journal-pin", raw, canonical(checkpoint), False, journal_pin="0" * 64)
    run("wrong-checkpoint-pin", raw, canonical(checkpoint), False, checkpoint_pin="0" * 64)
    name = next(name for name in failed if "/lost-recorder-" in name and name.endswith(".jsonl"))
    rows = [json.loads(line) for line in failed[name].splitlines()]
    run("lost-recorder-borrowed-checkpoint", *rechain(rows, checkpoint), False)
    result = dict(
        schema="hol-gauntlet-native-process-events-proof.v1",
        reader_source_commit=manifest["source_commit"],
        reader_sha256=manifest["files"]["mac-verifier"]["sha256"],
        fixture_source_commit=VM_SOURCE,
        archives=PINS,
        native_tests_passed=10,
        worker_records_preserved=298,
        bindings=bindings,
        cases=calls,
        cases_passed=len(calls),
        refusals=sum(not row["accepted"] for row in calls),
        process_custody_authenticated=False,
        all_native_descendants_verified=False,
        execution_eligible=False,
        guard_causality_verified=False,
        model_requests=0,
    )
    save(evidence / "native-trace-readback-proof-001.json", canonical(result))
    print(json.dumps({key: value for key, value in result.items() if key not in ["cases", "bindings"]}, sort_keys=True))


if __name__ == "__main__":
    prove(Path(sys.argv[1]).resolve())
