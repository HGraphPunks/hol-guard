"""Exercise the frozen Rust hook reader; never manufacture missing input credit."""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

from verify_native_mcp_artifacts_20261027 import ARCHIVES, LEGACY
from verify_native_process_artifacts_20261027 import INTERPRETER, OBSERVER

SOURCE = "72f49ab8f5210880b90f69d46eeb42751d82717c"
VERIFIER = "e08140b1869502f92f64ef1bc64dd5f394cadced52f1c5e9775eb8ec7b93f4ed"
PROCESS_PROOF = "96244f19ed22058152295fd2716a2a2aff6ea3c945d12d5bb02f27e4e970a175"
MCP_PROOF = "e264b89b3d286cc0b1955e67b3629c29e59ffcb85121fcfd15a8a92dcfa5660a"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(directory, index):
    assert index.isdigit() and len(index) == 3
    exe = directory / "native-hook-artifact-verifier-003"
    assert sha(exe.read_bytes()) == VERIFIER
    raw = (directory / "native-process-artifact-proof-001.json").read_bytes()
    assert sha(raw) == PROCESS_PROOF
    processes = json.loads(raw)
    raw = (directory / "native-mcp-artifact-proof-001.json").read_bytes()
    assert sha(raw) == MCP_PROOF
    mcp = json.loads(raw)
    envelopes = {r["case"]: r for r in mcp["cases"]}
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    journal = directory / "native-host-keyed-host-pins-001"
    before = {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    records, actual, hook_counts = [], {}, []

    def arguments(role):
        p = jobs[role]
        return [
            str(exe),
            str(journal),
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

    def hooks(role, path, pin):
        return [*arguments(role), "--hook-artifacts", path, pin, INTERPRETER, OBSERVER]

    def run(name, args, code):
        result = subprocess.run(args, capture_output=True, timeout=60)
        for suffix, raw in [("stdout", result.stdout), ("stderr", result.stderr)]:
            with (directory / ("native-hook-artifact-proof-" + index + "-" + name + "." + suffix)).open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        records.append(
            {
                "case": name,
                "returncode": result.returncode,
                "stdout_sha256": sha(result.stdout),
                "stderr_sha256": sha(result.stderr),
            }
        )
        assert result.returncode == code, (name, result.returncode, result.stdout.decode(), result.stderr.decode())
        if code == 2:
            assert not result.stdout and result.stderr
        return result.stdout

    for role in ARCHIVES:
        path, pin = archive(role)
        raw = run("envelope-" + role, arguments(role), 0)
        assert sha(raw) == envelopes["envelope-" + role]["stdout_sha256"]
        raw = run("mcp-regression-" + role, [*arguments(role), "--mcp-artifacts", path, pin], 0)
        assert sha(raw) == mcp["actual_readback_sha256"][role]
        raw = run(
            "process-regression-" + role, [*arguments(role), "--process-artifacts", path, pin, INTERPRETER, OBSERVER], 0
        )
        assert sha(raw) == processes["actual_readback_sha256"][role]
        raw = run("actual-" + role, hooks(role, path, pin), 0)
        assert run("restart-" + role, hooks(role, path, pin), 0) == raw
        relation = json.loads(raw)["hook_artifacts"]["relations"]
        assert relation["journal_report_binding_checked"] is False
        assert relation["hook_input_deliveries_checked"] == 0
        assert all(v["historical_input_receipt_missing"] for v in relation["hook_input_relations"])
        assert relation["contained_result_checked"] == (role != "cancel")
        if role == "cancel":
            assert relation["contained_sink_input"] is None
        else:
            assert relation["contained_sink_input"]["historical_input_receipt_missing"] is True
        for name in [
            "cancelled_sink_lifecycle_graded",
            "native_process_custody_checked",
            "physical_effect_causality_checked",
            "qualified_role_complete",
            "outside_signing_key_admitted",
            "execution_eligible",
            "guard_causality_verified",
        ]:
            assert relation[name] is False
        assert relation["model_requests"] == 0
        hook_counts.append(relation["actual_hook_captures_checked"])
        actual[role] = sha(raw)
    assert hook_counts == [3, 4, 4, 3, 3, 2]
    for role, (option, pin) in LEGACY.items():
        path, digest = archive(role)
        assert sha(run("regression-" + role, [*arguments(role), option, path, digest], 0)) == pin
    path, pin = archive("success")
    run("wrong-digest", hooks("success", path, "0" * 64), 2)
    other, digest = archive("boundary")
    run("cross-job", hooks("success", other, digest), 2)
    wrong = hooks("success", path, pin)
    wrong[8] = "boundary"
    run("wrong-role", wrong, 2)
    for position, name in [(-2, "wrong-interpreter"), (-1, "wrong-observer")]:
        wrong = hooks("success", path, pin)
        wrong[position] = "0" * 64
        run(name, wrong, 2)
    with tarfile.open(path, "r:") as source:
        original = {m.name: source.extractfile(m).read() for m in source.getmembers()}
    target = directory / ("native-hook-artifact-mutations-" + index)
    target.mkdir(mode=0o700)

    def mutated(name, change):
        files = dict(original)
        change(files)
        inventory = json.loads(files["results.sha256.json"])
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
        run(name, hooks("success", str(output), sha(output.read_bytes())), 2)

    event_file = "combined/cell/native-supervisor-events.v1.jsonl"

    def rows(files):
        return [json.loads(line) for line in files[event_file].splitlines()]

    def save(files, events):
        previous = "0" * 64
        for i, row in enumerate(events):
            row["sequence"] = i
            row["previous_sha256"] = previous
            previous = sha(canonical(row))
        files[event_file] = b"".join(canonical(r) + b"\n" for r in events)

    control = json.loads(original["combined/worker/report.json"])["controller_report"]

    def altered_capture(hook):
        def change(files):
            events = rows(files)
            pin = control["plane"]["hooks"][hook]["stdout_sha256"]
            matches = [
                r for r in events if r["kind"] == "capture-terminal" and r["data"]["files"]["stdout"]["sha256"] == pin
            ]
            assert len(matches) == 1
            item = matches[0]["data"]["files"]["stdout"]
            name = "combined/cell/" + item["file"]
            raw = b'{"decision":"allow","reason_code":"substituted"}\n'
            files[name] = raw
            item.update(bytes=len(raw), sha256=sha(raw))
            save(files, events)

        return change

    for hook, name in [(0, "changed-prompt-capture"), (1, "changed-pre-capture"), (2, "changed-post-capture")]:
        mutated(name, altered_capture(hook))

    def invented_receipt(kind):
        def change(files):
            events = rows(files)
            events.append({"schema": "hol-gauntlet-cell-event.v1", "kind": kind, "data": {}})
            save(files, events)

        return change

    mutated("legacy-report-cannot-admit-invented-binding", invented_receipt("capture-input-bound"))
    mutated("legacy-report-cannot-admit-invented-terminal", invented_receipt("capture-input-terminal"))
    events = rows(original)
    pin = control["plane"]["hooks"][1]["stdout_sha256"]
    item = next(
        r["data"]["files"]["stdout"]
        for r in events
        if r["kind"] == "capture-terminal" and r["data"]["files"]["stdout"]["sha256"] == pin
    )
    mutated("missing-native-capture", lambda files: files.pop("combined/cell/" + item["file"]))
    assert len(records) == 43
    assert before == {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    result = {
        "schema": "hol-gauntlet-native-hook-artifact-verifier-proof.v1",
        "verifier_source_commit": SOURCE,
        "verifier_sha256": VERIFIER,
        "cases": records,
        "actual_readback_sha256": actual,
        "actual_hook_captures_checked": 19,
        "actual_contained_results_checked": 5,
        "historical_hook_input_deliveries_checked": 0,
        "host_pin_journal_unchanged": True,
        "fresh_current_source_execution": False,
        "native_process_custody_checked": False,
        "physical_effect_causality_checked": False,
        "qualified_role_complete": False,
        "outside_signing_key_admitted": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    with (directory / ("native-hook-artifact-proof-" + index + ".json")).open("xb") as stream:
        stream.write(canonical(result) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return result


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 3:
        raise SystemExit(
            "usage (assertions enabled): verify_native_hook_artifacts_20261027.py EVIDENCE_DIRECTORY INDEX"
        )
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))
