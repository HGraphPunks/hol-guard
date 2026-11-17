"""Courier for Rust control-artifact checks; old execution remains unqualified."""

from __future__ import annotations

import base64
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

SOURCE = "575c83a918a04aadb8d57676ced0a3721065cf0a"
VERIFIER = "2055cbccac1650be2f23deced43e49c11a3314781a11252c1b07bd730859ce28"
PROOFS = {
    "mcp": "e264b89b3d286cc0b1955e67b3629c29e59ffcb85121fcfd15a8a92dcfa5660a",
    "process": "96244f19ed22058152295fd2716a2a2aff6ea3c945d12d5bb02f27e4e970a175",
    "hook": "ad90843d05257efb5c78189952e4b548373ab908b9e3983258ac833607481a36",
}
COUNTS = {
    "success": (9, 8, 6, 0, 0),
    "input-binding": (20, 22, 10, 9, 3),
    "injection": (11, 13, 10, 0, 3),
    "boundary": (9, 9, 6, 0, 1),
    "timeout": (9, 8, 6, 0, 0),
    "cancel": (8, 7, 5, 0, 0),
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(directory, index):
    assert index.isdigit() and len(index) == 3 and len(SOURCE) == 40
    exe = directory / "native-control-artifact-verifier-001"
    assert sha(exe.read_bytes()) == VERIFIER
    prior = {}
    for mode, pin in PROOFS.items():
        number = "002" if mode == "hook" else "001"
        raw = (directory / ("native-" + mode + "-artifact-proof-" + number + ".json")).read_bytes()
        assert sha(raw) == pin
        prior[mode] = json.loads(raw)
    envelopes = {r["case"]: r for r in prior["mcp"]["cases"]}
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    journal = directory / "native-host-keyed-host-pins-001"
    before = {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    records, actual = [], {}

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

    def controls(role, path, pin):
        return [*arguments(role), "--control-artifacts", path, pin, INTERPRETER, OBSERVER]

    def run(name, args, code):
        result = subprocess.run(args, capture_output=True, timeout=60)
        for suffix, raw in [("stdout", result.stdout), ("stderr", result.stderr)]:
            with (directory / ("native-control-artifact-proof-" + index + "-" + name + "." + suffix)).open(
                "xb"
            ) as stream:
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
        assert sha(run("envelope-" + role, arguments(role), 0)) == envelopes["envelope-" + role]["stdout_sha256"]
        for mode in PROOFS:
            args = [*arguments(role), "--" + mode + "-artifacts", path, pin]
            if mode != "mcp":
                args += [INTERPRETER, OBSERVER]
            assert sha(run(mode + "-regression-" + role, args, 0)) == prior[mode]["actual_readback_sha256"][role]
        raw = run("actual-" + role, controls(role, path, pin), 0)
        assert run("restart-" + role, controls(role, path, pin), 0) == raw
        relation = json.loads(raw)["control_artifacts"]["relations"]
        launches, streams, clients = (
            relation["product_launches"],
            relation["capture_streams"],
            relation["native_clients"],
        )
        counts = (
            launches["prefix_python_launches_checked"],
            streams["captures_checked"],
            clients["installed_runtime_clients_checked"],
            len(clients["missing_internal_client_observations"]),
            launches["non_prefix_helper_launches_not_graded"],
        )
        assert counts == COUNTS[role], (role, counts)
        assert streams["partial_captures"] == int(role == "cancel")
        assert relation["hooks"]["journal_report_binding_checked"] is False
        assert relation["hooks"]["hook_input_deliveries_checked"] == 0
        for name in [
            "outside_child_death_observed",
            "all_native_runtime_descendants_graded",
            "outside_signing_key_admitted",
            "qualified_role_complete",
            "execution_eligible",
            "guard_causality_verified",
        ]:
            assert relation[name] is False
        assert clients["internal_native_request_bytes_checked"] is False and relation["model_requests"] == 0
        if role in ["cancel", "timeout"]:
            life = relation["role_relations"]
            assert life["held_ready_generation_checked"] and life["closed_effect_relation_checked"]
            assert life["outside_child_death_observed"] is False
            assert life["missing_cancel_result_and_post_preserved"] == (role == "cancel")
            assert life["actual_timeout_capture_checked"] == (role == "timeout")
        actual[role] = sha(raw)
    for role, (option, expected) in LEGACY.items():
        path, pin = archive(role)
        assert sha(run("legacy-" + role, [*arguments(role), option, path, pin], 0)) == expected
    path, pin = archive("success")
    run("wrong-digest", controls("success", path, "0" * 64), 2)
    other, digest = archive("boundary")
    run("cross-job", controls("success", other, digest), 2)
    wrong = controls("success", path, pin)
    wrong[8] = "boundary"
    run("wrong-role", wrong, 2)
    for position, name in [(-2, "wrong-interpreter"), (-1, "wrong-observer")]:
        wrong = controls("success", path, pin)
        wrong[position] = "0" * 64
        run(name, wrong, 2)

    target = directory / ("native-control-artifact-mutations-" + index)
    target.mkdir(mode=0o700)
    originals = {}
    for role in ["success", "timeout", "cancel"]:
        with tarfile.open(archive(role)[0], "r:") as source:
            originals[role] = {m.name: source.extractfile(m).read() for m in source.getmembers()}

    def mutated(role, name, change):
        files = dict(originals[role])
        inventory = json.loads(files["results.sha256.json"])
        change(files, inventory)
        assert files["combined/worker/report.json"] == originals[role]["combined/worker/report.json"]
        inventory["files"] = {
            n: {"bytes": len(r), "sha256": sha(r)} for n, r in files.items() if n != "results.sha256.json"
        }
        inventory["filesystem"] = {n: v for n, v in inventory["filesystem"].items() if n in files}
        files["results.sha256.json"] = canonical(inventory)
        output = target / (name + ".tar")
        with (
            output.open("xb") as stream,
            tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive_out,
        ):
            for member, raw in sorted(files.items()):
                info = tarfile.TarInfo(member)
                info.mode = 0o600
                info.uid = info.gid = info.mtime = 0
                info.size = len(raw)
                archive_out.addfile(info, io.BytesIO(raw))
        run(name, controls(role, str(output), sha(output.read_bytes())), 2)

    kernel_name = "proof/outside-kernel.json"
    event_name = "combined/cell/native-supervisor-events.v1.jsonl"

    def kernel(change):
        def apply(files, inventory):
            value = json.loads(files[kernel_name])
            change(value["observations"])
            files[kernel_name] = canonical(value)

        return apply

    def events(change):
        def apply(files, inventory):
            rows = [json.loads(line) for line in files[event_name].splitlines()]
            change(rows)
            previous = "0" * 64
            for sequence, row in enumerate(rows):
                row["sequence"], row["previous_sha256"] = sequence, previous
                previous = sha(canonical(row))
            files[event_name] = b"".join(canonical(row) + b"\n" for row in rows)

        return apply

    success = json.loads(originals["success"]["combined/worker/report.json"])["controller_report"]
    first = success["plane"]["hooks"][0]["stdout_sha256"]
    rows = [json.loads(line) for line in originals["success"][event_name].splitlines()]
    terminal = next(
        i
        for i, r in enumerate(rows)
        if r["kind"] == "capture-terminal" and r["data"]["files"]["stdout"]["sha256"] == first
    )
    gate = next(r["data"] for r in reversed(rows[:terminal]) if r["kind"] == "gated-product-process")
    cli_pid = gate["identity"]["pid"]

    def primary(rows):
        return next(r for r in rows if r["pid"] == cli_pid and r["executable_sha256"] == INTERPRETER)

    def native(rows):
        return next(r for r in rows if r["parent_pid"] == cli_pid and "\0resident-client-stream\0" in r["argv_utf8"])

    for name, select, field, value in [
        ("changed-cli-executable", primary, "executable_sha256", "f" * 64),
        ("changed-native-executable", native, "executable_sha256", "f" * 64),
        ("changed-native-parent", native, "parent_pid", 1),
        ("native-predates-cli", native, "start_ticks", gate["identity"]["start_ticks"] - 1),
    ]:
        mutated("success", name, kernel(lambda rows, s=select, f=field, v=value: s(rows).__setitem__(f, v)))

    def conflict(rows):
        other = dict(primary(rows))
        other["lsm_label"] = "unconfined"
        rows.append(other)

    mutated("success", "contradictory-cli-sample", kernel(conflict))
    for name, field, value in [
        ("changed-cli-uid", "Uid", "10004 10004 0 10004"),
        ("changed-cli-capability", "CapEff", "0000000000000001"),
    ]:
        mutated("success", name, kernel(lambda rows, f=field, v=value: primary(rows)["status"].__setitem__(f, v)))
    for name, member, field, value in [
        ("replaced-effect-inode", "combined/workspace/native-contained.txt", "inode", 1),
        ("writable-effect", "combined/workspace/native-contained.txt", "mode", 0o666),
        ("wrong-fixture-owner", "combined/workspace/tests/test_control.py", "uid", 0),
    ]:
        mutated("success", name, lambda files, inv, m=member, f=field, v=value: inv["filesystem"][m].__setitem__(f, v))
    mutated(
        "success",
        "changed-effect-bytes",
        lambda files, inv: files.__setitem__("combined/workspace/native-contained.txt", b"substitute"),
    )
    mutated(
        "success",
        "changed-node-result",
        lambda files, inv: files.__setitem__("combined/workspace/node-runtime-control.json", b"{}"),
    )
    mutated(
        "success",
        "changed-fixture",
        lambda files, inv: files.__setitem__("combined/workspace/tests/test_control.py", b"pass\n"),
    )

    def terminal_chunk(rows):
        return next(
            r["data"]["chunk"]
            for r in rows
            if r["kind"] == "product-stream"
            and r["data"]["handle"] == gate["handle"]
            and r["data"]["chunk"]["returncode"] is not None
        )

    for name, field, value in [
        ("changed-stream-count", "output_bytes", 1),
        ("changed-stream-exit", "returncode", 9),
        ("unclosed-stream", "stdout_eof", False),
        ("untyped-stream-eof", "stderr_eof", 1),
        ("changed-stream-bytes", "stdout", base64.b64encode(b"changed").decode()),
    ]:
        mutated("success", name, events(lambda rows, f=field, v=value: terminal_chunk(rows).__setitem__(f, v)))

    def omit(rows, kind):
        row = next(r for r in rows if r["kind"] == kind and r["data"]["handle"] == gate["handle"])
        rows.remove(row)

    mutated("success", "missing-release", events(lambda rows: omit(rows, "product-release")))
    mutated("success", "missing-retirement", events(lambda rows: omit(rows, "retired-product-process")))

    for role in ["timeout", "cancel"]:
        control = json.loads(originals[role]["combined/worker/report.json"])["controller_report"]
        child_pid = control["router"]["lifecycle"]["detached_child"]["pid"]

        def child(rows, pid=child_pid):
            return next(
                r
                for r in rows
                if r["pid"] == pid and r.get("synthetic_lifecycle_view", {}).get("files", {}).get("detached-ready.json")
            )

        for name, field, value in [
            ("ready-inode", "inode", 1),
            ("ready-bytes", "utf8", "{}"),
            ("ready-links", "links", 2),
        ]:
            mutated(
                role,
                role + "-" + name,
                kernel(
                    lambda rows, s=child, f=field, v=value: s(rows)["synthetic_lifecycle_view"]["files"][
                        "detached-ready.json"
                    ].__setitem__(f, v)
                ),
            )
        for name, field, value in [
            ("late-effect", "late-detached-effect.txt", {}),
            ("pending-name", "detached-ready.pending", {}),
        ]:
            mutated(
                role,
                role + "-" + name,
                kernel(
                    lambda rows, s=child, f=field, v=value: s(rows)["synthetic_lifecycle_view"]["files"].__setitem__(
                        f, v
                    )
                ),
            )
        mutated(role, role + "-wrong-parent", kernel(lambda rows, s=child: s(rows).__setitem__("parent_pid", 1)))

        def no_ready(rows, pid=child_pid):
            for row in rows:
                if row["pid"] == pid:
                    row["synthetic_lifecycle_view"]["files"]["detached-ready.json"] = None

        mutated(role, role + "-missing-ready-sample", kernel(no_ready))
        name = "combined/physical-lifecycle-absence.json"
        mutated(role, role + "-missing-lower-absence", lambda files, inv, n=name: files.pop(n))
        mutated(role, role + "-changed-lower-absence", lambda files, inv, n=name: files.__setitem__(n, b"{}"))
    assert len(records) == 81
    assert before == {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    result = {
        "schema": "hol-gauntlet-native-control-artifact-verifier-proof.v1",
        "verifier_source_commit": SOURCE,
        "verifier_sha256": VERIFIER,
        "cases": records,
        "actual_readback_sha256": actual,
        "prefix_python_launches_checked": 66,
        "actual_capture_streams_checked": 67,
        "actual_native_clients_checked": 43,
        "historical_internal_client_gaps": 9,
        "non_prefix_helper_launches_not_graded": 7,
        "held_lifecycle_roles_checked": 2,
        "host_pin_journal_unchanged": True,
        "fresh_current_source_execution": False,
        "outside_child_death_observed": False,
        "outside_signing_key_admitted": False,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    with (directory / ("native-control-artifact-proof-" + index + ".json")).open("xb") as stream:
        stream.write(canonical(result) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return result


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 3:
        raise SystemExit(
            "usage (assertions enabled): verify_native_control_artifacts_20261027.py EVIDENCE_DIRECTORY INDEX"
        )
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))
