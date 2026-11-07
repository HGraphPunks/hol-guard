"""Courier for the frozen Rust process reader; preserve gaps and all failures."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path

from verify_native_mcp_artifacts_20261027 import ARCHIVES, LEGACY

SOURCE = "70c0d1d929be4b04c12d82cf32372eda3928ae03"
VERIFIER = "47274c5283c534be79757dbfffc68d50a114b63d1c42682a036048e34592da43"
INTERPRETER = "c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960"
OBSERVER = "dba8f56bcbac3610e18f77c292dea957f61c744dabba989a9bd36b89c9041c0a"
MCP_PROOF = "e264b89b3d286cc0b1955e67b3629c29e59ffcb85121fcfd15a8a92dcfa5660a"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def verify(directory, index):
    assert index.isdigit() and len(index) == 3
    exe = directory / "native-process-artifact-verifier-001"
    assert sha(exe.read_bytes()) == VERIFIER
    previous_raw = (directory / "native-mcp-artifact-proof-001.json").read_bytes()
    assert sha(previous_raw) == MCP_PROOF
    previous = json.loads(previous_raw)
    old_cases = {r["case"]: r for r in previous["cases"]}
    journal = directory / "native-host-keyed-host-pins-001"
    before = {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    jobs = json.loads((directory / "native-host-keyed-job-inputs-001.json").read_bytes())["jobs"]
    records = []
    observed_negatives = []
    actual = {}

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

    def process(role, path, digest):
        return [*arguments(role), "--process-artifacts", path, digest, INTERPRETER, OBSERVER]

    def run(name, args, code):
        result = subprocess.run(args, capture_output=True, timeout=60)
        for suffix, raw in [("stdout", result.stdout), ("stderr", result.stderr)]:
            with (directory / ("native-process-artifact-proof-" + index + "-" + name + "." + suffix)).open(
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
        raw = run("envelope-" + role, arguments(role), 0)
        assert sha(raw) == old_cases["envelope-" + role]["stdout_sha256"]
        raw = run("mcp-regression-" + role, [*arguments(role), "--mcp-artifacts", path, pin], 0)
        assert sha(raw) == previous["actual_readback_sha256"][role]
        raw = run("actual-" + role, process(role, path, pin), 0)
        assert run("restart-" + role, process(role, path, pin), 0) == raw
        relation = json.loads(raw)["process_artifacts"]["relations"]
        assert relation["sdk_and_mcp_processes_checked"] == 8
        assert relation["public_sdk_helpers_checked"] == 8
        assert relation["outside_kernel_observations_checked"] is True
        assert relation["raw_sdk_request_bytes_checked"] is False and relation["raw_sdk_requests_checked"] == 0
        for name in [
            "interpreter_prelaunch_pinned",
            "independent_process_custody_checked",
            "outside_observer_admitted",
            "outside_signing_key_admitted",
            "qualified_role_complete",
            "execution_eligible",
            "guard_causality_verified",
        ]:
            assert relation[name] is False
        assert relation["model_requests"] == 0
        observed_negatives.append(relation["independently_observed_negative_probes"])
        actual[role] = sha(raw)
    assert observed_negatives == [2, 2, 0, 1, 2, 1]
    for role, (option, pin) in LEGACY.items():
        path, digest = archive(role)
        assert sha(run("regression-" + role, [*arguments(role), option, path, digest], 0)) == pin
    path, pin = archive("success")
    run("wrong-digest", process("success", path, "0" * 64), 2)
    other, digest = archive("boundary")
    run("cross-job", process("success", other, digest), 2)
    wrong = process("success", path, pin)
    wrong[8] = "boundary"
    run("wrong-role", wrong, 2)
    for position, name in [(-2, "wrong-interpreter"), (-1, "wrong-observer")]:
        wrong = process("success", path, pin)
        wrong[position] = "0" * 64
        run(name, wrong, 2)
    with tarfile.open(path, "r:") as source:
        original = {m.name: source.extractfile(m).read() for m in source.getmembers()}
    control = json.loads(original["combined/worker/report.json"])["controller_report"]
    sdk = control["measurements"]["pre_import_binding"]["peer"]["identity"]
    target = directory / ("native-process-artifact-mutations-" + index)
    target.mkdir(mode=0o700)

    def mutated(name, change, code=2):
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
        return run(name, process("success", str(output), sha(output.read_bytes())), code)

    def observed(change):
        def update(files):
            name = "proof/outside-kernel.json"
            value = json.loads(files[name])
            change(value)
            files[name] = canonical(value)

        return update

    def sdk_rows(value):
        return [r for r in value["observations"] if r["pid"] == sdk["pid"] and r["start_ticks"] == sdk["start_ticks"]]

    def field(parts, replacement):
        def update(value):
            rows = sdk_rows(value)
            assert rows
            for row in rows:
                leaf = row
                for part in parts[:-1]:
                    leaf = leaf[part]
                leaf[parts[-1]] = replacement

        return observed(update)

    for name, parts, replacement in [
        ("changed-start", ["start_ticks"], sdk["start_ticks"] + 1),
        ("changed-executable", ["executable_sha256"], "f" * 64),
        ("effective-root", ["status", "Uid"], "10001 0 10001 10001"),
        ("saved-root-group", ["status", "Gid"], "10001 10001 0 10001"),
        ("extra-group", ["status", "Groups"], "10001 0"),
        ("capability-retained", ["status", "CapBnd"], "0000000000000001"),
        ("no-new-privileges-boolean", ["status", "NoNewPrivs"], True),
        ("missing-seccomp-filter", ["status", "Seccomp_filters"], "0"),
        ("namespace-boolean", ["namespaces", "net"], True),
        ("unbounded-memory", ["limits", "memory.max"], "max"),
        ("foreign-label", ["lsm_label"], "unconfined"),
    ]:
        mutated(name, field(parts, replacement))

    def changed_argv(value):
        for row in sdk_rows(value):
            row["argv_utf8"] += "--foreign\0"
            row["argv_sha256"] = sha(row["argv_utf8"].encode())

    mutated("changed-raw-argv", observed(changed_argv))

    def missing_sdk(value):
        value["observations"] = [r for r in value["observations"] if r not in sdk_rows(value)]

    mutated("missing-sdk-sample", observed(missing_sdk))

    def contradiction(value):
        other = copy.deepcopy(sdk_rows(value)[0])
        other["limits"]["pids.max"] = "max"
        value["observations"].append(other)

    mutated("contradictory-matching-sample", observed(contradiction))
    relay = control["mcp"]["frontends"][0]["peer"]["peer"]["identity"]

    def parent(value):
        for row in value["observations"]:
            if row["pid"] == relay["pid"] and row["start_ticks"] == relay["start_ticks"]:
                row["parent_pid"] = sdk["pid"] + 1

    mutated("foreign-sdk-relay-parent", observed(parent))
    mutated("changed-observer-claim", observed(lambda value: value.update(observer_sha256="e" * 64)))
    binding = control["measurements"]["pre_import_binding"]
    negative_pids = {binding[name]["outside"]["pid"] for name in ["same_uid_negative", "mcp_same_uid_negative"]}

    def invalid_negative(value):
        for row in value["observations"]:
            if row["pid"] in negative_pids:
                row["status"]["Groups"] = "0"

    mutated("invalid-observed-negative-probe", observed(invalid_negative))

    def absent_negative(value):
        value["observations"] = [r for r in value["observations"] if r["pid"] not in negative_pids]

    raw = mutated("missing-negative-samples-stay-unverified", observed(absent_negative), 0)
    relation = json.loads(raw)["process_artifacts"]["relations"]
    assert relation["independently_observed_negative_probes"] == 0
    assert relation["outside_observer_admitted"] is relation["qualified_role_complete"] is False
    mutated("missing-public-sdk-helper", lambda files: files.pop("combined/sdk-public/builtin_guard_bridge.ts"))
    assert len(records) == 50
    assert before == {p.name: sha(p.read_bytes()) for p in journal.iterdir()}
    result = {
        "schema": "hol-gauntlet-native-process-artifact-verifier-proof.v1",
        "verifier_source_commit": SOURCE,
        "verifier_sha256": VERIFIER,
        "interpreter_readback_sha256": INTERPRETER,
        "observer_readback_sha256": OBSERVER,
        "cases": records,
        "actual_readback_sha256": actual,
        "unique_outside_observations": 420,
        "primary_process_tuples_checked": 48,
        "independently_observed_negative_probes": 8,
        "missing_negative_probe_samples": 4,
        "host_pin_journal_unchanged": True,
        "raw_historical_sdk_requests_checked": 0,
        "fresh_current_source_execution": False,
        "interpreter_prelaunch_pinned": False,
        "outside_observer_admitted": False,
        "outside_signing_key_admitted": False,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }
    with (directory / ("native-process-artifact-proof-" + index + ".json")).open("xb") as stream:
        stream.write(canonical(result) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    return result


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 3:
        raise SystemExit(
            "usage (assertions enabled): verify_native_process_artifacts_20261027.py EVIDENCE_DIRECTORY INDEX"
        )
    print(json.dumps(verify(Path(sys.argv[1]), sys.argv[2]), sort_keys=True))
