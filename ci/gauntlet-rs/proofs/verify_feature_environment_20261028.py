"""Compare retained audits before/after the Rust test-environment correction."""

import ast
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from verify_feature_executor_20261028 import (
    AUDIT_HASH,
    MAC_READER_HASH,
    PRODUCT,
    PYTHON_BASELINE,
    archive,
    read,
    sha,
    write,
)

W = Path(__file__).resolve().parents[3]
COMMIT = "cb9ea66e7848ef113735f69bf4658c6ea8024fb3"
NEW_ARCHIVE = "7de5dcb693cd466930a3a8f420da0ede4035111126a7640ca7f85454e37ceb8c"
NEW_REPORT = "28353f575d031eddfe933d7bf866af20455d35f7c84029880f80c9631527e9f7"
ARM_ARCHIVE = "34c5661d9eb7cb8c4888540310016c521569cb172bfb03d71282242b31992192"


def main(evidence):
    old = archive(evidence / "native-feature-executor-vm-results-002.tar", 32 * 1024**2, AUDIT_HASH, 104)
    new = archive(evidence / "native-feature-executor-vm-results-003.tar", 32 * 1024**2, NEW_ARCHIVE, 104)
    for data in [old, new]:
        manifest = json.loads(data["manifest.json"])
        assert set(manifest) == set(data) - {"manifest.json"}
        for name, row in manifest.items():
            assert row == dict(bytes=len(data[name]), sha256=sha(data[name]))
    before = json.loads(old["proof/feature-stdout.json"])
    after = json.loads(new["proof/feature-stdout.json"])
    assert sha(new["proof/feature-stdout.json"]) == NEW_REPORT
    assert new["proof/feature-stdout.json"] == new["output/contracts.v2.json"]
    assert before["status"] == "failed" and after["status"] == "incomplete"
    old_spec = json.loads(old["inputs/feature-spec.json"])
    new_spec = json.loads(new["inputs/feature-spec.json"])
    assert new_spec["audit_id"] == "e2c701baf1475803" and new_spec["source_sha"] == PRODUCT
    for key in set(old_spec) - {"audit_id", "executor_sha256"}:
        assert old_spec[key] == new_spec[key]
    assert before["source_compiler_sha256"] == after["source_compiler_sha256"]
    assert (
        sha(new["inputs/gauntlet-feature-executor"])
        == new_spec["executor_sha256"]
        == "2f5b02b29451f5c94fbb0df430bbea24138d269c3ae8051fea73ae0843e96f9c"
    )
    assert sha(new["producer.py"]) == "3534e3d7c9aa1ef2e41b8cb720877a1b4e1f06e2ec512a9dec0480477d8db22f"
    source = new["inputs/source-map.json"]
    assert sha(source) == "ebc283be6f4c0ea8205d0ea44c4d2fa0b03eab14f1c5af7322d0167292e33096"
    pins = json.loads(source)["files"]
    assert len(pins) == 708
    names = sorted(pins)
    assert all(n.startswith("ci/gauntlet-rs/") and ":" not in n and "\n" not in n for n in names)
    query = "".join(COMMIT + ":" + n + "\n" for n in names).encode()
    blobs = subprocess.run(["git", "cat-file", "--batch"], cwd=W, input=query, capture_output=True, check=True)
    assert not blobs.stderr and len(blobs.stdout) <= 32 * 1024**2
    at = 0
    for name in names:
        end = blobs.stdout.index(b"\n", at)
        fields = blobs.stdout[at:end].split()
        assert len(fields) == 3 and fields[1] == b"blob"
        size = int(fields[2])
        at = end + 1
        assert sha(blobs.stdout[at : at + size]) == pins[name]
        at += size
        assert blobs.stdout[at : at + 1] == b"\n"
        at += 1
    assert at == len(blobs.stdout)
    baseline = subprocess.check_output(
        ["git", "show", PYTHON_BASELINE + ":ci/gauntlet/control_plane/feature_entry.py"], cwd=W
    )
    assert sha(baseline) == "d3d5b72d7bd9c725d7cc9b90aa3bb7bc442a99a5e188943f4686bf34e4c048de"
    fn = next(n for n in ast.parse(baseline).body if isinstance(n, ast.FunctionDef) and n.name == "junit")
    ns = {"Path": Path, "ET": ET}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "<immutable-python-junit>", "exec"), ns)
    stage = evidence / "native-feature-environment-host-readback-001"
    stage.mkdir()
    for name, raw in new.items():
        write(stage / name, raw)
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    changed = []
    for previous, group in zip(before["groups"], after["groups"], strict=True):
        for key in ["id", "label", "tests", "evidence_kind", "attempted"]:
            assert previous[key] == group[key]
        name = group["id"]
        assert sha(new[f"output/{name}.log"]) == group["log_sha256"]
        assert sha(new[f"output/{name}.xml"]) == group["junit_sha256"]
        observed = ns["junit"](stage / "output" / (name + ".xml"))
        assert observed == group["counts"]
        cases = list(ET.fromstring(new[f"output/{name}.xml"]).iter("testcase"))
        actual = dict(
            tests=len(cases),
            failures=sum(len(c.findall("failure")) for c in cases),
            errors=sum(len(c.findall("error")) for c in cases),
            skipped=sum(len(c.findall("skipped")) for c in cases),
        )
        assert actual == observed
        for key in counts:
            counts[key] += actual[key]
        if previous["status"] != group["status"]:
            changed.append(name)
        if name == "codex_claude":
            assert previous["counts"]["failures"] == 1 and group["counts"]["failures"] == 0
            assert group["status"] == "passed" and group["counts"]["tests"] == 59
        else:
            assert previous["counts"] == group["counts"] and previous["status"] == group["status"]
    assert changed == ["codex_claude"] and counts == dict(tests=1289, failures=0, errors=0, skipped=1)
    assert sum(g["status"] == "passed" for g in after["groups"]) == 27
    cleanup = json.loads(new["proof/cleanup.json"])
    assert cleanup["preserved_records"] == 333 and all(
        cleanup[k] is True for k in ["container_absent", "cgroup_absent", "profile_absent"]
    )
    samples = json.loads(new["proof/outside-samples.json"])
    assert len(samples) == 70
    for row in samples:
        assert row["exe_sha256"] == new_spec["executor_sha256"] and row["nspid"][-1] == "1"
        assert (
            row["limits"]["memory.max"] == str(12 * 1024**3)
            and row["limits"]["memory.swap.max"] == "0"
            and row["limits"]["pids.max"] == "2048"
        )
        quota, period = map(int, row["limits"]["cpu.max"].split())
        assert quota == 2 * period
    arm = archive(evidence / "native-feature-env-readback-vm-results-001.tar", 1024 * 1024, ARM_ARCHIVE, 5)
    arm_result = json.loads(arm["result.json"])
    assert arm_result["preserved_records"] == 333 and arm_result["report_sha256"] == NEW_REPORT
    assert arm_result["reader_sha256"] == "ce3384735e511f83ac7401bec1b52be3feb6bca741ddedc7c1b3b0c72e6062af"
    assert arm["actual.stdout"] == arm["restart.stdout"]
    reader = evidence / "native-feature-readback-mac-reader-001"
    assert sha(read(reader, 8 * 1024**2)) == MAC_READER_HASH
    args = [
        str(reader),
        str(stage / "inputs/feature-spec.json"),
        sha(new["inputs/feature-spec.json"]),
        str(stage / "proof/feature-stdout.json"),
        NEW_REPORT,
        str(stage / "output"),
    ]
    outputs = []
    for label in ["actual", "restart"]:
        result = subprocess.run(
            args, stdin=subprocess.DEVNULL, capture_output=True, env={"PATH": "/usr/bin:/bin"}, timeout=30
        )
        assert result.returncode == 1 and not result.stderr and result.stdout == arm["actual.stdout"]
        write(stage / ("mac-" + label + ".stdout"), result.stdout)
        outputs.append(result.stdout)
    assert outputs[0] == outputs[1] and json.loads(outputs[0])["status"] == "incomplete"
    assert sha(read(reader, 8 * 1024**2)) == MAC_READER_HASH
    record = dict(
        schema="hol-gauntlet-feature-environment-fixed-host-proof.v1",
        executor_commit=COMMIT,
        git_blobs_checked=708,
        old_archive_sha256=AUDIT_HASH,
        corrected_archive_sha256=NEW_ARCHIVE,
        arm_archive_sha256=ARM_ARCHIVE,
        source_commit=PRODUCT,
        counts=counts,
        passed_groups=27,
        incomplete_groups=1,
        only_changed_group=changed[0],
        python_counts_matched=28,
        outside_samples=70,
        readback_sha256=sha(outputs[0]),
        worker_records_preserved=333,
        script_sha256=sha(read(Path(__file__).resolve(), 128 * 1024)),
        shared_proof_sha256=sha(
            read(Path(__file__).with_name("verify_feature_executor_20261028.py").resolve(), 128 * 1024)
        ),
        execution_eligible=False,
        qualification_eligible=False,
    )
    write(
        evidence / "native-feature-environment-fixed-host-proof-001.json", json.dumps(record, sort_keys=True).encode()
    )
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    assert len(sys.argv) == 2
    main(Path(sys.argv[1]).resolve(strict=True))
