"""Read the fixed three-test ARM capture-input proof; grant no admission."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from verify_native_mcp_transport_20261027 import archive, parse, sha

SOURCE = "052cbabd00a889d5b862205c22f58a5b695140d8"
INPUT = "ec73a5b4524ed8f10870e643f7f488d266768773107eede5f84a69cea4108179"
EXPORT = "1d34a7411d1f41091f4f9e058d6eb77129b40b61ddc4b47674180fbd7d12b041"
ELF = "257235f58cff57b6e5984a17bfc2d73edc7766bdc550b990f15cd99e69b408a6"
LOG = "b206d807bc3df9225013c192fbe01bbd5573b7fb383b3252eb6d63fa62cdaf06"


def verify(directory):
    inputs = archive(directory / "native-capture-input-arm-input-001.tar", INPUT, 9605120, 2)
    data = archive(directory / "native-capture-input-arm-vm-results-001.tar", EXPORT, 10240, 6)
    transfer = parse(inputs["transfer.json"])
    assert transfer == parse(data["transfer.json"]) and transfer["source_commit"] == SOURCE
    assert transfer["compiled_before_commit_source_bytes_verified"] is True
    assert set(transfer["source_files"]) == {"lib.rs", "supervisor_capture.rs", "supervisor_capture_input.rs"}
    work = Path(__file__).resolve().parents[3]
    for name, pin in transfer["source_files"].items():
        path = SOURCE + ":ci/gauntlet-rs/crates/gauntlet-cell-rootfs/src/" + name
        assert sha(subprocess.check_output(["git", "show", path], cwd=work)) == pin
    install, proof = parse(data["install.json"]), parse(data["proof.json"])
    assert install["source_commit"] == proof["source_commit"] == SOURCE
    assert install["root_owned"] and install["files"] == transfer["files"]
    assert install["input_sha256"] == proof["input_sha256"] == INPUT
    assert proof["worker_files_preserved"] == 284
    assert proof["both_worker_leases_held"] and proof["owned_product_cgroups_absent"]
    for value in [transfer, install, proof]:
        assert value["execution_eligible"] is False and value["model_requests"] == 0
    assert proof["guard_causality_verified"] is False
    metadata = parse(data["results.sha256.json"])["filesystem"]
    for name in set(data) - {"results.sha256.json"}:
        assert metadata[name]["uid"] == metadata[name]["gid"] == 0
        assert metadata[name]["mode"] == 0o400 and metadata[name]["links"] == 1
    raw = inputs["evidence-tests"]
    assert raw[:4] == b"\x7fELF" and raw[18:20] == b"\xb7\0" and sha(raw) == ELF
    assert transfer["files"] == {"evidence-tests": {"bytes": len(raw), "sha256": ELF}}
    result = parse(data["input-tests.json"])
    assert proof["results"] == [result]
    assert result["source_commit"] == SOURCE and result["executable_sha256"] == ELF
    assert result["filter"] == "supervisor_capture_input::tests" and result["returncode"] == 0
    assert result["results"] == [["ok", "3", "0", "0"]]
    assert result["log_sha256"] == sha(data["input-tests.log"]) == LOG
    assert re.findall(
        rb"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", data["input-tests.log"]
    ) == [(b"ok", b"3", b"0", b"0")]
    return {
        "schema": "hol-gauntlet-native-capture-input-arm-host-readback.v1",
        "rust_source_commit": SOURCE,
        "input_sha256": INPUT,
        "export_sha256": EXPORT,
        "native_capture_input_tests": 3,
        "retained_worker_files_unchanged": 284,
        "fresh_native_capture_execution": False,
        "qualified_role_complete": False,
        "execution_eligible": False,
        "guard_causality_verified": False,
        "model_requests": 0,
    }


if __name__ == "__main__":
    if not __debug__ or len(sys.argv) != 2:
        raise SystemExit("usage (assertions enabled): verify_native_capture_input_arm_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
