"""Read original Root test exports; never execute code or admit a benchmark."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tarfile


def verify(directory: Path) -> dict:
    cases = [
        ("store", "75a3500975bfe6a4a75d33aeecdfe565d4d331bb3056c41f9710267d8762b4ef",
         "fc8d15214c363d213a17ae4a7f3ea2a55b21bf810d2b421103ce528ccecb7617", 161, 4),
        ("socket", "acda30cc83212123fd91cdbde822eec76bccceb20e1d5e49231b5c45b182fb5c",
         "d214c2c09dabb363418ffd5a1120bc422a77c6ef256eee578f65c26244c9c7e8", 164, 3),
    ]
    results = {}
    for role, archive_pin, binary_pin, passed, focused in cases:
        path = directory / f"rust-mcp-root-{role}-native-results-001.tar"
        raw = path.read_bytes()
        assert len(raw) == 30720 and hashlib.sha256(raw).hexdigest() == archive_pin
        with tarfile.open(path, mode="r:") as archive:
            members = archive.getmembers()
            assert len(members) == 3 and {m.name for m in members} == {
                "result.json", "stdout", "stderr"}
            assert all(m.isfile() and 0 <= m.size < 1024 * 1024 for m in members)
            data = {m.name: archive.extractfile(m).read() for m in members}
        result = json.loads(data["result.json"])
        assert result["schema"] == f"hol-gauntlet-rust-mcp-root-{role}-tests.v1"
        assert result["binary_sha256"] == binary_pin
        assert result["machine"] == "aarch64" and result["uid"] == 0
        assert result["returncode"] == 0 and result["results"] == [["ok", str(passed), "0", "24"]]
        tests = result[f"root_{role}_tests"]
        assert len(tests) == focused and len(set(tests)) == focused
        module = "store" if role == "store" else "sockets"
        assert all(s.startswith(f"test native_mcp_{module}::tests::")
                   and s.endswith(" ... ok") for s in tests)
        assert all(data["stdout"].decode().count(s) == 1 for s in tests)
        for name in ("stdout", "stderr"):
            assert hashlib.sha256(data[name]).hexdigest() == result[name + "_sha256"]
        assert data["stderr"] == b""
        assert result["execution_eligible"] is False
        assert result["guard_causality_verified"] is False and result["model_requests"] == 0
        results[role] = {"archive_sha256": archive_pin, "binary_sha256": binary_pin,
                         "passed": passed, "focused_tests": focused, "ignored": 24}
    return {"schema": "hol-gauntlet-rust-mcp-root-host-readback.v1", "results": results,
            "archives_verified": True, "authenticated_mcp_execution": False,
            "execution_eligible": False, "guard_causality_verified": False, "model_requests": 0}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify_rust_mcp_root_boundary_20261027.py EVIDENCE_DIRECTORY")
    print(json.dumps(verify(Path(sys.argv[1])), sort_keys=True))
