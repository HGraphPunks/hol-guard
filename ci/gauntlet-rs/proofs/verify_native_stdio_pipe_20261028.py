"""Independently read the retained public pipe fixture export with pinned Rust."""

import hashlib
import io
import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile

from native_stdio_arm_proof_20261028 import verify as verify_arm

assert len(sys.argv) == 3, "usage: EVIDENCE_DIRECTORY NEW_RUN_INDEX"
E = pathlib.Path(sys.argv[1])
RUN_INDEX = sys.argv[2]
assert len(RUN_INDEX) == 3 and RUN_INDEX.isdigit()
W = pathlib.Path(__file__).resolve().parents[3]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


source = "018890172c5a0976f9cad606bf55433d8be8a027"
tools_raw = (E / "native-stdio-readback-tools-001.json").read_bytes()
assert sha(tools_raw) == "6e56f4ab17d6fa9d41f61599d97d0b5338042d1917ad1a9fc0a0f24f627eb473"
meta = json.loads(tools_raw)
assert meta["source_commit"] == "bd262dcad72278b58ae1059866a217acf366c90b"
reader_pin = meta["files"]["mac-stdio-reader"]
reader = E / "native-stdio-readback-mac-stdio-reader-001"


def stable():
    assert (
        sha(reader.read_bytes())
        == reader_pin["sha256"]
        == "dd9ce2f5e7424e7ec96c71d9111f1434316d5e855a1ffbfb44e8dddb55cfbb80"
    )


stable()
raw = (E / "native-stdio-capture-vm-results-001.tar").read_bytes()
assert len(raw) == 655360 and sha(raw) == "e29a91ec9f5f356f76c0a74828a3124220fe2822e52a493d31280d737856c780"
files = {}
with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as t:
    members = t.getmembers()
    assert len(members) == 82
    for m in members:
        assert m.isfile() and m.uid == m.gid == m.mtime == 0 and m.mode == 0o600 and 0 <= m.size < 1024 * 1024
        assert (
            m.name not in files
            and not pathlib.PurePosixPath(m.name).is_absolute()
            and ".." not in pathlib.PurePosixPath(m.name).parts
        )
        b = t.extractfile(m).read(m.size + 1)
        assert len(b) == m.size
        files[m.name] = b


def parsed(name):
    return json.loads(files[name])


index = parsed("results.sha256.json")
assert set(index["files"]) == set(files) - {"results.sha256.json"}
for name, pin in index["files"].items():
    assert pin == dict(bytes=len(files[name]), sha256=sha(files[name]))
for name, m in index["filesystem"].items():
    assert name in files and m["uid"] == m["gid"] == 0 and m["mode"] == 0o600 and m["links"] == 1
tools = parsed("tools.json")
pins = {
    "001": dict(
        source="f137c1b026be4563798366fcd959e6ff4e6b35db",
        rootfs="d628071c610794d3c8fde6588b5e76e4b85b8e47d086a7ae6f3273dd495a8512",
        fixture="a812494fe5c6121d1449f5cf24fb472b4c294ad5a4e392828dc683f0dc56d02b",
    ),
    "002": dict(
        source=source,
        rootfs="c36a25679b12f961a55c57b89a8aa4afb93977d32f5968c1e3444419ab8d6f90",
        fixture="0e140c668570441fd0346ad0af3592f117d6ca0f363eb7e9b778a9f4eb467574",
    ),
}
for episode, pin in pins.items():
    transfer = parsed("input/" + episode + "/transfer.json")
    src = parsed("input/" + episode + "/source.json")
    assert transfer["source_commit"] == src["source_commit"] == pin["source"]
    for path, h in src["files"].items():
        assert path.startswith("ci/gauntlet-rs/crates/gauntlet-cell-rootfs/src/")
        assert sha(subprocess.check_output(["git", "show", pin["source"] + ":" + path], cwd=W)) == h
    for name in ["source.json", "mac-workspace.log"]:
        b = files["input/" + episode + "/" + name]
        assert transfer["files"][name] == dict(bytes=len(b), sha256=sha(b))
    for name, key, mode in [("rootfs-tests", "rootfs", 0o500), ("fixture", "fixture", 0o555)]:
        tool = tools[episode][name]
        assert (
            tool["sha256"] == pin[key]
            and tool["uid"] == tool["gid"] == 0
            and tool["links"] == 1
            and tool["mode"] == mode
        )
        assert transfer["files"][name] == {k: tool[k] for k in ["bytes", "sha256"]}
    assert tools[episode]["public-fixture"]["sha256"] == pin["fixture"]
    assert tools[episode]["public-fixture"]["mode"] == 0o555 and tools[episode]["public-fixture"]["links"] == 1
    assert tools[episode]["public-fixture"]["uid"] == tools[episode]["public-fixture"]["gid"] == 0
assert parsed("input/002/source.json")["mac_workspace_source_commit"] == pins["001"]["source"]
mac = files["input/001/mac-workspace.log"]
assert mac == files["input/002/mac-workspace.log"]
counts = re.findall(rb"test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored;", mac)
assert [sum(int(v[i]) for v in counts) for i in range(3)] == [607, 0, 0]
for episode, passed, failed in [("001", 0, 6), ("002", 4, 2)]:
    log = files["proof/" + episode + "/pipe-fixtures.stdout"]
    assert re.findall(rb"test result: FAILED\. ([0-9]+) passed; ([0-9]+) failed;", log) == [
        (str(passed).encode(), str(failed).encode())
    ]
    record = parsed("proof/" + episode + "/pipe-fixtures.json")
    assert record["returncode"] == 101 and record["counts"] == [] and record["stdout_sha256"] == sha(log)
    assert record["stderr_sha256"] == sha(files["proof/" + episode + "/pipe-fixtures.stderr"])
result = parsed("proof/003/result.json")
assert result["source_commit"] == source and (result["passed"], result["failed"], result["ignored"]) == (22, 0, 0)
assert (result["complete_pipe_histories"], result["expected_pipe_refusals"], result["captured_bytes"]) == (4, 3, 4161)
for label, count in [("syscall-decoder", 9), ("pipe-fixtures", 6), ("legacy-process-fixtures", 7)]:
    record = parsed("proof/003/" + label + ".json")
    assert (
        record == result["results"][label]
        and record["source_commit"] == source
        and record["returncode"] == 0
        and record["counts"] == [[count, 0, 0]]
    )
    for kind in ["stdout", "stderr"]:
        assert record[kind + "_sha256"] == sha(files["proof/003/" + label + "." + kind])
    assert not files["proof/003/" + label + ".stderr"]
assert (
    sha(files["proof/003/final-worker-hashes.json"])
    == "16b21c170df5494738bc40b188694f186c87a2f9caca75d1f50d05459d4aa9be"
)
assert len(parsed("proof/003/final-worker-hashes.json")) == 326
final = parsed("final.json")
assert (
    final["both_worker_leases_held"] is True
    and final["worker_files_preserved"] == 326
    and final["fresh_product_execution"] is False
)
output = E / ("native-stdio-capture-independent-readback-" + RUN_INDEX)
output.mkdir(mode=0o700)
runs = {}


def save(path, raw):
    with path.open("xb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(raw)


def run(label, stdio, process, checkpoint, rc=0, wrong=None):
    dest = output / label
    dest.mkdir(mode=0o700)
    values = [stdio, process, checkpoint]
    names = ["stdio.jsonl", "process.jsonl", "checkpoint.json"]
    args = [str(reader)]
    for i, (name, data) in enumerate(zip(names, values, strict=True)):
        path = dest / name
        save(path, data)
        args.extend([str(path), "0" * 64 if wrong == i else sha(data)])
    actual = subprocess.run(args, capture_output=True, timeout=20)
    save(dest / "stdout", actual.stdout)
    save(dest / "stderr", actual.stderr)
    record = dict(returncode=actual.returncode, stdout_sha256=sha(actual.stdout), stderr_sha256=sha(actual.stderr))
    save(dest / "result.json", json.dumps(record, sort_keys=True).encode())
    runs[label] = record
    assert actual.returncode == rc, (label, record, actual.stderr.decode())
    if rc == 0:
        assert not actual.stderr
        value = json.loads(actual.stdout)
        for key in [
            "atomic_kernel_pipe_bytes_verified",
            "concurrent_memory_authenticated",
            "request_semantics_verified",
            "outside_observer_admitted",
            "outside_signing_key_admitted",
            "execution_eligible",
            "guard_causality_verified",
        ]:
            assert value[key] is False
        return value
    assert not actual.stdout and actual.stderr
    return None


complete = []
for name in files:
    if not name.startswith("proof/003/fixtures/native-stdio-") or not name.endswith("/stdio-test-result.json"):
        continue
    checkpoint = parsed(name)
    parent = name.rsplit("/", 1)[0]
    stdio = files[parent + "/native-stdio-events.v1.jsonl"]
    process = files[parent + "/native-process-events.v1.jsonl"]
    mode = parent.rsplit("/", 1)[1].rsplit("-", 1)[0]
    if checkpoint.get("complete") is True:
        value = run(mode, stdio, process, files[name])
        assert value["scope"] == "owned-process-fixture" and len(value["streams"]) == 1
        stream = value["streams"][0]
        if mode in ["native-stdio-scalar", "native-stdio-vector"]:
            frame = b'\0\0\0\x09{"x":123}'
            assert stream["read"]["sha256"] == stream["written"]["sha256"] == sha(frame)
            assert stream["read"]["complete_frames"] == stream["written"]["complete_frames"] == 1
        elif mode == "native-stdio-partial":
            assert stream["written"]["bytes"] == 4096 and stream["written"]["sha256"] == sha(b"P" * 4096)
            assert stream["written"]["status"] == "invalid-length" and stream["read"]["bytes"] == 0
        elif mode == "native-stdio-linger":
            assert stream["interrupted_stdio_call_observed"] is True
            assert stream["read"]["bytes"] == 0 and stream["read_eof_observed"] is False
            assert stream["written"]["sha256"] == sha(b'\0\0\0\x09{"x":123}')
        else:
            raise AssertionError(mode)
        complete.append((mode, stdio, process, files[name]))
    else:
        assert checkpoint["expected_refusal"] is True
        run(mode + "-refused", stdio, process, files[name], 2)
assert len(complete) == 4
_, stdio, process, checkpoint = next(v for v in complete if v[0] == "native-stdio-scalar")
for index in range(3):
    run("wrong-outside-pin-" + str(index), stdio, process, checkpoint, 2, index)
# Alter actual captured bytes while recomputing the chain and public caller
# pins. The retained per-transfer content digest must still reject the data.
rows = [json.loads(v) for v in stdio.splitlines()]
for row in rows:
    if row["kind"] == "stdio-bytes":
        import base64

        data = bytearray(base64.b64decode(row["data"]["base64"]))
        data[0] ^= 1
        row["data"]["base64"] = base64.b64encode(data).decode()
        break
previous = "0" * 64
altered = b""
for sequence, row in enumerate(rows):
    row["sequence"] = sequence
    row["previous_sha256"] = previous
    line = json.dumps(row, sort_keys=True, separators=(",", ":")).encode()
    previous = sha(line)
    altered += line + b"\n"
cp = json.loads(checkpoint)
cp["native_stdio"]["journal"].update(events=len(rows), bytes=len(altered), tail_sha256=previous)
run(
    "rehashed-wrong-captured-bytes", altered, process, json.dumps(cp, sort_keys=True, separators=(",", ":")).encode(), 2
)
arm = verify_arm(E, W, files, runs, meta)
stable()
summary = dict(
    schema="hol-gauntlet-native-stdio-capture-independent-readback.v1",
    producer_source_commit=source,
    reader_source_commit=meta["source_commit"],
    reader_source_committed=True,
    reader_sha256=reader_pin["sha256"],
    archive_sha256=sha(raw),
    public_members=82,
    mac_workspace_source_commit=pins["001"]["source"],
    mac_tests_passed=607,
    arm_tests_passed=22,
    complete_pipe_histories=4,
    expected_pipe_refusals=3,
    additional_reader_refusals=4,
    captured_bytes=4161,
    runs=runs,
    worker_files_preserved=326,
    arm_verification=arm,
    execution_eligible=False,
    guard_causality_verified=False,
    model_requests=0,
)
save(output / "summary.json", json.dumps(summary, sort_keys=True, separators=(",", ":")).encode())
print(json.dumps(summary, sort_keys=True))
