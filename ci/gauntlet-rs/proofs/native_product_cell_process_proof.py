"""Exercise the Rust actor through Python's existing authenticated cell client.

Explicit local proof only. The Docker fixture has no network and runs the
actor as PID1, UID/GID 10004, with zero capabilities and NNP. Root setup copies
the two hash-checked apparatus inputs into its disposable filesystem. This
does not run Guard, a provider, the benchmark, or a production VM deployment.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import select
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
# These reference imports follow the explicit checkout insertion above.
from ci.gauntlet.benchmark.product_cell_protocol import CellCodec  # noqa: E402
from ci.gauntlet.benchmark.vm_bridge_io import BridgeIO  # noqa: E402
from ci.gauntlet.benchmark.vm_bridge_rpc import BridgeClient, BridgeRemoteError  # noqa: E402

LIBRARY_SHA = "3d128123b494ca9e88f3c237b0912397145af1754e86ea99f460af6857441f19"
IMAGE = "rust:1.88.0-slim-bookworm"
FILTER_READY = b"HOL_CELL_FILTER_READY_V1\n"
LABEL_QUERY = '{{index .Config.Labels "hol-gauntlet-rust-proof"}}'


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True, timeout=15, check=check)


def await_marker(process):
    data = bytearray()
    deadline = time.monotonic() + 10
    while len(data) < len(FILTER_READY):
        left = deadline - time.monotonic()
        if left <= 0 or not select.select([process.stdout], [], [], max(left, 0))[0]:
            raise TimeoutError("Rust actor readiness deadline")
        chunk = os.read(process.stdout.fileno(), len(FILTER_READY) - len(data))
        if not chunk:
            reason = process.stderr.read(4096).decode(errors="replace")
            raise RuntimeError("Rust actor stopped before readiness: " + reason)
        data.extend(chunk)
    assert data == FILTER_READY, repr(bytes(data))


def refused(client, operation, payload):
    try:
        client.call(operation, payload, timeout=3)
    except BridgeRemoteError:
        return
    raise AssertionError(f"{operation} unexpectedly accepted an invalid operation")


def drain(client, handle, *, over_budget=False):
    output = [bytearray(), bytearray()]
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            row = client.call("read", {"handle": handle, "wait_ms": 100}, timeout=3)
        except BridgeRemoteError:
            if over_budget:
                return None
            raise
        for index, key in enumerate(("stdout", "stderr")):
            output[index].extend(base64.b64decode(row[key], validate=True))
        assert sum(map(len, output)) <= 8 * 1024 * 1024
        if row["returncode"] is not None and row["stdout_eof"] and row["stderr_eof"]:
            assert not over_budget, "over-budget output was accepted"
            return row["returncode"], tuple(map(bytes, output))
    raise TimeoutError("bounded product did not drain")


def run_profile(inputs, profile, boot):
    nonce = uuid.uuid4().hex
    name = "hol-gauntlet-rust-cell-proof-" + nonce[:16]
    cidfile = inputs / ("container-" + profile + ".cid")
    script = r"""#!/bin/sh
set -eu
/usr/bin/install -D -o 0 -g 0 -m 0555 /inputs/gauntlet-product-cell /public/gauntlet-product-cell
/usr/bin/install -D -o 0 -g 0 -m 0444 /inputs/libseccomp.so.2.5.5 /usr/lib/aarch64-linux-gnu/libseccomp.so.2.5.5
/usr/bin/install -D -o 0 -g 0 -m 0444 /inputs/product_vm_seccomp_oci_v1.json /public/product_vm_seccomp_oci_v1.json
/usr/bin/install -D -o 0 -g 0 -m 0444 /inputs/network-PROFILE /etc/hol-cell-network-profile
/bin/mkdir -p /task /product
/bin/chown 10004:10004 /task /product
exec /usr/bin/setpriv --reuid=10004 --regid=10004 --clear-groups --no-new-privs \
    --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
    /public/gauntlet-product-cell actor
""".replace("PROFILE", profile)
    setup = inputs / ("setup-" + profile + ".sh")
    with setup.open("x") as stream:
        stream.write(script)
    process = subprocess.Popen([
        "docker", "run", "--rm", "--pull=never", "--name", name, "--network", "none",
        "--cidfile", str(cidfile), "--label", "hol-gauntlet-rust-proof=" + nonce,
        "--memory", "1g", "--cpus", "1", "--pids-limit", "128", "--interactive",
        "--env", "HOL_GAUNTLET_PROBE_POISON=must-not-reach-product",
        "--volume", str(inputs) + ":/inputs:ro", "--entrypoint", "/bin/sh", IMAGE,
        "/inputs/" + setup.name,
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    clean = False
    owned = None
    try:
        await_marker(process)
        owned = cidfile.read_text().strip()
        assert len(owned) == 64 and all(character in "0123456789abcdef" for character in owned)
        label = docker("inspect", "--format", LABEL_QUERY, owned)
        assert label.stdout.decode().strip() == nonce
        key = os.urandom(32)
        session = str(uuid.uuid4())
        raw = json.dumps({"schema": "product-cell-private-bootstrap.v1", "key_hex": key.hex(),
                          "session": session, "boot_id": boot}, separators=(",", ":")).encode()
        packet = len(raw).to_bytes(4, "big") + raw
        assert process.stdin.write(packet) == len(packet)
        codec = CellCodec(key, session=session, local_role="cell-supervisor", local_boot=boot, peer_boot=boot)
        client = BridgeClient(BridgeIO(process.stdout.fileno(), process.stdin.fileno(), codec))
        hello = client.call("hello", {}, timeout=3)
        assert hello == {"schema": "product-cell-actor.v2", "local_pid": 1, "uid": 10004, "gid": 10004,
                         "limits": {"active_children": 64, "total_spawns": 1024, "read_wait_ms": 100}}
        refused(client, "not_registered", {})
        refused(client, "spawn", {"argv": ["relative"]})
        refused(client, "release", {"handle": "unowned"})
        command = ('test -z "${HOL_GAUNTLET_PROBE_POISON+x}" || exit 19; '
                   'test "$HOME" = /product/home || exit 20; '
                   'test "$PATH" = /usr/bin:/bin || exit 21; '
                   'printf released > /task/gated.txt; /usr/bin/id -u; printf standard-error >&2')
        spawned = client.call("spawn", {"argv": ["/bin/sh", "-c", command]}, timeout=5)
        handle = spawned["handle"]
        assert spawned["gate_ready"] is True and spawned["local_pid"] > 1
        absent = docker("exec", owned, "/usr/bin/test", "-e", "/task/gated.txt", check=False)
        assert absent.returncode == 1, "product ran before its measured gate was released"
        refused(client, "read", {"handle": handle, "wait_ms": True})
        refused(client, "write", {"handle": handle, "data": "YQ=="})
        assert client.call("release", {"handle": handle}, timeout=3) == {"released": True}
        refused(client, "release", {"handle": handle})
        assert client.call("end_input", {"handle": handle}, timeout=3) == {"stdin_closed": True}
        assert drain(client, handle) == (0, (b"10004\n", b"standard-error"))
        assert docker("exec", owned, "/bin/cat", "/task/gated.txt").stdout == b"released"
        assert client.call("retire", {"handle": handle}, timeout=3) == {"retired": True}
        refused(client, "read", {"handle": handle})
        cat = client.call("spawn", {"argv": ["/bin/cat"]}, timeout=5)["handle"]
        client.call("release", {"handle": cat}, timeout=3)
        payload = b"actual stdin\x00binary bytes\n"
        encoded = base64.b64encode(payload).decode()
        assert client.call("write", {"handle": cat, "data": encoded}, timeout=3) == {"written": len(payload)}
        refused(client, "write", {"handle": cat, "data": "!invalid!"})
        refused(client, "write", {"handle": cat, "data": "A" * 350001})
        client.call("end_input", {"handle": cat}, timeout=3)
        assert drain(client, cat) == (0, (payload, b""))
        client.call("retire", {"handle": cat}, timeout=3)
        noisy = client.call("spawn", {"argv": ["/usr/bin/head", "-c", "8388609", "/dev/zero"]}, timeout=5)["handle"]
        client.call("release", {"handle": noisy}, timeout=3)
        client.call("end_input", {"handle": noisy}, timeout=3)
        assert drain(client, noisy, over_budget=True) is None
        assert client.call("hello", {}, timeout=3) == hello
        assert client.call("close", {}, timeout=3) == {"closed": True, "outside_descendant_cleanup_required": True}
        assert process.wait(timeout=5) == 0, process.stderr.read(4096).decode(errors="replace")
        clean = True
        return {"profile": profile, "hello": hello, "gated_execution": True, "single_release": True,
                "fixed_environment": True, "binary_stdin_stdout": True, "stderr_drained": True,
                "output_budget_refused": True, "foreign_handle_refused": True, "clean_exit": True,
                "execution_eligible": False}
    finally:
        if not clean:
            if owned is None and cidfile.exists():
                candidate = cidfile.read_text().strip()
                if len(candidate) == 64 and all(character in "0123456789abcdef" for character in candidate):
                    label = docker("inspect", "--format", LABEL_QUERY, candidate, check=False)
                    if label.returncode == 0 and label.stdout.decode().strip() == nonce:
                        owned = candidate
            if owned:
                docker("rm", "--force", owned, check=False)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.read_bytes()
    library = args.library.read_bytes()
    assert hashlib.sha256(binary).hexdigest() == args.binary_sha256
    assert hashlib.sha256(library).hexdigest() == LIBRARY_SHA
    args.output.mkdir(mode=0o700)
    profile_bytes = (ROOT / "ci/gauntlet/benchmark/product_vm_seccomp_oci_v1.json").read_bytes()
    for name, raw in [("gauntlet-product-cell", binary), ("libseccomp.so.2.5.5", library),
                      ("product_vm_seccomp_oci_v1.json", profile_bytes)]:
        with (args.output / name).open("xb") as stream:
            stream.write(raw)
    for profile in ("unix-only-v1", "private-loopback-v1"):
        with (args.output / ("network-" + profile)).open("x") as stream:
            stream.write(profile + "\n")
    boot = docker("run", "--rm", "--pull=never", "--network", "none", "--entrypoint", "/bin/cat",
                  IMAGE, "/proc/sys/kernel/random/boot_id").stdout.decode().strip()
    results = [run_profile(args.output.resolve(), profile, boot) for profile in ("unix-only-v1", "private-loopback-v1")]
    record = {"schema": "hol-gauntlet-rust-product-cell-process-proof.v1", "binary_sha256": args.binary_sha256,
              "library_sha256": LIBRARY_SHA, "profiles": results, "model_requests": 0, "execution_eligible": False}
    raw = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
    with (args.output / "result.json").open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"result": str(args.output / "result.json"), "sha256": hashlib.sha256(raw).hexdigest(),
                      "profiles_passed": len(results), "execution_eligible": False}))


if __name__ == "__main__":
    main()
