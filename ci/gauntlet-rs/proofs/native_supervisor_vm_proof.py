"""Stage a retained image/runtime for the Rust-owned native cell VM proof.

The retained Python adapter owns only staging/image lease and independent final
readback. The Rust executable owns the actual service, kernel measurements,
bootstrap, actor operations, capture and cell cleanup. No inference is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import traceback
import types

HELPERS = ("/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/aa-exec",
           "/usr/bin/unshare", "/usr/sbin/apparmor_parser")


def read_root(path, maximum):
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("canonical Root input required")
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("immutable Root ancestry required")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size <= maximum):
            raise ValueError("bounded immutable Root file required")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(other, key)
                                          for key in fields for other in (after, path.lstat())):
            raise ValueError("Root input changed while reading")
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    path.chmod(0o400)


def run(args, base):
    directory = Path(args.inputs)
    for name, pin in (("gauntlet-cell-rootfs", args.constructor_sha256),
                      ("gauntlet-native-cell-proof", args.proof_sha256)):
        if sha(read_root(directory / name, 16 * 1024**2)) != pin:
            raise ValueError("Rust executable differs from outside pin")
    controller = Path("/opt/hol-gauntlet") / ("controller-" + args.controller_source[:16])
    verifier = Path("/opt/hol-gauntlet") / ("native-cell-input-" + args.controller_source[:16]) / "gauntlet-controller-install-verify-shadow"
    if sha(read_root(verifier, 16 * 1024**2)) != args.verifier_sha256:
        raise ValueError("controller verifier differs from outside pin")

    def verify():
        result = subprocess.run([str(verifier), args.controller_source, args.controller_tree_sha256],
                                capture_output=True, check=True, timeout=30)
        return json.loads(result.stdout)

    before = verify()
    legacy = Path("/opt/hol-gauntlet/rust-shadow-candidates/b70d59e2681c4a3f/provisional-66703091ba2f7815-8ef7a22ac7a4d01b.json")
    raw = read_root(legacy, 1024**2)
    if sha(raw) != args.legacy_config_sha256:
        raise ValueError("retained config differs from outside pin")
    config = json.loads(raw)
    output = Path(args.output)
    base.trusted_parents(output)
    output.mkdir(mode=0o700)
    result = {"schema": "hol-gauntlet-native-supervisor-parent.v1", "case": args.case,
              "status": "failed", "constructor_sha256": args.constructor_sha256,
              "proof_sha256": args.proof_sha256, "controller_before": before,
              "model_requests": 0, "execution_eligible": False, "rust_image_lease_owned": False}
    plane = None
    try:
        # Import only after the independent whole-tree verifier matched it.
        sys.path.insert(0, str(controller))
        from ci.gauntlet.benchmark.developer_product_runtime import OperationBudget
        from ci.gauntlet.benchmark.private_cell_factory import PrivateCellConfig, build_private_cell
        workspace = output / "workspace"
        workspace.mkdir(mode=0o700)
        os.chown(workspace, 10001, 10001)
        prefix = Path("/opt") / config["assets"]["guard_prefix"]["path"]
        cell_config = {"schema": "developer-private-cell-config.v1",
                       "artifacts": str(legacy.parent / "cell-artifacts-rust-v2"),
                       "artifact_manifest_sha256": args.artifact_manifest_sha256,
                       **config["runtime"]["private_cell"]}
        plane = build_private_cell(root=output / "cell", config=PrivateCellConfig.parse(cell_config),
            python=prefix / "bin/python", source_sha=config["runtime"]["guard_source_sha"],
            prefix_digest=config["assets"]["guard_prefix"]["sha256"],
            bwrap_sha256=config["runtime"]["guard_bwrap_sha256"], image_id=config["runtime"]["guard_executor_image_id"],
            workspace_source=workspace, workspace_custody_root=output, provider_mounts=(), provider_custody_root=None,
            wall_seconds=180, operation_budget=OperationBudget(4), package_version=config["runtime"]["guard_package_version"])
        stage = output / "cell"
        declaration = {"schema": "hol-gauntlet-product-rootfs.v1", "stage": str(stage),
            "initializer_sha256": cell_config["initializer_sha256"],
            "artifact_manifest_sha256": args.artifact_manifest_sha256,
            "system_spec_sha256": plane.cell.system_digest, "task_spec_sha256": plane.cell.task_digest,
            "runtime_spec_sha256": sha(read_root(stage / "runtime.json", 8192)),
            "idmap_runtime": cell_config["idmap_runtime"], "state": "persistent-v1",
            "network_profile": "private-loopback-v1", "parent_network_namespace": os.readlink("/proc/self/ns/net")}
        save(stage / "native-rootfs.v1.json", declaration)
        helper_pins = {name: sha(read_root(Path(name), 16 * 1024**2)) for name in HELPERS}
        supervisor = {"schema": "hol-gauntlet-cell-supervisor.v1", "rootfs_declaration": str(stage / "native-rootfs.v1.json"),
            "rootfs_sha256": sha(read_root(stage / "native-rootfs.v1.json", 8192)),
            "constructor": str(directory / "gauntlet-cell-rootfs"), "constructor_sha256": args.constructor_sha256,
            "wall_seconds": 180, "cpu_profile": "single-core-v1", "job_slice": None, "host_helpers": helper_pins}
        save(stage / "native-supervisor.v1.json", supervisor)
        digest = sha(read_root(stage / "native-supervisor.v1.json", 8192))
        completed = subprocess.run([str(directory / "gauntlet-native-cell-proof"),
                                   str(stage / "native-supervisor.v1.json"), digest, args.case],
                                  capture_output=True, timeout=150)
        save(output / "rust-process.json", {"returncode": completed.returncode,
             "stdout": completed.stdout.decode(errors="replace"), "stderr": completed.stderr.decode(errors="replace")})
        report = json.loads(completed.stdout)
        if (completed.returncode or report.get("status") != "passed" or report.get("rust_supervisor_owned") is not True
                or report.get("cell_cleanup_complete") is not True or report.get("supervisor_declaration_sha256") != digest):
            raise ValueError("Rust-owned supervisor proof failed")
        result.update(status="passed", rust_report=report)
    except BaseException:
        result["traceback"] = traceback.format_exc()
        raise
    finally:
        try:
            intervened = []
            if plane is not None:
                # Independently resolve only the fresh journal's registered service.
                journal = output / "cell/native-supervisor-events.v1.jsonl"
                if journal.exists():
                    first = read_root(journal, 64 * 1024**2).splitlines()[0]
                    profile = json.loads(first)["data"]["profile"]
                    if re.fullmatch(r"hol-product-cell-[0-9a-f]{32}", profile) is None:
                        raise ValueError("unexpected owned Rust service name")
                    cgroup = Path("/sys/fs/cgroup/system.slice") / (profile + ".service")
                    if cgroup.exists():
                        intervened.append("systemd-stop")
                        subprocess.run(["/usr/bin/systemctl", "stop", profile + ".service"], check=True, timeout=10)
                    profiles = Path("/sys/kernel/security/apparmor/profiles").read_text()
                    if any(line.split()[0] == profile for line in profiles.splitlines()):
                        intervened.append("AppArmor-remove")
                        subprocess.run(["/usr/sbin/apparmor_parser", "--remove", str(output / "cell/native-cell.apparmor")], check=True, timeout=10)
                    if cgroup.exists():
                        raise ValueError("Rust product service survived independent cleanup")
                plane.close()
                result["image_cleanup_complete"] = plane.cleanup_complete
            result["outside_cleanup_interventions"] = intervened
            result["controller_after"] = verify()
            if intervened:
                raise ValueError("Rust cleanup required outside intervention; apparatus proof remains failed")
        except BaseException:
            result["status"] = "failed"
            result["cleanup_traceback"] = traceback.format_exc()
            raise
        finally:
            save(output / "result.json", result)
    print(json.dumps({key: result[key] for key in ("case", "status", "model_requests", "execution_eligible", "image_cleanup_complete")}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inputs", "driver", "driver-sha256", "constructor-sha256", "proof-sha256", "controller-source",
                 "controller-tree-sha256", "verifier-sha256", "legacy-config-sha256", "artifact-manifest-sha256", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--case", choices=("success", "timeout", "cancel"), required=True)
    args = parser.parse_args()
    raw = read_root(Path(args.driver), 128 * 1024)
    if sha(raw) != args.driver_sha256:
        raise ValueError("outside diagnostic driver pin differs")
    base = types.ModuleType("pinned_native_driver")
    exec(compile(raw, args.driver, "exec"), base.__dict__)
    with base.worker_leases():
        run(args, base)


if __name__ == "__main__":
    main()
