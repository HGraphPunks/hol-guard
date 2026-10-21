"""Fixed one-role Python executor for a future Rust-owned staging supervisor.

This adapter cannot create a conformance package or admit a candidate. Rust
must pin the controller, provisional config, signing key and one-use job before
launch, and must independently read and score the retained control afterwards.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import stat
import sys
from pathlib import Path

from .contracts import canonical_json
from .product_version import validate_version


ROLES = frozenset({'success', 'input-binding', 'injection', 'boundary', 'timeout', 'cancel'})
HEX16 = re.compile(r'[0-9a-f]{16}\Z')
HEX40 = re.compile(r'[0-9a-f]{40}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
MAX_CONTROL_BYTES = 8 * 1024 * 1024
WORKER_LOCK = Path('/opt/hol-gauntlet/worker.lock')


def parse_args(argv):
    if len(argv) != 7:
        raise ValueError('exact build job, staging run, source, version, config, manifest and role required')
    build_job, run_id, source, version, config_digest, private_manifest, role = argv
    if (HEX16.fullmatch(build_job) is None or HEX16.fullmatch(run_id) is None
            or HEX40.fullmatch(source) is None or HEX64.fullmatch(config_digest) is None
            or HEX64.fullmatch(private_manifest) is None or role not in ROLES):
        raise ValueError('invalid fixed staging control identity')
    validate_version(version)
    return build_job, run_id, source, version, config_digest, private_manifest, role


def staging_config_path(build_job, private_manifest, config_digest):
    return (Path('/opt/hol-gauntlet/rust-shadow-candidates') / build_job
            / ('provisional-' + private_manifest[:16] + '-' + config_digest[:16] + '.json'))


def _read_control(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
                or not 0 < before.st_size <= MAX_CONTROL_BYTES):
            raise ValueError('retained staging record is unsafe or oversized')
        raw = stream.read(MAX_CONTROL_BYTES + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) != before.st_size or len(raw) > MAX_CONTROL_BYTES
            or any(getattr(before, name) != getattr(after, name) for name in fields)):
        raise ValueError('retained staging record changed while reading')
    return hashlib.sha256(raw).hexdigest(), len(raw)


def _locked_worker():
    descriptor = os.open(WORKER_LOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        raise ValueError('exclusive Root-owned Python worker lock required')
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def run(argv):
    build_job, run_id, source, version, config_digest, private_manifest, role = parse_args(argv)
    if (sys.platform != 'linux' or os.geteuid() != 0 or not sys.flags.isolated
            or not sys.dont_write_bytecode or sys.flags.optimize):
        raise ValueError('isolated, assertion-enabled Linux Root controller required')
    from .ci_pipeline import _rust_worker_signing_key, vm_lease
    key = _rust_worker_signing_key('deterministic')
    if key is None:
        raise ValueError('sealed Rust worker controller key required')
    from .ci_runner import private_state
    from .ci_runner_config import load_config, verify_assets
    from .ci_runner_preflight import controller_environment
    from .deterministic_control import run_control
    from ci.gauntlet.control_plane.stage_outcome import require_cleanup

    config = staging_config_path(build_job, private_manifest, config_digest)
    state = Path('/home/hx-' + run_id)
    os.umask(0o022)
    worker_lock = _locked_worker()
    try:
        loaded = load_config(config, expected_digest=config_digest, asset_root=Path('/opt'))
        expected_id = 'rust-shadow-' + source + '-' + build_job + '-' + private_manifest[:16]
        assets = loaded['config']['assets']
        if (loaded['config']['schema'] != 'gauntlet-ci-runner.v7'
                or loaded['config']['id'] != expected_id
                or loaded['runtime']['guard_source_sha'] != source
                or loaded['runtime']['guard_package_version'] != version
                or assets['guard_prefix']['path'] != 'hol-gauntlet/rust-shadow-candidates/' + build_job + '/prefix'
                or assets['private_cell']['sha256'] != private_manifest
                or assets['private_cell']['path'] != 'hol-gauntlet/rust-shadow-candidates/' + build_job + '/cell-artifacts'):
            raise ValueError('staging config differs from fixed shadow candidate')
        verify_assets(loaded)
        try:
            private_state(state, create=True, immutable_ancestry=True)
        except FileExistsError:
            private_state(state, immutable_ancestry=True)
        # Existing Python workers use this second lock for their CI checks.
        # Keep the same lock order as the installed lifecycle path.
        with vm_lease(), controller_environment(loaded):
            record = run_control(state / role, loaded, role, controller_key=key)
        digest, size = _read_control(state / role / 'control.json')
        cleanup = True
        try:
            require_cleanup(record)
        except ValueError:
            cleanup = False
        result = {
            'schema': 'hol-gauntlet-rust-staging-control-adapter.v1',
            'build_job_id': build_job, 'run_id': run_id, 'source_sha': source,
            'config_digest': config_digest, 'role': role, 'record_sha256': digest,
            'record_bytes': size, 'controller_public_key_hex': key.public_key().public_bytes_raw().hex(),
            'control_completed_claim': record.get('control_completed') is True,
            'cleanup_verified_by_python': cleanup, 'execution_eligible': False,
        }
        return result, 0 if cleanup else 2
    finally:
        os.close(worker_lock)


def main(argv=None):
    try:
        result, status = run(sys.argv[1:] if argv is None else argv)
        print(canonical_json(result))
        return status
    except (Exception, KeyboardInterrupt) as error:
        print('staging control adapter unavailable: ' + type(error).__name__ + ': ' + str(error)[:1024],
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
