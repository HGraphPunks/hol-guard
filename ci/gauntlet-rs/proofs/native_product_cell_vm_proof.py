"""Opt-in dedicated-VM apparatus proof; no model calls or eligible verdicts.

Run only against a separately installed, outside-pinned controller generation.
The existing Python adapter drives the actual Rust actor/exec gate and Guard.
Each invocation requires a fresh Root output directory and both worker leases.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import sys
import time
import traceback
from pathlib import Path


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def trusted_parents(path):
    if not path.is_absolute() or path.resolve()!=path:
        raise ValueError('canonical literal Root path required')
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise ValueError('immutable Root ancestry required')


def read_root(path,maximum):
    trusted_parents(path)
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_nlink!=1
                or before.st_mode&0o022 or not 0<before.st_size<=maximum):
            raise ValueError('bounded immutable Root input required')
        raw=stream.read(maximum+1)
        after=os.fstat(stream.fileno())
        if len(raw)!=before.st_size or identity(before)!=identity(after) or identity(path.lstat())!=identity(before):
            raise ValueError('Root input changed during read')
    return raw


@contextlib.contextmanager
def worker_leases():
    with contextlib.ExitStack() as stack:
        for name in ('/var/lib/hol-gauntlet-rust/worker-state/active.lock','/opt/hol-gauntlet/worker.lock'):
            path=Path(name)
            trusted_parents(path)
            fd=os.open(path,os.O_RDWR|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
            stack.callback(os.close,fd)
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
                raise ValueError('private existing worker lock required')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            if identity(path.lstat())!=identity(os.fstat(fd)):
                raise ValueError('worker lock was replaced')
        yield


def save(path,value):
    with path.open('x') as stream:
        json.dump(value,stream,sort_keys=True,separators=(',',':'))
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)


def gated_effect(cell,workspace):
    marker=workspace/'rust-gate-effect'
    program=("from pathlib import Path;"
             "Path('/runtime/home/project/rust-gate-effect').write_bytes(b'rust gate released\\n')")
    handle=cell.spawn(['/usr/bin/python3','-I','-B','-c',program])
    gate=cell.children[handle]
    if gate['argv'][:2]!=['/public/gauntlet-product-cell','exec-gate'] or marker.exists():
        raise ValueError('unreleased native gate or outside absence check failed')
    cell.release(handle)
    cell._call('end_input',{'handle':handle})
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        chunk=cell._call('read',{'handle':handle,'wait_ms':100},deadline)
        if chunk['returncode'] is not None and chunk['stdout_eof'] and chunk['stderr_eof']:
            if chunk['returncode']!=0:
                raise ValueError('released gated program failed')
            cell.retire(handle)
            break
    else:
        raise TimeoutError('gated effect drain deadline')
    info=marker.lstat()
    if marker.read_bytes()!=b'rust gate released\n' or (info.st_uid,info.st_gid)!=(10001,10001):
        raise ValueError('outside idmapped effect bytes or owner mismatch')
    return {'before_release_absent':True,'after_release_sha256':sha256(marker.read_bytes()),
            'physical_uid':info.st_uid,'physical_gid':info.st_gid,'gate_argv':gate['argv'][:2]}


def execute(args):
    if os.geteuid()!=0 or platform.system()!='Linux' or platform.machine()!='aarch64':
        raise ValueError('dedicated Linux ARM64 Root VM required')
    if re.fullmatch('[0-9a-f]{40}',args.controller_source) is None:
        raise ValueError('exact controller source required')
    for pin in (args.controller_tree_sha256,args.verifier_sha256,args.artifact_manifest_sha256,
                args.actor_sha256,args.legacy_config_sha256):
        if re.fullmatch('[0-9a-f]{64}',pin) is None:
            raise ValueError('exact outside digest required')
    generation=args.controller_source[:16]
    controller=Path('/opt/hol-gauntlet')/('controller-'+generation)
    verifier=Path('/opt/hol-gauntlet')/('native-cell-input-'+generation)/'gauntlet-controller-install-verify-shadow'
    if sha256(read_root(verifier,8*1024**2))!=args.verifier_sha256:
        raise ValueError('outside controller verifier pin differs')
    def verify_controller():
        result=subprocess.run([str(verifier),args.controller_source,args.controller_tree_sha256],
                              check=True,capture_output=True,timeout=30,
                              env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent'})
        return json.loads(result.stdout)
    before=verify_controller()
    legacy=Path('/opt/hol-gauntlet/rust-shadow-candidates/b70d59e2681c4a3f/provisional-66703091ba2f7815-8ef7a22ac7a4d01b.json')
    raw=read_root(legacy,1024**2)
    if sha256(raw)!=args.legacy_config_sha256:
        raise ValueError('outside retained candidate config pin differs')
    config=json.loads(raw)
    artifacts=legacy.parent/'cell-artifacts-rust-v2'
    sys.path.insert(0,str(controller))
    from ci.gauntlet.benchmark.developer_product_runtime import OperationBudget
    from ci.gauntlet.benchmark.private_cell_campaign_inputs import verify_artifacts
    from ci.gauntlet.benchmark.private_cell_factory import PrivateCellConfig, build_private_cell
    from ci.gauntlet.benchmark.product_cell_layout import RUST_ACTOR, read_artifact_runtime
    cell_config={'schema':'developer-private-cell-config.v1','artifacts':str(artifacts),
                 'artifact_manifest_sha256':args.artifact_manifest_sha256,**config['runtime']['private_cell']}
    inventory=verify_artifacts(cell_config)
    manifest,argv=read_artifact_runtime(read_root(artifacts/'manifest.json',1024**2),
                                      args.artifact_manifest_sha256,cell_config['initializer_sha256'])
    if argv!=list(RUST_ACTOR) or manifest['runtime']['actor_sha256']!=args.actor_sha256:
        raise ValueError('explicit outside-pinned native actor required')
    output=Path(args.output)
    trusted_parents(output)
    output.mkdir(mode=0o700)
    workspace=output/'workspace'
    workspace.mkdir(mode=0o700)
    os.chown(workspace,10001,10001)
    prefix=Path('/opt')/config['assets']['guard_prefix']['path']
    plane=None
    result={'schema':'hol-gauntlet-native-cell-vm-proof.v1','case':args.case,'status':'failed',
            'controller_source':args.controller_source,'controller_tree_sha256':args.controller_tree_sha256,
            'candidate_source':config['runtime']['guard_source_sha'],
            'candidate_version':config['runtime']['guard_package_version'],
            'artifact_manifest_sha256':args.artifact_manifest_sha256,'actor_sha256':args.actor_sha256,
            'inert_artifact_files':len(inventory['files']),'controller_before':before,
            'model_requests':0,'execution_eligible':False}
    try:
        plane=build_private_cell(root=output/'cell',config=PrivateCellConfig.parse(cell_config),
            python=prefix/'bin/python',source_sha=config['runtime']['guard_source_sha'],
            prefix_digest=config['assets']['guard_prefix']['sha256'],
            bwrap_sha256=config['runtime']['guard_bwrap_sha256'],
            image_id=config['runtime']['guard_executor_image_id'],workspace_source=workspace,
            workspace_custody_root=output,provider_mounts=(),provider_custody_root=None,
            wall_seconds=180,operation_budget=OperationBudget(4),
            package_version=config['runtime']['guard_package_version'])
        plane.start()
        actor=Path(f'/proc/{plane.cell.pid}/exe')
        if sha256(actor.read_bytes())!=args.actor_sha256:
            raise ValueError('actual kernel actor executable differs from outside pin')
        result['installed_guard_identity']=plane.identity_claim
        result['native_daemon_started']=plane.started
        if args.case=='success':
            result['gate_effect']=gated_effect(plane.cell,workspace)
            raw=b'native Rust VM stdin\x00payload\xff\n'
            echo=plane.cell.capture(['/usr/bin/python3','-I','-B','-c',
                'import sys;sys.stdout.buffer.write(sys.stdin.buffer.read());sys.stderr.write("native stderr\\n")'],raw)
            if echo.returncode or echo.stdout!=raw or echo.stderr!=b'native stderr\n':
                raise ValueError('actual binary stream roundtrip failed')
            result['binary_stdio_sha256']=sha256(echo.stdout)
        else:
            started=time.monotonic()
            try:
                plane.cell.capture_execution(['/usr/bin/sleep','30'],timeout=1 if args.case=='timeout' else 30,
                    cancelled=(lambda:time.monotonic()-started>0.25) if args.case=='cancel' else None)
            except (TimeoutError,InterruptedError) as error:
                expected=TimeoutError if args.case=='timeout' else InterruptedError
                if not isinstance(error,expected) or not plane.cell.closed:
                    raise ValueError('expected bounded collector failure/cleanup differs') from error
                result['expected_interruption']=type(error).__name__
            else:
                raise ValueError('expected collector interruption did not occur')
        result['status']='passed'
    except BaseException as error:
        result['error_type']=type(error).__name__
        result['traceback']=traceback.format_exc()
        raise
    finally:
        try:
            if plane is not None:
                plane.close()
                result['cleanup_complete']=plane.cleanup_complete
                save(output/'plane.json',plane.declaration())
            result['controller_after']=verify_controller()
        except BaseException as error:
            result['status']='failed'
            result['cleanup_or_readback_error']=str(error)
            raise
        finally:
            save(output/'result.json',result)
    fields=('schema','case','status','cleanup_complete','model_requests','execution_eligible',
            'actor_sha256','artifact_manifest_sha256','native_daemon_started','expected_interruption')
    print(json.dumps({key:result[key] for key in fields if key in result},sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('controller-source','controller-tree-sha256','verifier-sha256',
                 'artifact-manifest-sha256','actor-sha256','legacy-config-sha256','output'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--case',choices=('success','timeout','cancel'),default='success')
    args=parser.parse_args()
    with worker_leases():
        execute(args)


if __name__=='__main__':
    main()
