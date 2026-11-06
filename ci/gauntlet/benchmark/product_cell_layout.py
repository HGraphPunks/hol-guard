"""Immutable layout and versioned artifact declarations for the cell adapter."""
import hashlib
import re
from pathlib import Path

from .json_data import strict_json_loads

DEFAULT={'workspace':'/task','path':'/usr/bin:/bin'}
WORKSPACES=frozenset({'/task','/runtime/home/project'})
PATHS=frozenset({'/usr/bin:/bin','/usr/local/bin:/usr/bin:/bin'})
NATIVE_ACTOR='public/gauntlet-product-cell'
PYTHON_ACTOR=('/usr/bin/python3','-I','-B','/public/actor.py','/public')
RUST_ACTOR=('/public/gauntlet-product-cell','actor')


def artifact_actor_argv(value):
    """Fixed data-only selection; the caller first authenticates manifest bytes."""
    if (type(value) is not dict or type(value.get('files')) is not dict
            or not 1<=len(value['files'])<=128
            or any(type(name) is not str or type(pin) is not str
                   or re.fullmatch('[0-9a-f]{64}',pin) is None for name,pin in value['files'].items())):
        raise ValueError('bounded cell artifact manifest required')
    if value.get('schema')=='product-cell-artifacts.v1' and set(value)=={'schema','files'}:
        if NATIVE_ACTOR in value['files']:
            raise ValueError('native actor requires an explicit v2 artifact manifest')
        return list(PYTHON_ACTOR)
    runtime=value.get('runtime')
    public={name for name in value['files'] if name.startswith('public/')}
    if (value.get('schema')!='product-cell-artifacts.v2' or set(value)!={'schema','files','runtime'}
            or type(runtime) is not dict or set(runtime)!={'schema','actor_sha256'}
            or runtime['schema']!='product-cell-native-runtime.v1'
            or runtime['actor_sha256']!=value['files'].get(NATIVE_ACTOR)
            or public!={NATIVE_ACTOR,'public/initializer','public/product_vm_seccomp_oci_v1.json'}):
        raise ValueError('explicit source-pinned native cell runtime required')
    return list(RUST_ACTOR)


def read_artifact_runtime(raw,expected,initializer=None):
    if (type(raw) is not bytes or len(raw)>1024**2 or type(expected) is not str
            or re.fullmatch('[0-9a-f]{64}',expected) is None or hashlib.sha256(raw).hexdigest()!=expected):
        raise ValueError('cell artifact manifest differs from outside pin')
    value=strict_json_loads(raw)
    argv=artifact_actor_argv(value)
    if initializer is not None and value['files'].get('public/initializer')!=initializer:
        raise ValueError('cell initializer differs from outside pin')
    return value,argv


def observed_actor_argv(rows,manifest_digest,initializer_digest):
    if type(rows) is not list or len(rows)>10000:
        raise ValueError('bounded cell runtime observations required')
    native=[row for row in rows if type(row) is dict and row.get('kind')=='native-cell-runtime']
    if not native:
        return list(PYTHON_ACTOR)
    if len(native)!=1 or set(native[0])!={'kind','artifact_manifest_raw'}:
        raise ValueError('one exact native cell runtime observation required')
    raw=native[0]['artifact_manifest_raw']
    if type(raw) is not str:
        raise ValueError('native cell manifest observation requires original bytes')
    _,argv=read_artifact_runtime(raw.encode(),manifest_digest,initializer_digest)
    if argv!=list(RUST_ACTOR):
        raise ValueError('native runtime observation cannot relabel Python artifacts')
    return argv


def measured_gate_prefix(actor_argv):
    if actor_argv==list(RUST_ACTOR):
        return ['/public/gauntlet-product-cell','exec-gate']
    if actor_argv==list(PYTHON_ACTOR):
        return ['/usr/bin/python3','-I','-B','/public/ci/gauntlet/benchmark/product_exec_gate.py']
    raise ValueError('fixed measured cell actor required')


def load_layout():
    path=Path('/etc/hol-cell-layout.json')
    if not path.exists() and not path.is_symlink():
        return dict(DEFAULT)
    info=path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid!=0 or info.st_mode&0o022:
        raise ValueError('immutable Root layout declaration required')
    with path.open('rb') as stream:
        raw=stream.read(2049)
    if len(raw)>2048:
        raise ValueError('layout declaration byte budget')
    value=strict_json_loads(raw)
    if (type(value) is not dict or set(value)!={'schema','workspace','path'}
            or value['schema']!='product-cell-layout.v1'
            or type(value['workspace']) is not str or type(value['path']) is not str
            or value['workspace'] not in WORKSPACES or value['path'] not in PATHS):
        raise ValueError('fixed declared cell workspace and executable path required')
    return {key:value[key] for key in ('workspace','path')}
