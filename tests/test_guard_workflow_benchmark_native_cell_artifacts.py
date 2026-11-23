"""Versioned deployment relations; inert fixtures do not qualify a VM run."""
import hashlib
import json
import stat

import pytest

from ci.gauntlet.benchmark import private_cell_campaign_inputs as inputs
from ci.gauntlet.benchmark import private_cell_factory as factory
from ci.gauntlet.benchmark.product_cell_layout import (
    NATIVE_ACTOR,
    PYTHON_ACTOR,
    RUST_ACTOR,
    measured_gate_prefix,
    observed_actor_argv,
    read_artifact_runtime,
)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def bundle(tmp_path,monkeypatch):
    files={name:raw for name,raw in inputs._sources().items()
           if not name.startswith('public/') or name=='public/product_vm_seccomp_oci_v1.json'}
    # These bytes must stay inert throughout the inventory and staging checks.
    files.update({NATIVE_ACTOR:b'raise RuntimeError("never execute candidate input")',
                  'public/initializer':b'inert initializer fixture'})
    root=tmp_path/'artifacts'
    for name,raw in files.items():
        target=root/name
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
    value={'schema':'product-cell-artifacts.v2','files':{name:digest(raw) for name,raw in files.items()},
           'runtime':{'schema':'product-cell-native-runtime.v1','actor_sha256':digest(files[NATIVE_ACTOR])}}
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    (root/'manifest.json').write_bytes(raw)
    config={'schema':'developer-private-cell-config.v1','artifacts':str(root),
            'artifact_manifest_sha256':digest(raw),'initializer_sha256':digest(files['public/initializer']),
            'native_sha256':'a'*64,'runtime_tree_digest':'b'*64,
            'idmap_runtime':'ubuntu2404-controller-v1','cpu_profile':'single-core-v1'}
    monkeypatch.setattr(inputs,'_trusted',lambda *args,**kwargs:None)
    monkeypatch.setattr(factory,'_trusted',lambda *args,**kwargs:None)
    return root,value,raw,config


def test_native_manifest_roundtrips_staging_without_public_python(bundle,tmp_path):
    root,_,raw,config=bundle
    inventory=inputs.verify_artifacts(config)
    assert len(inventory['files'])==25 and inventory['candidate_code_executed'] is False
    assert not any(name.startswith('public/') and name.endswith('.py') for name in inventory['files'])
    _,argv=read_artifact_runtime(raw,config['artifact_manifest_sha256'],config['initializer_sha256'])
    assert argv==list(RUST_ACTOR)
    stage=tmp_path/'stage'
    stage.mkdir(mode=0o700)
    factory._stage_public(root,stage,config['artifact_manifest_sha256'])
    assert (stage/'cell-artifact-manifest.json').read_bytes()==raw
    assert stat.S_IMODE((stage/'cell-artifact-manifest.json').stat().st_mode)==0o444
    assert stat.S_IMODE((stage/NATIVE_ACTOR).stat().st_mode)==0o555
    assert {path.name for path in (stage/'public').iterdir()}=={
        'initializer','gauntlet-product-cell','product_vm_seccomp_oci_v1.json'}
    assert measured_gate_prefix(argv)==['/public/gauntlet-product-cell','exec-gate']


@pytest.mark.parametrize('mutation',['actor-bytes','source','extra-python','runtime-pin','legacy-label',
                                     'initializer','manifest-pin','missing-runtime'])
def test_native_substitutions_refuse_before_execution(bundle,mutation):
    root,value,_,config=bundle
    if mutation=='actor-bytes':
        (root/NATIVE_ACTOR).write_bytes(b'changed after capture')
    elif mutation=='source':
        name='code/ci/gauntlet/benchmark/product_vm_rootfs.py'
        (root/name).write_bytes(b'candidate-controlled Root code')
        value['files'][name]=digest((root/name).read_bytes())
    elif mutation=='extra-python':
        (root/'public/actor.py').write_bytes(b'undeclared Python')
        value['files']['public/actor.py']=digest(b'undeclared Python')
    elif mutation=='runtime-pin':
        value['runtime']['actor_sha256']='e'*64
    elif mutation=='legacy-label':
        value['schema']='product-cell-artifacts.v1'
        del value['runtime']
    elif mutation=='initializer':
        config['initializer_sha256']='e'*64
    elif mutation=='missing-runtime':
        del value['runtime']
    raw=json.dumps(value).encode()
    (root/'manifest.json').write_bytes(raw)
    config['artifact_manifest_sha256']='e'*64 if mutation=='manifest-pin' else digest(raw)
    with pytest.raises(ValueError):
        inputs.verify_artifacts(config)


def test_native_observation_needs_exact_outside_manifest_and_initializer(bundle):
    _,_,raw,config=bundle
    row={'kind':'native-cell-runtime','artifact_manifest_raw':raw.decode()}
    pins=(config['artifact_manifest_sha256'],config['initializer_sha256'])
    assert observed_actor_argv([row],*pins)==list(RUST_ACTOR)
    assert observed_actor_argv([],*pins)==list(PYTHON_ACTOR)
    for rows,manifest,initializer in (([row,row],*pins),([dict(row,trusted=True)],*pins),
                                    ([row],'f'*64,pins[1]),([row],pins[0],'f'*64)):
        with pytest.raises(ValueError):
            observed_actor_argv(rows,manifest,initializer)
    with pytest.raises(ValueError):
        measured_gate_prefix(['/candidate/custom-gate'])


def test_legacy_manifest_cannot_be_relabelled_as_a_native_observation():
    raw=json.dumps({'schema':'product-cell-artifacts.v1','files':{'public/initializer':'a'*64}}).encode()
    with pytest.raises(ValueError,match='relabel'):
        observed_actor_argv([{'kind':'native-cell-runtime','artifact_manifest_raw':raw.decode()}],digest(raw),'a'*64)
