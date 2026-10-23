"""The fixed staging adapter must bind the artifact version before execution."""
import hashlib
import json

import pytest

from ci.gauntlet.benchmark import private_cell_campaign_inputs, stage_control_adapter


def loaded(native):
    base='hol-gauntlet/rust-shadow-candidates/aabbccddeeff0011/'
    name=base+('cell-artifacts-rust-v2' if native else 'cell-artifacts')
    files={'public/initializer':'a'*64}
    value={'schema':'product-cell-artifacts.v1','files':files}
    if native:
        files.update({'public/gauntlet-product-cell':'b'*64,'public/product_vm_seccomp_oci_v1.json':'c'*64})
        value.update(schema='product-cell-artifacts.v2',
                     runtime={'schema':'product-cell-native-runtime.v1','actor_sha256':'b'*64})
    raw=json.dumps(value).encode()
    pin=hashlib.sha256(raw).hexdigest()
    return {'config':{'assets':{'private_cell':{'path':name,'sha256':pin}}},
            'runtime':{'guard_private_cell':{'artifacts':'/opt/'+name,
                'artifact_manifest_sha256':pin,'initializer_sha256':'a'*64}}},raw,pin


@pytest.mark.parametrize('native',[False,True])
def test_staging_accepts_both_exact_authenticated_artifact_versions(monkeypatch,native):
    value,raw,pin=loaded(native)
    reads=[]
    def read(path,*,maximum):
        reads.append((str(path),maximum))
        return raw
    monkeypatch.setattr(private_cell_campaign_inputs,'_read',read)
    stage_control_adapter.verify_cell_artifact_path(value,'aabbccddeeff0011',pin)
    assert reads==[(value['runtime']['guard_private_cell']['artifacts']+'/manifest.json',1024**2)]


@pytest.mark.parametrize('mutation',['other-job','escape','runtime-directory','manifest-pin','actor-version',
                                     'changed-manifest','initializer-pin'])
def test_staging_refuses_cross_version_paths_and_substituted_manifest(monkeypatch,mutation):
    value,raw,pin=loaded(True)
    asset=value['config']['assets']['private_cell']
    cell=value['runtime']['guard_private_cell']
    if mutation=='other-job':
        asset['path']=asset['path'].replace('aabbccddeeff0011','1122334455667788')
    elif mutation=='escape':
        asset['path']='hol-gauntlet/rust-shadow-candidates/aabbccddeeff0011/../cell-artifacts-rust-v2'
    elif mutation=='runtime-directory':
        cell['artifacts']='/opt/other-bundle'
    elif mutation=='manifest-pin':
        cell['artifact_manifest_sha256']='f'*64
    elif mutation=='actor-version':
        asset['path']=asset['path'].removesuffix('-rust-v2')
        cell['artifacts']='/opt/'+asset['path']
    elif mutation=='changed-manifest':
        raw+=b'\n'
    elif mutation=='initializer-pin':
        cell['initializer_sha256']='f'*64
    monkeypatch.setattr(private_cell_campaign_inputs,'_read',lambda *args,**kwargs:raw)
    with pytest.raises(ValueError):
        stage_control_adapter.verify_cell_artifact_path(value,'aabbccddeeff0011',pin)
