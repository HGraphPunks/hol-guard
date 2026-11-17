"""Setup contracts; mocked product responses establish no native conformance."""
import ast
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.gauntlet.benchmark import private_cell_readiness as module


def specimen(monkeypatch, response=None, status=0):
    monkeypatch.setattr(module.time, 'monotonic', lambda: 100)
    events, calls = [], []
    def capture(command, **options):
        calls.append((command, options))
        return SimpleNamespace(returncode=status, stdout=json.dumps(response).encode())
    plane=SimpleNamespace(workspace_path='/runtime/home/project', python=Path('/frozen/bin/python'),
                          cell=SimpleNamespace(capture=capture), observations=events,
                          _emit=lambda target,row: target.append(row))
    return plane, calls


def test_one_native_setup_request_precedes_hook_admission_with_existing_deadline(monkeypatch):
    plane,calls=specimen(monkeypatch, deepcopy(module.EXPECTED))
    module.require_native_workspace(plane, deadline=120)
    assert len(calls)==1 and calls[0][1]=={'timeout':20}
    assert calls[0][0][:4]==['/frozen/bin/python','-I','-B','-c']
    assert calls[0][0][-2:]==['/runtime/home/project','20']
    assert plane.observations==[{'kind':'native-workspace-readiness','returncode':0,
                                'response':module.EXPECTED}]


@pytest.mark.parametrize('mutation', [
    {'ready':False}, {'native_required':False}, {'native_route':'python'},
    {'workspace_acknowledged':False}, {'worker_ready':False}, {'ready':1}, {'extra':True}])
def test_unready_or_unmanaged_setup_never_retries_or_becomes_ready(monkeypatch,mutation):
    response={**module.EXPECTED,**mutation}
    plane,calls=specimen(monkeypatch,response)
    with pytest.raises(ValueError,match='not confirmed'):
        module.require_native_workspace(plane,deadline=160)
    assert len(calls)==1 and plane.observations[0]['response']==response


def test_http_failure_cannot_be_hidden_by_a_ready_body(monkeypatch):
    plane,calls=specimen(monkeypatch,module.EXPECTED,status=69)
    with pytest.raises(ValueError,match='not confirmed'):
        module.require_native_workspace(plane,deadline=160)
    assert len(calls)==1 and plane.observations[0]['returncode']==69


@pytest.mark.parametrize('response', [None, {}, [], 'ready'])
def test_missing_or_nonobject_readiness_is_not_admission(monkeypatch,response):
    plane,calls=specimen(monkeypatch,response)
    with pytest.raises(ValueError,match='not confirmed'):
        module.require_native_workspace(plane,deadline=160)
    assert len(calls)==1


def test_expired_setup_budget_stops_before_product_execution(monkeypatch):
    plane,calls=specimen(monkeypatch,module.EXPECTED)
    with pytest.raises(TimeoutError):
        module.require_native_workspace(plane,deadline=101)
    assert calls==[]


def assert_current_product_exports(tree, context):
    # Parse source only: importing the product could launch Native helpers.
    root = Path(__file__).resolve().parents[1]
    imports = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
               and node.module and node.module.startswith('codex_plugin_scanner.')]
    assert imports
    for node in imports:
        source = root / 'src' / Path(*node.module.split('.')).with_suffix('.py')
        assert source.is_file(), f'{context}: missing current module {node.module}'
        definitions = {item.name: item for item in ast.parse(source.read_text()).body
                       if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        for alias in node.names:
            assert alias.name in definitions, f'{context}: missing export {alias.name}'
            if alias.name == 'load_guard_daemon_auth_token':
                loader = definitions[alias.name]
                assert isinstance(loader, ast.FunctionDef)
                positional = loader.args.posonlyargs + loader.args.args
                assert positional or loader.args.vararg is not None
                assert len(positional) - len(loader.args.defaults) <= 1
                assert all(default is not None for default in loader.args.kw_defaults)


@pytest.mark.parametrize('adapter', [
    'native_guard_identity_v1.py', 'native_workspace_readiness_v1.py',
    'native_mcp_identity_v1.py.txt', 'native_mcp_proxy_v1.py.txt',
])
def test_rust_native_adapters_import_existing_current_product_exports(adapter):
    root = Path(__file__).resolve().parents[1]
    tree = ast.parse((root / 'ci/gauntlet-rs/adapters' / adapter).read_text())
    assert_current_product_exports(tree, adapter)


def test_current_python_readiness_probe_imports_existing_product_exports():
    assert_current_product_exports(ast.parse(module.PROBE), 'current Python readiness')
