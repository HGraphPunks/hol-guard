from contextlib import redirect_stdout
import ast
import io
import json
from pathlib import Path
import sys
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

from ci.gauntlet.benchmark.native_sandbox_diagnostics import HOOK,NATIVE,PROBE


class NativeProbeTests(unittest.TestCase):
    def test_hook_probe_imports_existing_current_product_exports(self):
        # Inspect the real current exports without importing product runtime.
        root=Path(__file__).resolve().parents[1]
        imports=[node for node in ast.walk(ast.parse(HOOK)) if isinstance(node,ast.ImportFrom)
                 and node.module and node.module.startswith('codex_plugin_scanner.')]
        self.assertTrue(imports)
        for node in imports:
            source=root/'src'/Path(*node.module.split('.')).with_suffix('.py')
            self.assertTrue(source.is_file(),node.module)
            definitions={item.name:item for item in ast.parse(source.read_text()).body
                         if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef))}
            for alias in node.names:
                self.assertIn(alias.name,definitions)
                if alias.name=='load_guard_daemon_auth_token':
                    loader=definitions[alias.name]
                    self.assertIsInstance(loader,ast.FunctionDef)
                    positional=loader.args.posonlyargs+loader.args.args
                    self.assertTrue(positional or loader.args.vararg is not None)
                    self.assertLessEqual(len(positional)-len(loader.args.defaults),1)
                    self.assertTrue(all(default is not None for default in loader.args.kw_defaults))

    def test_binding_token_is_reset_and_native_preparation_is_not_execution(self):
        token=object();bind=Mock(return_value=token);reset=Mock()
        native=Mock(return_value={'profile':'workspace-contained-v1'})
        modules={}
        for name,exports in {
            'codex_plugin_scanner.guard.native_context':{'bind_context_digest_home':bind,'reset_context_digest_home':reset},
            'codex_plugin_scanner.guard.native_restricted_pytest':{'restricted_native':native},
        }.items():
            module=ModuleType(name);module.__dict__.update(exports);modules[name]=module
        for failure in (None,RuntimeError('native backend unavailable')):
            native.side_effect=failure
            output=io.StringIO()
            with patch.dict(sys.modules,modules),patch.object(sys,'argv',['probe','/runtime/home']), \
                 patch('subprocess.run',return_value=SimpleNamespace(returncode=0,stderr=b'')),redirect_stdout(output):
                exec(compile(NATIVE,'<unprivileged-native-probe>','exec'),{})
            value=json.loads(output.getvalue())
            self.assertEqual(value['prepared'],failure is None)
            self.assertEqual(native.call_args.args[0],'prepare_workspace_contained')
            self.assertEqual(str(native.call_args.args[1]['home']),'/runtime/home')
            reset.assert_called_with(token)
        compile(PROBE,'<bounded-namespace-overlay-native-probe>','exec')
