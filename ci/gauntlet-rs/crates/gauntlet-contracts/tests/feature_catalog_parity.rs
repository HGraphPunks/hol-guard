use gauntlet_contracts::legacy_catalog::{fixed_legacy_catalog, LegacyCatalogKind};
use gauntlet_contracts::{fixed_feature_catalog, fixed_feature_schedule};
use serde_json::{json, Value};
use std::path::Path;
use std::process::Command;

#[test]
fn python_catalog_order_contexts_and_all_pytest_vectors_match() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/control_plane/feature_entry.py");
    let code = r#"
import ast,hashlib,json,pathlib,sys
raw=pathlib.Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(raw).hexdigest()=='d3d5b72d7bd9c725d7cc9b90aa3bb7bc442a99a5e188943f4686bf34e4c048de'
tree=ast.parse(raw);scope={}
for node in tree.body:
 if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)and node.targets[0].id in {'FEATURES','SOURCE_MODE'}:
  value=node.value.args[0]if isinstance(node.value,ast.Call)else node.value
  scope[node.targets[0].id]=ast.literal_eval(value)
catalog=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='catalog')
exec(compile(ast.Module(body=[catalog],type_ignores=[]),'fixed-feature-catalog','exec'),scope)
run=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run')
ordered=next(n for n in ast.walk(run)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ordered'for t in n.targets))
exec(compile(ast.Module(body=[ordered],type_ignores=[]),'fixed-feature-order','exec'),scope)
command=next(n for n in ast.walk(run)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='command'for t in n.targets))
commands={}
for key,label,tests in scope['FEATURES']:
 scope.update(tests=tests,report=pathlib.Path('/output')/(key+'.xml'))
 exec(compile(ast.Module(body=[command],type_ignores=[]),'fixed-feature-pytest-command','exec'),scope)
 commands[key]=scope['command'][1:]
print(json.dumps(dict(groups=scope['catalog'](),schedule=[r[0]for r in scope['ordered']],commands=commands),sort_keys=True))
"#;
    let output = Command::new("python3")
        .args(["-I", "-B", "-c", code])
        .arg(source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    let groups = fixed_feature_catalog().unwrap();
    assert_eq!(groups.len(), 28);
    assert_eq!(groups.iter().map(|g| g.tests().len()).sum::<usize>(), 52);
    assert_eq!(groups.iter().filter(|g| g.source_native()).count(), 13);
    assert_eq!(
        json!(groups.iter().map(|g| g.to_json()).collect::<Vec<_>>()),
        expected["groups"]
    );
    let scheduled = fixed_feature_schedule().unwrap();
    assert_eq!(
        json!(scheduled.iter().map(|g| g.id()).collect::<Vec<_>>()),
        expected["schedule"]
    );
    for group in groups {
        assert_eq!(json!(group.pytest_argv()), expected["commands"][group.id()]);
    }
}

#[test]
fn retained_legacy_v1_normalization_and_listing_match_pinned_python_nodes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    // V1's original full reader SHA d13b78214fddf6550f5e4e2712d116f7ade0c34b5a6ff54407a3645dc4b036ac
    // remains historical. Main's validator rejects old Watch commands. Only its
    // byte-identical Scenario and constructor are used for normalization here;
    // this is not current loader acceptance or support for expanded catalogs.
    let code = r#"
import ast,hashlib,json,sys
from dataclasses import asdict,dataclass
from pathlib import Path
def prevent_runtime(event,args):
 if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','socket.connect','socket.bind'}:
  raise RuntimeError('catalog comparison permits no process or network execution')
 if event=='import' and (args[0] in {'hol_guard','src'} or args[0].startswith(('hol_guard.','src.','ci.native_runtime'))):
  raise RuntimeError('product runtime imports are forbidden')
sys.addaudithook(prevent_runtime)
root=Path(sys.argv[1])
source=root/'ci/gauntlet/catalog.py'
raw=source.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='4ac590490a62dae40b038efb66c7d449b98a5ad6c23c540a731fbfb586c9877b'
def pinned_nodes(text):
 tree=ast.parse(text)
 scenario=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Scenario')
 loader=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='load_catalog_data')
 constructor=next(n for n in ast.walk(loader) if isinstance(n,ast.Assign) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='Scenario')
 for node,pin in [(scenario,'b1918b30c4d44cf75ec4dda3bd385aa72b2855db1770d2d3ba9000b3547eeb13'),(constructor,'a351d82b3924e922a05ec47317cb8706dd93adc0c513f5537ecc202521be8708')]:
  if hashlib.sha256(ast.get_source_segment(text,node).encode()).hexdigest()!=pin:
   raise ValueError('retained v1 Python normalization node drifted')
 return scenario,constructor
text=raw.decode()
scenario,constructor=pinned_nodes(text)
changed=text.replace('tuple(row.get("commands", ()))','()',1)
assert changed!=text
try:pinned_nodes(changed)
except ValueError:pass
else:raise AssertionError('changed constructor acquired retained v1 identity')
scope={'dataclass':dataclass,'__name__':'__main__'}
future=ast.parse('from __future__ import annotations').body[0]
exec(compile(ast.Module(body=[future,scenario],type_ignores=[]),'pinned-legacy-v1-fields','exec'),scope)
construct=compile(ast.Module(body=[constructor],type_ignores=[]),'pinned-legacy-v1-constructor','exec')
def digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
result={}
fixtures=Path(sys.argv[2])
catalogs={'core':(fixtures/'legacy_core_catalog_v1.json','414970688ed3c105821c5961c3bdcd8897c7e018c4cd2d28c46510e570852517'),
 'approval-retry':(fixtures/'legacy_approval_retry_catalog_v1.json','9f27cef5f9312cd6fdd3c4084dbb47f6cc07bc06acc3afc87897c00dbb19d7d7'),
 'connector-setup':(root/'ci/gauntlet/connector_setup.json','df96a3ef882dc1c1b8f064cdb9f42b3382cbba350db6abc7c380e689b2a500e6'),
 'full-tasks':(root/'ci/gauntlet/full_tasks.json','fd335da0b43599061661ab0e3f4ef2b390cf01039f3473b5d15d550f24d9f6e2')}
for profile,(path,pin) in catalogs.items():
 catalog=path.read_bytes()
 assert hashlib.sha256(catalog).hexdigest()==pin
 rows=[]
 for row in json.loads(catalog)['scenarios']:
  scope['row']=row
  exec(construct,scope)
  rows.append(scope['scenario'])
 assert all(len(asdict(row))==11 for row in rows)
 result[profile]={'count':len(rows),'rows_sha256':digest([asdict(row) for row in rows]),'listing_sha256':digest([{'id':row.id,'expectation':row.expectation,'oracle':row.oracle} for row in rows])}
assert not any(name in {'hol_guard','src'} or name.startswith(('hol_guard.','src.','ci.native_runtime')) for name in sys.modules)
print(json.dumps(result,sort_keys=True))
"#;
    let output = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", code])
        .arg(root)
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() < 4096);
    let expected: Value = serde_json::from_slice(&output.stdout).unwrap();
    for kind in LegacyCatalogKind::ALL {
        let catalog = fixed_legacy_catalog(kind).unwrap();
        let rows = serde_json::to_vec(catalog.scenarios()).unwrap();
        let listing = serde_json::to_vec(&catalog.listing()).unwrap();
        assert_eq!(
            json!(catalog.scenarios().len()),
            expected[kind.profile()]["count"]
        );
        assert_eq!(
            gauntlet_contracts::canonical_sha256(&rows).unwrap(),
            expected[kind.profile()]["rows_sha256"]
        );
        assert_eq!(
            gauntlet_contracts::canonical_sha256(&listing).unwrap(),
            expected[kind.profile()]["listing_sha256"]
        );
    }
}
