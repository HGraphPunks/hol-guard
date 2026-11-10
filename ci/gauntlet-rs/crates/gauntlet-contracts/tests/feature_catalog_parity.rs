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
fn legacy_inventory_and_listing_match_the_actual_python_reader() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    let code = r#"
import hashlib,json,sys
from dataclasses import asdict
from pathlib import Path
def prevent_runtime(event,args):
 if event in {'subprocess.Popen','os.system','os.exec','os.posix_spawn','socket.connect','socket.bind'}:
  raise RuntimeError('catalog comparison permits no process or network execution')
 if event=='import' and (args[0] in {'hol_guard','src'} or args[0].startswith(('hol_guard.','src.','ci.native_runtime'))):
  raise RuntimeError('product runtime imports are forbidden')
sys.addaudithook(prevent_runtime)
root=Path(sys.argv[1])
source=root/'ci/gauntlet/catalog.py'
assert hashlib.sha256(source.read_bytes()).hexdigest()=='1acb014b980db01f026b71655474e353f277bc0e7ea316704a5c150a74ef869c'
sys.path.insert(0,str(root))
from ci.gauntlet.catalog import load_catalog
def digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
result={}
for profile,file in {'core':'scenarios.json','approval-retry':'approval_retry.json','connector-setup':'connector_setup.json','full-tasks':'full_tasks.json'}.items():
 rows=load_catalog(root/'ci/gauntlet'/file)
 result[profile]={'count':len(rows),'rows_sha256':digest([asdict(row) for row in rows]),'listing_sha256':digest([{'id':row.id,'expectation':row.expectation,'oracle':row.oracle} for row in rows])}
assert not any(name in {'hol_guard','src'} or name.startswith(('hol_guard.','src.','ci.native_runtime')) for name in sys.modules)
print(json.dumps(result,sort_keys=True))
"#;
    let output = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", code])
        .arg(root)
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
