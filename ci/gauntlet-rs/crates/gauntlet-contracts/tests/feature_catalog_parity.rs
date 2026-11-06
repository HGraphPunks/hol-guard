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
