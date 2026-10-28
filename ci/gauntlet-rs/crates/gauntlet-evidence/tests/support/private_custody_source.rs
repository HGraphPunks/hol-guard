use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

// The native actor added a separately verified runtime path to the enclosing
// Python verifier. Keep the original vectors and their complete source pin,
// and prove the functions they exercise are unchanged in the reviewed source.
const REVIEWED_CURRENT_SHA256: &str =
    "5be923a6164459e79664419767e07591581355c8060bf941545b48a7adf859bd";

pub fn assert_private_custody_source(fixture: &Value, functions: &[&str]) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let historical = manifest.join("tests/fixtures/private_cell_custody_python_v1.py.txt");
    let current = manifest
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/private_cell_custody.py");
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(&historical).unwrap())),
        "historical Python source must retain the original fixture pin"
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(&current).unwrap())),
        REVIEWED_CURRENT_SHA256,
        "review the full source change before accepting a new compatibility relation"
    );
    let output = Command::new("python3")
        .args(["-I", "-B", "-c"])
        .arg(
            r#"import ast,json,sys
from pathlib import Path
names=set(json.loads(sys.argv[3]))
def functions(path):
    nodes=[n for n in ast.parse(Path(path).read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name in names]
    assert len(nodes)==len(names), 'missing or duplicate Python oracle function'
    return {n.name:ast.dump(n,include_attributes=False) for n in nodes}
assert functions(sys.argv[1])==functions(sys.argv[2]), 'Python oracle function semantics changed'
"#,
        )
        .arg(historical)
        .arg(current)
        .arg(serde_json::to_string(functions).unwrap())
        .output()
        .expect("Python differential oracle must be available");
    assert!(
        output.status.success(),
        "Python source compatibility failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
