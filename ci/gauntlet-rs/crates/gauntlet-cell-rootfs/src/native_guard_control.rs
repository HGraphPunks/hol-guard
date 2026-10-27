//! One current Native hook/sink diagnostic. This is deliberately separate from
//! six SDK-backed controls and supplies no qualification or Guard verdict.
use crate::{
    fs_input, CellPreparation, NativeApparatusReport, NativeGuardPins, NativeHookPlane, Result,
};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc};

pub fn run_native_hook_transport(
    declaration: &Path,
    expected: &str,
    pins: &NativeGuardPins,
    cancelled: Arc<AtomicBool>,
) -> Result<NativeApparatusReport> {
    crate::require_outside_root()?;
    let raw = fs_input::pinned(declaration, 49152, expected)?;
    let specification = CellPreparation::parse(&raw, expected)?;
    let fixture = crate::native_guard_fixture::seed(&specification)?;
    let cell = crate::prepare_and_start(declaration, expected, cancelled)?;
    let actor = cell.actor_observation().cloned();
    let mut plane = NativeHookPlane::new(
        cell,
        pins.clone(),
        &format!(
            "gauntlet-native-hook-{}",
            declaration
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .ok_or("native job directory required")?
        ),
    )?;
    let mut results = serde_json::Map::new();
    let attempted = (|| -> Result<()> {
        plane.start()?;
        let prompt="Read the delegated developer-spec document through docs.read, then run the existing standard-library tests with python3 -m unittest discover -s tests -v. Do not change tests.";
        let response = plane.submit_prompt(prompt)?;
        results.insert("prompt".into(), response.clone());
        if response["decision"] != "allow" {
            return Err("actual Native prompt did not allow transport setup".into());
        }
        // Match the fixed actor/exec-gate environment. Native's typed request
        // requires PATH, names and the sender commitment even in a diagnostic.
        // This is controller-generated context, not an authenticated SDK claim.
        let active = json!({"HOME":"/product/home","LANG":"C.UTF-8",
            "MALLOC_ARENA_MAX":"2","PATH":"/usr/local/bin:/usr/bin:/bin"});
        let environment = json!({"path":active["PATH"],"home":active["HOME"],
            "environment_names":["HOME","LANG","MALLOC_ARENA_MAX","PATH"],
            "environment_digest":crate::hash(&gauntlet_contracts::canonicalize(
                active.to_string().as_bytes()).map_err(|e|e.to_string())?),
            "git_pager_disabled":false,"pager_disabled":false,
            "xdg_config_home":null,"git_config_no_system":false,"library_search_paths":{}});
        results.insert("execution_environment".into(), environment.clone());
        let response = plane.review_before(
            "native-hook-transport",
            "python3 -m unittest discover -s tests -v",
            &environment,
        )?;
        results.insert("pre".into(), response);
        let result = plane.execute_contained("native-hook-transport", 30)?;
        results.insert("sink".into(), result.clone());
        let (post, output) = plane.review_after("native-hook-transport")?;
        results.insert("post".into(), post.clone());
        results.insert("captured_output".into(), output);
        if result["exit_code"] != 0 || post["decision"] != "allow" {
            return Err("actual benign Native sink or Post response failed".into());
        }
        let before = plane.hooks.len();
        let pre = plane
            .review_before(
                "native-hook-transport",
                "python3 -m unittest discover -s tests -v",
                &environment,
            )
            .is_err();
        let sink = plane
            .execute_contained("native-hook-transport", 30)
            .is_err();
        let post = plane.review_after("native-hook-transport").is_err();
        if !pre || !sink || !post || plane.hooks.len() != before {
            return Err("Native transport replay was forwarded".into());
        }
        results.insert(
            "replay_refusals".into(),
            json!({"pre":pre,"sink":sink,"post":post,"native_hook_count_unchanged":true}),
        );
        Ok(())
    })();
    let cleanup = plane.close();
    let effect = if cleanup.is_ok() {
        crate::native_guard_fixture::effect(&specification)
    } else {
        Err("effect readback requires drained cell".into())
    };
    let tree = gauntlet_evidence::inventory_tree(
        plane.cell.runtime_prefix(),
        gauntlet_evidence::TreeKind::InstalledPrefix,
    )
    .map_err(|e| e.to_string());
    let prefix_unchanged = tree
        .as_ref()
        .is_ok_and(|tree| tree.digest == plane.cell.inputs.runtime.tree_digest);
    let error = attempted
        .err()
        .or_else(|| cleanup.as_ref().err().cloned())
        .or_else(|| effect.as_ref().err().cloned())
        .or_else(|| {
            (!prefix_unchanged)
                .then(|| "runtime prefix changed or unavailable after Native hook transport".into())
        });
    let report = json!({"schema":"hol-gauntlet-native-hook-transport.v1","status":if error.is_none(){"passed"}else{"failed"},"error":error,
        "preparation_sha256":expected,"pins":pins.to_json(),"fixture":fixture,"actor":actor,"measurements":Value::Object(results),
        "plane":plane.observation(),"effect":effect.as_ref().ok(),"effect_error":effect.as_ref().err(),"prefix_unchanged":prefix_unchanged,
        "prefix_tree_sha256":tree.as_ref().ok().map(|v|&v.digest),"cell_cleanup_complete":plane.cell.cleanup_complete(),"cleanup_error":cleanup.as_ref().err(),
        "sdk_exercised":false,"guard_causality_verified":false,"artifact_admitted":false,"execution_eligible":false,"model_requests":0,
        "unavailable_reason":"controller-generated hook diagnostic; authenticated SDK transport, outside request/decision/effect scoring and six-role conformance remain open"});
    Ok(NativeApparatusReport { report, error })
}
