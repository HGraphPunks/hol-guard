//! Bind snapshots to the versioned launch, signed closure and Root file identity.
use crate::native_diagnostic_artifacts::{require, Artifacts};
use crate::Result;
use serde_json::Value;

const FILE: &str = "combined/cell/native-stdio-events.v1.jsonl";
pub(crate) fn verify(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    images: &Value,
    hooks: &Value,
) -> Result<Option<Value>> {
    let launch = &preparation["launch"];
    if launch["schema"] != "hol-gauntlet-cell-supervisor.v4" {
        require(!artifacts.contains(FILE))?;
        return Ok(None);
    }
    let plane = &control["plane"];
    let bound = crate::native_capture_input::journal_binding(plane, artifacts)?;
    require(
        crate::native_process_trace_diagnostic::verify(preparation, plane, artifacts, bound)?
            .is_some(),
    )?;
    let checkpoint = &plane["process_events"]["checkpoint"];
    let capture = &checkpoint["native_stdio"];
    require(
        launch["process_events"] == "outside-root-ptrace.v2"
            && launch["native_stdio"] == "outside-root-native-stdio.v1"
            && capture["declaration"]["scope"] == "owned-product-native-stream"
            && launch["native_runtime_sha256"] == control["guard_pins"]["native_sha256"]
            && launch["native_runtime_sha256"] == capture["declaration"]["native_runtime_sha256"],
    )?;
    let metadata = artifacts.metadata(FILE)?;
    for key in ["device", "inode", "uid", "gid", "mode", "links"] {
        require(metadata.get(key).is_some() && metadata[key] == capture["journal"][key])?;
    }
    let readback = crate::native_stdio_events::replay(
        artifacts.raw(FILE)?,
        artifacts.raw("combined/cell/native-process-events.v1.jsonl")?,
        checkpoint,
    )?;
    let relations =
        crate::native_stdio_hook_relations::verify(control, artifacts, &readback, images, hooks)?;
    let mut result = readback.summary;
    result["copied_hook_relations"] = relations;
    Ok(Some(result))
}
