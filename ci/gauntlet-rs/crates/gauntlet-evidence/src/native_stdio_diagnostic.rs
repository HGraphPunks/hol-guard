//! Bind snapshots to the versioned launch, signed closure and Root file identity.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{digest, parse, require, text, Artifacts};
use crate::native_process_event_files::native_pipe_events;
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

const FILE: &str = "combined/cell/native-stdio-events.v1.jsonl";
const PIPE: &str = "combined/cell/native-pipe-events.v1.jsonl";

fn unique<'a>(events: &'a [Value], kind: &str) -> Result<(usize, &'a Value)> {
    let mut rows = events.iter().enumerate().filter(|(_, r)| r["kind"] == kind);
    let (sequence, row) = rows
        .next()
        .ok_or(EvidenceError::Invalid("Native lifecycle event missing"))?;
    require(rows.next().is_none())?;
    Ok((sequence, &row["data"]))
}

pub(crate) fn pipe_lifecycle(
    plane: &Value,
    artifacts: &Artifacts<'_>,
    started: usize,
    ready: usize,
    closed: usize,
) -> Result<()> {
    let observation = &plane["native_pipe_bytes"];
    let schema = text(observation, "schema")?;
    require(matches!(
        schema,
        native_pipe_events::V1 | native_pipe_events::V2
    ))?;
    let (owner_ready, start) = unique(&artifacts.events, "native-pipe-owner-ready")?;
    let (terminal, end) = unique(&artifacts.events, "native-pipe-owner-terminal")?;
    let (cleanup, _) = unique(&artifacts.events, "terminal-cleanup")?;
    require(
        started < owner_ready
            && owner_ready < ready
            && closed < terminal
            && terminal < cleanup
            && start == &json!({"schema":schema,"execution_eligible":false})
            && exact_keys(
                observation,
                &[
                    "schema",
                    "available",
                    "binding",
                    "execution_eligible",
                    "exclusive_product_authorship_verified",
                ],
            )
            && observation["available"] == true
            && observation["execution_eligible"] == false
            && observation["exclusive_product_authorship_verified"] == false
            && *end
                == json!({"available":true,"binding":observation["binding"],"execution_eligible":false}),
    )?;
    let metadata = artifacts.metadata(PIPE)?;
    for key in ["device", "inode", "uid", "gid", "mode", "links"] {
        require(metadata.get(key).is_some() && metadata[key] == observation["binding"][key])?;
    }
    let mut objects = std::collections::BTreeSet::new();
    for name in [
        PIPE,
        "combined/cell/native-process-events.v1.jsonl",
        "combined/cell/native-supervisor-events.v1.jsonl",
    ] {
        let metadata = artifacts.metadata(name)?;
        require(objects.insert((
            crate::native_process_kernel::number(&metadata["device"])?,
            crate::native_process_kernel::number(&metadata["inode"])?,
        )))?;
    }
    Ok(())
}

fn declaration(artifacts: &Artifacts<'_>, name: &str, limit: usize) -> Result<Value> {
    let raw = artifacts.raw(name)?;
    require(!raw.is_empty() && raw.len() <= limit)?;
    let metadata = artifacts.metadata(name)?;
    for (key, expected) in [("uid", 0), ("gid", 0), ("mode", 0o444), ("links", 1)] {
        require(metadata[key].as_u64() == Some(expected))?;
    }
    crate::native_process_kernel::number(&metadata["device"])?;
    crate::native_process_kernel::number(&metadata["inode"])?;
    parse(raw)
}

fn pipes(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    checkpoint: &Value,
) -> Result<Value> {
    let plane = &control["plane"];
    let pins = if control["schema"] == "hol-gauntlet-native-hook-transport.v2" {
        require(
            preparation["control_profile"] == "python-readonly.v1"
                && control.get("guard_pins").is_none()
                && control.get("control_role").is_none(),
        )?;
        &control["pins"]
    } else {
        &control["guard_pins"]
    };
    let config_file = "combined/cell/native-wire.v1.json";
    let config = declaration(artifacts, config_file, 4096)?;
    let rootfs_file = "combined/cell/native-rootfs.v1.json";
    let rootfs = declaration(artifacts, rootfs_file, 8192)?;
    require(
        exact_keys(&rootfs, &["schema", "stage", "initializer_sha256", "artifact_manifest_sha256",
            "system_spec_sha256", "task_spec_sha256", "runtime_spec_sha256", "idmap_runtime", "state",
            "network_profile", "parent_network_namespace", "native_wire_sha256"])
            && rootfs["schema"] == "hol-gauntlet-product-rootfs.v2"
            && rootfs["stage"] == preparation["stage"]
            && rootfs["initializer_sha256"] == preparation["initializer_sha256"]
            && rootfs["artifact_manifest_sha256"] == preparation["artifact_manifest_sha256"]
            && rootfs["native_wire_sha256"] == sha256(artifacts.raw(config_file)?)
            && rootfs["idmap_runtime"] == "ubuntu2404-controller-v1"
            && rootfs["state"] == "persistent-v1"
            && rootfs["network_profile"] == "private-loopback-v1"
            && config["native_sha256"] == preparation["launch"]["native_runtime_sha256"]
            && config["native_sha256"] == pins["native_sha256"]
            && config["native_program"] == format!("{}/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime", text(preparation, "runtime_prefix")?),
    )?;
    for key in [
        "system_spec_sha256",
        "task_spec_sha256",
        "runtime_spec_sha256",
    ] {
        require(crate::native_process_kernel::hex(text(&rootfs, key)?, 64))?;
    }
    let namespace = text(&rootfs, "parent_network_namespace")?
        .strip_prefix("net:[")
        .and_then(|s| s.strip_suffix(']'))
        .ok_or(EvidenceError::Invalid("parent network namespace missing"))?;
    require(crate::native_process_kernel::decimal(namespace)? > 0)?;
    let supervisor_file = "combined/cell/native-supervisor.v1.json";
    let supervisor = declaration(artifacts, supervisor_file, 8192)?;
    let mut expected = preparation["launch"].clone();
    expected["rootfs_declaration"] = json!(format!(
        "{}/native-rootfs.v1.json",
        text(preparation, "stage")?
    ));
    expected["rootfs_sha256"] = json!(sha256(artifacts.raw(rootfs_file)?));
    require(supervisor == expected)?;
    let (prepared, pin) = unique(&artifacts.events, "prepared")?;
    let (bound, binding) = unique(&artifacts.events, "rust-preparation-bound")?;
    let preparation_pin = if control["schema"] == "hol-gauntlet-native-hook-transport.v2" {
        let raw = artifacts.raw("combined/preparation.v1.json")?;
        require(parse(raw)? == *preparation)?;
        sha256(raw)
    } else {
        digest(preparation)?
    };
    require(
        prepared == 0
            && prepared < bound
            && pin["supervisor_declaration_sha256"] == sha256(artifacts.raw(supervisor_file)?)
            && pin["rootfs_declaration_sha256"] == expected["rootfs_sha256"]
            && pin["constructor_sha256"] == preparation["launch"]["constructor_sha256"]
            && binding["preparation_sha256"] == preparation_pin
            && control["preparation_sha256"] == binding["preparation_sha256"]
            && binding["rust_image_lease_owned"] == true
            && binding["image_id"] == preparation["image_id"]
            && binding["runtime_tree_digest"] == preparation["runtime_tree_digest"]
            && binding["artifact_manifest_sha256"] == preparation["artifact_manifest_sha256"]
            && artifacts
                .events
                .iter()
                .enumerate()
                .all(|(i, r)| r["kind"] != "gated-product-process" || i > bound),
    )?;
    let manifest_file = "combined/cell/cell-artifact-manifest.json";
    declaration(artifacts, manifest_file, 1024 * 1024)?;
    let manifest = crate::verify_native_private_cell_manifest(
        artifacts.raw(manifest_file)?,
        text(preparation, "artifact_manifest_sha256")?,
        text(preparation, "initializer_sha256")?,
    )?;
    let connector = manifest
        .native_actor_sha256()
        .ok_or(EvidenceError::Invalid("Native connector pin missing"))?;
    require(
        plane["native_launch_adapter_sha256"]
            == sha256(crate::native_diagnostic_artifacts::PIPE_LAUNCH.as_bytes()),
    )?;
    let mut result = crate::native_process_event_files::native_pipe_events::verify(
        artifacts.raw(PIPE)?,
        artifacts.raw("combined/cell/native-process-events.v1.jsonl")?,
        checkpoint,
        &plane["native_pipe_bytes"]["binding"],
        &config,
        connector,
        text(&plane["native_pipe_bytes"], "schema")?,
    )?;
    result["journal_report_binding_checked"] = json!(true);
    result["report_preparation_declarations_checked"] = json!(true);
    result["native_launch_adapter_sha256"] = plane["native_launch_adapter_sha256"].clone();
    Ok(result)
}
pub(crate) fn verify(
    control: &Value,
    preparation: &Value,
    artifacts: &Artifacts<'_>,
    images: &Value,
    hooks: &Value,
) -> Result<Option<Value>> {
    let launch = &preparation["launch"];
    let pipe = launch["schema"] == "hol-gauntlet-cell-supervisor.v5";
    if !pipe && launch["schema"] != "hol-gauntlet-cell-supervisor.v4" {
        require(!artifacts.contains(FILE) && !artifacts.contains(PIPE))?;
        return Ok(None);
    }
    let plane = &control["plane"];
    let bound = crate::native_capture_input::journal_binding(plane, artifacts)?;
    require(
        crate::native_process_trace_diagnostic::verify(preparation, plane, artifacts, bound)?
            .is_some(),
    )?;
    let checkpoint = &plane["process_events"]["checkpoint"];
    if pipe {
        require(bound && launch["native_stdio"] == "outside-root-native-pipes.v1")?;
        return pipes(control, preparation, artifacts, checkpoint).map(Some);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_process_trace_diagnostic::tests::{pipe_fixture, reindex};
    use std::collections::BTreeMap;

    fn read(control: &Value, prep: &Value, files: &BTreeMap<String, Vec<u8>>) -> Result<Value> {
        verify(
            control,
            prep,
            &Artifacts::new(files)?,
            &Value::Null,
            &Value::Null,
        )?
        .ok_or(EvidenceError::Invalid("pipe fixture unavailable"))
    }
    fn refresh(files: &mut BTreeMap<String, Vec<u8>>) {
        let metadata = parse(&files["results.sha256.json"]).unwrap()["filesystem"].clone();
        reindex(files, metadata);
    }
    #[test]
    fn v5_binds_pipe_bytes_to_report_lifecycle_manifest_and_preparation_declarations() {
        let (control, prep, files) = pipe_fixture();
        let value = read(&control, &prep, &files).unwrap();
        assert_eq!(value["native_client_streams"], 1);
        assert_eq!(value["journal_report_binding_checked"], true);
        assert_eq!(value["report_preparation_declarations_checked"], true);
        assert_eq!(value["actual_pipe_byte_rows_present"], true);
        for key in [
            "outside_preparation_joined",
            "outside_observer_admitted",
            "outside_signing_key_admitted",
            "exclusive_product_authorship_verified",
            "request_semantics_verified",
            "effect_writer_attribution_checked",
            "execution_eligible",
            "guard_causality_verified",
        ] {
            assert_eq!(value[key], false, "{key}");
        }
    }
    #[test]
    fn historical_pipe_reader_refuses_the_mixed_socket_transport_schema() {
        let (mut control, prep, files) = pipe_fixture();
        control["plane"]["native_pipe_bytes"]["schema"] =
            json!("hol-gauntlet-native-transports.v2");
        assert!(read(&control, &prep, &files).is_err());
    }
    #[test]
    fn mixed_transport_artifacts_require_the_same_explicit_schema_and_all_declarations() {
        let (control, prep, files) =
            crate::native_process_trace_diagnostic::tests::transport_fixture();
        let result = read(&control, &prep, &files).unwrap();
        assert_eq!(
            result["schema"],
            "hol-gauntlet-native-transport-readback.v2"
        );
        assert_eq!(result["connection_count"], 2);
        assert_eq!(result["socket_helper_count"], 1);
        assert_eq!(result["journal_report_binding_checked"], true);
        assert_eq!(result["socket_bytes_observed"], false);
        assert_eq!(result["execution_eligible"], false);
        let mut old = control.clone();
        old["plane"]["native_pipe_bytes"]["schema"] = json!(native_pipe_events::V1);
        assert!(read(&old, &prep, &files).is_err());
        for name in files.keys().filter(|p| p.as_str() != "results.sha256.json") {
            let mut missing = files.clone();
            missing.remove(name);
            refresh(&mut missing);
            assert!(read(&control, &prep, &missing).is_err(), "{name}");
        }
    }
    #[test]
    fn missing_declarations_or_journals_cannot_borrow_a_reported_complete_pipe_owner() {
        let (control, prep, files) = pipe_fixture();
        for name in files.keys().filter(|p| p.as_str() != "results.sha256.json") {
            let mut changed = files.clone();
            changed.remove(name);
            refresh(&mut changed);
            assert!(read(&control, &prep, &changed).is_err(), "{name}");
        }
        for pointer in [
            "/plane/native_launch_adapter_sha256",
            "/plane/capture_journal/tail_sha256",
            "/plane/native_pipe_bytes/binding/tail_sha256",
            "/preparation_sha256",
            "/guard_pins/native_sha256",
        ] {
            let mut changed = control.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("f".repeat(64));
            assert!(read(&changed, &prep, &files).is_err(), "{pointer}");
        }
    }
    #[test]
    fn reindexed_configuration_modes_and_preparation_substitutions_refuse() {
        let (control, prep, files) = pipe_fixture();
        for name in [
            "combined/cell/native-wire.v1.json",
            "combined/cell/native-rootfs.v1.json",
            "combined/cell/native-supervisor.v1.json",
            "combined/cell/cell-artifact-manifest.json",
        ] {
            let mut changed = files.clone();
            let mut value = parse(&changed[name]).unwrap();
            value["injected"] = json!(true);
            changed.insert(name.into(), crate::canonical_value(&value).unwrap());
            refresh(&mut changed);
            assert!(read(&control, &prep, &changed).is_err(), "{name}");
            let mut changed = files.clone();
            let mut metadata =
                parse(&changed["results.sha256.json"]).unwrap()["filesystem"].clone();
            metadata[name]["uid"] = json!(10004);
            reindex(&mut changed, metadata);
            assert!(read(&control, &prep, &changed).is_err(), "{name}");
        }
        for (pointer, value) in [
            ("/launch/process_events", json!("outside-root-ptrace.v2")),
            (
                "/launch/native_stdio",
                json!("outside-root-native-stdio.v1"),
            ),
            ("/runtime_prefix", json!("/opt/hol-gauntlet/other/prefix")),
        ] {
            let mut changed = prep.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(read(&control, &changed, &files).is_err(), "{pointer}");
        }
    }
    #[test]
    fn owner_start_and_terminal_order_duplicates_and_journal_object_aliases_refuse() {
        let (control, _, files) = pipe_fixture();
        let plane = &control["plane"];
        let mut artifacts = Artifacts::new(&files).unwrap();
        assert!(pipe_lifecycle(plane, &artifacts, 2, 4, 7).is_ok());
        artifacts.events.swap(3, 4);
        assert!(pipe_lifecycle(plane, &artifacts, 2, 3, 7).is_err());
        artifacts.events.swap(3, 4);
        artifacts.events.push(artifacts.events[8].clone());
        assert!(pipe_lifecycle(plane, &artifacts, 2, 4, 7).is_err());
        let mut changed = files;
        let mut metadata = parse(&changed["results.sha256.json"]).unwrap()["filesystem"].clone();
        metadata["combined/cell/native-supervisor-events.v1.jsonl"]["inode"] = json!(3);
        reindex(&mut changed, metadata);
        assert!(pipe_lifecycle(plane, &Artifacts::new(&changed).unwrap(), 2, 4, 7).is_err());
    }
}
