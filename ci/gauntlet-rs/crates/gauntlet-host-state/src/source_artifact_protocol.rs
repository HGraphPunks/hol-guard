//! Closed Root export, acknowledgement and retirement commitments.
use super::super::text as candidate_text;
use super::{bytes, hex, sha, text};
use serde_json::{json, Value};
pub(in crate::native_operation::artifact) fn candidate_read_header(
    i: &Value,
    p: &Value,
    proof: &Value,
) -> Value {
    json!({"schema":"hol-gauntlet-native-candidate-artifact-completed-read.v1","operation":i["operation"],
        "job_id":i["job_id"],"source_sha":i["source_sha"],"source_archive_sha256":i["source_archive_sha256"],
        "archive_sha256":i["archive_sha256"],"version":i["version"],"original_producer_sha256":i["worker_sha256"],
        "host_pin_sha256":p["host_pin_sha256"],"result_sha256":p["result_sha256"],
        "storage_receipt_sha256":p["storage_receipt_sha256"],"reader_generation":p["reader_generation"],"proof":proof})
}
pub(in crate::native_operation::artifact) fn candidate_read_args(
    i: &Value,
    p: &Value,
) -> Result<Vec<String>, String> {
    let generation = text(p, "reader_generation")?;
    let mut a = vec![
        format!("/opt/hol-gauntlet/rust-native-dependency-worker-{generation}"),
        if i["operation"] == "capture" {
            "--read-candidate-capture-v1"
        } else {
            "--read-candidate-wheel-stage-v1"
        }
        .into(),
    ];
    for k in [
        "job_id",
        "source_sha",
        "source_archive_sha256",
        "archive_sha256",
        "version",
        "worker_sha256",
    ] {
        a.push(candidate_text(i, k).into());
    }
    for k in [
        "host_pin_sha256",
        "result_sha256",
        "storage_receipt_sha256",
        "reader_generation",
    ] {
        a.push(text(p, k)?.into());
    }
    Ok(a)
}
pub(in crate::native_operation::artifact) fn candidate_proof(
    intent: &Value,
    value: &Value,
    captured: Option<&Value>,
) -> Result<(), String> {
    let stage = intent["operation"] == "wheel-stage";
    let mut expected = json!({"schema":if stage {"hol-gauntlet-candidate-wheel-stage-shadow.v1"}
        else {"hol-gauntlet-candidate-capture-shadow.v1"},"job_id":intent["job_id"],
        "source_sha":intent["source_sha"],"archive_sha256":intent["archive_sha256"],
        "version":intent["version"],"artifact_admitted":false,"execution_eligible":false});
    let bounded = |key: &str, max: u64| value[key].as_u64().is_some_and(|n| n > 0 && n <= max);
    if stage {
        let captured = captured.ok_or("completed retained capture is required")?;
        for (key, expected_value) in [
            ("wheel_sha256", captured["wheel_sha256"].clone()),
            ("native_sha256", captured["native_sha256_claim"].clone()),
            ("readback_verified", json!(true)),
            ("candidate_executed", json!(false)),
            ("installed_prefix_created", json!(false)),
        ] {
            expected[key] = expected_value;
        }
        for key in [
            "wheel_entries",
            "wheel_uncompressed_bytes",
            "stage_tree_digest",
            "stage_tree_entries",
            "stage_tree_bytes",
        ] {
            expected[key] = value[key].clone();
        }
        if !hex(candidate_text(value, "stage_tree_digest"), 64)
            || !bounded("wheel_entries", 20_000)
            || !bounded("stage_tree_entries", 200_000)
            || !bounded("wheel_uncompressed_bytes", 512 * 1024 * 1024)
            || !bounded("stage_tree_bytes", 512 * 1024 * 1024)
        {
            return Err("bounded inert wheel stage proof required".into());
        }
    } else {
        for (key, expected_value) in [
            (
                "source_archive_sha256",
                intent["source_archive_sha256"].clone(),
            ),
            ("native_bytes_verified", json!(false)),
            ("container_absent", json!(true)),
            ("candidate_cgroup_absent", json!(true)),
            ("build_profile_absent", json!(true)),
        ] {
            expected[key] = expected_value;
        }
        for key in [
            "archive_bytes",
            "wheel",
            "wheel_sha256",
            "wheel_bytes",
            "native_sha256_claim",
        ] {
            expected[key] = value[key].clone();
        }
        let wheel = candidate_text(value, "wheel")
            .strip_prefix("hol_guard-")
            .and_then(|v| v.strip_suffix("-py3-none-linux_aarch64.whl"));
        if wheel.is_none_or(|v| {
            v.is_empty()
                || !v
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
        }) || !hex(candidate_text(value, "wheel_sha256"), 64)
            || !hex(candidate_text(value, "native_sha256_claim"), 64)
            || !bounded("archive_bytes", 256 * 1024 * 1024)
            || !bounded("wheel_bytes", 256 * 1024 * 1024)
        {
            return Err("bounded captured wheel identity proof required".into());
        }
    }
    if value != &expected {
        return Err(
            "artifact proof differs from exact outside identity or cleanup contract".into(),
        );
    }
    Ok(())
}
fn closed(v: &Value, fields: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
}
pub(super) fn pins(i: &Value) -> Value {
    let s = &i["source"]["intent"];
    json!({"source_sha":s["source_sha"],"job_id":i["job_id"],"original_worker_generation":s["worker_generation"],"kind":i["kind"],
        "storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"archive_sha256":i["archive_sha256"],"result_sha256":i["result_sha256"],
        "host_binding_sha256":i["flow"]["host_binding_sha256"],"exporter_generation":i["exporter_generation"]})
}
pub(super) fn export_args(i: &Value, selector: &str) -> Result<Vec<String>, String> {
    let p = pins(i);
    let mut out = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-dependency-worker-{}",
            text(i, "exporter_generation")?
        ),
        selector.into(),
    ];
    for key in [
        "source_sha",
        "job_id",
        "original_worker_generation",
        "kind",
        "storage_receipt_sha256",
        "archive_sha256",
        "result_sha256",
        "host_binding_sha256",
        "exporter_generation",
    ] {
        out.push(text(&p, key)?.into());
    }
    Ok(out)
}
pub(super) fn export(i: &Value, v: &Value) -> Result<Value, String> {
    if !closed(
        v,
        &[
            "schema",
            "status",
            "intent_sha256",
            "receipt",
            "receipt_sha256",
        ],
    ) || v["schema"] != "hol-gauntlet-source-artifact-export-state.v1"
        || v["status"] != "complete"
    {
        return Err("original artifact export remains unknown or malformed".into());
    }
    let r = &v["receipt"];
    let mut expected = pins(i);
    expected["schema"] = json!("hol-gauntlet-source-artifact-export.v1");
    expected["artifact_read_sha256"] = r["artifact_read_sha256"].clone();
    expected["archive_bytes"] = r["archive_bytes"].clone();
    if r != &expected
        || !hex(text(r, "artifact_read_sha256")?, 64)
        || !r["archive_bytes"]
            .as_u64()
            .is_some_and(|n| (1..=256 * 1024 * 1024).contains(&n))
        || v["receipt_sha256"] != sha(&bytes(r)?)
    {
        return Err("Root export receipt differs from exact original outside pins".into());
    }
    expected.as_object_mut().unwrap().remove("archive_bytes");
    expected["schema"] = json!("hol-gauntlet-source-artifact-export-intent.v1");
    if v["intent_sha256"] != sha(&bytes(&expected)?) {
        return Err("Root export intent commitment differs".into());
    }
    Ok(v.clone())
}
pub(super) fn ack_body(i: &Value, export: &Value, host_sha: &str) -> Value {
    let mut p = pins(i);
    p["schema"] = json!("hol-gauntlet-source-artifact-ack.v1");
    p["export_binding_sha256"] = export["receipt_sha256"].clone();
    p["host_receipt_sha256"] = json!(host_sha);
    p
}
pub(super) fn ack(i: &Value, export: &Value, host_sha: &str, v: &Value) -> Result<Value, String> {
    let expected = ack_body(i, export, host_sha);
    if !closed(v, &["schema", "receipt", "receipt_sha256"])
        || v["schema"] != "hol-gauntlet-source-artifact-ack-result.v1"
        || v["receipt"] != expected
        || v["receipt_sha256"] != sha(&bytes(&expected)?)
    {
        return Err("Root acknowledgement differs from actual retained Host receipt".into());
    }
    Ok(v.clone())
}
pub(super) fn retirement_intent(
    i: &Value,
    export: &Value,
    ack: &Value,
    host_sha: &str,
    generation: &str,
) -> Value {
    let s = &i["source"]["intent"];
    let authority = json!({"schema":"hol-gauntlet-source-storage-retirement-authority.v1","artifact_read_sha256":export["receipt"]["artifact_read_sha256"],
        "export_binding_sha256":export["receipt_sha256"],"host_ack_sha256":ack["receipt_sha256"],"result_sha256":i["result_sha256"],
        "host_binding_sha256":i["flow"]["host_binding_sha256"],"host_receipt_sha256":host_sha});
    json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":s["source_sha"],"job_id":i["job_id"],"worker_generation":s["worker_generation"],
        "mke2fs_sha256":s["mke2fs_sha256"],"profile":s["storage_profile"],"retirer_generation":generation,"authority":authority,
        "storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"archive_sha256":i["archive_sha256"]})
}
pub(super) fn retirement(i: &Value, intent: &Value, v: &Value) -> Result<Value, String> {
    let s = &i["source"]["intent"];
    let expected = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":s["source_sha"],"job_id":i["job_id"],"worker_generation":s["worker_generation"],
        "profile":s["storage_profile"],"retirer_generation":intent["retirer_generation"],"retirement_intent_sha256":sha(&bytes(intent)?),
        "storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"archive_sha256":i["archive_sha256"],"partial":false,
        "volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,
        "execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    if v != &expected {
        return Err(
            "Source retirement differs from independently pinned acknowledgement and intent".into(),
        );
    }
    Ok(v.clone())
}
