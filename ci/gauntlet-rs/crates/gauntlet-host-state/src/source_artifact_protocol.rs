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

pub(super) fn failure_pins(i: &Value) -> Value {
    let s = &i["source"]["intent"];
    json!({"source_sha":s["source_sha"],"job_id":i["job_id"],"original_worker_generation":s["worker_generation"],
        "storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"source_archive_sha256":s["source_archive_sha256"],
        "result_sha256":i["flow"]["result_sha256"],"host_pin_sha256":i["flow"]["host_pin_sha256"],
        "host_anchor_sha256":i["flow"]["host_anchor_sha256"],"reader_generation":i["reader_generation"]})
}
pub(super) fn failure_args(i: &Value, selector: &str) -> Result<Vec<String>, String> {
    let p = failure_pins(i);
    let mut a = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-dependency-worker-{}",
            text(i, "reader_generation")?
        ),
        selector.into(),
    ];
    for k in [
        "source_sha",
        "job_id",
        "original_worker_generation",
        "storage_receipt_sha256",
        "source_archive_sha256",
        "result_sha256",
        "host_pin_sha256",
        "host_anchor_sha256",
        "reader_generation",
    ] {
        a.push(text(&p, k)?.into());
    }
    Ok(a)
}
pub(super) fn failure_export(i: &Value, v: &Value) -> Result<Value, String> {
    let mut intent = failure_pins(i);
    intent["schema"] = json!("hol-gauntlet-failed-build-export-intent.v1");
    if !closed(
        v,
        &[
            "schema",
            "intent_sha256",
            "export",
            "export_complete",
            "retry_allowed",
        ],
    ) || v["schema"] != "hol-gauntlet-failed-build-export-state.v1"
        || v["intent_sha256"] != sha(&bytes(&intent)?)
        || v["export_complete"] != true
        || v["retry_allowed"] != false
    {
        return Err("original failed-build export remains unknown or changed".into());
    }
    let e = &v["export"];
    let r = &e["receipt"];
    let mut expected = failure_pins(i);
    expected["schema"] = json!("hol-gauntlet-failed-build-export.v1");
    for k in ["archive_sha256", "archive_bytes", "manifest_sha256"] {
        expected[k] = r[k].clone();
    }
    expected["exit_code"] = i["flow"]["exit_code"].clone();
    expected["execution_eligible"] = json!(false);
    expected["qualification_eligible"] = json!(false);
    if !closed(e, &["schema", "receipt", "receipt_sha256"])
        || e["schema"] != "hol-gauntlet-failed-build-export-result.v1"
        || *r != expected
        || ["archive_sha256", "manifest_sha256"]
            .iter()
            .any(|k| !r[*k].as_str().is_some_and(|s| hex(s, 64)))
        || r["archive_bytes"]
            .as_u64()
            .is_none_or(|n| !(1024..=super::file::FAILURE_LIMIT as u64).contains(&n))
        || e["receipt_sha256"] != sha(&bytes(r)?)
    {
        return Err("failed-build export differs from original terminal and outside pins".into());
    }
    Ok(e.clone())
}
pub(super) fn failure_state(i: &Value, v: &Value) -> Result<Option<Value>, String> {
    let mut intent = failure_pins(i);
    intent["schema"] = json!("hol-gauntlet-failed-build-export-intent.v1");
    if !closed(
        v,
        &[
            "schema",
            "intent_sha256",
            "export",
            "export_complete",
            "retry_allowed",
        ],
    ) || v["schema"] != "hol-gauntlet-failed-build-export-state.v1"
        || v["intent_sha256"] != sha(&bytes(&intent)?)
        || v["retry_allowed"] != false
    {
        return Err("original failed-build export state differs".into());
    }
    if v["export_complete"] == false && v["export"].is_null() {
        return Ok(None);
    }
    failure_export(i, v).map(Some)
}
pub(super) fn failure_ack_body(e: &Value, host: &str) -> Value {
    let mut r = e["receipt"].clone();
    r["schema"] = json!("hol-gauntlet-failed-build-ack.v1");
    r["export_receipt_sha256"] = e["receipt_sha256"].clone();
    r["host_receipt_sha256"] = json!(host);
    r
}
pub(super) fn failure_ack(e: &Value, host: &str, v: &Value) -> Result<Value, String> {
    let r = failure_ack_body(e, host);
    if !closed(v, &["schema", "receipt", "receipt_sha256"])
        || v["schema"] != "hol-gauntlet-failed-build-ack-result.v1"
        || v["receipt"] != r
        || v["receipt_sha256"] != sha(&bytes(&r)?)
    {
        return Err("failed-build acknowledgement differs from actual Host bytes".into());
    }
    Ok(v.clone())
}
pub(super) fn failure_retirement(
    i: &Value,
    e: &Value,
    a: &Value,
    host: &str,
    generation: &str,
) -> Value {
    let s = &i["source"]["intent"];
    let authority = json!({"schema":"hol-gauntlet-failed-build-storage-retirement-authority.v1",
        "export_receipt_sha256":e["receipt_sha256"],"host_ack_sha256":a["receipt_sha256"],"host_receipt_sha256":host,
        "result_sha256":i["flow"]["result_sha256"],"host_pin_sha256":i["flow"]["host_pin_sha256"],
        "host_anchor_sha256":i["flow"]["host_anchor_sha256"],"manifest_sha256":e["receipt"]["manifest_sha256"]});
    json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":s["source_sha"],"job_id":i["job_id"],
        "worker_generation":s["worker_generation"],"mke2fs_sha256":s["mke2fs_sha256"],"profile":"build-v1","retirer_generation":generation,
        "authority":authority,"storage_receipt_sha256":i["source"]["storage_receipt_sha256"],"archive_sha256":e["receipt"]["archive_sha256"]})
}
pub(super) fn failure_retirement_request(i: &Value, intent: &Value) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-host-failed-build-retirement-request.v1",
        "intent_sha256":sha(&bytes(i)?),"retirer_generation":intent["retirer_generation"],
        "retirement_intent_sha256":sha(&bytes(intent)?)}),
    )
}
pub(super) fn failure_marker(i: &Value, operation: &str) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-failed-build-dispatch.v1","intent_sha256":sha(&bytes(i)?),"operation":operation,"retry_allowed":false}),
    )
}
pub(super) fn retained_failure_export(j: &super::Journal, i: &Value) -> Result<Value, String> {
    let e = super::value(j, i, super::failure::EXPORT)?;
    let mut intent = failure_pins(i);
    intent["schema"] = json!("hol-gauntlet-failed-build-export-intent.v1");
    failure_export(
        i,
        &json!({"schema":"hol-gauntlet-failed-build-export-state.v1","intent_sha256":sha(&bytes(&intent)?),"export":e,"export_complete":true,"retry_allowed":false}),
    )
}

#[cfg(test)]
mod failure_tests {
    use super::super::{failure, tests::failure_fixture, value, Journal};
    use super::*;
    use std::{fs, path::Path};
    #[test]
    fn failed_build_changed_original_nonce_anchor_result_or_missing_authority_refuses_before_contact(
    ) {
        for kind in ["nonce", "anchor", "log", "dispatch", "pin", "claim"] {
            let (_temp, j, i, mut rpc) = failure_fixture("");
            let job = text(&i, "job_id").unwrap();
            let path = Path::new(text(&i["flow"], "journal").unwrap());
            if matches!(kind, "nonce" | "anchor" | "log") {
                let result = path.join(Journal::name(job, "bounded-build-return").unwrap());
                let mut v: Value = serde_json::from_slice(&fs::read(&result).unwrap()).unwrap();
                v[match kind {
                    "nonce" => "host_nonce_hex",
                    "anchor" => "host_anchor_sha256",
                    _ => "stderr_sha256",
                }] = json!("0".repeat(64));
                v.as_object_mut().unwrap().remove("result_sha256");
                v["result_sha256"] = json!(sha(&bytes(&v).unwrap()));
                let mut raw = bytes(&v).unwrap();
                raw.push(b'\n');
                fs::write(result, raw).unwrap();
                let claim = path.join(Journal::name(job, "bounded-build-claim").unwrap());
                let mut c: Value = serde_json::from_slice(&fs::read(&claim).unwrap()).unwrap();
                c["result_sha256"] = v["result_sha256"].clone();
                fs::write(claim, bytes(&c).unwrap()).unwrap();
            } else {
                let name = if kind == "pin" {
                    format!("{job}.candidate-build-pin.json")
                } else {
                    Journal::name(
                        job,
                        if kind == "dispatch" {
                            "bounded-build-dispatch"
                        } else {
                            "bounded-build-claim"
                        },
                    )
                    .unwrap()
                };
                fs::remove_file(path.join(name)).unwrap();
            }
            assert!(failure::parse(&bytes(&i).unwrap()).is_err(), "{kind}");
            assert!(
                failure::download(&j, &i, "failure-download", &mut rpc).is_err(),
                "{kind}"
            );
            assert_eq!(rpc.calls, 0);
            assert!(j.absent(job, failure::DOWNLOAD).unwrap());
        }
    }
    #[test]
    fn failed_build_export_state_and_ack_cannot_substitute_pins_or_promote_unknown() {
        let (_temp, j, i, mut rpc) = failure_fixture("");
        let mut original = failure_pins(&i);
        original["schema"] = json!("hol-gauntlet-failed-build-export-intent.v1");
        let unknown = json!({"schema":"hol-gauntlet-failed-build-export-state.v1","intent_sha256":sha(&bytes(&original).unwrap()),"export":null,"export_complete":false,"retry_allowed":false});
        assert_eq!(failure_state(&i, &unknown).unwrap(), None);
        assert!(failure_export(&i, &unknown).is_err());
        failure::download(&j, &i, "failure-download", &mut rpc).unwrap();
        let e = value(&j, &i, failure::EXPORT).unwrap();
        let state = json!({"schema":"hol-gauntlet-failed-build-export-state.v1","intent_sha256":sha(&bytes(&original).unwrap()),"export":e,"export_complete":true,"retry_allowed":false});
        for key in [
            "result_sha256",
            "host_pin_sha256",
            "host_anchor_sha256",
            "reader_generation",
            "source_archive_sha256",
        ] {
            let mut changed = state.clone();
            changed["export"]["receipt"][key] = json!("0".repeat(64));
            changed["export"]["receipt_sha256"] =
                json!(sha(&bytes(&changed["export"]["receipt"]).unwrap()));
            assert!(failure_export(&i, &changed).is_err(), "{key}");
        }
        let host = "a".repeat(64);
        let body = failure_ack_body(&e, &host);
        let mut ack = json!({"schema":"hol-gauntlet-failed-build-ack-result.v1","receipt":body,"receipt_sha256":sha(&bytes(&body).unwrap())});
        assert!(failure_ack(&e, &host, &ack).is_ok());
        ack["receipt"]["host_receipt_sha256"] = json!("b".repeat(64));
        ack["receipt_sha256"] = json!(sha(&bytes(&ack["receipt"]).unwrap()));
        assert!(failure_ack(&e, &host, &ack).is_err());
    }
}
