//! Closed Root data receipts joined to the Host's retained source/read chain.
use super::{bytes, hex, sha, text};
use serde_json::{json, Value};

fn count(v: &Value, key: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    v[key]
        .as_u64()
        .filter(|n| (minimum..=maximum).contains(n))
        .ok_or_else(|| format!("bounded prefix {key} required"))
}
fn tree(v: &Value) -> Result<(), String> {
    if !hex(text(v, "prefix_tree_sha256")?, 64) {
        return Err("computed prefix tree digest required".into());
    }
    count(v, "prefix_entries", 1, 100_000)?;
    count(v, "prefix_bytes", 1, 2 * 1024 * 1024 * 1024)?;
    Ok(())
}
pub(super) fn python_version(raw: &str) -> bool {
    raw.strip_prefix("3.12.").is_some_and(|n| {
        !n.is_empty()
            && n.len() <= 3
            && n.bytes().all(|b| b.is_ascii_digit())
            && (n.len() == 1 || !n.starts_with('0'))
    })
}
fn dependency(i: &Value, v: &Value) -> Result<(), String> {
    let inputs = &i["inputs"];
    let p = &inputs["pins"];
    let s = &i["source"]["intent"];
    tree(v)?;
    count(v, "dependency_files", 1, 100_000)?;
    if !hex(text(v, "dependency_entry_bytes_sha256")?, 64) {
        return Err("dependency archive member digest required".into());
    }
    let expected = json!({"schema":"hol-gauntlet-native-dependency-prefix.v1","job_id":i["job_id"],
        "source_sha":s["source_sha"],"source_archive_sha256":s["source_archive_sha256"],
        "intent_sha256":inputs["dependency_intent_sha256"],"result_sha256":inputs["flow"]["result_sha256"],
        "dependency_archive_sha256":inputs["flow"]["archive_sha256"],"pyproject_sha256":p["pyproject_sha256"],
        "uv_lock_sha256":p["uv_lock_sha256"],"run_generation":p["runner_binary_sha256"],
        "stage_generation":i["worker_generation"],"python_sha256":i["python"],"python_path":"/usr/bin/python3.12",
        "prefix_tree_sha256":v["prefix_tree_sha256"],"prefix_entries":v["prefix_entries"],"prefix_bytes":v["prefix_bytes"],
        "dependency_files":v["dependency_files"],"dependency_entry_bytes_sha256":v["dependency_entry_bytes_sha256"],
        "artifact_admitted":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if v != &expected {
        return Err("dependency prefix receipt differs from original readback pins".into());
    }
    Ok(())
}
fn candidate(i: &Value, v: &Value) -> Result<(), String> {
    let s = &i["source"]["intent"];
    let inputs = &i["inputs"];
    let dep = &i["dependency"];
    tree(v)?;
    count(v, "wheel_files", 1, 20_000)?;
    let expected = json!({"schema":"hol-gauntlet-native-candidate-prefix.v1","job_id":i["job_id"],
        "source_sha":s["source_sha"],"source_archive_sha256":s["source_archive_sha256"],
        "archive_sha256":inputs["flow"]["archive_sha256"],"version":inputs["version"],
        "baseline_tree_sha256":dep["receipt"]["prefix_tree_sha256"],"stage_tree_sha256":inputs["stage_tree_sha256"],
        "prefix_tree_sha256":v["prefix_tree_sha256"],"prefix_entries":v["prefix_entries"],"prefix_bytes":v["prefix_bytes"],
        "wheel_files":v["wheel_files"],"clone_generation":i["worker_generation"],
        "dependency_job_id":dep["receipt"]["job_id"],"dependency_prefix_receipt_sha256":dep["receipt_sha256"],
        "console_scripts":6,"candidate_executed":false,"dependency_validation_completed":false,
        "conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0});
    if v != &expected {
        return Err(
            "candidate clone differs from original staged wheel or dependency prefix".into(),
        );
    }
    Ok(())
}
fn requirements(i: &Value, v: &Value) -> Result<(), String> {
    let input = &i["inputs"]["candidate"];
    let clone = &i["inputs"]["clone"]["receipt"];
    let names = v["active_names"]
        .as_array()
        .ok_or("dependency names absent")?;
    let total = count(v, "requirements", 0, 1024)?;
    let active = count(v, "active_requirements", 0, total)?;
    let inactive = count(v, "inactive_requirements", 0, total)?;
    count(v, "installed_distributions", 1, 1024)?;
    let mut previous = "";
    for name in names {
        let name = name.as_str().ok_or("dependency name invalid")?;
        if name.is_empty()
            || name.len() > 200
            || name <= previous
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        {
            return Err("unique canonical dependency names required".into());
        }
        previous = name;
    }
    if active + inactive != total
        || names.len() as u64 > active
        || (active == 0) != names.is_empty()
    {
        return Err("dependency requirement counts differ".into());
    }
    let expected = json!({"schema":"hol-gauntlet-candidate-dependencies-shadow.v1","job_id":i["job_id"],
        "source_sha":i["source"]["intent"]["source_sha"],"archive_sha256":input["flow"]["archive_sha256"],
        "native_sha256":input["native_sha256"],"prefix_tree_sha256":clone["prefix_tree_sha256"],
        "python_full_version":i["python"],"installed_distributions":v["installed_distributions"],
        "requirements":total,"active_requirements":active,"inactive_requirements":inactive,"active_names":names,
        "all_active_requirements_satisfied":true,"candidate_executed":false,"conformance_completed":false,
        "artifact_admitted":false,"execution_eligible":false});
    if v != &expected {
        return Err("runtime dependency proof differs from original inputs".into());
    }
    Ok(())
}
fn runtime(i: &Value, v: &Value) -> Result<(), String> {
    let inputs = &i["inputs"];
    let c = &inputs["candidate"];
    let clone = &inputs["clone"];
    let s = &i["source"]["intent"];
    requirements(i, &v["dependency_requirements"])?;
    let expected = json!({"schema":"hol-gauntlet-native-runtime-publication.v1","job_id":i["job_id"],
        "source_sha":s["source_sha"],"version":c["version"],"clone_receipt_sha256":clone["receipt_sha256"],
        "source_archive_sha256":s["source_archive_sha256"],"archive_sha256":c["flow"]["archive_sha256"],
        "dependency_prefix_receipt_sha256":clone["receipt"]["dependency_prefix_receipt_sha256"],
        "prefix":format!("/opt/hol-gauntlet/candidates/{}/prefix",text(s,"source_sha")?),
        "prefix_tree_sha256":clone["receipt"]["prefix_tree_sha256"],"prefix_entries":clone["receipt"]["prefix_entries"],
        "prefix_bytes":clone["receipt"]["prefix_bytes"],"native_sha256":c["native_sha256"],
        "publisher_generation":i["worker_generation"],"dependency_requirements":v["dependency_requirements"],
        "candidate_executed":false,"conformance_completed":false,"artifact_admitted":false,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0});
    if v != &expected {
        return Err("runtime publication differs from original clone or Source".into());
    }
    Ok(())
}
pub(super) fn receipt(i: &Value, raw: &[u8]) -> Result<(Value, String), String> {
    let frame = raw
        .strip_suffix(b"\n")
        .filter(|v| !v.contains(&b'\n') && v.len() <= 131072)
        .ok_or("canonical bounded prefix response frame required")?;
    let mut v: Value = serde_json::from_slice(frame).map_err(|_| "prefix reply JSON invalid")?;
    if bytes(&v)? != frame {
        return Err("canonical prefix receipt required".into());
    }
    let outside = if i["operation"] == "prefix-stage" {
        None
    } else {
        Some(
            v.as_object_mut()
                .ok_or("prefix reply object required")?
                .remove("receipt_sha256")
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or("prefix receipt digest absent")?,
        )
    };
    let digest = sha(&bytes(&v)?);
    if outside.as_ref().is_some_and(|expected| expected != &digest) {
        return Err("bare prefix receipt digest differs".into());
    }
    match text(i, "operation")? {
        "prefix-stage" => dependency(i, &v)?,
        "prefix-clone" => candidate(i, &v)?,
        "runtime-publish" => runtime(i, &v)?,
        _ => return Err("closed prefix operation required".into()),
    }
    Ok((v, digest))
}
