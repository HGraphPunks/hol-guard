//! Join actual read-call expectations, signed receipts and physical provider DB.
//! Transport and prelaunch provenance must be established by the caller.
use crate::crypto::{decode_base64, verify_ed25519};
use crate::native_diagnostic_artifacts::{digest, ineligible, require, text, Artifacts};
use crate::{canonical_value, verify_native_world_database, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub fn verify_native_world_diagnostic(
    mcp: &Value,
    files: &BTreeMap<String, Vec<u8>>,
    actual_calls: &[Value],
) -> Result<Value> {
    ineligible(mcp)?;
    let world = &mcp["world"];
    ineligible(world)?;
    require(
        world["schema"] == "hol-gauntlet-native-mcp-world.v1"
            && world["database"] == "mcp-world.db"
            && world["agent_mounts_verified"] == false
            && mcp["outside_signing_key_admitted"] == false,
    )?;
    let artifacts = Artifacts::new(files)?;
    let metadata = artifacts.metadata("combined/mcp-world.db")?;
    for field in ["uid", "gid", "mode", "device", "inode"] {
        require(world.get(field).is_some() && world[field] == metadata[field])?;
    }
    require(
        world["uid"] == 0
            && world["gid"] == 0
            && world["mode"] == 0o600
            && metadata["links"] == 1
            && world["device"].as_u64().is_some_and(|n| n > 0)
            && world["inode"].as_u64().is_some_and(|n| n > 0),
    )?;
    let initial = &mcp["initial"];
    require(
        initial == &mcp["final"]
            && initial["schema"] == "gauntlet-workflow-snapshot.v1"
            && initial["actor_id"] == "fixture-actor"
            && initial["provider_scope"] == json!({"tenants":["task-tenant"]})
            && initial.as_object().is_some_and(|m| m.len() == 4),
    )?;
    let values = initial["records"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or(EvidenceError::Invalid(
            "two Native synthetic provider records required",
        ))?;
    let mut records = BTreeMap::new();
    for value in values {
        let id = text(value, "id")?;
        require(records.insert(id.to_owned(), value.clone()).is_none())?;
    }
    require(records.contains_key("developer-spec") && records.contains_key("message"))?;
    let receipts = mcp["receipts"].as_array().ok_or(EvidenceError::Invalid(
        "Native physical provider receipts missing",
    ))?;
    require(actual_calls.len() == 1 && receipts.len() == actual_calls.len())?;
    let public_text = text(world, "public_key")?;
    let public = decode_base64(public_text, 32)?;
    let mut previous = "0".repeat(64);
    for (index, (envelope, call)) in receipts.iter().zip(actual_calls).enumerate() {
        let args = json!({"record_id":"developer-spec"});
        require(
            call["jsonrpc"] == "2.0"
                && call["method"] == "tools/call"
                && call["params"]["name"] == "docs.read"
                && call["params"]["arguments"] == args
                && call["id"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty() && s.len() <= 256),
        )?;
        let after = &records["developer-spec"];
        let expected = json!({"actor":"fixture-actor","after":after,"before":null,
            "args_digest":digest(&json!({"operation":"docs.read","args":args,"actor":"fixture-actor"}))?,
            "effect":"read","operation":"docs.read","previous_hash":previous,
            "raw_args_digest":digest(&args)?,"request_id":call["id"],"result_digest":digest(after)?,
            "sequence":index+1,"status":"ok"});
        require(
            envelope.as_object().is_some_and(|m| m.len() == 2) && envelope["event"] == expected,
        )?;
        verify_ed25519(
            &public,
            &canonical_value(&expected)?,
            &decode_base64(text(envelope, "signature")?, 64)?,
        )?;
        previous = digest(envelope)?;
    }
    let mut meta = initial.clone();
    meta.as_object_mut()
        .ok_or(EvidenceError::Invalid("Native provider metadata missing"))?
        .remove("records");
    meta["producer"] = public_text.into();
    let database = verify_native_world_database(
        artifacts.raw("combined/mcp-world.db")?,
        &meta,
        &records,
        receipts,
    )?;
    require(
        mcp["sockets"]["socket_namespace_retired"] == true
            && mcp["sockets"]["accepted_streams_drained"] == false
            && mcp["sockets"]["peer_authenticated"] == false,
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-native-world-diagnostic-relations.v1",
        "physical_database":database,"signed_read_receipts_checked":receipts.len(),
        "actual_call_and_physical_record_bound":true,"qualified_role_complete":false,
        "outside_signing_key_admitted":false,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_world_diagnostic_tests.rs"]
mod tests;
