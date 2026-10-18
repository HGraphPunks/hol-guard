//! One-time legacy admission requires the retained credential-store anchor,
//! not a database's assertion that it was once enrolled.
use super::*;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn authenticated(envelope: &Value, key: &[u8], purpose: &str) -> Result<Value, String> {
    let data = envelope["record"]
        .as_str()
        .ok_or("pack_lifecycle_legacy_invalid")?;
    if data.is_empty() || data.len() > 512 * 1024 {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    let mut derive =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| "pack_lifecycle_key_invalid")?;
    derive.update(b"hol-guard.extension-control-authority.v1\0");
    derive.update(purpose.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&derive.finalize().into_bytes())
        .map_err(|_| "pack_lifecycle_key_invalid")?;
    mac.update(data.as_bytes());
    let signature = hex::decode(
        envelope["mac"]
            .as_str()
            .ok_or("pack_lifecycle_legacy_invalid")?,
    )
    .map_err(|_| "pack_lifecycle_legacy_invalid")?;
    mac.verify_slice(&signature)
        .map_err(|_| "pack_lifecycle_legacy_authentication_failed")?;
    if envelope["digest"] != hex::encode(Sha256::digest(data.as_bytes())) {
        return Err("pack_lifecycle_legacy_authentication_failed".into());
    }
    let value: Value = serde_json::from_str(data).map_err(|_| "pack_lifecycle_legacy_invalid")?;
    if value["authority_schema_version"] != 1 || value["purpose"] != purpose {
        return Err("pack_lifecycle_legacy_invalid".into());
    }
    Ok(value)
}

pub(super) fn migrate(input: &Value, key: &[u8]) -> Result<Value, String> {
    let stamp = "guard.command-pack-enrolled.v1";
    if !input["floor"].is_null() && !input["floor"].is_string() {
        return Err("pack_lifecycle_floor_invalid".into());
    }
    if let Some(record) = input["floor"].as_str() {
        decode(record, key)?;
        if !input["stamp"].is_null() && input["stamp"] != stamp {
            return Err("pack_lifecycle_enrollment_stamp_invalid".into());
        }
        return Ok(json!({"record":record,"stamp":stamp}));
    }
    if !input["stamp"].is_null() {
        return Err("pack_lifecycle_protected_floor_missing".into());
    }
    if input["legacy_anchor"].is_null() && input["legacy_snapshot"].is_null() {
        return Ok(json!({"record":null,"stamp":null}));
    }
    let legacy_key = hex::decode(
        input["legacy_key"]
            .as_str()
            .ok_or("pack_lifecycle_key_invalid")?,
    )
    .map_err(|_| "pack_lifecycle_key_invalid")?;
    if legacy_key.len() != 32 {
        return Err("pack_lifecycle_key_invalid".into());
    }
    let anchor = authenticated(
        &input["legacy_anchor"],
        &legacy_key,
        "extension-control.anchor",
    )?;
    let snapshot = authenticated(
        &input["legacy_snapshot"],
        &legacy_key,
        "extension-control.snapshot",
    )?;
    if anchor["phase"] != "committed"
        || anchor["revision"].as_u64().is_none()
        || anchor["revision"] != snapshot["revision"]
        || anchor["snapshot_digest"] != input["legacy_snapshot"]["digest"]
        || !input["legacy_activation"].is_null()
    {
        return Err("pack_lifecycle_legacy_anchor_mismatch".into());
    }
    let candidate = release::identity(input)?;
    let record = encode(
        &Floor {
            schema: "guard.command-pack-floor.v1".into(),
            source: candidate.source.clone(),
            authority: candidate.authority,
            revocation: candidate.revocation,
            installed: Some(candidate),
            remote: None,
        },
        key,
    )?;
    Ok(json!({"record":record,"stamp":stamp}))
}
