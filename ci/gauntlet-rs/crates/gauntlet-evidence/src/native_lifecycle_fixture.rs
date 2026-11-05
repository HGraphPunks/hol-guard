//! Compiled role/job fixture and exact held readiness generation.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{parse, require, text};
use crate::native_process_kernel::{hex, number};
use crate::Result;
use serde_json::{json, Value};

pub(crate) struct Fixture {
    pub(crate) token: String,
    pub(crate) code: String,
    pub(crate) body: String,
}
pub(crate) fn fixture(role: &str, job: &str) -> Result<Fixture> {
    require(matches!(role, "cancel" | "timeout") && hex(job, 16))?;
    let token = format!("hol-gauntlet-native-detached-{role}-{job}");
    let code = include_str!("../../../adapters/native_lifecycle_child_v2.py.txt")
        .replace("HOL_LIFECYCLE_ROLE_JSON", &json!(role).to_string())
        .replace("HOL_LIFECYCLE_TOKEN_JSON", &json!(token).to_string());
    let body = include_str!("../../../adapters/native_lifecycle_parent_v2.py.txt")
        .replace("HOL_DETACHED_CODE_JSON", &json!(code).to_string());
    Ok(Fixture { token, code, body })
}
pub(crate) fn readiness(ready: &Value, role: &str, job: &str, local: u64) -> Result<()> {
    let spec = fixture(role, job)?;
    require(
        (2..=u32::MAX as u64).contains(&local)
            && *ready
                == json!({"schema":"hol-gauntlet-native-detached-ready.v1","role":role,
            "token":spec.token,"pid":local,"sid":local,"pgrp":local}),
    )
}
pub(crate) fn held_file(file: &Value, ready: &Value) -> Result<()> {
    let raw = text(file, "utf8")?.as_bytes();
    let links = file["final_links"].as_u64();
    require(
        !raw.is_empty()
            && raw.len() <= 4096
            && parse(raw)? == *ready
            && file["view"] == "kernel-held-process-cwd.v1"
            && file["file"] == "detached-ready.json"
            && file["sha256"] == sha256(raw)
            && file["bytes"].as_u64() == Some(raw.len() as u64)
            && file["uid"].as_u64() == Some(10004)
            && file["gid"].as_u64() == Some(10004)
            && file["mode"].as_u64() == Some(0o600)
            && file["original_links"].as_u64() == Some(1)
            && matches!(links, Some(0 | 1))
            && file["overlay_cleanup_unlinked"].as_bool() == links.map(|n| n == 0)
            && file["held_bytes_unchanged"] == true
            && file["late_effect_absent"] == true,
    )?;
    number(&file["device"])?;
    number(&file["inode"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn job_role_and_detached_session_cannot_be_substituted() {
        let job = "0123456789abcdef";
        let f = fixture("cancel", job).unwrap();
        let ready = json!({"schema":"hol-gauntlet-native-detached-ready.v1","role":"cancel","token":f.token,"pid":4,"sid":4,"pgrp":4});
        readiness(&ready, "cancel", job, 4).unwrap();
        assert!(readiness(&ready, "timeout", job, 4).is_err());
        assert!(readiness(&ready, "cancel", "fedcba9876543210", 4).is_err());
        let mut changed = ready;
        changed["sid"] = json!(1);
        assert!(readiness(&changed, "cancel", job, 4).is_err());
        assert!(fixture("success", job).is_err());
        assert!(f.body.contains(&json!(f.code).to_string()));
    }
    #[test]
    fn retained_generation_requires_exact_bytes_typed_links_and_close_state() {
        let ready = json!({"actual":"ready"});
        let raw = ready.to_string();
        let file = json!({"view":"kernel-held-process-cwd.v1","file":"detached-ready.json","utf8":raw,
            "sha256":sha256(raw.as_bytes()),"bytes":raw.len(),"device":3,"inode":8,"uid":10004,"gid":10004,
            "mode":384,"original_links":1,"final_links":0,"overlay_cleanup_unlinked":true,
            "held_bytes_unchanged":true,"late_effect_absent":true});
        held_file(&file, &ready).unwrap();
        for (key, value) in [
            ("utf8", json!("{}")),
            ("final_links", json!(true)),
            ("final_links", json!(2)),
            ("overlay_cleanup_unlinked", json!(false)),
            ("late_effect_absent", json!(false)),
            ("mode", json!(420)),
            ("uid", json!(0)),
        ] {
            let mut changed = file.clone();
            changed[key] = value;
            assert!(held_file(&changed, &ready).is_err(), "{key}");
        }
    }
}
