//! Exact pinned OCI syscall floor and the native-only socket floor.
use crate::{CellError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const PROFILE_SHA256: &str = "c904570e61ccaf7d03b9814796c625913650d08f97144e32e7030c19adbbfee5";
pub const LIBRARY_SHA256: &str = "3d128123b494ca9e88f3c237b0912397145af1754e86ea99f460af6857441f19";
pub(crate) const ALLOW: u32 = 0x7fff0000;
pub(crate) const ERRNO: u32 = 0x00050000;
const INVALID: CellError =
    CellError("product syscall profile differs from the pinned native floor");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProfile {
    UnixOnly,
    PrivateLoopback,
}
impl NetworkProfile {
    pub fn declaration(self) -> &'static str {
        match self {
            Self::UnixOnly => "unix-only-v1",
            Self::PrivateLoopback => "private-loopback-v1",
        }
    }
}
pub(crate) fn action(rule: &Value) -> Result<u32> {
    match rule["action"].as_str() {
        Some("SCMP_ACT_ALLOW") if rule.get("errnoRet").is_none() => Ok(ALLOW),
        Some("SCMP_ACT_ERRNO") => rule["errnoRet"]
            .as_u64()
            .filter(|n| (1..=4095).contains(n))
            .map(|n| ERRNO | n as u32)
            .ok_or(INVALID),
        _ => Err(INVALID),
    }
}
pub(crate) fn comparison(value: &str) -> Result<i32> {
    match value {
        "SCMP_CMP_NE" => Ok(1),
        "SCMP_CMP_LT" => Ok(2),
        "SCMP_CMP_EQ" => Ok(4),
        "SCMP_CMP_GT" => Ok(6),
        _ => Err(INVALID),
    }
}
pub fn validate_product_seccomp(raw: &[u8]) -> Result<Value> {
    if raw.len() > 128 * 1024 || format!("{:x}", Sha256::digest(raw)) != PROFILE_SHA256 {
        return Err(INVALID);
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let p: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if p.as_object().is_none_or(|o| o.len() != 4)
        || p["architectures"] != serde_json::json!(["SCMP_ARCH_AARCH64", "SCMP_ARCH_ARM"])
        || p["defaultAction"] != "SCMP_ACT_ERRNO"
        || p["defaultErrnoRet"] != 38
    {
        return Err(INVALID);
    }
    let rules = p["syscalls"]
        .as_array()
        .filter(|a| a.len() == 21)
        .ok_or(INVALID)?;
    for rule in rules {
        let object = rule.as_object().ok_or(INVALID)?;
        if !object.contains_key("names")
            || !object.contains_key("action")
            || object
                .keys()
                .any(|s| !matches!(s.as_str(), "names" | "action" | "args" | "errnoRet"))
        {
            return Err(INVALID);
        }
        let names = rule["names"]
            .as_array()
            .filter(|a| (1..=512).contains(&a.len()))
            .ok_or(INVALID)?;
        if names.iter().any(|n| {
            n.as_str().is_none_or(|s| {
                s.is_empty()
                    || !s.is_ascii()
                    || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
        }) {
            return Err(INVALID);
        }
        action(rule)?;
        if let Some(args) = rule.get("args") {
            for arg in args.as_array().filter(|a| a.len() <= 6).ok_or(INVALID)? {
                if arg.as_object().is_none_or(|o| o.len() != 3)
                    || arg["index"].as_u64().is_none_or(|n| n > 5)
                    || arg["value"].as_u64().is_none()
                {
                    return Err(INVALID);
                }
                comparison(arg["op"].as_str().ok_or(INVALID)?)?;
            }
        }
    }
    Ok(p)
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub fn install_product_filter(raw: &[u8], network: NetworkProfile) -> Result<Value> {
    let p = validate_product_seccomp(raw)?;
    crate::seccomp_library::install(&p, network)
}
#[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
pub fn install_product_filter(_raw: &[u8], _network: NetworkProfile) -> Result<Value> {
    Err(CellError(
        "product syscall profile requires native Linux ARM64",
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_pinned_floor_and_declared_actions_are_valid() {
        let raw = include_bytes!("../../../../gauntlet/benchmark/product_vm_seccomp_oci_v1.json");
        assert_eq!(
            validate_product_seccomp(raw).unwrap()["syscalls"]
                .as_array()
                .unwrap()
                .len(),
            21
        );
        let mut changed = raw.to_vec();
        changed.push(b' ');
        assert!(validate_product_seccomp(&changed).is_err());
        assert!(action(&serde_json::json!({"action":"SCMP_ACT_ERRNO","errnoRet":true})).is_err());
        assert!(action(&serde_json::json!({"action":"SCMP_ACT_ERRNO","errnoRet":0})).is_err());
        assert!(comparison("SCMP_CMP_MASKED_EQ").is_err());
    }
}
