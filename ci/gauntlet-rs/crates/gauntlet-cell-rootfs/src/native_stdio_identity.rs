//! Closed source-specific selection. This grants no memory-read authority.
use crate::{hex, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) const MODE: &str = "outside-root-native-stdio.v1";

pub(crate) fn privilege_floor(image: &Value, actor: &Value) -> Result<()> {
    let task = &image["task"];
    if task["tid"] != task["tgid"]
        || image["namespaces"] != actor["namespaces"]
        || image["lsm_label"] != actor["lsm_label"]
    {
        return Err("Native stdio leader or actor isolation differs".into());
    }
    for field in ["Uid", "Gid"] {
        if task["status"][field]
            .as_str()
            .map(|v| v.split_ascii_whitespace().collect::<Vec<_>>())
            != Some(vec!["10004"; 4])
        {
            return Err("Native stdio UID/GID floor differs".into());
        }
    }
    if task["status"]["Groups"]
        .as_str()
        .is_none_or(|v| !v.trim().is_empty())
        || task["status"]["NoNewPrivs"] != "1"
    {
        return Err("Native stdio groups or no-new-privileges differs".into());
    }
    for key in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        if task["status"][key] != "0000000000000000" {
            return Err("Native stdio capabilities must be empty".into());
        }
    }
    let exe = &image["executable"];
    if exe["uid"] != 0
        || exe["gid"] != 0
        || exe["links"] != 1
        || exe["mode"].as_u64().is_none_or(|v| v & 0o6022 != 0)
    {
        return Err("Root-owned non-writable Native stdio executable required".into());
    }
    Ok(())
}

pub(crate) fn command(image: &Value) -> Result<Vec<Vec<u8>>> {
    let raw = image["argv_base64"]
        .as_str()
        .and_then(|s| STANDARD.decode(s).ok())
        .filter(|v| !v.is_empty() && v.len() <= 65536 && v.ends_with(&[0]))
        .ok_or("bounded Native stdio command bytes required")?;
    if image["argv_sha256"] != crate::hash(&raw) {
        return Err("Native stdio command digest differs".into());
    }
    Ok(raw[..raw.len() - 1]
        .split(|v| *v == 0)
        .map(<[u8]>::to_vec)
        .collect())
}

/// Select only this Native client's public framed pipe transport. A process
/// with another operation never supplies even a candidate memory range.
pub(crate) fn selected(image: &Value, actor: &Value, native: &str) -> Result<bool> {
    if !hex(native, 64) {
        return Err("exact Native stdio ELF digest required".into());
    }
    let args = command(image)?;
    if args.get(1).map(Vec::as_slice) != Some(b"resident-client-stream") {
        return Ok(false);
    }
    if image["executable"]["sha256"] != native {
        return Err("Native stream executable differs from the launch digest".into());
    }
    if args.len() != 4
        || !args[0].starts_with(b"/")
        || !args[0].ends_with(b"/hol-guard-runtime")
        || args[2] != b"--stdin"
        || args[3] != b"/product/guard/native-runtime"
    {
        return Err("fixed owned Native stream command required".into());
    }
    privilege_floor(image, actor)?;
    if image["task"]["status"]["Seccomp"] != "2" {
        return Err("filtered Native stdio process required".into());
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn image() -> Value {
        let raw = b"/product/runtime/bin/hol-guard-runtime\0resident-client-stream\0--stdin\0/product/guard/native-runtime\0";
        let mut image = json!({"task":{"tid":14,"tgid":14,"status":{
            "Uid":"10004\t10004\t10004\t10004","Gid":"10004\t10004\t10004\t10004",
            "Groups":"","NoNewPrivs":"1","Seccomp":"2"}},
            "namespaces":{"pid":"4:22"},"lsm_label":"owned (enforce)",
            "argv_base64":STANDARD.encode(raw),"argv_sha256":crate::hash(raw),
            "executable":{"uid":0,"gid":0,"links":1,"mode":365,"sha256":"a".repeat(64)}});
        for key in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
            image["task"]["status"][key] = json!("0000000000000000");
        }
        image
    }

    #[test]
    fn only_the_source_bound_stream_shape_and_privilege_floor_can_select() {
        let good = image();
        assert!(selected(&good, &good, &"a".repeat(64)).unwrap());
        assert!(selected(&good, &good, &"b".repeat(64)).is_err());
        for (pointer, value) in [
            ("/task/tgid", json!(15)),
            ("/task/status/Uid", json!("0\t0\t0\t0")),
            ("/task/status/Gid", json!("10004 10004 10004 0")),
            ("/task/status/Groups", json!("10004")),
            ("/task/status/CapEff", json!("0000000000000001")),
            ("/task/status/NoNewPrivs", json!("0")),
            ("/task/status/Seccomp", json!("0")),
            ("/namespaces/pid", json!("4:23")),
            ("/lsm_label", json!("unconfined")),
            ("/executable/uid", json!(10004)),
            ("/executable/mode", json!(0o777)),
            ("/executable/links", json!(2)),
            ("/argv_sha256", json!("b".repeat(64))),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(selected(&bad, &good, &"a".repeat(64)).is_err(), "{pointer}");
        }
    }

    #[test]
    fn unrelated_operations_skip_and_malformed_stream_arguments_refuse() {
        let good = image();
        for (raw, skip) in [
            (b"/native\0capabilities\0--json\0".as_slice(), true),
            (
                b"/native\0resident-client-stream\0--stdin\0/private\0".as_slice(),
                false,
            ),
            (
                b"/native\0resident-client-stream\0--stdin\0/product/guard/native-runtime\0extra\0"
                    .as_slice(),
                false,
            ),
        ] {
            let mut value = good.clone();
            value["argv_base64"] = json!(STANDARD.encode(raw));
            value["argv_sha256"] = json!(crate::hash(raw));
            let result = selected(&value, &good, &"a".repeat(64));
            if skip {
                assert!(!result.unwrap());
            } else {
                assert!(result.is_err());
            }
        }
    }
}
