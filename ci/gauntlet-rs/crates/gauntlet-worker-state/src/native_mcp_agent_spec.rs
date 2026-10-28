//! Independent checks on the Root-owned agent inspection. No producer claim
//! is accepted as a substitute for the later kernel namespace/cgroup sample.
use crate::NATIVE_SDK_AGENT_IMAGE;
use serde_json::Value;
use std::collections::BTreeMap;
pub(crate) fn check_inspection(
    value: &Value,
    name: &str,
    job: &str,
    nonce: &str,
    mounts: &BTreeMap<String, (String, bool)>,
    running: bool,
) -> Result<(String, u32), String> {
    let id = value["Id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("MCP container ID unavailable")?;
    if value["Name"]
        .as_str()
        .map(|s| s.strip_prefix('/').unwrap_or(s))
        != Some(name)
        || value["Image"]
            .as_str()
            .map(|s| s.strip_prefix("sha256:").unwrap_or(s))
            != NATIVE_SDK_AGENT_IMAGE.strip_prefix("sha256:")
        || value["Config"]["User"] != "10005:10005"
        || value["Config"]["WorkingDir"] != "/product/home/project"
        || value["Path"] != "/usr/bin/sleep"
        || value["Args"] != serde_json::json!(["240"])
        || value["Config"]["Labels"]["hol.gauntlet.mcp.job"] != job
        || value["Config"]["Labels"]["hol.gauntlet.mcp.nonce"] != nonce
        || value["Config"]["Labels"]["hol.gauntlet.mcp.profile"] != "native-mcp-transport-v1"
        || value["State"]["Running"] != running
        || value["AppArmorProfile"] != name
    {
        return Err("MCP container identity, label or fixed init differs".into());
    }
    let h = &value["HostConfig"];
    if h["Privileged"] != false
        || h["ReadonlyRootfs"] != true
        || h["NetworkMode"] != "none"
        || h["Memory"] != 1073741824_u64
        || h["PidsLimit"] != 256
        || h["NanoCpus"] != 1000000000_u64
        || h["CpusetCpus"] != "0"
        || h["CgroupParent"] != format!("holgauntletrust{job}.slice")
        || h["CapAdd"].as_array().is_none_or(|a| !a.is_empty())
    {
        return Err("MCP agent isolation or resource settings differ".into());
    }
    let drops = h["CapDrop"]
        .as_array()
        .ok_or("MCP capability drop missing")?;
    let expanded = [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_NET_BIND_SERVICE",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT",
    ];
    let values = drops
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let all = drops.len() == 1 && matches!(drops[0].as_str(), Some("ALL" | "CAP_ALL"));
    let expanded_all = drops.len() == expanded.len() && values == expanded.into_iter().collect();
    if !(all || expanded_all)
        || ["BoundingCaps", "EffectiveCaps"].iter().any(|key| {
            value
                .get(*key)
                .is_none_or(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
        })
    {
        return Err("MCP must drop every capability".into());
    }
    let opts = h["SecurityOpt"]
        .as_array()
        .ok_or("MCP security options missing")?;
    if opts.len() != 2
        || !opts.contains(&Value::String("no-new-privileges".into()))
        || !opts.contains(&Value::String(format!("apparmor={name}")))
    {
        return Err("MCP NNP/enforcing profile options differ".into());
    }
    let actual = value["Mounts"]
        .as_array()
        .ok_or("MCP bind inventory missing")?;
    if actual.len() != mounts.len() {
        return Err("MCP mount inventory differs".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for m in actual {
        let dest = m["Destination"].as_str().ok_or("MCP destination missing")?;
        let expected = mounts.get(dest).ok_or("unexpected MCP mount")?;
        if !seen.insert(dest)
            || m["Type"] != "bind"
            || m["Source"] != expected.0
            || m["RW"] != expected.1
            || m["Propagation"] != "rprivate"
        {
            return Err("MCP bind source, permissions or propagation differs".into());
        }
    }
    let pid = if running {
        u32::try_from(
            value["State"]["Pid"]
                .as_u64()
                .ok_or("MCP init PID missing")?,
        )
        .ok()
        .filter(|p| *p > 1)
        .ok_or("MCP init PID invalid")?
    } else {
        0
    };
    Ok((id.into(), pid))
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn mcp_inspection_refuses_changed_owner_boundary_and_extra_mounts() {
        let name = "hol-mcp-example";
        let job = "a".repeat(16);
        let nonce = "b".repeat(32);
        let mounts = BTreeMap::from([("/product/public".into(), ("/opt/public".into(), false))]);
        let value = json!({"Id":"c".repeat(64),"Name":format!("/{name}"),"Image":NATIVE_SDK_AGENT_IMAGE,
            "Path":"/usr/bin/sleep","Args":["240"],"AppArmorProfile":name,"State":{"Running":true,"Pid":41},
            "Config":{"User":"10005:10005","WorkingDir":"/product/home/project","Labels":{"hol.gauntlet.mcp.job":job,
                "hol.gauntlet.mcp.nonce":nonce,"hol.gauntlet.mcp.profile":"native-mcp-transport-v1"}},
            "BoundingCaps":null,"EffectiveCaps":[],"HostConfig":{"Privileged":false,"ReadonlyRootfs":true,"NetworkMode":"none","Memory":1073741824_u64,
                "PidsLimit":256,"NanoCpus":1000000000_u64,"CpusetCpus":"0","CgroupParent":format!("holgauntletrust{job}.slice"),
                "CapAdd":[],"CapDrop":["CAP_ALL"],"SecurityOpt":["no-new-privileges",format!("apparmor={name}")]},
            "Mounts":[{"Destination":"/product/public","Source":"/opt/public","Type":"bind","RW":false,"Propagation":"rprivate"}]});
        assert!(check_inspection(&value, name, &job, &nonce, &mounts, true).is_ok());
        let mut other_display = value.clone();
        other_display["Name"] = json!(name);
        other_display["Image"] = json!(NATIVE_SDK_AGENT_IMAGE.strip_prefix("sha256:").unwrap());
        assert!(check_inspection(&other_display, name, &job, &nonce, &mounts, true).is_ok());
        other_display["HostConfig"]["CapDrop"] = json!([
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_NET_BIND_SERVICE",
            "CAP_SETFCAP",
            "CAP_SETGID",
            "CAP_SETPCAP",
            "CAP_SETUID",
            "CAP_SYS_CHROOT"
        ]);
        assert!(check_inspection(&other_display, name, &job, &nonce, &mounts, true).is_ok());
        other_display["HostConfig"]["CapDrop"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(check_inspection(&other_display, name, &job, &nonce, &mounts, true).is_err());
        let mut changed = value.clone();
        changed["BoundingCaps"] = json!(["CAP_SYS_ADMIN"]);
        assert!(check_inspection(&changed, name, &job, &nonce, &mounts, true).is_err());
        changed = value.clone();
        changed.as_object_mut().unwrap().remove("EffectiveCaps");
        assert!(check_inspection(&changed, name, &job, &nonce, &mounts, true).is_err());
        for (pointer, bad) in [
            ("/Config/User", json!("0:0")),
            ("/Image", json!("other")),
            ("/Config/Labels/hol.gauntlet.mcp.nonce", json!("changed")),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/ReadonlyRootfs", json!(false)),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/CapAdd", json!(["CAP_SYS_ADMIN"])),
            ("/HostConfig/PidsLimit", json!(0)),
            ("/Mounts/0/RW", json!(true)),
            ("/Mounts/0/Source", json!("/root")),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(
                check_inspection(&changed, name, &job, &nonce, &mounts, true).is_err(),
                "{pointer}"
            )
        }
    }
}
