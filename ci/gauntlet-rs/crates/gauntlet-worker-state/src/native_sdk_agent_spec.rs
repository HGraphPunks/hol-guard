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
    check_profile(
        value,
        name,
        job,
        nonce,
        mounts,
        running,
        ("native-sdk-transport-v1", 240),
    )
}
pub(crate) fn check_mcp_inspection(
    value: &Value,
    name: &str,
    job: &str,
    nonce: &str,
    mounts: &BTreeMap<String, (String, bool)>,
    running: bool,
) -> Result<(String, u32), String> {
    check_profile(
        value,
        name,
        job,
        nonce,
        mounts,
        running,
        ("native-sdk-mcp-transport-v1", 240),
    )
}
pub(crate) fn check_live_inspection(
    value: &Value,
    name: &str,
    job: &str,
    nonce: &str,
    mounts: &BTreeMap<String, (String, bool)>,
    running: bool,
) -> Result<(String, u32), String> {
    check_profile(
        value,
        name,
        job,
        nonce,
        mounts,
        running,
        (
            "native-sdk-mcp-transport-v1",
            crate::native_live_spec::PREPARATION_SECONDS,
        ),
    )
}
fn check_profile(
    value: &Value,
    name: &str,
    job: &str,
    nonce: &str,
    mounts: &BTreeMap<String, (String, bool)>,
    running: bool,
    (profile, seconds): (&str, u64),
) -> Result<(String, u32), String> {
    let id = value["Id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("SDK container ID unavailable")?;
    if value["Name"]
        .as_str()
        .map(|s| s.strip_prefix('/').unwrap_or(s))
        != Some(name)
        || value["Image"]
            .as_str()
            .map(|s| s.strip_prefix("sha256:").unwrap_or(s))
            != NATIVE_SDK_AGENT_IMAGE.strip_prefix("sha256:")
        || value["Config"]["User"] != "10001:10001"
        || value["Config"]["WorkingDir"] != "/runtime/home/project"
        || value["Path"] != "/usr/bin/sleep"
        || value["Args"] != serde_json::json!([seconds.to_string()])
        || value["Config"]["Labels"]["hol.gauntlet.sdk.job"] != job
        || value["Config"]["Labels"]["hol.gauntlet.sdk.nonce"] != nonce
        || value["Config"]["Labels"]["hol.gauntlet.sdk.profile"] != profile
        || value["State"]["Running"] != running
        || value["AppArmorProfile"] != name
    {
        return Err("SDK container identity, label or fixed init differs".into());
    }
    let h = &value["HostConfig"];
    if h["Privileged"] != false
        || h["ReadonlyRootfs"] != true
        || h["NetworkMode"] != "none"
        || h["Memory"] != 2147483648_u64
        || h["PidsLimit"] != 256
        || h["NanoCpus"] != 2000000000_u64
        || h["CpusetCpus"] != "0-1"
        || h["CgroupParent"] != format!("holgauntletrust{job}.slice")
        || h["CapAdd"].as_array().is_none_or(|a| !a.is_empty())
    {
        return Err("SDK agent isolation or resource settings differ".into());
    }
    let drops = h["CapDrop"]
        .as_array()
        .ok_or("SDK capability drop missing")?;
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
        return Err("SDK must drop every capability".into());
    }
    let opts = h["SecurityOpt"]
        .as_array()
        .ok_or("SDK security options missing")?;
    if opts.len() != 2
        || !opts.contains(&Value::String("no-new-privileges".into()))
        || !opts.contains(&Value::String(format!("apparmor={name}")))
    {
        return Err("SDK NNP/enforcing profile options differ".into());
    }
    let actual = value["Mounts"]
        .as_array()
        .ok_or("SDK bind inventory missing")?;
    let tmpfs = if actual.iter().any(|m| m["Type"] == "tmpfs") {
        crate::native_job_storage::check_tmpfs(value)?
    } else {
        0
    };
    if actual.len() != mounts.len() + tmpfs {
        return Err("SDK mount inventory differs".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for m in actual {
        let dest = m["Destination"].as_str().ok_or("SDK destination missing")?;
        if matches!(m["Type"].as_str(), Some("tmpfs" | "bind"))
            && tmpfs == 4
            && crate::native_job_storage::tmpfs_limits()
                .iter()
                .any(|(p, _, _)| *p == dest)
        {
            if !seen.insert(dest) || m["RW"] != true {
                return Err("bounded Native tmpfs repeated or readonly".into());
            }
            continue;
        }
        let expected = mounts.get(dest).ok_or("unexpected SDK mount")?;
        if !seen.insert(dest)
            || m["Type"] != "bind"
            || m["Source"] != expected.0
            || m["RW"] != expected.1
            || m["Propagation"] != "rprivate"
        {
            return Err("SDK bind source, permissions or propagation differs".into());
        }
    }
    let pid = if running {
        u32::try_from(
            value["State"]["Pid"]
                .as_u64()
                .ok_or("SDK init PID missing")?,
        )
        .ok()
        .filter(|p| *p > 1)
        .ok_or("SDK init PID invalid")?
    } else {
        0
    };
    Ok((id.into(), pid))
}
fn cleanup_task_identity(value: &Value, kernel: Option<&Value>) -> Result<Option<u32>, String> {
    let running = value["State"]["Running"]
        .as_bool()
        .ok_or("cleanup task running state unavailable")?;
    let pid = value["State"]["Pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("cleanup PID unavailable")?;
    if !running {
        return if pid == 0 {
            Ok(None)
        } else {
            Err("stopped cleanup container retains a live PID".into())
        };
    }
    let original =
        kernel.ok_or("running cleanup lacks original task identity; retain enforcement")?;
    if pid <= 1
        || original["pid"] != pid
        || original["start_ticks"].as_u64().is_none_or(|n| n == 0)
        || !original["cgroup"]
            .as_str()
            .is_some_and(|s| s.starts_with('/'))
    {
        return Err("cleanup task PID differs from retained container".into());
    }
    Ok(Some(pid))
}
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn check_retained_cleanup_task(
    value: &Value,
    kernel: Option<&Value>,
) -> Result<(), String> {
    let Some(pid) = cleanup_task_identity(value, kernel)? else {
        return Ok(());
    };
    let original = kernel.ok_or("original cleanup task unavailable")?;
    let held = crate::linux_process::HeldProcessRoot::open(pid)?;
    if held.observation()?["start_ticks"] != original["start_ticks"]
        || original["cgroup"] != held.cgroup()?
    {
        return Err("cleanup task start/cgroup differs from retained kernel identity".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_job_storage::{check_tmpfs, tmpfs_limits};
    #[test]
    fn cleanup_cannot_adopt_a_running_task_or_treat_a_live_pid_as_stopped() {
        let running = json!({"State":{"Running":true,"Pid":4312}});
        let original =
            json!({"pid":4312,"start_ticks":91234,"cgroup":"/machine.slice/libpod-original.scope"});
        assert_eq!(
            cleanup_task_identity(&running, Some(&original)).unwrap(),
            Some(4312)
        );
        assert!(cleanup_task_identity(&running, None).is_err());
        for (field, bad) in [
            ("pid", json!(4313)),
            ("start_ticks", json!(0)),
            ("cgroup", json!(null)),
        ] {
            let mut changed = original.clone();
            changed[field] = bad;
            assert!(
                cleanup_task_identity(&running, Some(&changed)).is_err(),
                "{field}"
            );
        }
        let stopped = json!({"State":{"Running":false,"Pid":0}});
        assert_eq!(cleanup_task_identity(&stopped, None).unwrap(), None);
        for state in [
            json!({"Running":false,"Pid":4312}),
            json!({"Pid":0}),
            json!({"Running":true,"Pid":1}),
        ] {
            assert!(cleanup_task_identity(&json!({"State":state}), Some(&original)).is_err());
        }
    }
    #[test]
    fn bounded_tmpfs_binds_cannot_borrow_another_job_scope_or_lose_protections() {
        let job = "0123456789abcdef";
        let mounts:Vec<_>=[("/tmp","tmp"),("/var/tmp","var-tmp"),("/run","run"),("/dev/shm","shm")]
            .into_iter().map(|(target,name)|json!({"Destination":target,"Type":"bind","RW":true,
                "Propagation":"rprivate","Source":format!("/var/lib/hol-gauntlet-rust/job-volumes/{job}/temporary/sdk/{name}")})).collect();
        let value = json!({"Config":{"Labels":{"hol.gauntlet.sdk.job":job}},"HostConfig":{"Tmpfs":{}},"Mounts":mounts});
        assert_eq!(check_tmpfs(&value).unwrap(), 4);
        for (field, bad) in [
            (
                "Source",
                json!("/var/lib/hol-gauntlet-rust/job-volumes/fedcba9876543210/temporary/sdk/tmp"),
            ),
            (
                "Source",
                json!(format!(
                    "/var/lib/hol-gauntlet-rust/job-volumes/{job}/temporary/mcp/tmp"
                )),
            ),
            ("RW", json!(false)),
            ("Propagation", json!("shared")),
            ("Type", json!("volume")),
        ] {
            let mut changed = value.clone();
            changed["Mounts"][0][field] = bad;
            assert!(check_tmpfs(&changed).is_err(), "{field}");
        }
        let mut missing = value.clone();
        missing["Mounts"].as_array_mut().unwrap().pop();
        assert!(check_tmpfs(&missing).is_err());
        let mut duplicate = value.clone();
        duplicate["Mounts"]
            .as_array_mut()
            .unwrap()
            .push(mounts[0].clone());
        assert!(check_tmpfs(&duplicate).is_err());
    }
    #[test]
    fn explicit_tmpfs_cannot_lose_either_capacity_or_a_mount() {
        let mut tmpfs = serde_json::Map::new();
        for (target, bytes, inodes) in tmpfs_limits() {
            tmpfs.insert(
                target.into(),
                json!(format!(
                    "rw,nosuid,nodev,noexec,size={bytes},nr_inodes={inodes},mode=1777"
                )),
            );
        }
        let value = json!({"HostConfig":{"Tmpfs":tmpfs}});
        assert_eq!(check_tmpfs(&value).unwrap(), 4);
        for (target, _, _) in tmpfs_limits() {
            for (from, to) in [
                ("nr_inodes=4096", "nr_inodes=0"),
                ("size=16777216", "size=0"),
                ("noexec", "exec"),
                ("nosuid", "suid"),
            ] {
                let mut altered = value.clone();
                let text = altered["HostConfig"]["Tmpfs"][target]
                    .as_str()
                    .unwrap()
                    .replace(from, to);
                if text == altered["HostConfig"]["Tmpfs"][target].as_str().unwrap() {
                    continue;
                }
                altered["HostConfig"]["Tmpfs"][target] = json!(text);
                assert!(check_tmpfs(&altered).is_err());
            }
            let mut missing = value.clone();
            missing["HostConfig"]["Tmpfs"]
                .as_object_mut()
                .unwrap()
                .remove(target);
            assert!(check_tmpfs(&missing).is_err());
        }
    }
    use serde_json::json;
    #[test]
    fn sdk_inspection_refuses_changed_owner_boundary_and_extra_mounts() {
        let name = "hol-sdk-example";
        let job = "a".repeat(16);
        let nonce = "b".repeat(32);
        let mounts = BTreeMap::from([("/runtime/bun".into(), ("/opt/bun".into(), false))]);
        let value = json!({"Id":"c".repeat(64),"Name":format!("/{name}"),"Image":NATIVE_SDK_AGENT_IMAGE,
            "Path":"/usr/bin/sleep","Args":["240"],"AppArmorProfile":name,"State":{"Running":true,"Pid":41},
            "Config":{"User":"10001:10001","WorkingDir":"/runtime/home/project","Labels":{"hol.gauntlet.sdk.job":job,
                "hol.gauntlet.sdk.nonce":nonce,"hol.gauntlet.sdk.profile":"native-sdk-transport-v1"}},
            "BoundingCaps":null,"EffectiveCaps":[],"HostConfig":{"Privileged":false,"ReadonlyRootfs":true,"NetworkMode":"none","Memory":2147483648_u64,
                "PidsLimit":256,"NanoCpus":2000000000_u64,"CpusetCpus":"0-1","CgroupParent":format!("holgauntletrust{job}.slice"),
                "CapAdd":[],"CapDrop":["CAP_ALL"],"SecurityOpt":["no-new-privileges",format!("apparmor={name}")]},
            "Mounts":[{"Destination":"/runtime/bun","Source":"/opt/bun","Type":"bind","RW":false,"Propagation":"rprivate"}]});
        assert!(check_inspection(&value, name, &job, &nonce, &mounts, true).is_ok());
        let mut legacy_tmpfs_display = value.clone();
        legacy_tmpfs_display["HostConfig"]["Tmpfs"] = json!({"/tmp":"rw,nosuid,nodev,size=65536k"});
        assert!(check_inspection(&legacy_tmpfs_display, name, &job, &nonce, &mounts, true).is_ok());
        assert!(check_mcp_inspection(&value, name, &job, &nonce, &mounts, true).is_err());
        let mut composed = value.clone();
        composed["Config"]["Labels"]["hol.gauntlet.sdk.profile"] =
            json!("native-sdk-mcp-transport-v1");
        assert!(check_mcp_inspection(&composed, name, &job, &nonce, &mounts, true).is_ok());
        assert!(check_live_inspection(&composed, name, &job, &nonce, &mounts, true).is_err());
        let mut live = composed.clone();
        live["Args"] =
            serde_json::json!([crate::native_live_spec::PREPARATION_SECONDS.to_string()]);
        assert!(check_live_inspection(&live, name, &job, &nonce, &mounts, true).is_ok());
        assert!(check_mcp_inspection(&live, name, &job, &nonce, &mounts, true).is_err());
        live["HostConfig"]["NetworkMode"] = serde_json::json!("host");
        assert!(check_live_inspection(&live, name, &job, &nonce, &mounts, true).is_err());
        assert!(check_inspection(&composed, name, &job, &nonce, &mounts, true).is_err());
        composed["Mounts"][0]["RW"] = json!(true);
        assert!(check_mcp_inspection(&composed, name, &job, &nonce, &mounts, true).is_err());
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
            ("/Config/Labels/hol.gauntlet.sdk.nonce", json!("changed")),
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
