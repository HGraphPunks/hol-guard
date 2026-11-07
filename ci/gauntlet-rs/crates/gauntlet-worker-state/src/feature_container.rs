//! Fixed feature container and exact full-ID/intent-label teardown. A name
//! collision never authorizes deleting another container.
use crate::builder_run_plan::BuilderRunPlan;
use crate::dependency_podman::run;
use crate::feature_files as files;
use gauntlet_contracts::FeatureRunIntent;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

pub(crate) fn job_root(audit: &str) -> String {
    format!("/var/lib/hol-gauntlet-rust/feature-jobs/{audit}")
}
fn arguments(intent: &FeatureRunIntent) -> Result<Vec<String>, String> {
    let p = intent.pins();
    let id = p.audit_id();
    let spec = p.spec();
    let root = job_root(id);
    let build = format!("/var/lib/hol-gauntlet/builds/{}", p.text("build_job_id"));
    let mut args = vec![
        "create".into(),
        "--pull=never".into(),
        "--name".into(),
        format!("hol-gauntlet-build-{id}"),
        "--label".into(),
        format!("hol-gauntlet.feature-intent={}", intent.digest()?),
        "--user=65532:65532".into(),
        "--cap-drop=ALL".into(),
        "--security-opt=no-new-privileges".into(),
        format!("--security-opt=apparmor=hol-gauntlet-build-{id}"),
        "--memory=12g".into(),
        "--memory-swap=12g".into(),
        "--cpus=2".into(),
        "--pids-limit=2048".into(),
        "--network=slirp4netns".into(),
        "--ipc=private".into(),
        "--cgroup-parent=system.slice".into(),
        "--entrypoint=/input/gauntlet-feature-executor".into(),
    ];
    for (source, target) in [
        (format!("{build}/source.tar.gz"), "/input/source.tar.gz"),
        (format!("{build}/candidate.zip"), "/input/candidate.zip"),
        (
            format!("{root}/feature-spec.json"),
            "/input/feature-spec.json",
        ),
        (
            crate::feature_assets::path("executor", spec.text("executor_sha256"))?,
            "/input/gauntlet-feature-executor",
        ),
        (
            crate::feature_assets::path("node", spec.text("node_sha256"))?,
            "/usr/local/bin/node",
        ),
    ] {
        args.extend(["--volume".into(), format!("{source}:{target}:ro")]);
    }
    args.extend([
        "--volume".into(),
        format!("{root}/export:/output:rw"),
        p.text("builder_image_id").into(),
        spec.digest(),
    ]);
    Ok(args)
}
pub(crate) fn validated_identity(v: &Value, intent: &FeatureRunIntent) -> Result<String, String> {
    let p = intent.pins();
    let id = p.audit_id();
    let cid = v["Id"]
        .as_str()
        .filter(|s| crate::hex(s, 64))
        .ok_or("full feature CID required")?;
    let image = v["Image"].as_str().is_some_and(|s| {
        s.trim_start_matches("sha256:") == p.text("builder_image_id").trim_start_matches("sha256:")
    });
    if v["Name"] != format!("hol-gauntlet-build-{id}")
        || !image
        || v["Config"]["Labels"]["hol-gauntlet.feature-intent"] != intent.digest()?
        || v["Config"]["User"] != "65532:65532"
        || v["HostConfig"]["Privileged"] != false
        || v["HostConfig"]["Memory"] != 12884901888u64
        || v["HostConfig"]["MemorySwap"] != 12884901888u64
        || v["HostConfig"]["PidsLimit"] != 2048
        || v["HostConfig"]["CpuQuota"] != 200000
        || v["HostConfig"]["CpuPeriod"] != 100000
    {
        return Err("feature container identity or limits differ from intent".into());
    }
    if v["HostConfig"]["NetworkMode"] != "slirp4netns"
        || v["HostConfig"]["IpcMode"] != "private"
        || v["HostConfig"]["SecurityOpt"]
            != json!([
                "no-new-privileges",
                format!("apparmor=hol-gauntlet-build-{id}")
            ])
    {
        return Err("feature container security options differ".into());
    }
    Ok(cid.into())
}
pub(crate) struct FeatureContainer<'a> {
    intent: &'a FeatureRunIntent,
    cid: Option<String>,
}
impl<'a> FeatureContainer<'a> {
    pub(crate) fn new(intent: &'a FeatureRunIntent) -> Self {
        Self { intent, cid: None }
    }
    fn pin(&self) -> &str {
        self.intent.pins().text("podman_sha256")
    }
    pub(crate) fn id(&self) -> Option<&str> {
        self.cid.as_deref()
    }
    fn identity(&self) -> Result<Option<String>, String> {
        let id = self.intent.pins().audit_id();
        let by_name =
            crate::builder_candidate_process::container_absent(id).map_err(|e| e.to_string())?;
        let by_id = self
            .cid
            .as_deref()
            .map(crate::builder_candidate_process::container_id_absent)
            .transpose()
            .map_err(|e| e.to_string())?
            .unwrap_or(true);
        if by_name && by_id {
            return Ok(None);
        }
        let target = self
            .cid
            .clone()
            .unwrap_or_else(|| format!("hol-gauntlet-build-{id}"));
        let raw = run(self.pin(), &["container".into(), "inspect".into(), target])?;
        let v: Value = serde_json::from_slice(&raw).map_err(|_| "feature inspect JSON")?;
        let row = v
            .as_array()
            .filter(|v| v.len() == 1)
            .and_then(|v| v.first())
            .ok_or("one feature container required")?;
        let observed = validated_identity(row, self.intent)?;
        if self.cid.as_ref().is_some_and(|id| id != &observed) {
            return Err("feature full CID changed".into());
        }
        Ok(Some(observed))
    }
    pub(crate) fn create(&mut self, slot: &std::os::fd::OwnedFd) -> Result<BuilderRunPlan, String> {
        if self.identity()?.is_some() {
            return Err("feature container already exists".into());
        }
        let result = run(self.pin(), &arguments(self.intent)?);
        self.cid = self.identity()?;
        let raw = result?;
        let reported = std::str::from_utf8(&raw)
            .map_err(|_| "feature CID UTF-8")?
            .trim();
        if self.cid.as_deref() != Some(reported) {
            return Err("feature create/inspect CID differ".into());
        }
        self.retain_identity(slot)?;
        Ok(BuilderRunPlan {
            argv: vec![
                "/usr/bin/podman".into(),
                "start".into(),
                "--attach".into(),
                reported.into(),
            ],
            job_id: self.intent.pins().audit_id().into(),
            source_archive_sha256: self
                .intent
                .pins()
                .spec()
                .text("source_archive_sha256")
                .into(),
            execution_eligible: false,
        })
    }
    fn retain_identity(&self, slot: &std::os::fd::OwnedFd) -> Result<(), String> {
        let cid = self
            .cid
            .as_deref()
            .ok_or("feature container identity missing")?;
        let body = json!({"schema":"hol-gauntlet-native-feature-container.v1","container_id":cid,"intent_sha256":self.intent.digest()?});
        let bytes = gauntlet_contracts::canonicalize(body.to_string().as_bytes())
            .map_err(|e| e.to_string())?;
        files::write(slot, "feature-container.v1.json", &bytes, (0, 0), 0o600)?;
        Ok(())
    }
    /// Recover the create/receipt gap only through a complete intent-labeled
    /// inspect. Preserve its full CID before any removal, never just the name.
    pub(crate) fn pin_repair_identity(
        &mut self,
        slot: Option<&std::os::fd::OwnedFd>,
    ) -> Result<(), String> {
        let observed = self.identity()?;
        if self.cid.is_none() {
            if let Some(cid) = observed {
                let slot = slot.ok_or("feature container lacks retained private job slot")?;
                self.cid = Some(cid);
                self.retain_identity(slot)?;
            }
        }
        Ok(())
    }
    pub(crate) fn restore(
        intent: &'a FeatureRunIntent,
        slot: Option<&std::os::fd::OwnedFd>,
    ) -> Result<Self, String> {
        let mut result = Self::new(intent);
        if let Some(slot) = slot {
            if let Some(raw) = files::read(slot, "feature-container.v1.json", (0, 0), 0o600, 2048)?
            {
                let v = crate::feature_journal::canonical(&raw)?;
                if v.as_object().is_none_or(|v| v.len() != 3)
                    || v["schema"] != "hol-gauntlet-native-feature-container.v1"
                    || v["intent_sha256"] != intent.digest()?
                    || !v["container_id"]
                        .as_str()
                        .is_some_and(|s| crate::hex(s, 64))
                {
                    return Err("feature CID receipt differs".into());
                }
                result.cid = v["container_id"].as_str().map(str::to_owned);
            }
        }
        Ok(result)
    }
    pub(crate) fn drain(&mut self) -> Result<(), String> {
        if let Some(cid) = self.identity()? {
            self.cid = Some(cid.clone());
            run(
                self.pin(),
                &["rm".into(), "--force".into(), "--time=5".into(), cid],
            )?;
        }
        if self.identity()?.is_some() {
            return Err("feature container survived cleanup".into());
        }
        if let Some(cid) = &self.cid {
            cgroup_absent(cid, true)?;
        }
        Ok(())
    }
}
fn cgroup_absent(cid: &str, wait: bool) -> Result<(), String> {
    let path = format!("/sys/fs/cgroup/system.slice/libpod-{cid}.scope");
    let start = Instant::now();
    loop {
        match std::fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Ok(_) if wait && start.elapsed() < Duration::from_secs(10) => {
                std::thread::sleep(Duration::from_millis(25))
            }
            _ => return Err("feature container cgroup absence uncertain".into()),
        }
    }
}
pub(crate) fn completed_absent(intent: &FeatureRunIntent, cid: Option<&str>) -> Result<(), String> {
    crate::builder_candidate_preflight::verify_file(
        "/usr/bin/podman",
        intent.pins().text("podman_sha256"),
        true,
        64 * 1024 * 1024,
    )
    .map_err(|e| e.to_string())?;
    if !crate::builder_candidate_process::container_absent(intent.pins().audit_id())
        .map_err(|e| e.to_string())?
    {
        return Err("feature container name exists".into());
    }
    if let Some(cid) = cid {
        if !crate::hex(cid, 64)
            || !crate::builder_candidate_process::container_id_absent(cid)
                .map_err(|e| e.to_string())?
        {
            return Err("feature full CID exists or differs".into());
        }
        cgroup_absent(cid, false)?;
    }
    crate::feature_state::client_absent(intent.pins().audit_id())?;
    if !crate::builder_policy::profile_absent(&format!(
        "hol-gauntlet-build-{}",
        intent.pins().audit_id()
    ))
    .map_err(|e| e.to_string())?
    {
        return Err("feature profile absence uncertain".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_full_intent_bound_unprivileged_container_can_be_owned() {
        let intent = crate::feature_journal::tests::fixture();
        let p = intent.pins();
        let id = p.audit_id();
        // Shape and resource values independently observed in the retained
        // 5803 Podman inspect, with this test's synthetic identity substituted.
        let v = json!({"Id":"c".repeat(64),"Name":format!("hol-gauntlet-build-{id}"),
            "Image":p.text("builder_image_id"),"Config":{"User":"65532:65532",
                "Labels":{"hol-gauntlet.feature-intent":intent.digest().unwrap()}},
            "HostConfig":{"Privileged":false,"Memory":12884901888u64,
                "MemorySwap":12884901888u64,"PidsLimit":2048,"CpuQuota":200000,"CpuPeriod":100000,
                "NetworkMode":"slirp4netns","IpcMode":"private",
                "SecurityOpt":["no-new-privileges",format!("apparmor=hol-gauntlet-build-{id}")]}});
        assert_eq!(validated_identity(&v, &intent).unwrap(), "c".repeat(64));
        for (pointer, wrong) in [
            ("/Id", json!("c".repeat(12))),
            ("/Name", json!("other")),
            ("/Image", json!(format!("sha256:{}", "d".repeat(64)))),
            ("/Config/User", json!("0:0")),
            (
                "/Config/Labels/hol-gauntlet.feature-intent",
                json!("e".repeat(64)),
            ),
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/PidsLimit", json!(512)),
            ("/HostConfig/Memory", json!(0)),
            ("/HostConfig/CpuQuota", json!(400000)),
            ("/HostConfig/SecurityOpt", json!([])),
            ("/HostConfig/NetworkMode", json!("host")),
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = wrong;
            assert!(validated_identity(&changed, &intent).is_err(), "{pointer}");
        }
    }
}
