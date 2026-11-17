//! A new v7 profile cannot release its controller before the host pin ack.
use crate::controller_key::{
    pin_controller_key_under_lease, require_pinned_controller_key_under_lease, ControllerKeyPin,
    SealedControllerKey,
};
use crate::{ActiveLease, BoottimeDeadline, NativeJobSpec, RunReservationJournal, StartedMarker};
use gauntlet_contracts::{PrelaunchPrepared, WorkerRequest};
use gauntlet_evidence::{
    verify_native_control_envelope, AuthenticatedNativeControlReport, NativeControlReportPins,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    os::fd::OwnedFd,
    sync::atomic::{AtomicBool, Ordering},
};

pub(crate) type NativeHostAck<'a> =
    dyn FnMut(&[u8], &BoottimeDeadline, &AtomicBool) -> Result<Vec<u8>, String> + 'a;

pub(crate) struct NativeSigningCustody {
    key: SealedControllerKey,
    pin: ControllerKeyPin,
    pub pins: NativeControlReportPins,
    acknowledgement_sha256: String,
}
impl NativeSigningCustody {
    pub fn descriptor(&self) -> &File {
        self.key.fd()
    }
    pub fn pin_sha256(&self) -> &str {
        &self.pin.raw_sha256
    }
    pub fn recheck(
        &self,
        journal: &RunReservationJournal,
        lease: &ActiveLease,
        started: &StartedMarker,
    ) -> Result<(), String> {
        require_pinned_controller_key_under_lease(journal, lease, started, &self.pin)
            .map_err(|e| e.to_string())
    }
    pub fn authenticate(&self, raw: &[u8]) -> Result<AuthenticatedNativeControlReport, String> {
        verify_native_control_envelope(raw, &self.pins).map_err(|e| e.to_string())
    }
    pub fn observation(&self) -> Result<Value, String> {
        Ok(json!({"schema":"hol-gauntlet-native-prelaunch-custody.v1",
            "prepared":serde_json::from_slice::<Value>(&self.pins.prelaunch.to_bytes().map_err(|e|e.to_string())?).map_err(|e|e.to_string())?,
            "acknowledgement_sha256":self.acknowledgement_sha256,"host_ack_received_before_controller_spawn":true,
            "independent_effects_scored":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}))
    }
}

pub(crate) fn reserve_native(
    journal: &RunReservationJournal,
    lease: &ActiveLease,
    request: &WorkerRequest,
    spec: &NativeJobSpec,
    deadline: &BoottimeDeadline,
    cancellation: &AtomicBool,
    acknowledge: Option<&mut NativeHostAck<'_>>,
) -> Result<(StartedMarker, Option<NativeSigningCustody>), String> {
    if spec.requires_host_pin() != acknowledge.is_some() {
        return Err("native job and explicit host-pinned execution mode differ".into());
    }
    let deployment = request
        .deployment_digest()
        .ok_or("native deployment required")?;
    let Some(acknowledge) = acknowledge else {
        return journal
            .reserve_under_lease(
                lease,
                request,
                &spec.source_sha,
                deployment,
                &spec.worker_generation,
            )
            .map(|started| (started, None))
            .map_err(|e| e.to_string());
    };
    if cancellation.load(Ordering::Acquire)
        || deadline.remaining().map_err(|e| e.to_string())?.is_zero()
    {
        return Err("native host-pinned launch expired or cancelled before reservation".into());
    }
    let key = SealedControllerKey::generate().map_err(|e| e.to_string())?;
    let started = journal
        .reserve_keyed_under_lease(
            lease,
            request,
            &spec.source_sha,
            deployment,
            &spec.worker_generation,
            key.public_key_hex(),
        )
        .map_err(|e| e.to_string())?;
    let pin = pin_controller_key_under_lease(journal, lease, &started, &key)
        .map_err(|e| e.to_string())?;
    let prepared = PrelaunchPrepared {
        job_id: spec.job_id.clone(),
        source_sha: spec.source_sha.clone(),
        deployment_digest: deployment.into(),
        worker_generation: spec.worker_generation.clone(),
        started_marker_sha256: started.sha256.clone(),
        controller_key_pin_sha256: pin.raw_sha256.clone(),
        controller_public_key_hex: pin.public_key_hex.clone(),
    };
    let raw = prepared.to_bytes().map_err(|e| e.to_string())?;
    let ack = acknowledge(&raw, deadline, cancellation)?;
    prepared
        .verify_acknowledgement(&ack)
        .map_err(|e| e.to_string())?;
    if cancellation.load(Ordering::Acquire)
        || deadline.remaining().map_err(|e| e.to_string())?.is_zero()
    {
        return Err("native host-pinned launch expired or cancelled after acknowledgement".into());
    }
    let custody = NativeSigningCustody {
        key,
        pin,
        pins: NativeControlReportPins {
            prelaunch: prepared,
            preparation_sha256: spec.preparation_sha256.clone(),
            role: spec.case().into(),
        },
        acknowledgement_sha256: format!("{:x}", Sha256::digest(&ack)),
    };
    custody.recheck(journal, lease, &started)?;
    Ok((started, Some(custody)))
}

pub(crate) const READONLY_FAILURE_PREFIX: &str = "hol-gauntlet-native-readonly-failure";
const FIELDS: [&str; 9] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "original_worker_generation",
    "preparation_sha256",
    "storage_receipt_sha256",
    "terminal_sha256",
    "report_sha256",
    "reader_generation",
];
pub(crate) struct ReadonlyFailurePins(pub(crate) Value);
impl ReadonlyFailurePins {
    pub(crate) fn new(args: &[String]) -> Result<Self, String> {
        let mut v = serde_json::Map::new();
        for (key, raw) in FIELDS.into_iter().zip(&args[2..11]) {
            let n = match key {
                "source_sha" => 40,
                "job_id" => 16,
                _ => 64,
            };
            if !crate::hex(raw, n) {
                return Err("exact original unsigned-failure pins required".into());
            }
            v.insert(key.into(), json!(raw));
        }
        Ok(Self(Value::Object(v)))
    }
    pub(crate) fn text(&self, key: &str) -> &str {
        self.0[key].as_str().unwrap_or("")
    }
    pub(crate) fn body(&self, suffix: &str) -> Value {
        let mut v = self.0.clone();
        v["schema"] = json!(format!("{READONLY_FAILURE_PREFIX}-{suffix}.v1"));
        v
    }
    pub(crate) fn slot(&self) -> Result<std::os::fd::OwnedFd, String> {
        let root = crate::open_root_owned_public_directory(std::path::Path::new(
            crate::native_job_storage::lifecycle::BASE,
        ))
        .map_err(|e| e.to_string())?;
        crate::feature_files::open_directory(&root, self.text("job_id"), (0, 0))
    }
}
pub(crate) fn failure_read(
    root: &std::os::fd::OwnedFd,
    name: &str,
) -> Result<Option<Value>, String> {
    crate::feature_files::read(root, name, (0, 0), 0o600, 49152)?
        .map(|raw| {
            let v: Value =
                serde_json::from_slice(&raw).map_err(|_| "unsigned-failure metadata JSON")?;
            if crate::native_job_storage::linux::canonical(&v)? != raw {
                return Err("canonical unsigned-failure metadata required".into());
            }
            Ok(v)
        })
        .transpose()
}
pub(crate) fn failure_required(root: &std::os::fd::OwnedFd, name: &str) -> Result<Value, String> {
    failure_read(root, name)?.ok_or_else(|| format!("original unsigned-failure {name} absent"))
}
pub(crate) fn failure_wrap(suffix: &str, body: Value) -> Result<Value, String> {
    crate::native_job_storage::artifact::failure_wrapper(
        &format!("{READONLY_FAILURE_PREFIX}-{suffix}-result.v1"),
        body,
    )
}
pub(crate) fn failure_prepared(
    raw: &[u8],
    p: &ReadonlyFailurePins,
) -> Result<PrelaunchPrepared, String> {
    let v = PrelaunchPrepared::parse(raw).map_err(|e| e.to_string())?;
    if v.source_sha != p.text("source_sha")
        || v.job_id != p.text("job_id")
        || v.deployment_digest != p.text("deployment_digest")
        || v.worker_generation != p.text("original_worker_generation")
    {
        return Err("unsigned-failure original prelaunch differs".into());
    }
    Ok(v)
}
pub(crate) fn failure_retained_prelaunch(
    root: &std::os::fd::OwnedFd,
    p: &ReadonlyFailurePins,
) -> Result<PrelaunchPrepared, String> {
    failure_prepared(
        &crate::native_job_storage::linux::canonical(&failure_required(
            root,
            "readonly-failure-prelaunch.json",
        )?)?,
        p,
    )
}
pub(crate) fn failure_intent(
    p: &ReadonlyFailurePins,
    pre: &PrelaunchPrepared,
) -> Result<Value, String> {
    let mut v = p.body("export-intent");
    v["prelaunch"] = serde_json::from_slice(&pre.to_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(v)
}

pub(crate) const READONLY_FAILURE_ARCHIVE_LIMIT: usize = 32 * 1024 * 1024 + 65536;
pub(crate) fn failure_export_body(
    p: &ReadonlyFailurePins,
    raw: &[u8],
    m: &Value,
) -> Result<Value, String> {
    let mut v = p.body("export");
    v["archive_sha256"] = json!(crate::native_job_storage::linux::sha(raw));
    v["archive_bytes"] = json!(raw.len());
    v["manifest_sha256"] = json!(crate::native_job_storage::linux::sha(
        &crate::native_job_storage::linux::canonical(m)?
    ));
    v["exit_code"] = m["exit_code"].clone();
    v["execution_eligible"] = json!(false);
    v["qualification_eligible"] = json!(false);
    failure_wrap("export", v)
}
pub(crate) fn failure_retained_export(
    p: &ReadonlyFailurePins,
    root: &OwnedFd,
) -> Result<Value, String> {
    let pre = failure_retained_prelaunch(root, p)?;
    if failure_required(root, "readonly-failure-intent.json")? != failure_intent(p, &pre)? {
        return Err("original unsigned failure intent changed".into());
    }
    let v = failure_required(root, "readonly-failure-export.json")?;
    let r = &v["receipt"];
    let m = failure_required(root, "readonly-failure-manifest.json")?;
    let mut expected = p.body("export");
    for key in ["archive_sha256", "archive_bytes"] {
        expected[key] = r[key].clone();
    }
    expected["manifest_sha256"] = json!(crate::native_job_storage::linux::sha(
        &crate::native_job_storage::linux::canonical(&m)?
    ));
    expected["exit_code"] = m["exit_code"].clone();
    expected["execution_eligible"] = json!(false);
    expected["qualification_eligible"] = json!(false);
    let initial = failure_required(root, "readonly-failure-initialization.json")?;
    if v != failure_wrap("export", expected)?
        || !crate::hex(r["archive_sha256"].as_str().unwrap_or(""), 64)
        || !r["archive_bytes"]
            .as_u64()
            .is_some_and(|n| (1..=READONLY_FAILURE_ARCHIVE_LIMIT as u64).contains(&n))
        || initial["source_sha"] != p.0["source_sha"]
        || initial["job_id"] != p.0["job_id"]
        || initial["worker_generation"] != p.0["original_worker_generation"]
        || initial["storage"]["receipt_sha256"] != p.0["storage_receipt_sha256"]
    {
        return Err("original unsigned failure export changed".into());
    }
    Ok(v)
}

pub(crate) const LIVE_FAILURE_PREFIX: &str = "hol-gauntlet-native-live-failure";
pub(crate) const LIVE_FAILURE_FIELDS: [&str; 11] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "original_worker_generation",
    "preparation_sha256",
    "storage_receipt_sha256",
    "live_prepared_sha256",
    "created_repair_sha256",
    "repair_sha256",
    "signed_envelope_sha256",
    "reader_generation",
];
pub(crate) struct LiveFailurePins(pub(crate) Value);
impl LiveFailurePins {
    pub(crate) fn new(args: &[String], observe: bool) -> Result<Self, String> {
        let mut p = serde_json::Map::new();
        let fields = LIVE_FAILURE_FIELDS
            .into_iter()
            .filter(|k| !observe || *k != "signed_envelope_sha256");
        for (k, v) in fields.zip(&args[2..]) {
            if !crate::hex(
                v,
                if k == "source_sha" {
                    40
                } else if k == "job_id" {
                    16
                } else {
                    64
                },
            ) {
                return Err("original signed Live failure pins required".into());
            }
            p.insert(k.into(), json!(v));
        }
        Ok(Self(Value::Object(p)))
    }
    pub(crate) fn text(&self, k: &str) -> &str {
        self.0[k].as_str().unwrap_or("")
    }
    pub(crate) fn body(&self, suffix: &str) -> Value {
        let mut p = self.0.clone();
        p["schema"] = json!(format!("{LIVE_FAILURE_PREFIX}-{suffix}.v1"));
        p
    }
    pub(crate) fn slot(&self) -> Result<OwnedFd, String> {
        let parent = crate::open_root_owned_public_directory(std::path::Path::new(
            crate::native_job_storage::lifecycle::BASE,
        ))
        .map_err(|e| e.to_string())?;
        crate::feature_files::open_directory(&parent, self.text("job_id"), (0, 0))
    }
    pub(crate) fn prepared(&self, raw: &[u8]) -> Result<PrelaunchPrepared, String> {
        let pre = PrelaunchPrepared::parse(raw).map_err(|e| e.to_string())?;
        if pre.source_sha != self.text("source_sha")
            || pre.job_id != self.text("job_id")
            || pre.deployment_digest != self.text("deployment_digest")
            || pre.worker_generation != self.text("original_worker_generation")
        {
            return Err("original Live failure prelaunch differs".into());
        }
        Ok(pre)
    }
    pub(crate) fn intent(&self, pre: &PrelaunchPrepared) -> Result<Value, String> {
        let mut v = self.body("export-intent");
        v["prelaunch"] = serde_json::from_slice(&pre.to_bytes().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(v)
    }
}
pub(crate) fn live_failure_wrap(suffix: &str, body: Value) -> Result<Value, String> {
    crate::native_job_storage::artifact::failure_wrapper(
        &format!("{LIVE_FAILURE_PREFIX}-{suffix}-result.v1"),
        body,
    )
}
pub(crate) fn live_failure_export(
    p: &LiveFailurePins,
    raw: &[u8],
    m: &Value,
) -> Result<Value, String> {
    let mut v = p.body("export");
    v["archive_sha256"] = json!(crate::native_job_storage::linux::sha(raw));
    v["archive_bytes"] = json!(raw.len());
    v["manifest_sha256"] = json!(crate::native_job_storage::linux::sha(
        &crate::native_job_storage::linux::canonical(m)?
    ));
    for (k, vv) in [
        ("exit_code", Value::Null),
        ("model_requests", Value::Null),
        ("execution_eligible", json!(false)),
        ("qualification_eligible", json!(false)),
    ] {
        v[k] = vv;
    }
    live_failure_wrap("export", v)
}

#[cfg(test)]
#[path = "native_prelaunch_tests.rs"]
mod tests;
