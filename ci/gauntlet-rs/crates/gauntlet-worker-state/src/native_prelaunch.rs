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

#[cfg(test)]
#[path = "native_prelaunch_tests.rs"]
mod tests;
