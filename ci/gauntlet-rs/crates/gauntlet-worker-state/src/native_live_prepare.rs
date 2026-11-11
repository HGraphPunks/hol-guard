//! Immutable live-only preparation. Root seeds never enter public receipts or
//! candidate mounts; only the World seed crosses the controller exec, sealed.
use crate::native_job_spec::NativeJobExecution;
use crate::{NativeJobSpec, NativeMcpWorld, RunReservationJournal};
use gauntlet_contracts::{canonicalize, WorkerRequest};
use ring::{
    rand::{SecureRandom, SystemRandom},
    signature::{Ed25519KeyPair, KeyPair},
};
use rustix::fs::{fsync, openat, Mode, OFlags};
use serde_json::{json, Value};
use std::{os::fd::OwnedFd, path::Path};

pub struct NativeLivePreparationPins<'a> {
    pub source_sha: &'a str,
    pub job_id: &'a str,
    pub deployment_digest: &'a str,
    pub worker_generation: &'a str,
    pub preparation_sha256: &'a str,
    pub spec_sha256: &'a str,
}
pub(crate) struct LivePrepared {
    pub raw: Vec<u8>,
    pub value: Value,
    pub database: Value,
    private: OwnedFd,
}
fn sha(raw: &[u8]) -> String {
    crate::native_live_model::sha(raw)
}
fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())
}
fn pair(raw: &[u8]) -> Result<Ed25519KeyPair, String> {
    Ed25519KeyPair::from_seed_unchecked(raw).map_err(|_| "live Root signing seed invalid".into())
}
fn public(key: &Ed25519KeyPair) -> String {
    key.public_key()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn seed(root: &OwnedFd, name: &str) -> Result<Ed25519KeyPair, String> {
    let mut raw = crate::feature_files::required(root, name, (0, 0), 0o600, 32)?;
    let value = pair(&raw);
    raw.fill(0);
    value
}
pub(crate) fn source_spec(live: &crate::NativeLiveJob) -> Result<Value, String> {
    let spec = gauntlet_evidence::feature_ai_support_spec().map_err(|e| e.to_string())?;
    if spec["execution_budget"]
        != json!({"episode_seconds":crate::native_live_spec::EPISODE_SECONDS,
        "preparation_wall_seconds":crate::native_live_spec::PREPARATION_SECONDS,"worker_active_seconds":crate::native_live_spec::ACTIVE_SECONDS})
    {
        return Err("live source-selected execution budget differs from worker profile".into());
    }
    if sha(&bytes(&spec)?) != live.spec_sha256 {
        return Err("live OMP spec differs from outside source-selected pin".into());
    }
    Ok(spec)
}
fn normal_receipt(job: &NativeJobSpec) -> Result<Vec<u8>, String> {
    let root = crate::open_root_owned_public_directory(Path::new(
        "/var/lib/hol-gauntlet-rust/native-initialization",
    ))
    .map_err(|e| e.to_string())?;
    crate::feature_files::required(
        &root,
        &format!("{}.preparation.json", job.job_id),
        (0, 0),
        0o600,
        8192,
    )
}
fn live(job: &NativeJobSpec) -> Result<&crate::NativeLiveJob, String> {
    match &job.execution {
        NativeJobExecution::HostPinnedLive { live, .. } => Ok(live),
        _ => Err("explicit live OMP profile required".into()),
    }
}
pub(crate) fn retained(job: &NativeJobSpec, deployment: &str) -> Result<LivePrepared, String> {
    let live = live(job)?;
    source_spec(live)?;
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let private = crate::feature_files::open_directory(&root, "live-private", (0, 0))?;
    let raw = crate::feature_files::required(&private, "prepared.json", (0, 0), 0o600, 8192)?;
    let custody_raw =
        crate::feature_files::required(&private, "custody.json", (0, 0), 0o600, 8192)?;
    if canonicalize(&raw).map_err(|_| "live preparation JSON invalid")? != raw
        || canonicalize(&custody_raw).map_err(|_| "live custody JSON invalid")? != custody_raw
    {
        return Err("canonical live preparation/custody required".into());
    }
    let value: Value = serde_json::from_slice(&raw).map_err(|_| "live preparation JSON invalid")?;
    let custody: Value =
        serde_json::from_slice(&custody_raw).map_err(|_| "live custody JSON invalid")?;
    if value.as_object().is_none_or(|o| o.len() != 13)
        || value["schema"] != "hol-gauntlet-native-live-prepared.v2"
        || value["source_sha"] != job.source_sha
        || value["job_id"] != job.job_id
        || value["deployment_digest"] != deployment
        || value["worker_generation"] != job.worker_generation
        || value["preparation_sha256"] != job.preparation_sha256
        || value["normal_preparation_receipt_sha256"] != sha(&normal_receipt(job)?)
        || value["role"] != live.role()
        || value["cell_id"] != live.cell_id
        || value["spec_sha256"] != live.spec_sha256
        || [
            "world_public_key_hex",
            "world_initial_sha256",
            "cleanup_public_key_hex",
        ]
        .iter()
        .any(|n| value[*n].as_str().is_none_or(|s| !crate::hex(s, 64)))
        || custody.as_object().is_none_or(|o| o.len() != 3)
        || custody["schema"] != "hol-gauntlet-native-live-custody.v1"
        || custody["prepared_sha256"] != sha(&raw)
    {
        return Err(
            "retained live preparation differs from exact job/deployment/source pins".into(),
        );
    }
    Ok(LivePrepared {
        raw,
        value,
        database: custody["database"].clone(),
        private,
    })
}
impl LivePrepared {
    pub(crate) fn world_handoff(
        &self,
    ) -> Result<crate::controller_key::SealedControllerKey, String> {
        let mut raw =
            crate::feature_files::required(&self.private, "world.seed", (0, 0), 0o600, 32)?;
        let result = (|| {
            let seed: &[u8; 32] = raw
                .as_slice()
                .try_into()
                .map_err(|_| "complete live World seed required")?;
            let key = crate::controller_key::SealedControllerKey::from_seed(seed)
                .map_err(|e| e.to_string())?;
            if self.value["world_public_key_hex"] != key.public_key_hex() {
                return Err("live World seed differs from retained outside pin".into());
            }
            Ok(key)
        })();
        raw.fill(0);
        result
    }
    pub(crate) fn open_world(
        &self,
        job: &NativeJobSpec,
        key: Ed25519KeyPair,
    ) -> Result<NativeMcpWorld, String> {
        if self.value["world_public_key_hex"] != public(&key) {
            return Err("live World key differs from preparation pin".into());
        }
        NativeMcpWorld::open_prepared(&job.job_id, key, &self.database)
    }
    pub(crate) fn cleanup_key(&self) -> Result<Ed25519KeyPair, String> {
        let key = seed(&self.private, "cleanup.seed")?;
        if self.value["cleanup_public_key_hex"] != public(&key) {
            return Err("live cleanup seed differs from retained outside pin".into());
        }
        Ok(key)
    }
}

pub fn prepare_native_live_omp(
    pins: &NativeLivePreparationPins<'_>,
    publish: bool,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(pins.worker_generation).map_err(|e| e.to_string())?;
    if !crate::hex(pins.source_sha, 40)
        || !crate::hex(pins.job_id, 16)
        || [
            pins.deployment_digest,
            pins.worker_generation,
            pins.preparation_sha256,
            pins.spec_sha256,
        ]
        .iter()
        .any(|s| !crate::hex(s, 64))
    {
        return Err("exact outside live preparation pins required".into());
    }
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","source_sha":pins.source_sha,"job_id":pins.job_id,"deployment_digest":pins.deployment_digest}).to_string().as_bytes()).map_err(|e|e.to_string())?;
    let (job, preparation) = crate::native_job_io::load(&request, pins.worker_generation)?;
    let live = live(&job)?;
    if job.preparation_sha256 != pins.preparation_sha256 || live.spec_sha256 != pins.spec_sha256 {
        return Err("live preparation differs from original deployment".into());
    }
    let spec = source_spec(live)?;
    if publish {
        crate::native_job_io::require_no_unknown_jobs(&journal)?;
        crate::dependency_state::require_idle()?;
        if journal
            .started(
                pins.job_id,
                pins.source_sha,
                pins.deployment_digest,
                pins.worker_generation,
            )
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("consumed live job cannot prepare again".into());
        }
        gauntlet_cell_rootfs::require_image_lease_absent(
            &preparation.image_id,
            &preparation.podman_sha256,
        )?;
        crate::require_rust_job_slice_absent(&job.job_id).map_err(|e| e.to_string())?;
        crate::native_initialize::job_initialization(
            pins.source_sha,
            pins.job_id,
            pins.worker_generation,
        )?;
        let root =
            crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
        let private = crate::feature_files::directory(&root, "live-private", (0, 0), true)?;
        let mut keys = Vec::new();
        for name in ["world.seed", "cleanup.seed"] {
            let mut raw = [0; 32];
            SystemRandom::new()
                .fill(&mut raw)
                .map_err(|_| "fresh live Root key unavailable")?;
            let key = pair(&raw)?;
            let written = crate::feature_files::write(&private, name, &raw, (0, 0), 0o600);
            raw.fill(0);
            written?;
            keys.push(key);
        }
        let cleanup_public = public(&keys.pop().unwrap());
        let world_key = keys.pop().unwrap();
        let world_public = public(&world_key);
        let initial = bytes(&crate::native_live_spec::initial_snapshot(&spec)?)?;
        let mut world = NativeMcpWorld::new(
            &job.job_id,
            std::str::from_utf8(&initial).map_err(|_| "source-selected initial World UTF8")?,
            world_key,
        )?;
        if bytes(&world.snapshot()?)? != initial || !world.receipts()?.is_empty() {
            return Err("fresh live World differs from source-selected initial state".into());
        }
        let database = world.database_identity();
        drop(world);
        let db = openat(
            &root,
            "mcp-world.db",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        fsync(&db)
            .and_then(|_| fsync(&root))
            .map_err(|e| e.to_string())?;
        let receipt = json!({"schema":"hol-gauntlet-native-live-prepared.v2","source_sha":pins.source_sha,"job_id":pins.job_id,
            "deployment_digest":pins.deployment_digest,"worker_generation":pins.worker_generation,"preparation_sha256":pins.preparation_sha256,
            "normal_preparation_receipt_sha256":sha(&normal_receipt(&job)?),"role":live.role(),"cell_id":live.cell_id,"spec_sha256":live.spec_sha256,
            "world_public_key_hex":world_public,"world_initial_sha256":sha(&initial),"cleanup_public_key_hex":cleanup_public});
        let raw = bytes(&receipt)?;
        crate::feature_files::write(
            &private,
            "custody.json",
            &bytes(
                &json!({"schema":"hol-gauntlet-native-live-custody.v1","prepared_sha256":sha(&raw),"database":database}),
            )?,
            (0, 0),
            0o600,
        )?;
        crate::feature_files::write(&private, "prepared.json", &raw, (0, 0), 0o600)?;
    }
    let prepared = retained(&job, pins.deployment_digest)?;
    prepared.world_handoff()?;
    prepared.cleanup_key()?;
    lease.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    bytes(
        &json!({"schema":"hol-gauntlet-native-live-preparation-result.v1","receipt":prepared.value,"receipt_sha256":sha(&prepared.raw)}),
    )
}

pub(crate) fn final_world(job: &NativeJobSpec, deployment: &str) -> Result<Value, String> {
    let prepared = retained(job, deployment)?;
    let key = seed(&prepared.private, "world.seed")?;
    let mut world = prepared.open_world(job, key)?;
    let snapshot = world.snapshot()?;
    let receipts = world.receipts()?;
    let tail = receipts
        .last()
        .map(|r| bytes(r).map(|raw| sha(&raw)))
        .transpose()?
        .unwrap_or_else(|| "0".repeat(64));
    Ok(
        json!({"schema":"hol-gauntlet-native-live-world-final.v1","prepared_sha256":sha(&prepared.raw),
        "world_public_key_hex":prepared.value["world_public_key_hex"],"world_initial_sha256":prepared.value["world_initial_sha256"],
        "world_final_sha256":sha(&bytes(&snapshot)?),"receipt_count":receipts.len(),"final_hash":tail,
        "database":world.database_identity()}),
    )
}

pub(crate) fn verify_unreleased(
    job: &NativeJobSpec,
    deployment: &str,
    expected: &str,
) -> Result<Value, String> {
    let prepared = retained(job, deployment)?;
    if !crate::hex(expected, 64) || sha(&prepared.raw) != expected {
        return Err("unreleased live World differs from original Host preparation".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for entry in rustix::fs::Dir::read_from(&prepared.private).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry
            .file_name()
            .to_str()
            .map_err(|_| "live private inventory UTF8")?;
        if !matches!(name, "." | "..") {
            names.insert(name.to_owned());
        }
        if names.len() > 4 {
            return Err("unreleased live private inventory differs".into());
        }
    }
    if names
        != [
            "world.seed",
            "cleanup.seed",
            "custody.json",
            "prepared.json",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    {
        return Err("complete exact live private inventory required for startup recovery".into());
    }
    prepared.cleanup_key()?;
    let key = seed(&prepared.private, "world.seed")?;
    let mut world = prepared.open_world(job, key)?;
    let snapshot = world.snapshot()?;
    let initial = crate::native_live_spec::initial_snapshot(&source_spec(live(job)?)?)?;
    let initial_sha256 = sha(&bytes(&snapshot)?);
    if snapshot != initial
        || prepared.value["world_initial_sha256"] != initial_sha256
        || !world.receipts()?.is_empty()
    {
        return Err("live World was used or changed before startup recovery".into());
    }
    let database = world.database_identity();
    drop(world);
    Ok(
        json!({"live_prepared_sha256":expected,"world_snapshot_sha256":initial_sha256,"world_receipt_count":0,
        "database":database,"world_key_retained":true,"cleanup_key_retained":true,"live_private_inventory_exact":true}),
    )
}
