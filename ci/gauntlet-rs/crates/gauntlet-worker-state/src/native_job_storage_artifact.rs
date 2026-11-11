//! Fixed original ZIP transfer and a separate outside Host receipt acknowledgement.
use super::{lifecycle, linux, source, JobStorageProfile};
use crate::RunReservationJournal;
use rustix::fs::{fstat, statat, AtFlags};
use serde_json::{json, Value};
use std::{os::fd::OwnedFd, path::Path};

pub(crate) struct Pins<'a> {
    pub source: &'a str,
    pub job: &'a str,
    pub original_worker: &'a str,
    pub kind: &'a str,
    pub storage_sha: &'a str,
    pub archive_sha: &'a str,
    pub result_sha: &'a str,
    pub host_binding: &'a str,
    pub exporter: &'a str,
}
impl Pins<'_> {
    fn profile(&self) -> Result<JobStorageProfile, String> {
        match self.kind {
            "candidate" => Ok(JobStorageProfile::Build),
            "dependency" => Ok(JobStorageProfile::Dependency),
            _ => Err("closed candidate|dependency artifact kind required".into()),
        }
    }
    fn valid(&self) -> Result<(), String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        if !crate::hex(self.source, 40)
            || !crate::hex(self.job, 16)
            || ![
                self.original_worker,
                self.storage_sha,
                self.archive_sha,
                self.result_sha,
                self.host_binding,
                self.exporter,
            ]
            .iter()
            .all(|s| crate::hex(s, 64))
        {
            return Err("exact outside original artifact/Host/worker pins required".into());
        }
        self.profile()?;
        crate::verify_running_binary(self.exporter).map_err(|e| e.to_string())
    }
}
fn value(slot: &OwnedFd, name: &str) -> Result<Value, String> {
    let raw = crate::feature_files::required(slot, name, (0, 0), 0o600, 24576)?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if linux::canonical(&v)? != raw {
        return Err("canonical original artifact transfer metadata required".into());
    }
    Ok(v)
}
fn text(v: &Value) -> Result<&str, String> {
    v.as_str()
        .ok_or_else(|| "original artifact acknowledgement text pin absent".into())
}
fn original(p: &Pins<'_>) -> Result<(OwnedFd, Value), String> {
    p.valid()?;
    let slot = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(p.job))
        .map_err(|e| e.to_string())?;
    let read = value(&slot, "artifact-read.json")?;
    if read.as_object().is_none_or(|o| o.len() != 10)
        || read["schema"] != "hol-gauntlet-source-storage-artifact-read.v1"
        || read["job_id"] != p.job
        || read["profile"] != p.profile()?.as_str()
        || read["storage_receipt_sha256"] != p.storage_sha
        || read["archive_sha256"] != p.archive_sha
        || read["result_sha256"] != p.result_sha
        || read["host_binding_sha256"] != p.host_binding
        || read["source_capture"]["source_sha"] != p.source
        || read["source_capture"]["worker_generation"] != p.original_worker
        || read["source_capture_sha256"] != linux::sha(&linux::canonical(&read["source_capture"])?)
    {
        return Err("artifact transfer differs from original bounded Host reconciliation".into());
    }
    Ok((slot, read))
}
fn intent(p: &Pins<'_>, read: &Value) -> Value {
    json!({"schema":"hol-gauntlet-source-artifact-export-intent.v1","source_sha":p.source,"job_id":p.job,"original_worker_generation":p.original_worker,"kind":p.kind,
        "storage_receipt_sha256":p.storage_sha,"archive_sha256":p.archive_sha,"result_sha256":p.result_sha,"host_binding_sha256":p.host_binding,"exporter_generation":p.exporter,
        "artifact_read_sha256":linux::sha(&linux::canonical(read).expect("validated canonical bounded Root read receipt"))})
}
fn quiescent(p: &Pins<'_>, read: &Value) -> Result<OwnedFd, String> {
    let root =
        crate::builder_candidate_source::open_fixed_build_slot(p.job).map_err(|e| e.to_string())?;
    if source::verify(p.job, &root, Some(p.profile()?))? != Some(read["source_capture"].clone()) {
        return Err("original bounded Source changed before artifact transfer".into());
    }
    crate::candidate_capture::inactive(p.job).map_err(|e| e.to_string())?;
    crate::require_rust_job_slice_absent(p.job).map_err(|e| e.to_string())?;
    crate::require_no_product_cell_units().map_err(|e| e.to_string())?;
    Ok(root)
}
fn collect(p: &Pins<'_>, read: &Value) -> Result<Vec<u8>, String> {
    let root = quiescent(p, read)?;
    let before = fstat(&root).map_err(|e| e.to_string())?;
    let name = if p.kind == "candidate" {
        "candidate.zip"
    } else {
        "dependencies.zip"
    };
    let file_before = statat(&root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    let raw = crate::dependency_io::read(&root, name, 0, 0o444, 256 * 1024 * 1024)?;
    if linux::sha(&raw) != p.archive_sha
        || crate::dependency_io::read(&root, name, 0, 0o444, 256 * 1024 * 1024)? != raw
    {
        return Err("original immutable artifact bytes/hash changed during transfer".into());
    }
    let current = quiescent(p, read)?;
    for s in [
        fstat(&root).map_err(|e| e.to_string())?,
        fstat(&current).map_err(|e| e.to_string())?,
    ] {
        if !crate::dependency_prefix_meta::same(&before, &s) {
            return Err("artifact volume root changed during export".into());
        }
    }
    if !crate::builder_candidate_source::same_file(
        &file_before,
        &statat(&root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?,
    ) {
        return Err("original artifact inode changed during transfer".into());
    }
    Ok(raw)
}
fn binding(p: &Pins<'_>, read: &Value, bytes: usize) -> Value {
    let mut v = intent(p, read);
    v["schema"] = json!("hol-gauntlet-source-artifact-export.v1");
    v["archive_bytes"] = json!(bytes);
    v
}
fn checked_binding(p: &Pins<'_>, slot: &OwnedFd, read: &Value) -> Result<Value, String> {
    let v = value(slot, "artifact-export.json")?;
    let bytes = v["archive_bytes"]
        .as_u64()
        .filter(|n| (1..=256 * 1024 * 1024).contains(n))
        .ok_or("bounded original artifact export size absent")?;
    if v != binding(p, read, bytes as usize)
        || value(slot, "artifact-export-intent.json")? != intent(p, read)
    {
        return Err("original artifact export binding changed".into());
    }
    Ok(v)
}
/// Initial export consumes a private intent before any bytes leave Root. An
/// explicit read reconciles only those same immutable bytes and original pins.
pub(crate) fn export(p: &Pins<'_>, readback: bool) -> Result<Vec<u8>, String> {
    let (slot, read) = original(p)?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let expected = linux::canonical(&intent(p, &read))?;
    if readback {
        if crate::feature_files::required(
            &slot,
            "artifact-export-intent.json",
            (0, 0),
            0o600,
            8192,
        )? != expected
        {
            return Err("artifact readback lacks original consumed export intent".into());
        }
    } else {
        crate::feature_files::write(
            &slot,
            "artifact-export-intent.json",
            &expected,
            (0, 0),
            0o600,
        )?;
    }
    let raw = collect(p, &read)?;
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    p.valid()?;
    let expected = linux::canonical(&binding(p, &read, raw.len()))?;
    match crate::feature_files::read(&slot, "artifact-export.json", (0, 0), 0o600, 8192)? {
        Some(v) if v == expected => {}
        Some(_) => return Err("original artifact export completion changed".into()),
        None => {
            crate::feature_files::write(&slot, "artifact-export.json", &expected, (0, 0), 0o600)?
        }
    }
    Ok(raw)
}
pub(crate) fn read_export(p: &Pins<'_>) -> Result<Vec<u8>, String> {
    let (slot, read) = original(p)?;
    let expected = intent(p, &read);
    let actual = value(&slot, "artifact-export-intent.json")?;
    if actual != expected {
        return Err("original artifact export intent differs".into());
    }
    let (status, receipt, receipt_sha256) = if crate::feature_files::read(
        &slot,
        "artifact-export.json",
        (0, 0),
        0o600,
        8192,
    )?
    .is_some()
    {
        let v = checked_binding(p, &slot, &read)?;
        let sha = linux::sha(&linux::canonical(&v)?);
        ("complete", v, Some(sha))
    } else {
        ("unknown", Value::Null, None)
    };
    linux::canonical(
        &json!({"schema":"hol-gauntlet-source-artifact-export-state.v1","status":status,"intent_sha256":linux::sha(&linux::canonical(&actual)?),"receipt":receipt,"receipt_sha256":receipt_sha256}),
    )
}
fn ack(p: &Pins<'_>, export_sha: &str, host_receipt: &str) -> Value {
    json!({"schema":"hol-gauntlet-source-artifact-ack.v1","source_sha":p.source,"job_id":p.job,"original_worker_generation":p.original_worker,"kind":p.kind,
        "storage_receipt_sha256":p.storage_sha,"archive_sha256":p.archive_sha,"result_sha256":p.result_sha,"host_binding_sha256":p.host_binding,
        "exporter_generation":p.exporter,"export_binding_sha256":export_sha,"host_receipt_sha256":host_receipt})
}
pub(crate) fn acknowledge(
    p: &Pins<'_>,
    export_sha: &str,
    host_receipt: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    if !crate::hex(export_sha, 64) || !crate::hex(host_receipt, 64) {
        return Err("outside durable Host receipt and original export binding required".into());
    }
    let (slot, read) = original(p)?;
    let journal =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let active = journal.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let exported = checked_binding(p, &slot, &read)?;
    if linux::sha(&linux::canonical(&exported)?) != export_sha {
        return Err("Host acknowledgement differs from original export binding".into());
    }
    let expected = linux::canonical(&ack(p, export_sha, host_receipt))?;
    if publish {
        collect(p, &read)?;
        crate::feature_files::write(
            &slot,
            "host-artifact-received.json",
            &expected,
            (0, 0),
            0o600,
        )?;
    }
    if crate::feature_files::required(&slot, "host-artifact-received.json", (0, 0), 0o600, 8192)?
        != expected
    {
        return Err("original Host artifact receipt acknowledgement differs".into());
    }
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    crate::native_initialize::initialization_result(
        &expected,
        "hol-gauntlet-source-artifact-ack-result.v1",
    )
}
pub(crate) fn retirement_ack(
    slot: &OwnedFd,
    read: &Value,
    host_receipt: &str,
) -> Result<Value, String> {
    if !crate::hex(host_receipt, 64) {
        return Err("outside original Host archive receipt SHA required".into());
    }
    let acknowledgement = value(slot, "host-artifact-received.json")?;
    let p = Pins {
        source: text(&read["source_capture"]["source_sha"])?,
        job: text(&read["job_id"])?,
        original_worker: text(&read["source_capture"]["worker_generation"])?,
        kind: text(&acknowledgement["kind"])?,
        storage_sha: text(&read["storage_receipt_sha256"])?,
        archive_sha: text(&read["archive_sha256"])?,
        result_sha: text(&read["result_sha256"])?,
        host_binding: text(&read["host_binding_sha256"])?,
        exporter: text(&acknowledgement["exporter_generation"])?,
    };
    if read["profile"] != p.profile()?.as_str() || !crate::hex(p.exporter, 64) {
        return Err("original acknowledged artifact profile/exporter differs".into());
    }
    let export = checked_binding(&p, slot, read)?;
    if acknowledgement != ack(&p, &linux::sha(&linux::canonical(&export)?), host_receipt) {
        return Err(
            "exact retained original Host archive acknowledgement required before retirement"
                .into(),
        );
    }
    Ok(
        json!({"schema":"hol-gauntlet-source-storage-retirement-authority.v1",
        "artifact_read_sha256":linux::sha(&linux::canonical(read)?),"export_binding_sha256":linux::sha(&linux::canonical(&export)?),
        "host_ack_sha256":linux::sha(&linux::canonical(&acknowledgement)?),"result_sha256":read["result_sha256"],
        "host_binding_sha256":read["host_binding_sha256"],"host_receipt_sha256":host_receipt}),
    )
}

/// Completed custody survives deletion of the acknowledged source volume.
/// This is a read of original Root records, never permission to reconstruct it.
pub(crate) fn retired_read(job: &str, profile: JobStorageProfile) -> Result<Option<Value>, String> {
    if !crate::hex(job, 16) || profile == JobStorageProfile::Native {
        return Err("closed retired Source job/profile required".into());
    }
    if !lifecycle::present(job)? {
        return Ok(None);
    }
    let slot = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(job))
        .map_err(|e| e.to_string())?;
    let Some(raw) = crate::feature_files::read(&slot, "retired.json", (0, 0), 0o600, 8192)? else {
        return Ok(None);
    };
    super::retire::verify_retired(&slot, job, &raw)?;
    let retired: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let read = value(&slot, "artifact-read.json")?;
    let storage = value(&slot, lifecycle::RECEIPT)?;
    let capture_raw = retired_links(job, profile, &read, &storage, &retired)?;
    super::admission::verify_admitted(&slot, &linux::canonical(&storage)?, &capture_raw)?;
    let ack = value(&slot, "host-artifact-received.json")?;
    let authority = retirement_ack(&slot, &read, text(&ack["host_receipt_sha256"])?)?;
    let expected = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1",
        "source_sha":storage["source_sha"],"job_id":job,"worker_generation":storage["worker_generation"],
        "mke2fs_sha256":storage["mke2fs_sha256"],"profile":profile.as_str(),"retirer_generation":retired["retirer_generation"],
        "authority":authority,"storage_receipt_sha256":read["storage_receipt_sha256"],"archive_sha256":read["archive_sha256"]});
    if value(&slot, "retirement.json")? != expected
        || retired["retirement_intent_sha256"] != linux::sha(&linux::canonical(&expected)?)
        || retired["storage_receipt_sha256"] != read["storage_receipt_sha256"]
        || retired["archive_sha256"] != read["archive_sha256"]
    {
        return Err("retired Source lacks exact original Host archive acknowledgement".into());
    }
    Ok(Some(read))
}

fn retired_links(
    job: &str,
    profile: JobStorageProfile,
    read: &Value,
    storage: &Value,
    retired: &Value,
) -> Result<Vec<u8>, String> {
    let capture = &read["source_capture"];
    let capture_raw = linux::canonical(capture)?;
    if capture["builder_executed"] != false
        || capture["execution_eligible"] != false
        || capture["model_requests"] != 0
        || !capture["source_archive_sha256"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
        || !capture["source_bytes"]
            .as_u64()
            .is_some_and(|n| (1..=256 * 1024 * 1024).contains(&n))
        || read.as_object().is_none_or(|o| o.len() != 10)
        || read["schema"] != "hol-gauntlet-source-storage-artifact-read.v1"
        || capture.as_object().is_none_or(|o| o.len() != 11)
        || capture["schema"] != "hol-gauntlet-native-source-capture.v2"
        || read["job_id"] != job
        || capture["job_id"] != job
        || storage["job_id"] != job
        || read["profile"] != profile.as_str()
        || capture["storage_profile"] != profile.as_str()
        || storage["profile"] != profile.as_str()
        || storage["schema"] != "hol-gauntlet-job-storage.v2"
        || capture["storage"]["receipt"] != *storage
        || capture["source_sha"] != storage["source_sha"]
        || capture["worker_generation"] != storage["worker_generation"]
        || capture["storage"]["receipt_sha256"] != linux::sha(&linux::canonical(storage)?)
        || read["storage_receipt_sha256"] != capture["storage"]["receipt_sha256"]
        || read["source_capture_sha256"] != linux::sha(&capture_raw)
        || [
            "archive_sha256",
            "result_sha256",
            "host_binding_sha256",
            "readback_sha256",
        ]
        .iter()
        .any(|k| !read[*k].as_str().is_some_and(|s| crate::hex(s, 64)))
        || retired["partial"] != false
        || retired["profile"] != profile.as_str()
        || retired["source_sha"] != storage["source_sha"]
        || retired["worker_generation"] != storage["worker_generation"]
    {
        return Err("retired Source custody differs from original completed storage".into());
    }
    Ok(capture_raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retired_source_links_cannot_borrow_a_foreign_volume_result_or_capture() {
        let job = "0123456789abcdef";
        let source = "a".repeat(40);
        let worker = "b".repeat(64);
        let storage = json!({"schema":"hol-gauntlet-job-storage.v2","job_id":job,"source_sha":source,
            "worker_generation":worker,"profile":"dependency-v1"});
        let storage_sha = linux::sha(&linux::canonical(&storage).unwrap());
        let capture = json!({"schema":"hol-gauntlet-native-source-capture.v2","source_sha":source,"job_id":job,
            "worker_generation":worker,"source_archive_sha256":"c".repeat(64),"source_bytes":4096,
            "storage_profile":"dependency-v1","storage":{"receipt":storage,"receipt_sha256":storage_sha},
            "builder_executed":false,"execution_eligible":false,"model_requests":0});
        let read = json!({"schema":"hol-gauntlet-source-storage-artifact-read.v1","source_capture":capture,
            "source_capture_sha256":linux::sha(&linux::canonical(&capture).unwrap()),"profile":"dependency-v1","job_id":job,
            "storage_receipt_sha256":storage_sha,"archive_sha256":"d".repeat(64),"result_sha256":"e".repeat(64),
            "host_binding_sha256":"f".repeat(64),"readback_sha256":"1".repeat(64)});
        let retired = json!({"partial":false,"profile":"dependency-v1","source_sha":source,"worker_generation":worker});
        assert!(retired_links(
            job,
            JobStorageProfile::Dependency,
            &read,
            &storage,
            &retired
        )
        .is_ok());
        for (pointer, bad) in [
            ("/source_capture/source_sha", json!("0".repeat(40))),
            (
                "/source_capture/storage/receipt/job_id",
                json!("fedcba9876543210"),
            ),
            ("/source_capture_sha256", json!("0".repeat(64))),
            ("/storage_receipt_sha256", json!("0".repeat(64))),
            ("/source_capture/model_requests", json!(1)),
            ("/readback_sha256", Value::Null),
        ] {
            let mut wrong = read.clone();
            *wrong.pointer_mut(pointer).unwrap() = bad;
            assert!(
                retired_links(
                    job,
                    JobStorageProfile::Dependency,
                    &wrong,
                    &storage,
                    &retired
                )
                .is_err(),
                "{pointer}"
            );
        }
        let mut wrong = retired;
        wrong["partial"] = json!(true);
        assert!(
            retired_links(job, JobStorageProfile::Dependency, &read, &storage, &wrong).is_err()
        );
        assert!(retired_links(job, JobStorageProfile::Build, &read, &storage, &wrong).is_err());
    }
}
