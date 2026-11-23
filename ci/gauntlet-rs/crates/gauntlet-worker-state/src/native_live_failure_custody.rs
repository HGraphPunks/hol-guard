//! Immutable signed-Live-failure export, Host ACK and original-volume cleanup.
use super::*;
fn retained_pre(root: &OwnedFd, p: &Pins) -> Result<PrelaunchPrepared, String> {
    p.prepared(&linux::canonical(&required(root, PRE)?)?)
}
fn retained_export(root: &OwnedFd, p: &Pins) -> Result<Value, String> {
    let pre = retained_pre(root, p)?;
    if required(root, INTENT)? != p.intent(&pre)? {
        return Err("original signed Live export intent changed".into());
    }
    let e = required(root, EXPORT)?;
    let m = required(root, MANIFEST)?;
    let mut body = p.body("export");
    for k in ["archive_sha256", "archive_bytes"] {
        body[k] = e["receipt"][k].clone();
    }
    body["manifest_sha256"] = json!(linux::sha(&linux::canonical(&m)?));
    body["exit_code"] = Value::Null;
    body["model_requests"] = Value::Null;
    body["execution_eligible"] = json!(false);
    body["qualification_eligible"] = json!(false);
    if e != wrap("export", body)?
        || e["receipt"]["archive_bytes"]
            .as_u64()
            .is_none_or(|n| !(1024..=LIMIT as u64).contains(&n))
        || !e["receipt"]["archive_sha256"]
            .as_str()
            .is_some_and(|s| crate::hex(s, 64))
    {
        return Err("original signed Live export receipt changed".into());
    }
    Ok(e)
}
fn export(
    p: &Pins,
    root: &OwnedFd,
    j: &RunReservationJournal,
    input: Option<(u64, bool)>,
) -> Result<Vec<u8>, String> {
    let pre = if let Some((count, resume)) = input {
        if !resume && (read(root, INTENT)?.is_some() || read(root, PRE)?.is_some()) {
            return Err("signed Live export consumed; use read/resume".into());
        }
        let pre = read_prelaunch(p, count)?;
        observed(p, &pre, j)?;
        once(
            root,
            PRE,
            &serde_json::from_slice(&pre.to_bytes().map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?,
        )?;
        once(root, INTENT, &p.intent(&pre)?)?;
        pre
    } else {
        retained_export(root, p)?;
        retained_pre(root, p)?
    };
    let a = collect(p, &pre, j)?;
    if a != collect(p, &pre, j)? {
        return Err("signed Live evidence changed between captures".into());
    }
    let e = export_body(p, &a.0, &a.1)?;
    if input.is_none() {
        if retained_export(root, p)? != e
            || required(root, MANIFEST)? != a.1
            || required(root, INITIAL)? != a.2
            || required(root, OBS)? != a.3
        {
            return Err("original signed Live read changed".into());
        }
        return Ok(a.0);
    }
    once(root, INITIAL, &a.2)?;
    once(root, OBS, &a.3)?;
    once(root, MANIFEST, &a.1)?;
    once(root, EXPORT, &e)?;
    retained_export(root, p)?;
    Ok(a.0)
}
fn read_prelaunch(p: &Pins, count: u64) -> Result<PrelaunchPrepared, String> {
    if !(1..=1024).contains(&count) {
        return Err("bounded original Live prelaunch required".into());
    }
    let mut raw = Vec::new();
    crate::native_source_stream::copy_source(
        std::io::stdin().as_raw_fd(),
        &mut raw,
        count,
        &crate::BoottimeDeadline::start(30).map_err(|e| e.to_string())?,
        crate::native_worker::cancellation_requested,
    )?;
    p.prepared(&raw)
}
fn ack(
    p: &Pins,
    root: &OwnedFd,
    export_sha: &str,
    host: &str,
    publish: bool,
    j: Option<&RunReservationJournal>,
) -> Result<Value, String> {
    let e = retained_export(root, p)?;
    if !crate::hex(host, 64) || e["receipt_sha256"] != export_sha {
        return Err("actual signed Live Host receipt/export pins required".into());
    }
    let mut body = e["receipt"].clone();
    body["schema"] = json!(format!("{PREFIX}-ack.v1"));
    body["export_receipt_sha256"] = json!(export_sha);
    body["host_receipt_sha256"] = json!(host);
    let expected = wrap("ack", body)?;
    if publish {
        let a = collect(
            p,
            &retained_pre(root, p)?,
            j.ok_or("Live ACK lease absent")?,
        )?;
        if export_body(p, &a.0, &a.1)? != e {
            return Err("signed Live archive changed before ACK".into());
        }
        once(root, ACK, &expected)?;
    }
    if required(root, ACK)? != expected {
        return Err("original signed Live Host ACK absent or changed".into());
    }
    Ok(expected)
}
fn authority(
    p: &Pins,
    e: &Value,
    a: &Value,
    host: &str,
    pre: &PrelaunchPrepared,
) -> Result<Value, String> {
    Ok(
        json!({"schema":format!("{PREFIX}-storage-retirement-authority.v1"),"export_receipt_sha256":e["receipt_sha256"],"host_ack_sha256":a["receipt_sha256"],"host_receipt_sha256":host,"prelaunch_sha256":linux::sha(&pre.to_bytes().map_err(|e|e.to_string())?),"live_prepared_sha256":p.0["live_prepared_sha256"],"repair_sha256":p.0["repair_sha256"],"created_repair_sha256":p.0["created_repair_sha256"],"signed_envelope_sha256":p.0["signed_envelope_sha256"],"manifest_sha256":e["receipt"]["manifest_sha256"]}),
    )
}
fn retire(
    p: &Pins,
    root: &OwnedFd,
    export_sha: &str,
    host: &str,
    generation: &str,
    publish: bool,
) -> Result<Vec<u8>, String> {
    let e = retained_export(root, p)?;
    let a = ack(p, root, export_sha, host, false, None)?;
    let pre = retained_pre(root, p)?;
    let initial = required(root, INITIAL)?;
    let pins = JobStoragePins {
        source_sha: &pre.source_sha,
        job_id: &pre.job_id,
        worker_generation: &pre.worker_generation,
        mke2fs_sha256: initial["storage"]["receipt"]["mke2fs_sha256"]
            .as_str()
            .ok_or("original Live formatter absent")?,
    };
    crate::native_job_storage::retire::retire(
        &pins,
        JobStorageProfile::Native,
        authority(p, &e, &a, host, &pre)?,
        Some(p.text("storage_receipt_sha256")),
        e["receipt"]["archive_sha256"].as_str(),
        generation,
        publish,
        || {
            let j = RunReservationJournal::open_root_owned(Path::new(
                crate::builder_image_context::RUST_STATE,
            ))
            .map_err(|e| e.to_string())?;
            let c = collect(p, &pre, &j)?;
            if c.2 != initial || export_body(p, &c.0, &c.1)? != e {
                return Err("original signed Live evidence changed before retirement".into());
            }
            Ok(())
        },
    )
}
pub(crate) fn dispatch(args: &[String]) -> Result<Option<Vec<u8>>, String> {
    let s = args.get(1).map(String::as_str).unwrap_or("");
    let count = match s {
        "--observe-native-live-failure-v1" => 13,
        "--export-native-live-failure-v1" | "--resume-native-live-failure-v1" => 14,
        "--read-native-live-failure-v1" | "--read-native-live-failure-export-v1" => 13,
        "--ack-native-live-failure-v1" | "--read-native-live-failure-ack-v1" => 15,
        "--retire-native-live-failure-storage-v1" | "--read-native-live-failure-retirement-v1" => {
            16
        }
        _ => return Ok(None),
    };
    if args.len() != count {
        return Err("exact signed Live failure arguments required".into());
    }
    gauntlet_cell_rootfs::require_outside_root()?;
    let observe = s == "--observe-native-live-failure-v1";
    let p = Pins::new(args, observe)?;
    let _scope = owner::scope()?;
    if count == 16 {
        crate::verify_running_binary(&args[15]).map_err(|e| e.to_string())?;
        return retire(
            &p,
            &p.slot()?,
            &args[13],
            &args[14],
            &args[15],
            s == "--retire-native-live-failure-storage-v1",
        )
        .map(Some);
    }
    crate::verify_running_binary(p.text("reader_generation")).map_err(|e| e.to_string())?;
    let j =
        RunReservationJournal::open_root_owned(Path::new(crate::builder_image_context::RUST_STATE))
            .map_err(|e| e.to_string())?;
    let lease = j.acquire_active_lease().map_err(|e| e.to_string())?;
    let python = crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
    let slot = p.slot()?;
    let raw = match s {
        "--observe-native-live-failure-v1" => {
            let pre = read_prelaunch(
                &p,
                args[12]
                    .parse()
                    .map_err(|_| "original prelaunch byte count required")?,
            )?;
            linux::canonical(&observed(&p, &pre, &j)?.value)?
        }
        "--export-native-live-failure-v1" | "--resume-native-live-failure-v1" => export(
            &p,
            &slot,
            &j,
            Some((
                args[13]
                    .parse()
                    .map_err(|_| "original prelaunch byte count required")?,
                s == "--resume-native-live-failure-v1",
            )),
        )?,
        "--read-native-live-failure-v1" => export(&p, &slot, &j, None)?,
        "--read-native-live-failure-export-v1" => {
            let pre = retained_pre(&slot, &p)?;
            let original = p.intent(&pre)?;
            if required(&slot, INTENT)? != original {
                return Err("original Live failure intent changed".into());
            }
            let e = if read(&slot, EXPORT)?.is_some() {
                Some(retained_export(&slot, &p)?)
            } else {
                None
            };
            linux::canonical(
                &json!({"schema":format!("{PREFIX}-export-state.v1"),"intent_sha256":linux::sha(&linux::canonical(&original)?),"export_complete":e.is_some(),"export":e,"retry_allowed":false}),
            )?
        }
        _ => linux::canonical(&ack(
            &p,
            &slot,
            &args[13],
            &args[14],
            s == "--ack-native-live-failure-v1",
            Some(&j),
        )?)?,
    };
    lease.verify(&j.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    Ok(Some(raw))
}

/// The unknown-job scan may use this only after the exact acknowledged archive
/// retired its original volume. No deleted workspace or namespace is reopened.
pub(crate) fn retired_repair(
    j: &RunReservationJournal,
    source: &str,
    job: &str,
    deployment: &str,
    generation: &str,
    repair_raw: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    use rustix::fs::{statat, AtFlags};
    let parent = crate::open_root_owned_public_directory(Path::new(
        crate::native_job_storage::lifecycle::BASE,
    ))
    .map_err(|e| e.to_string())?;
    match statat(&parent, job, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(e) => return Err(e.to_string()),
        Ok(_) => {}
    }
    let root = crate::feature_files::open_directory(&parent, job, (0, 0))?;
    if read(&root, INTENT)?.is_none() || read(&root, "retired.json")?.is_none() {
        return Ok(None);
    }
    let f = required(&root, INTENT)?;
    let mut a = vec!["worker".into(), "historical-live-failure".into()];
    for k in crate::native_prelaunch::LIVE_FAILURE_FIELDS {
        a.push(
            f[k].as_str()
                .ok_or("retired Live failure pin absent")?
                .into(),
        );
    }
    let p = Pins::new(&a, false)?;
    if p.text("source_sha") != source
        || p.text("job_id") != job
        || p.text("deployment_digest") != deployment
        || p.text("original_worker_generation") != generation
        || linux::sha(repair_raw) != p.text("repair_sha256")
    {
        return Err("retired Live failure original identity differs".into());
    }
    let pre = retained_pre(&root, &p)?;
    let started = j
        .started(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("original Live reservation absent")?;
    let pin = crate::controller_key::read_pin(j, &started, true).map_err(|e| e.to_string())?;
    if pre.started_marker_sha256 != started.sha256
        || pre.controller_key_pin_sha256 != pin.raw_sha256
        || pre.controller_public_key_hex != pin.public_key_hex
    {
        return Err("retired Live prelaunch differs from original key".into());
    }
    let running = j
        .running_marker(job, source, deployment, generation)
        .map_err(|e| e.to_string())?
        .ok_or("retired Live running marker absent")?;
    crate::native_repair_receipt::verify_live_keyed(
        repair_raw,
        &pre,
        p.text("preparation_sha256"),
        &running.sha256,
        p.text("live_prepared_sha256"),
    )?;
    let o = required(&root, OBS)?;
    let prepared = &o["live_prepared"];
    let envelope = o["signed_envelope_utf8"]
        .as_str()
        .ok_or("retained signed Live envelope absent")?;
    if linux::sha(envelope.as_bytes()) != p.text("signed_envelope_sha256")
        || linux::sha(&linux::canonical(prepared)?) != p.text("live_prepared_sha256")
        || prepared["source_sha"] != source
        || prepared["job_id"] != job
        || prepared["deployment_digest"] != deployment
        || prepared["worker_generation"] != generation
        || prepared["preparation_sha256"] != p.0["preparation_sha256"]
        || o["records_sha256"]["running"] != running.sha256
        || o["records_sha256"]["native-repair"] != p.0["repair_sha256"]
    {
        return Err("retired Live observation differs from original source/preparation".into());
    }
    let signed = verify_native_control_envelope(
        envelope.as_bytes(),
        &NativeControlReportPins {
            prelaunch: pre.clone(),
            preparation_sha256: p.text("preparation_sha256").into(),
            role: prepared["role"]
                .as_str()
                .ok_or("retained Live role absent")?
                .into(),
        },
    )
    .map_err(|_| "retired Live failure signature differs")?;
    if signed.report()["status"] != "failed"
        || signed.report()["controller_identity"]
            != json!({"pid":running.process.pid,"start_ticks":running.process.start_ticks})
    {
        return Err("retired Live failed controller differs".into());
    }
    let e = retained_export(&root, &p)?;
    let a = required(&root, ACK)?;
    let host = a["receipt"]["host_receipt_sha256"]
        .as_str()
        .filter(|v| crate::hex(v, 64))
        .ok_or("original actual Host file receipt pin absent")?;
    if ack(
        &p,
        &root,
        e["receipt_sha256"]
            .as_str()
            .ok_or("original Live export SHA absent")?,
        host,
        false,
        None,
    )? != a
    {
        return Err("retired Live actual Host ACK differs".into());
    }
    let m = required(&root, MANIFEST)?;
    if m["observation_sha256"] != linux::sha(&linux::canonical(&o)?)
        || m["files"]["worker/native-repair.json"]["sha256"] != p.0["repair_sha256"]
        || m["files"]["native.stdout"]["sha256"] != p.0["signed_envelope_sha256"]
        || m["files"]["sdk/created-repair.json"]["sha256"] != p.0["created_repair_sha256"]
    {
        return Err("retired Live archive is not the original observed failure".into());
    }
    let initial = required(&root, INITIAL)?;
    let storage = &initial["storage"];
    if initial["source_sha"] != source
        || initial["job_id"] != job
        || initial["worker_generation"] != generation
        || storage["receipt_sha256"] != p.0["storage_receipt_sha256"]
        || linux::sha(&linux::canonical(&storage["receipt"])?) != p.text("storage_receipt_sha256")
    {
        return Err("retired Live original initialization differs".into());
    }
    let context = required(&root, "retirement.json")?;
    let expected = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":source,"job_id":job,"worker_generation":generation,"mke2fs_sha256":storage["receipt"]["mke2fs_sha256"],"profile":"native-v1","retirer_generation":context["retirer_generation"],"authority":authority(&p,&e,&a,host,&pre)?,"storage_receipt_sha256":p.0["storage_receipt_sha256"],"archive_sha256":e["receipt"]["archive_sha256"]});
    if context != expected
        || context["retirer_generation"]
            .as_str()
            .is_none_or(|v| !crate::hex(v, 64))
    {
        return Err("retired Live original cleanup authority differs".into());
    }
    let retired = required(&root, "retired.json")?;
    let expected = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":source,"job_id":job,"worker_generation":generation,"profile":"native-v1","retirer_generation":context["retirer_generation"],"retirement_intent_sha256":linux::sha(&linux::canonical(&context)?),"storage_receipt_sha256":p.0["storage_receipt_sha256"],"archive_sha256":e["receipt"]["archive_sha256"],"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    if retired != expected {
        return Err("retired Live receipt differs from original acknowledged bytes".into());
    }
    crate::native_job_storage::retire::verify_retired(&root, job, &linux::canonical(&retired)?)?;
    Ok(Some(repair_raw.to_vec()))
}
