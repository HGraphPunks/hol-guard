//! Completed Native cleanup consumes only the retained authenticated archive.
use super::{
    binding, bytes, dispatch, hex, name, read_stable, sha, validate_archive, Intent, Journal, Lima,
};
use crate::HostControllerKeyPinJournal;
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::{fs::File, path::Path};
const INTENT: &str = "storage-retirement-intent";
const DISPATCH: &str = "storage-retirement-dispatch";
const RESULT: &str = "storage-retirement-result";
pub(super) const USAGE: &str = "retire PRIVATE_JOURNAL JOB_ID INTENT_SHA256 RETIRER_SHA256\nretire-read|retire-resume PRIVATE_JOURNAL JOB_ID INTENT_SHA256\nOnly completed bounded Native jobs with the original private archive may retire storage. Resume retains the original consumed cleanup; read never changes Root state. Model usage remains unknown.";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str()
        .ok_or_else(|| format!("Native retirement {k} absent"))
}
struct Archive {
    file: File,
    stamp: Stat,
    identity: Value,
}
impl Archive {
    fn check(&self, j: &Journal, i: &Intent) -> Result<(), String> {
        j.stable()?;
        let after = fstat(&self.file).map_err(|_| "Native archive descriptor unavailable")?;
        let visible = statat(&j.root, name(i).as_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "Native archive name unavailable")?;
        if !crate::private_jobs::same_file(&self.stamp, &after)
            || !crate::private_jobs::same_file(&self.stamp, &visible)
        {
            return Err("original Native archive identity changed".into());
        }
        Ok(())
    }
}
fn context(j: &Journal, i: &Intent, generation: &str) -> Result<(Value, Archive), String> {
    if !hex(generation, 64) {
        return Err("outside Native retirer generation required".into());
    }
    j.require_dispatch(i)?;
    let storage = super::super::preparation::retained_storage(j, i)?
        .ok_or("Native retirement requires original initialized bounded storage")?;
    let completion = j.read(i.job(), "completion")?;
    let verified = j.verify(i, &completion)?;
    let keys = HostControllerKeyPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let record = keys.read(i.job()).map_err(|e| e.to_string())?;
    if verified.observation()["host_pin_sha256"] != record.raw_sha256
        || j.read(i.job(), "export-dispatch")? != bytes(&dispatch(i, &verified)?)?
    {
        return Err("Native retirement differs from original completed Host authority".into());
    }
    let export_raw = j.read(i.job(), "export-binding")?;
    let export: Value =
        serde_json::from_slice(&export_raw).map_err(|_| "Native export binding JSON")?;
    let digest = text(&export, "archive_sha256")?;
    if !hex(digest, 64) || bytes(&export)? != export_raw {
        return Err("original Native export binding invalid".into());
    }
    let fd = openat(
        &j.root,
        name(i).as_str(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "original private Native archive absent")?;
    let stamp = fstat(&fd).map_err(|_| "Native archive metadata unavailable")?;
    if FileType::from_raw_mode(stamp.st_mode) != FileType::RegularFile
        || stamp.st_uid != j.owner
        || stamp.st_nlink != 1
        || stamp.st_mode & 0o7777 != 0o600
        || stamp.st_size < 1024
        || stamp.st_size > super::LIMIT as i64
    {
        return Err("original Native archive requires private0600 single-link custody".into());
    }
    let archive = Archive {
        file: File::from(fd),
        identity: json!({"device":stamp.st_dev,"inode":stamp.st_ino,"uid":stamp.st_uid,
        "gid":stamp.st_gid,"mode":stamp.st_mode&0o7777,"links":stamp.st_nlink,"bytes":stamp.st_size,
        "mtime":stamp.st_mtime,"mtime_nsec":stamp.st_mtime_nsec,"ctime":stamp.st_ctime,"ctime_nsec":stamp.st_ctime_nsec}),
        stamp,
    };
    let raw = read_stable(&j.path.join(name(i)), digest)?;
    if binding(i, &verified, &raw)? != export {
        return Err("Native archive differs from completed export binding".into());
    }
    validate_archive(i, &verified, &raw)?;
    archive.check(j, i)?;
    let p = &record.pins;
    let prelaunch = gauntlet_contracts::PrelaunchPrepared {
        job_id: p.job_id.clone(),
        source_sha: p.source_sha.clone(),
        deployment_digest: p.deployment_digest.clone(),
        worker_generation: p.worker_generation.clone(),
        started_marker_sha256: p.started_marker_sha256.clone(),
        controller_key_pin_sha256: p.controller_key_pin_sha256.clone(),
        controller_public_key_hex: p.controller_public_key_hex.clone(),
    };
    let prelaunch: Value =
        serde_json::from_slice(&prelaunch.to_bytes().map_err(|e| e.to_string())?)
            .map_err(|_| "original Native prelaunch JSON")?;
    let observed = verified.observation();
    let authority = json!({"schema":"hol-gauntlet-native-storage-export.v1","prelaunch":prelaunch,"preparation_sha256":i.text("preparation_sha256"),
        "role":i.text("role"),"storage_receipt_sha256":storage["receipt_sha256"],"archive_sha256":digest,"archive_bytes":raw.len(),
        "terminal_sha256":observed["terminal_sha256"],"report_sha256":observed["report_sha256"]});
    let retirement = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
        "worker_generation":i.text("worker_generation"),"mke2fs_sha256":storage["receipt"]["mke2fs_sha256"],"profile":"native-v1","retirer_generation":generation,
        "authority":authority,"storage_receipt_sha256":storage["receipt_sha256"],"archive_sha256":digest});
    let initial: Value = serde_json::from_slice(&j.read(i.job(), "initialize-result")?)
        .map_err(|_| "original Native initialization JSON")?;
    Ok((
        json!({"schema":"hol-gauntlet-host-native-storage-retirement.v1","job_id":i.job(),"native_intent_sha256":i.digest()?,
        "initialization_sha256":initial["receipt_sha256"],"host_pin_sha256":record.raw_sha256,"completion_sha256":sha(&completion),
        "export_binding_sha256":sha(&export_raw),"archive_identity":archive.identity,"parent_custody":super::super::context::snapshot(&j.path)?,"retirement":retirement}),
        archive,
    ))
}
fn marker(a: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-native-storage-retirement-dispatch.v1","intent_sha256":sha(&bytes(a)?),"retry_allowed":false}),
    )
}
fn parsed(j: &Journal, i: &Intent) -> Result<Value, String> {
    let raw = j.read(i.job(), INTENT)?;
    let a: Value = serde_json::from_slice(&raw).map_err(|_| "Native retirement intent JSON")?;
    if raw != bytes(&a)? {
        return Err("canonical Native retirement intent required".into());
    }
    Ok(a)
}
fn validate(a: &Value, raw: &[u8]) -> Result<Value, String> {
    let frame = raw.strip_suffix(b"\n").unwrap_or(raw);
    let v: Value = serde_json::from_slice(frame).map_err(|_| "Native retirement reply JSON")?;
    let r = &a["retirement"];
    let expected = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":r["source_sha"],"job_id":r["job_id"],"worker_generation":r["worker_generation"],
        "profile":"native-v1","retirer_generation":r["retirer_generation"],"retirement_intent_sha256":sha(&bytes(r)?),"storage_receipt_sha256":r["storage_receipt_sha256"],
        "archive_sha256":r["archive_sha256"],"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,
        "job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    if frame.len() > 8192 || bytes(&v)? != frame || v != expected {
        return Err("Native retirement differs from original complete archive authority".into());
    }
    Ok(v)
}
fn argv(i: &Intent, a: &Value, read: bool) -> Result<Vec<String>, String> {
    let r = &a["retirement"];
    let p = &r["authority"]["prelaunch"];
    let g = text(r, "retirer_generation")?;
    let mut out = vec![
        format!("/opt/hol-gauntlet/rust-native-host-pinned-worker-{g}"),
        if read {
            "--read-native-job-storage-retirement-v1"
        } else {
            "--retire-native-job-storage-v1"
        }
        .into(),
    ];
    for k in [
        "source_sha",
        "job_id",
        "deployment_digest",
        "worker_generation",
        "started_marker_sha256",
        "controller_key_pin_sha256",
        "controller_public_key_hex",
    ] {
        out.push(text(p, k)?.into());
    }
    out.extend([
        i.text("preparation_sha256").into(),
        i.text("role").into(),
        g.into(),
        text(r, "storage_receipt_sha256")?.into(),
        text(r, "archive_sha256")?.into(),
    ]);
    Ok(out)
}
fn execute(
    j: &Journal,
    i: &Intent,
    mode: &str,
    generation: Option<&str>,
    run: impl FnOnce(&[String]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    let (a, held) = if mode == "retire" {
        let (a, held) = context(
            j,
            i,
            generation.ok_or("outside Native retirer SHA required")?,
        )?;
        j.require_idle()?;
        for suffix in [INTENT, DISPATCH, RESULT] {
            if !j.absent(i.job(), suffix)? {
                return Err("Native retirement consumed; use explicit read/resume".into());
            }
        }
        j.write(i.job(), INTENT, &bytes(&a)?)?;
        j.write(i.job(), DISPATCH, &marker(&a)?)?;
        (a, held)
    } else {
        let a = parsed(j, i)?;
        let (expected, held) = context(j, i, text(&a["retirement"], "retirer_generation")?)?;
        if a != expected || j.read(i.job(), DISPATCH)? != marker(&a)? {
            return Err("original Native retirement intent/dispatch required".into());
        }
        (a, held)
    };
    held.check(j, i)?;
    let raw = run(&argv(i, &a, mode == "retire-read")?).map_err(|_| {
        "Native cleanup uncertain; retain all evidence and reconcile original operation"
    })?;
    j.retain(
        i.job(),
        &format!("storage-retirement-frame-{}", sha(&raw)),
        &raw,
    )?;
    let result = validate(&a, &raw)?;
    held.check(j, i)?;
    let (expected, _) = context(j, i, text(&a["retirement"], "retirer_generation")?)?;
    if a != expected
        || j.read(i.job(), INTENT)? != bytes(&a)?
        || j.read(i.job(), DISPATCH)? != marker(&a)?
    {
        return Err("original Native retirement custody changed".into());
    }
    j.retain(i.job(), RESULT, &bytes(&result)?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-native-storage-retired.v1","job_id":i.job(),"source_sha":i.text("source_sha"),
        "native_intent_sha256":i.digest()?,"retirement_intent_sha256":sha(&bytes(&a)?),"receipt_sha256":sha(&bytes(&result)?),
        "archive_sha256":a["retirement"]["archive_sha256"],"storage_receipt_sha256":a["retirement"]["storage_receipt_sha256"],
        "storage_retired":true,"job_consumed":true,"exit_code":null,"model_requests":null,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(in crate::native_operation) fn run_command(args: &[String]) -> Result<Value, String> {
    if !matches!(
        (args.first().map(String::as_str), args.len()),
        (Some("retire"), 5) | (Some("retire-read" | "retire-resume"), 4)
    ) || !hex(&args[2], 16)
        || !hex(&args[3], 64)
    {
        return Err(USAGE.into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = j.intent(&args[2])?;
    if i.digest()? != args[3] {
        return Err("outside original Native intent differs".into());
    }
    let mut lima = Lima::open(&i)?;
    execute(&j, &i, &args[0], args.get(4).map(String::as_str), |argv| {
        super::super::preparation::prepared_job_transport(&mut lima, i.text("vm"), argv, b"")
    })
}
pub(in crate::native_operation) fn verify_idle_record(
    j: &Journal,
    name: &str,
) -> Result<(), String> {
    let Some((job, suffix)) = name
        .split_once(".native-storage-retirement-")
        .filter(|(job, _)| hex(job, 16))
    else {
        return Ok(());
    };
    if j.absent(job, INTENT)? || j.absent(job, DISPATCH)? {
        return Err("orphan Native retirement state blocks dispatch".into());
    }
    if suffix == "intent.json" {
        let i = j.intent(job)?;
        let a = parsed(j, &i)?;
        let (expected, _) = context(j, &i, text(&a["retirement"], "retirer_generation")?)?;
        if a != expected || j.read(job, DISPATCH)? != marker(&a)? {
            return Err("original Native retirement binding changed".into());
        }
        validate(&a, &j.read(job, RESULT)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, fs, os::unix::fs::PermissionsExt};
    fn fixture() -> super::super::tests::Fixture {
        let mut f = super::super::tests::fixture();
        let storage = super::super::super::job_storage_fixture(
            f.i.text("source_sha"),
            f.i.job(),
            f.i.text("worker_generation"),
            &"a".repeat(64),
            "native-v1",
        );
        let initial = json!({"schema":"hol-gauntlet-host-native-initialization-intent.v2","job_id":f.i.job(),"source_sha":f.i.text("source_sha"),
            "worker_generation":f.i.text("worker_generation"),"vm":f.i.text("vm"),"limactl":f.i.text("limactl"),"lima_sha256":f.i.text("lima_sha256"),
            "transport_context":f.i.0["transport_context"],"mke2fs_sha256":"a".repeat(64)});
        let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{}", f.i.job());
        let receipt = json!({"schema":"hol-gauntlet-native-job-initialization.v2","job_id":f.i.job(),"source_sha":f.i.text("source_sha"),"worker_generation":f.i.text("worker_generation"),
            "job_directory":storage["receipt"]["root_directory"],"workspace":{"source":format!("{root}/workspace"),"destination":"/runtime/home/project","custody_root":root,
            "device":storage["receipt"]["root_directory"]["device"],"inode":52,"uid":10001,"gid":10001,"mode":448},"storage":storage,
            "job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
        let initialized = json!({"schema":"hol-gauntlet-native-job-initialization-result.v2","receipt_sha256":sha(&bytes(&receipt).unwrap()),"receipt":receipt});
        for (suffix, v) in [
            ("initialize-intent", initial.clone()),
            (
                "initialize-dispatch",
                json!({"schema":"hol-gauntlet-host-native-initialization-dispatch.v1","job_id":f.i.job(),"initialization_intent_sha256":sha(&bytes(&initial).unwrap()),"retry_allowed":false}),
            ),
            ("initialize-result", initialized),
        ] {
            f.j.write(f.i.job(), suffix, &bytes(&v).unwrap()).unwrap();
        }
        let mut completion: Value =
            serde_json::from_slice(&f.j.read(f.i.job(), "completion").unwrap()).unwrap();
        completion["report"]["retained_storage"] = storage;
        crate::native_control_readback::tests::refresh(&mut completion);
        let raw = bytes(&completion).unwrap();
        for suffix in ["return", "completion"] {
            fs::write(
                f.j.path.join(Journal::name(f.i.job(), suffix).unwrap()),
                &raw,
            )
            .unwrap();
        }
        f.verified = f.j.verify(&f.i, &raw).unwrap();
        let mut files = super::super::members(&f.raw).unwrap();
        files.insert(
            "combined/worker/report.json".into(),
            bytes(&completion["report"]).unwrap(),
        );
        let mut index: Value = serde_json::from_slice(&files["results.sha256.json"]).unwrap();
        index["report_sha256"] = f.verified.observation()["report_sha256"].clone();
        index["terminal_sha256"] = f.verified.observation()["terminal_sha256"].clone();
        let report = &files["combined/worker/report.json"];
        index["files"]["combined/worker/report.json"] =
            json!({"bytes":report.len(),"sha256":sha(report)});
        index["filesystem"]["combined/worker/report.json"]["bytes"] = json!(report.len());
        files.insert("results.sha256.json".into(), bytes(&index).unwrap());
        f.raw = super::super::tests::archive(&files);
        super::super::retain_archive(&f.j, &f.i, &f.raw).unwrap();
        f.j.write(
            f.i.job(),
            "export-dispatch",
            &bytes(&dispatch(&f.i, &f.verified).unwrap()).unwrap(),
        )
        .unwrap();
        f.j.write(
            f.i.job(),
            "export-binding",
            &bytes(&binding(&f.i, &f.verified, &f.raw).unwrap()).unwrap(),
        )
        .unwrap();
        f
    }
    fn receipt(a: &Value) -> Vec<u8> {
        let r = &a["retirement"];
        bytes(&json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":r["source_sha"],"job_id":r["job_id"],"worker_generation":r["worker_generation"],
            "profile":"native-v1","retirer_generation":r["retirer_generation"],"retirement_intent_sha256":sha(&bytes(r).unwrap()),"storage_receipt_sha256":r["storage_receipt_sha256"],
            "archive_sha256":r["archive_sha256"],"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,
            "execution_eligible":false,"qualification_eligible":false,"model_requests":null})).unwrap()
    }
    #[test]
    fn completed_native_retirement_recovers_partial_cleanup_under_exact_retained_archive_authority()
    {
        let f = fixture();
        let g = "b".repeat(64);
        let (a, _) = context(&f.j, &f.i, &g).unwrap();
        let phase = Cell::new(0);
        assert!(execute(&f.j, &f.i, "retire", Some(&g), |argv| {
            assert_eq!(argv.len(), 14);
            phase.set(1);
            Err("lost after unmount".into())
        })
        .is_err());
        let dispatch = f.j.read(f.i.job(), DISPATCH).unwrap();
        assert!(execute(&f.j, &f.i, "retire-read", None, |argv| {
            assert_eq!(argv[1], "--read-native-job-storage-retirement-v1");
            Err("incomplete".into())
        })
        .is_err());
        assert!(execute(&f.j, &f.i, "retire", Some(&g), |_| panic!(
            "fresh cleanup replay"
        ))
        .is_err());
        let output = execute(&f.j, &f.i, "retire-resume", None, |argv| {
            assert_eq!(phase.get(), 1);
            assert_eq!(argv[1], "--retire-native-job-storage-v1");
            phase.set(2);
            Ok(receipt(&a))
        })
        .unwrap();
        assert!(output["model_requests"].is_null());
        assert_eq!(f.j.read(f.i.job(), DISPATCH).unwrap(), dispatch);
        execute(&f.j, &f.i, "retire-read", None, |argv| {
            assert_eq!(argv[1], "--read-native-job-storage-retirement-v1");
            Ok(receipt(&a))
        })
        .unwrap();
        verify_idle_record(&f.j, &Journal::name(f.i.job(), INTENT).unwrap()).unwrap();
        assert!(f.j.require_idle().is_ok());
    }
    #[test]
    fn retirement_cannot_adopt_intent_without_dispatch_or_tampered_original_archive_and_pin() {
        let f = fixture();
        let g = "b".repeat(64);
        let (a, _) = context(&f.j, &f.i, &g).unwrap();
        f.j.write(f.i.job(), INTENT, &bytes(&a).unwrap()).unwrap();
        assert!(execute(&f.j, &f.i, "retire-resume", None, |_| panic!(
            "missing dispatch"
        ))
        .is_err());
        f.j.write(f.i.job(), DISPATCH, &marker(&a).unwrap())
            .unwrap();
        let mut wrong = f.i.clone();
        wrong.0["source_sha"] = json!("0".repeat(40));
        assert!(execute(&f.j, &wrong, "retire-read", None, |_| panic!(
            "substitute pin"
        ))
        .is_err());
        let path = f.j.path.join(name(&f.i));
        let mut corrupt = f.raw.clone();
        corrupt[600] ^= 1;
        fs::write(&path, corrupt).unwrap();
        assert!(execute(&f.j, &f.i, "retire-resume", None, |_| panic!(
            "changed archive"
        ))
        .is_err());
    }
    #[test]
    fn retirement_refuses_legacy_missing_private_custody_and_rehashed_retirement_substitution() {
        let legacy = super::super::tests::fixture();
        assert!(context(&legacy.j, &legacy.i, &"b".repeat(64)).is_err());
        let f = fixture();
        let g = "b".repeat(64);
        let (a, _) = context(&f.j, &f.i, &g).unwrap();
        let mut wrong: Value = serde_json::from_slice(&receipt(&a)).unwrap();
        wrong["archive_sha256"] = json!("0".repeat(64));
        assert!(validate(&a, &bytes(&wrong).unwrap()).is_err());
        fs::set_permissions(f.j.path.join(name(&f.i)), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(context(&f.j, &f.i, &g).is_err());
    }
}
