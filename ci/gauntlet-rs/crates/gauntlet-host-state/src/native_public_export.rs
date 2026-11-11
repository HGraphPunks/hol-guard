//! Retrieve only the fixed worker's completed public export. The archive is
//! private and immutable on Host; its producer does not choose guest paths.
use super::{bytes, hex, sha, transport::Lima, Intent, Journal};
use crate::native_diagnostic_archive::{members, read_stable};
use crate::{HostControllerKeyPinJournal, HostNativeControlReadback};
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::io::Errno;
use serde_json::{json, Value};
use std::{fs::File, io::Write, path::PathBuf, time::Duration};

const LIMIT: usize = 128 * 1024 * 1024;
#[path = "native_storage_retirement.rs"]
mod retirement;
pub(super) use retirement::{
    run_command as run_retirement_command, verify_idle_record as verify_retirement_idle_record,
};
pub(super) fn require_private_input(path: &std::path::Path) -> Result<(), String> {
    let owner = rustix::process::geteuid().as_raw();
    let parent = path.parent().ok_or("private artifact parent required")?;
    let root = crate::private_jobs::state_root(parent, owner)
        .map_err(|_| "artifact archive requires a private0700 parent")?;
    let name = path
        .file_name()
        .ok_or("private artifact filename required")?;
    let directory = fstat(&root).map_err(|_| "private artifact parent unavailable")?;
    let file = statat(&root, name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "private artifact archive unavailable")?;
    if directory.st_mode & 0o7777 != 0o700
        || FileType::from_raw_mode(file.st_mode) != FileType::RegularFile
        || file.st_uid != owner
        || file.st_nlink != 1
        || file.st_mode & 0o7777 != 0o600
        || file.st_size < 1024
        || file.st_size > LIMIT as i64
    {
        return Err("artifact archive requires private0700 parent and0600 single-link file".into());
    }
    Ok(())
}
fn name(intent: &Intent) -> String {
    format!("{}.native-public-export.tar", intent.job())
}
fn dispatch(intent: &Intent, verified: &HostNativeControlReadback) -> Result<Value, String> {
    let observed = verified.observation();
    Ok(
        json!({"schema":"hol-gauntlet-host-native-public-export-dispatch.v1","job_id":intent.job(),"source_sha":intent.text("source_sha"),
        "intent_sha256":intent.digest()?,"host_pin_sha256":observed["host_pin_sha256"],"terminal_sha256":observed["terminal_sha256"],
        "report_sha256":observed["report_sha256"],"exporter_sha256":intent.text("worker_generation"),"read_only":true}),
    )
}
fn binding(
    intent: &Intent,
    verified: &HostNativeControlReadback,
    raw: &[u8],
) -> Result<Value, String> {
    let mut value = dispatch(intent, verified)?;
    value["schema"] = json!("hol-gauntlet-host-native-public-export.v1");
    value["archive_sha256"] = json!(sha(raw));
    value["archive_bytes"] = json!(raw.len());
    Ok(value)
}
fn safe_archive(j: &Journal, intent: &Intent) -> Result<(), String> {
    j.stable()?;
    let s = statat(&j.root, name(intent).as_str(), AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "private public-export archive unavailable")?;
    if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
        || s.st_uid != j.owner
        || s.st_nlink != 1
        || s.st_mode & 0o777 != 0o600
        || s.st_size < 1024
        || s.st_size > LIMIT as i64
    {
        return Err("private public-export archive custody unsafe".into());
    }
    Ok(())
}
fn validate_archive(
    intent: &Intent,
    verified: &HostNativeControlReadback,
    raw: &[u8],
) -> Result<(), String> {
    if raw.len() > LIMIT {
        return Err("native public export exceeds bound".into());
    }
    let files = members(raw)?;
    let index_raw = files
        .get("results.sha256.json")
        .ok_or("native public export index missing")?;
    let index: Value =
        serde_json::from_slice(index_raw).map_err(|_| "native public export index invalid")?;
    let observed = verified.observation();
    if bytes(&index)? != *index_raw
        || index.as_object().is_none_or(|o| o.len() != 14)
        || index["schema"]
            != if intent.is_live() {
                "hol-gauntlet-native-public-artifacts.v2"
            } else {
                "hol-gauntlet-native-public-artifacts.v1"
            }
        || index["source_sha"] != intent.text("source_sha")
        || index["job_id"] != intent.job()
        || index["deployment_digest"] != intent.text("deployment_digest")
        || index["worker_generation"] != intent.text("worker_generation")
        || index["preparation_sha256"] != intent.text("preparation_sha256")
        || index["control_role"] != intent.text("role")
        || index["terminal_sha256"] != observed["terminal_sha256"]
        || index["report_sha256"] != observed["report_sha256"]
        || index["execution_eligible"] != false
        || index["guard_causality_verified"] != false
        || index["model_requests"] != observed["model_requests"]
    {
        return Err("native public export index differs from original completed job".into());
    }
    let pins = index["files"]
        .as_object()
        .ok_or("native export file index absent")?;
    let metadata = index["filesystem"]
        .as_object()
        .ok_or("native export metadata index absent")?;
    if pins.len() + 1 != files.len() || metadata.len() != pins.len() {
        return Err("native export membership differs".into());
    }
    for (name, pin) in pins {
        let raw = files.get(name).ok_or("native indexed artifact absent")?;
        let meta = metadata.get(name).ok_or("native indexed metadata absent")?;
        if pin != &json!({"bytes":raw.len(),"sha256":sha(raw)})
            || meta.as_object().is_none_or(|o| o.len() != 11)
            || meta["bytes"].as_u64() != Some(raw.len() as u64)
            || meta["links"].as_u64() != Some(1)
            || ["device", "inode", "uid", "gid", "mode"]
                .iter()
                .any(|k| meta[*k].as_u64().is_none())
            || ["mtime", "mtime_nsec", "ctime", "ctime_nsec"]
                .iter()
                .any(|k| meta[*k].as_i64().is_none())
        {
            return Err("native exported artifact differs from indexed bytes or metadata".into());
        }
    }
    for (file, expected) in [
        (
            "combined/worker/report.json",
            observed["report_sha256"].as_str(),
        ),
        (
            "combined/preparation.v1.json",
            Some(intent.text("preparation_sha256")),
        ),
        (
            "combined/declaration.json",
            Some(intent.text("deployment_digest")),
        ),
    ] {
        if files
            .get(file)
            .is_none_or(|raw| Some(sha(raw).as_str()) != expected)
        {
            return Err("native export core records differ from retained Host pins".into());
        }
    }
    Ok(())
}
fn retain_archive(j: &Journal, intent: &Intent, raw: &[u8]) -> Result<(), String> {
    if raw.len() > LIMIT {
        return Err("native public export exceeds bound".into());
    }
    j.stable()?;
    let fd = openat(
        &j.root,
        name(intent).as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "native public-export destination exists or is uncertain")?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|_| "native export private mode unavailable")?;
    let mut file = File::from(fd);
    file.write_all(raw)
        .and_then(|_| file.sync_all())
        .map_err(|_| "native public-export commit uncertain")?;
    fsync(&j.root).map_err(|_| "native public-export directory commit uncertain")?;
    j.stable()
}
pub(super) fn fetch(
    j: &Journal,
    intent: &Intent,
    verified: &HostNativeControlReadback,
) -> Result<(PathBuf, String), String> {
    let mut lima = Lima::open(intent)?;
    fetch_with_lima(j, intent, verified, &mut lima)
}
fn fetch_with_lima(
    j: &Journal,
    intent: &Intent,
    verified: &HostNativeControlReadback,
    lima: &mut Lima,
) -> Result<(PathBuf, String), String> {
    j.require_dispatch(intent)?;
    let expected_dispatch = bytes(&dispatch(intent, verified)?)?;
    j.retain(intent.job(), "export-dispatch", &expected_dispatch)?;
    let path = j.path.join(name(intent));
    if !j.absent(intent.job(), "export-binding")? {
        let retained: Value = serde_json::from_slice(&j.read(intent.job(), "export-binding")?)
            .map_err(|_| "retained native export binding invalid")?;
        let digest = retained["archive_sha256"]
            .as_str()
            .filter(|s| hex(s, 64))
            .ok_or("native export digest absent")?;
        safe_archive(j, intent)?;
        let raw = read_stable(&path, digest)?;
        if bytes(&retained)? != j.read(intent.job(), "export-binding")?
            || binding(intent, verified, &raw)? != retained
        {
            return Err("retained native export differs from completed job".into());
        }
        validate_archive(intent, verified, &raw)?;
        safe_archive(j, intent)?;
        return Ok((path, digest.into()));
    }
    if !matches!(
        statat(&j.root, name(intent).as_str(), AtFlags::SYMLINK_NOFOLLOW),
        Err(Errno::NOENT)
    ) {
        return Err(
            "native export archive is unbound or partial; preserve it without replacement".into(),
        );
    }
    let keys = HostControllerKeyPinJournal::open(&j.path).map_err(|e| e.to_string())?;
    let record = keys.read(intent.job()).map_err(|e| e.to_string())?;
    if verified.observation()["host_pin_sha256"] != record.raw_sha256 {
        return Err("native export Host pin changed".into());
    }
    let p = &record.pins;
    let worker = format!(
        "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
        intent.text("worker_generation")
    );
    let mut command = lima.command(intent.text("vm"))?;
    command.args([
        worker.as_str(),
        "--export-native-host-pinned-v1",
        &p.source_sha,
        &p.job_id,
        &p.deployment_digest,
        &p.worker_generation,
        &p.started_marker_sha256,
        &p.controller_key_pin_sha256,
        &p.controller_public_key_hex,
        intent.text("preparation_sha256"),
        intent.text("role"),
        intent.text("worker_generation"),
    ]);
    let raw =
        crate::stream_process::run_streamed_command(command, &[], Duration::from_secs(180), LIMIT)
            .map_err(|_| "native public export unavailable; completed job cannot rerun")?;
    lima.recheck()?;
    if keys.read(intent.job()).map_err(|e| e.to_string())? != record
        || j.read(intent.job(), "export-dispatch")? != expected_dispatch
    {
        return Err("native export Host custody changed".into());
    }
    retain_archive(j, intent, &raw)?;
    validate_archive(intent, verified, &raw)?;
    safe_archive(j, intent)?;
    let digest = sha(&raw);
    if read_stable(&path, &digest)? != raw {
        return Err("native public archive changed during commit".into());
    }
    j.write(
        intent.job(),
        "export-binding",
        &bytes(&binding(intent, verified, &raw)?)?,
    )?;
    j.require_dispatch(intent)?;
    Ok((path, digest))
}

pub(super) fn report(j: &Journal, i: &Intent, args: &[String]) -> Result<Value, String> {
    j.require_dispatch(i)?;
    let verified = j.verify(i, &j.read(i.job(), "completion")?)?;
    let (archive, archive_sha) = if args.len() == 6 {
        require_private_input(std::path::Path::new(&args[4]))?;
        (PathBuf::from(&args[4]), args[5].clone())
    } else {
        fetch(j, i, &verified)?
    };
    let judgment = verified.judge_artifacts(
        &archive,
        &archive_sha,
        i.text("interpreter_sha256"),
        i.text("observer_sha256"),
    )?;
    let output = json!({"schema":"hol-gauntlet-host-deterministic-report.v1","job_id":i.job(),"source_sha":i.text("source_sha"),
                "intent_sha256":i.digest()?,"archive_sha256":archive_sha,"readback":verified.observation(),"independent_judgment":judgment,
                "execution_eligible":false,"qualification_eligible":false,"model_requests":0});
    j.require_dispatch(i)?;
    let raw = bytes(&output)?;
    j.retain(i.job(), &format!("judgment-{}", sha(&raw)), &raw)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};
    pub(super) fn archive(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (name, raw) in files {
            let mut header = tar::Header::new_ustar();
            header.set_size(raw.len() as u64);
            header.set_mode(0o600);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, name, raw.as_slice())
                .unwrap();
        }
        builder.into_inner().unwrap()
    }
    pub(super) struct Fixture {
        _temp: tempfile::TempDir,
        pub(super) j: Journal,
        pub(super) i: Intent,
        pub(super) verified: HostNativeControlReadback,
        pub(super) raw: Vec<u8>,
        lima: Lima,
        transport: PathBuf,
    }
    pub(super) fn fixture() -> Fixture {
        let source = "2".repeat(40);
        let prep = bytes(
            &json!({"runtime_prefix":format!("/opt/hol-gauntlet/candidates/{source}/prefix")}),
        )
        .unwrap();
        let declaration=bytes(&json!({"schema":"hol-gauntlet-native-worker-job.v7","profile":"native-host-pinned-control-v1",
            "source_sha":source,"job_id":"1".repeat(16),"worker_generation":"4".repeat(64),"preparation_sha256":sha(&prep),
            "guard":{"source_sha":source},"role":"timeout"})).unwrap();
        let (temp, expected, _, completion) =
            crate::native_control_readback::tests::fixture_with_pins(
                "timeout",
                &sha(&declaration),
                &sha(&prep),
            );
        let root = temp.path().canonicalize().unwrap();
        let j = Journal::open(&root).unwrap();
        let transport = root.join("export-lima");
        let script=b"#!/bin/sh\nprintf x >> \"$0.calls\"\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat \"$0.export\"\n";
        std::fs::write(&transport, script).unwrap();
        std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut i = super::super::tests::intent(&expected.job_id, &root);
        i.0["deployment_digest"] = json!(expected.deployment_digest);
        i.0["preparation_sha256"] = json!(sha(&prep));
        i.0["lima_sha256"] = json!(sha(script));
        j.write(i.job(), "intent", &i.raw().unwrap()).unwrap();
        j.write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
            .unwrap();
        let completion_raw = bytes(&completion).unwrap();
        j.observe(&i, "run", &completion_raw).unwrap();
        let verified = j.verify(&i, &completion_raw).unwrap();
        let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::from([
            (
                "combined/worker/report.json".into(),
                bytes(&completion["report"]).unwrap(),
            ),
            ("combined/preparation.v1.json".into(), prep),
            ("combined/declaration.json".into(), declaration),
        ]);
        let pins = files
            .iter()
            .map(|(name, raw)| (name.clone(), json!({"bytes":raw.len(),"sha256":sha(raw)})))
            .collect::<serde_json::Map<_, _>>();
        let metadata = files
            .iter()
            .enumerate()
            .map(|(n, (name, raw))| {
                (
                    name.clone(),
                    json!({"device":1,"inode":100+n,"uid":0,"gid":0,"mode":0o100600,
            "links":1,"bytes":raw.len(),"mtime":1,"mtime_nsec":0,"ctime":1,"ctime_nsec":0}),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let index = json!({"schema":"hol-gauntlet-native-public-artifacts.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
            "deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),"preparation_sha256":i.text("preparation_sha256"),
            "control_role":i.text("role"),"terminal_sha256":verified.observation()["terminal_sha256"],"report_sha256":verified.observation()["report_sha256"],
            "files":pins,"filesystem":metadata,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
        files.insert("results.sha256.json".into(), bytes(&index).unwrap());
        let raw = archive(&files);
        std::fs::write(transport.with_extension("export"), &raw).unwrap();
        let lima =
            Lima::open_path(transport.clone(), &sha(script), &i.0["transport_context"]).unwrap();
        Fixture {
            _temp: temp,
            j,
            i,
            verified,
            raw,
            lima,
            transport,
        }
    }
    #[test]
    fn fixed_public_export_is_retained_once_then_judged_without_external_assembly() {
        let mut f = fixture();
        let (path, digest) = fetch_with_lima(&f.j, &f.i, &f.verified, &mut f.lima).unwrap();
        assert_eq!(digest, sha(&f.raw));
        assert_eq!(read_stable(&path, &digest).unwrap(), f.raw);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let judgment = f
            .verified
            .judge_artifacts(
                &path,
                &digest,
                f.i.text("interpreter_sha256"),
                f.i.text("observer_sha256"),
            )
            .unwrap();
        assert_eq!(
            judgment["judgment"]["independent_grade"],
            "invalid-evidence"
        );
        assert_eq!(
            fetch_with_lima(&f.j, &f.i, &f.verified, &mut f.lima).unwrap(),
            (path.clone(), digest)
        );
        assert_eq!(
            std::fs::read(f.transport.with_extension("calls")).unwrap(),
            b"x"
        );
        let mut changed = f.raw.clone();
        changed[600] ^= 1;
        std::fs::write(&path, changed).unwrap();
        assert!(fetch_with_lima(&f.j, &f.i, &f.verified, &mut f.lima).is_err());
        assert_eq!(
            std::fs::read(f.transport.with_extension("calls")).unwrap(),
            b"x"
        );
    }
    #[test]
    fn export_rejects_wrong_completed_identity_changed_bytes_and_unbound_partial_file() {
        let mut f = fixture();
        let files = members(&f.raw).unwrap();
        for key in [
            "job_id",
            "source_sha",
            "deployment_digest",
            "worker_generation",
            "preparation_sha256",
            "control_role",
            "terminal_sha256",
            "report_sha256",
        ] {
            let mut altered = files.clone();
            let mut index: Value = serde_json::from_slice(&altered["results.sha256.json"]).unwrap();
            index[key] = json!("wrong");
            altered.insert("results.sha256.json".into(), bytes(&index).unwrap());
            assert!(
                validate_archive(&f.i, &f.verified, &archive(&altered)).is_err(),
                "{key}"
            );
        }
        let mut altered = files;
        altered.get_mut("combined/worker/report.json").unwrap()[0] ^= 1;
        assert!(validate_archive(&f.i, &f.verified, &archive(&altered)).is_err());
        std::fs::write(f.j.path.join(name(&f.i)), b"partial").unwrap();
        assert!(fetch_with_lima(&f.j, &f.i, &f.verified, &mut f.lima).is_err());
        assert!(!f.transport.with_extension("calls").exists());
        assert_eq!(
            std::fs::read(f.j.path.join(name(&f.i))).unwrap(),
            b"partial"
        );
    }
}
