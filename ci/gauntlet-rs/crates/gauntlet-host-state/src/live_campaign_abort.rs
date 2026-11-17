//! Original, never-dispatched Live preparation retirement. No inference runs.
use super::{bytes, exact, hex, parse, preparation, provisioned, sha, spec, text, Intent, Journal};
use crate::{HostControllerKeyPinJournal, HostKeyPinError};
use serde_json::{json, Value};
use std::path::Path;

const PREFIX: &str = "live-prepared-abort-";
const INTENT: &str = "live-prepared-abort-intent";
const DISPATCH: &str = "live-prepared-abort-dispatch";
const RESULT: &str = "live-prepared-abort-result";
const FIELDS: [&str; 12] = [
    "source_sha",
    "job_id",
    "deployment_digest",
    "worker_generation",
    "preparation_sha256",
    "initialization_sha256",
    "normal_preparation_receipt_sha256",
    "live_prepared_sha256",
    "storage_receipt_sha256",
    "mke2fs_sha256",
    "podman_sha256",
    "aborter_generation",
];
fn records(j: &Journal, job: &str) -> Result<Value, String> {
    let allowed = [
        "intent",
        "initialize-intent",
        "initialize-dispatch",
        "initialize-return",
        "initialize-result",
        "prepare-bundle",
        "prepare-dispatch",
        "prepare-return",
        "prepare-result",
        "live-provision-dispatch",
        "live-prepared",
    ];
    let mut values = serde_json::Map::new();
    for (count, row) in rustix::fs::Dir::read_from(&j.root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if count > 4098 {
            return Err("prepared Live abort inventory exceeds bound".into());
        }
        let row = row.map_err(|e| e.to_string())?;
        let name = row
            .file_name()
            .to_str()
            .map_err(|_| "prepared Live abort filename UTF8")?;
        if !name.starts_with(&format!("{job}.")) {
            continue;
        }
        if let Some(suffix) = allowed
            .iter()
            .find(|s| Journal::name(job, s).as_deref() == Ok(name))
        {
            values.insert((*suffix).into(), json!(sha(&j.read(job, suffix)?)));
            continue;
        }
        if let Some(suffix) = name.strip_prefix(&format!("{job}.native-{PREFIX}")) {
            let suffix = suffix
                .strip_suffix(".json")
                .ok_or("closed prepared Live abort name required")?;
            if matches!(suffix, "intent" | "dispatch" | "result")
                || suffix.strip_prefix("frame-").is_some_and(|s| hex(s, 64))
                || suffix
                    .strip_prefix("attempt-")
                    .is_some_and(|s| matches!(s, "1" | "2" | "3" | "4"))
            {
                continue;
            }
        }
        return Err("dispatch, pin, logs or unknown state blocks inert Live abort".into());
    }
    if !matches!(
        HostControllerKeyPinJournal::open(&j.path)
            .map_err(|_| "Host pin custody unavailable")?
            .read(job),
        Err(HostKeyPinError::Missing)
    ) {
        return Err("inert prepared Live abort requires an absent official Host pin".into());
    }
    j.stable()?;
    Ok(Value::Object(values))
}
pub(super) fn require_not_aborted(j: &Journal, job: &str) -> Result<(), String> {
    for (n, row) in rustix::fs::Dir::read_from(&j.root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if n > 4098 {
            return Err("prepared Live abort journal exceeds bound".into());
        }
        if row
            .map_err(|e| e.to_string())?
            .file_name()
            .to_bytes()
            .starts_with(format!("{job}.native-{PREFIX}").as_bytes())
        {
            return Err(
                "prepared Live abort permanently consumes this job; read/resume cleanup only"
                    .into(),
            );
        }
    }
    j.stable()
}
fn evidence(j: &Journal, i: &Intent) -> Result<Value, String> {
    let initial = preparation::inert_abort_initialization(j, i)?;
    let normal = preparation::require_prepared(j, i)?;
    let prepared = provisioned(j, i)?;
    let bundle = parse(&j.read(i.job(), "prepare-bundle")?)?;
    let (mut source, _) = spec()?;
    source["initial_snapshot"]["records"]
        .as_array_mut()
        .ok_or("source World records absent")?
        .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(
        json!({"initialization":initial,"normal":normal,"prepared":prepared,"bundle":bundle,"world":source["initial_snapshot"]}),
    )
}
fn context(j: &Journal, i: &Intent, generation: &str) -> Result<Value, String> {
    if !i.is_live() || !hex(generation, 64) {
        return Err("explicit original Live intent/abort generation required".into());
    }
    let host_records = records(j, i.job())?;
    let e = evidence(j, i)?;
    if e["initialization"]["intent"]["schema"]
        != "hol-gauntlet-host-native-initialization-intent.v2"
    {
        return Err("original bounded Live initialization required".into());
    }
    let pins = json!({"source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest"),"worker_generation":i.text("worker_generation"),
        "preparation_sha256":i.text("preparation_sha256"),"initialization_sha256":e["initialization"]["result"]["receipt_sha256"],
        "normal_preparation_receipt_sha256":e["normal"]["receipt_sha256"],"live_prepared_sha256":e["prepared"]["receipt_sha256"],
        "storage_receipt_sha256":e["initialization"]["result"]["receipt"]["storage"]["receipt_sha256"],
        "mke2fs_sha256":e["initialization"]["intent"]["mke2fs_sha256"],"podman_sha256":e["bundle"]["preparation"]["podman_sha256"],"aborter_generation":generation});
    if !exact(&pins, &FIELDS)
        || FIELDS.iter().any(|k| {
            !pins[*k].as_str().is_some_and(|s| {
                hex(
                    s,
                    if *k == "source_sha" {
                        40
                    } else if *k == "job_id" {
                        16
                    } else {
                        64
                    },
                )
            })
        })
    {
        return Err("complete original prepared Live abort pins required".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-host-live-prepared-abort.v1","native_intent_sha256":i.digest()?,"pins":pins,"host_records":host_records}),
    )
}
fn dispatch(f: &Value) -> Result<Vec<u8>, String> {
    bytes(
        &json!({"schema":"hol-gauntlet-host-live-prepared-abort-dispatch.v1","abort_intent_sha256":sha(&bytes(f)?),"retry_allowed":false}),
    )
}
fn verify_reply(j: &Journal, i: &Intent, f: &Value, raw: &[u8]) -> Result<Value, String> {
    let raw = raw.strip_suffix(b"\n").unwrap_or(raw);
    if raw.len() > 8192 {
        return Err("prepared Live abort receipt exceeds bound".into());
    }
    let v = parse(raw)?;
    let s = &v["snapshot"];
    let p = &f["pins"];
    let e = evidence(j, i)?;
    let initial = &e["initialization"]["result"]["receipt"];
    let mut public = serde_json::Map::new();
    for (name, value) in [
        ("initialization", initial),
        ("declaration", &e["bundle"]["declaration"]),
        ("preparation", &e["bundle"]["preparation"]),
        ("normal_preparation", &e["normal"]["receipt"]),
        ("live_prepared", &e["prepared"]["receipt"]),
        ("world_initial", &e["world"]),
    ] {
        let raw = bytes(value)?;
        public.insert(name.into(), json!({"sha256":sha(&raw),"bytes":raw.len()}));
    }
    let world = &s["world_before"];
    let db = &world["database"];
    let expected = json!({"schema":"hol-gauntlet-native-prepared-live-abort-snapshot.v1","pins":p,"workspace":initial["workspace"],
        "world_before":world,"public_records":public,"model_requests":null,"exit_code":null});
    if !exact(&v, &["schema", "snapshot", "receipt", "receipt_sha256"])
        || v["schema"] != "hol-gauntlet-native-prepared-live-abort-result.v1"
        || *s != expected
        || !exact(
            world,
            &[
                "live_prepared_sha256",
                "world_snapshot_sha256",
                "world_receipt_count",
                "database",
                "world_key_retained",
                "cleanup_key_retained",
                "live_private_inventory_exact",
            ],
        )
        || world["live_prepared_sha256"] != p["live_prepared_sha256"]
        || world["world_snapshot_sha256"] != e["prepared"]["receipt"]["world_initial_sha256"]
        || world["world_receipt_count"] != 0
        || [
            "world_key_retained",
            "cleanup_key_retained",
            "live_private_inventory_exact",
        ]
        .iter()
        .any(|k| world[*k] != true)
        || !exact(db, &["device", "inode", "uid", "gid", "mode", "links"])
        || db["device"] != initial["job_directory"]["device"]
        || db["inode"].as_u64().is_none_or(|v| v == 0)
        || db["uid"] != 0
        || db["gid"] != 0
        || db["mode"] != 0o600
        || db["links"] != 1
    {
        return Err("prepared Live abort differs from original unused public evidence".into());
    }
    let authority = json!({"schema":"hol-gauntlet-native-prepared-live-storage-authority.v1","initialization_sha256":p["initialization_sha256"],
        "storage_receipt_sha256":p["storage_receipt_sha256"],"snapshot_sha256":sha(&bytes(s)?),"podman_sha256":p["podman_sha256"]});
    let retirement = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":p["source_sha"],"job_id":p["job_id"],"worker_generation":p["worker_generation"],
        "mke2fs_sha256":p["mke2fs_sha256"],"profile":"native-v1","retirer_generation":p["aborter_generation"],"authority":authority,
        "storage_receipt_sha256":p["storage_receipt_sha256"],"archive_sha256":null});
    let receipt = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":p["source_sha"],"job_id":p["job_id"],"worker_generation":p["worker_generation"],
        "profile":"native-v1","retirer_generation":p["aborter_generation"],"retirement_intent_sha256":sha(&bytes(&retirement)?),"storage_receipt_sha256":p["storage_receipt_sha256"],
        "archive_sha256":null,"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,
        "execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    if v["receipt"] != receipt || v["receipt_sha256"] != sha(&bytes(&receipt)?) {
        return Err("prepared Live retirement differs from original storage authority".into());
    }
    Ok(v)
}
fn execute(
    j: &Journal,
    i: &Intent,
    f: &Value,
    read: bool,
    resume: bool,
    run: impl FnOnce(&[String]) -> Result<Vec<u8>, String>,
) -> Result<Value, String> {
    if context(j, i, text(&f["pins"], "aborter_generation")?)? != *f {
        return Err("prepared Live abort original custody changed".into());
    }
    if read || resume {
        if j.read(i.job(), INTENT)? != bytes(f)? {
            return Err("original prepared Live abort intent required".into());
        }
        if resume && j.absent(i.job(), DISPATCH)? {
            j.write(i.job(), DISPATCH, &dispatch(f)?)?;
        }
        if j.read(i.job(), DISPATCH)? != dispatch(f)? {
            return Err("original prepared Live abort dispatch required".into());
        }
    } else {
        require_not_aborted(j, i.job())?;
        j.write(i.job(), INTENT, &bytes(f)?)?;
        j.write(i.job(), DISPATCH, &dispatch(f)?)?;
    }
    let attempt = (1..=4)
        .find_map(
            |n| match j.absent(i.job(), &format!("{PREFIX}attempt-{n}")) {
                Ok(true) => Some(Ok(n)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            },
        )
        .transpose()?
        .ok_or("prepared Live abort read/resume bound exhausted")?;
    j.write(i.job(),&format!("{PREFIX}attempt-{attempt}"),&bytes(&json!({"schema":"hol-gauntlet-host-live-prepared-abort-attempt.v1","abort_intent_sha256":sha(&bytes(f)?),"operation":if read{"read"}else if resume{"resume"}else{"abort"}}))?)?;
    let mut argv = vec![
        format!(
            "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
            text(&f["pins"], "aborter_generation")?
        ),
        if read {
            "--read-native-prepared-live-abort-v1"
        } else {
            "--abort-native-prepared-live-storage-v1"
        }
        .into(),
    ];
    for key in FIELDS {
        argv.push(text(&f["pins"], key)?.into());
    }
    let raw = run(&argv).map_err(|_| {
        "prepared Live abort uncertain; retain original intent and use explicit read/resume"
    })?;
    j.retain(i.job(), &format!("{PREFIX}frame-{}", sha(&raw)), &raw)?;
    let v = verify_reply(j, i, f, &raw)?;
    if context(j, i, text(&f["pins"], "aborter_generation")?)? != *f {
        return Err("prepared Live abort state changed during transport".into());
    }
    j.retain(i.job(), RESULT, &bytes(&v)?)?;
    Ok(
        json!({"schema":"hol-gauntlet-host-live-prepared-aborted.v1","job_id":i.job(),"source_sha":i.text("source_sha"),
        "native_intent_sha256":i.digest()?,"abort_intent_sha256":sha(&bytes(f)?),"snapshot_sha256":sha(&bytes(&v["snapshot"])?),
        "receipt_sha256":v["receipt_sha256"],"status":"aborted-prepared-unreleased","job_consumed":true,"exit_code":null,
        "model_requests":null,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn command(args: &[String]) -> Result<Value, String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or("prepared Live abort action absent")?;
    if !matches!(
        (action, args.len()),
        ("abort-prepared", 5) | ("abort-prepared-read" | "abort-prepared-resume", 4)
    ) || !hex(&args[2], 16)
        || !hex(&args[3], 64)
        || (args.len() == 5 && !hex(&args[4], 64))
    {
        return Err("abort-prepared JOURNAL JOB LIVE_INTENT_SHA ABORTER_SHA; abort-prepared-read|abort-prepared-resume JOURNAL JOB LIVE_INTENT_SHA".into());
    }
    let mut j = Journal::open(Path::new(&args[1]))?;
    j.lock()?;
    let i = j.intent(&args[2])?;
    if !i.is_live() || i.digest()? != args[3] {
        return Err("original Live intent SHA required for inert abort".into());
    }
    let read = action == "abort-prepared-read";
    let resume = action == "abort-prepared-resume";
    let f = if read || resume {
        parse(&j.read(i.job(), INTENT)?)?
    } else {
        context(&j, &i, &args[4])?
    };
    let mut lima = super::super::transport::Lima::open(&i)?;
    execute(&j, &i, &f, read, resume, |argv| {
        preparation::inert_transport(&mut lima, i.text("vm"), argv, &[])
    })
}
pub(super) fn verify_idle_record(j: &Journal, name: &str) -> Result<(), String> {
    if let Some((job, _)) = name
        .split_once(&format!(".native-{PREFIX}"))
        .filter(|(job, _)| hex(job, 16))
    {
        let i = j.intent(job)?;
        let f = parse(&j.read(job, INTENT)?)?;
        if context(j, &i, text(&f["pins"], "aborter_generation")?)? != f
            || j.read(job, DISPATCH)? != dispatch(&f)?
        {
            return Err("orphan or changed prepared Live abort blocks new work".into());
        }
        verify_reply(j, &i, &f, &j.read(job, RESULT)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (tempfile::TempDir, Journal, Intent, Value, Value) {
        let (temp, j, i, initialized, prepared) = super::super::channel::tests::prepared_fixture();
        let f = context(&j, &i, &"9".repeat(64)).unwrap();
        let p = &f["pins"];
        let e = evidence(&j, &i).unwrap();
        let mut records = serde_json::Map::new();
        for (name, v) in [
            ("initialization", &initialized["receipt"]),
            ("declaration", &e["bundle"]["declaration"]),
            ("preparation", &e["bundle"]["preparation"]),
            ("normal_preparation", &e["normal"]["receipt"]),
            ("live_prepared", &prepared["receipt"]),
            ("world_initial", &e["world"]),
        ] {
            let raw = bytes(v).unwrap();
            records.insert(name.into(), json!({"sha256":sha(&raw),"bytes":raw.len()}));
        }
        let s = json!({"schema":"hol-gauntlet-native-prepared-live-abort-snapshot.v1","pins":p,"workspace":initialized["receipt"]["workspace"],"public_records":records,"model_requests":null,"exit_code":null,
            "world_before":{"live_prepared_sha256":p["live_prepared_sha256"],"world_snapshot_sha256":prepared["receipt"]["world_initial_sha256"],"world_receipt_count":0,"database":{"device":initialized["receipt"]["job_directory"]["device"],"inode":81,"uid":0,"gid":0,"mode":0o600,"links":1},"world_key_retained":true,"cleanup_key_retained":true,"live_private_inventory_exact":true}});
        let authority = json!({"schema":"hol-gauntlet-native-prepared-live-storage-authority.v1","initialization_sha256":p["initialization_sha256"],"storage_receipt_sha256":p["storage_receipt_sha256"],"snapshot_sha256":sha(&bytes(&s).unwrap()),"podman_sha256":p["podman_sha256"]});
        let retirement = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":p["source_sha"],"job_id":p["job_id"],"worker_generation":p["worker_generation"],"mke2fs_sha256":p["mke2fs_sha256"],"profile":"native-v1","retirer_generation":p["aborter_generation"],"authority":authority,"storage_receipt_sha256":p["storage_receipt_sha256"],"archive_sha256":null});
        let r = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":p["source_sha"],"job_id":p["job_id"],"worker_generation":p["worker_generation"],"profile":"native-v1","retirer_generation":p["aborter_generation"],"retirement_intent_sha256":sha(&bytes(&retirement).unwrap()),"storage_receipt_sha256":p["storage_receipt_sha256"],"archive_sha256":null,"partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,"job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
        let v = json!({"schema":"hol-gauntlet-native-prepared-live-abort-result.v1","snapshot":s,"receipt_sha256":sha(&bytes(&r).unwrap()),"receipt":r});
        verify_reply(&j, &i, &f, &bytes(&v).unwrap()).unwrap();
        (temp, j, i, f, v)
    }
    #[test]
    fn lost_reply_reads_original_retirement_without_workload_replay_and_bounds_attempts() {
        let (_temp, j, i, f, v) = fixture();
        assert!(execute(&j, &i, &f, false, false, |argv| {
            assert_eq!(argv.len(), 14);
            assert_eq!(argv[1], "--abort-native-prepared-live-storage-v1");
            Err("lost original reply".into())
        })
        .is_err());
        assert!(j.require_idle().is_err());
        let reopened = Journal::open(&j.path).unwrap();
        let observed = execute(&reopened, &i, &f, true, false, |argv| {
            assert_eq!(argv[1], "--read-native-prepared-live-abort-v1");
            bytes(&v)
        })
        .unwrap();
        assert!(observed["model_requests"].is_null() && observed["exit_code"].is_null());
        verify_idle_record(&reopened, &Journal::name(i.job(), RESULT).unwrap()).unwrap();
        assert!(reopened.require_idle().is_ok());
        assert!(require_not_aborted(&reopened, i.job()).is_err());
        assert!(execute(&reopened, &i, &f, false, false, |_| panic!("fresh replay")).is_err());
        for _ in 0..2 {
            execute(&reopened, &i, &f, true, false, |_| bytes(&v)).unwrap();
        }
        assert!(execute(&reopened, &i, &f, true, false, |_| panic!(
            "unbounded retry"
        ))
        .is_err());
        assert!(reopened.absent(i.job(), "dispatch").unwrap());
        assert!(reopened.absent(i.job(), "completion").unwrap());
    }
    #[test]
    fn intent_only_crash_requires_explicit_same_context_resume_before_rpc() {
        let (_temp, j, i, f, v) = fixture();
        j.write(i.job(), INTENT, &bytes(&f).unwrap()).unwrap();
        assert!(execute(&j, &i, &f, true, false, |_| panic!(
            "read cannot create dispatch"
        ))
        .is_err());
        assert!(j.absent(i.job(), DISPATCH).unwrap());
        let reopened = Journal::open(&j.path).unwrap();
        execute(&reopened, &i, &f, false, true, |argv| {
            assert!(!reopened.absent(i.job(), DISPATCH).unwrap());
            assert_eq!(argv[1], "--abort-native-prepared-live-storage-v1");
            bytes(&v)
        })
        .unwrap();
        let mut changed = f.clone();
        changed["pins"]["worker_generation"] = json!("0".repeat(64));
        assert!(execute(&reopened, &i, &changed, false, true, |_| panic!(
            "foreign original generation"
        ))
        .is_err());
    }
    #[test]
    fn used_jobs_and_rehashed_foreign_or_zero_usage_claims_refuse() {
        let (_temp, j, i, f, v) = fixture();
        for (pointer, bad) in [
            ("/snapshot/world_before/world_receipt_count", json!(1)),
            ("/snapshot/world_before/database/device", json!(0)),
            (
                "/snapshot/world_before/live_private_inventory_exact",
                json!(false),
            ),
            (
                "/snapshot/public_records/world_initial/sha256",
                json!("0".repeat(64)),
            ),
            ("/snapshot/model_requests", json!(0)),
            ("/snapshot/exit_code", json!(0)),
            ("/receipt/model_requests", json!(0)),
            ("/receipt/retirer_generation", json!("0".repeat(64))),
            ("/receipt/storage_receipt_sha256", json!("0".repeat(64))),
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            changed["receipt_sha256"] = json!(sha(&bytes(&changed["receipt"]).unwrap()));
            assert!(
                verify_reply(&j, &i, &f, &bytes(&changed).unwrap()).is_err(),
                "{pointer}"
            );
        }
        j.write(i.job(), "dispatch", &Journal::dispatch_raw(&i).unwrap())
            .unwrap();
        assert!(context(&j, &i, text(&f["pins"], "aborter_generation").unwrap()).is_err());
        assert!(execute(&j, &i, &f, false, false, |_| panic!(
            "started job cannot abort inertly"
        ))
        .is_err());
        let (_temp, j, i, f, _) = fixture();
        let pre = gauntlet_contracts::PrelaunchPrepared {
            source_sha: i.text("source_sha").into(),
            job_id: i.job().into(),
            deployment_digest: i.text("deployment_digest").into(),
            worker_generation: i.text("worker_generation").into(),
            started_marker_sha256: "7".repeat(64),
            controller_key_pin_sha256: "8".repeat(64),
            controller_public_key_hex: "1".repeat(64),
        };
        HostControllerKeyPinJournal::open(&j.path)
            .unwrap()
            .accept_prepared(&pre.to_bytes().unwrap(), &i.expected())
            .unwrap();
        assert!(j.absent(i.job(), "dispatch").unwrap());
        assert!(context(&j, &i, text(&f["pins"], "aborter_generation").unwrap()).is_err());
    }
}
