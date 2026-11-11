//! Closed public storage claims, pinned before dispatch and reobserved by Root.
use super::{bytes, hex, sha, Journal};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
pub(in crate::native_operation::preparation) fn verify_abort(
    i: &super::Initialization,
    initial: &Value,
    a: &Value,
    raw: &[u8],
) -> Result<Value, String> {
    let frame = raw.strip_suffix(b"\n").unwrap_or(raw);
    let v: Value =
        serde_json::from_slice(frame).map_err(|_| "initialization abort JSON invalid")?;
    let s = &v["snapshot"];
    let p = &s["preparation"];
    if frame.len() > 8192
        || bytes(&v)? != frame
        || v.as_object().is_none_or(|o| o.len() != 4)
        || v["schema"] != "hol-gauntlet-native-initialization-abort-result.v1"
        || s != &json!({"schema":"hol-gauntlet-native-unstarted-snapshot.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
            "worker_generation":i.text("worker_generation"),"initialization_sha256":a["initialization_sha256"],
            "storage_receipt_sha256":a["storage_receipt_sha256"],"workspace":initial["receipt"]["workspace"],"preparation":p})
    {
        return Err("abort snapshot differs from original initialization".into());
    }
    if !p.is_null()
        && (p.as_object().is_none_or(|o| o.len() != 8)
            || !p["sha256"].as_str().is_some_and(|s| hex(s, 64))
            || p["bytes"].as_u64().is_none_or(|n| n > 49152)
            || p["device"].as_u64().is_none()
            || p["inode"].as_u64().is_none_or(|n| n == 0)
            || p["uid"] != 0
            || p["gid"] != 0
            || p["mode"] != 0o600
            || p["links"] != 1)
    {
        return Err("bounded preserved preparation metadata required".into());
    }
    let authority = json!({"schema":"hol-gauntlet-native-unstarted-storage-authority.v1","initialization_sha256":a["initialization_sha256"],
        "storage_receipt_sha256":a["storage_receipt_sha256"],"snapshot_sha256":sha(&bytes(s)?),"podman_sha256":a["podman_sha256"]});
    let context = json!({"schema":"hol-gauntlet-job-storage-retirement-intent.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
        "worker_generation":i.text("worker_generation"),"mke2fs_sha256":i.text("mke2fs_sha256"),"profile":"native-v1",
        "retirer_generation":a["aborter_generation"],"authority":authority,"storage_receipt_sha256":a["storage_receipt_sha256"],"archive_sha256":null});
    let expected = json!({"schema":"hol-gauntlet-job-storage-retired.v1","source_sha":i.text("source_sha"),"job_id":i.job(),
        "worker_generation":i.text("worker_generation"),"profile":"native-v1","retirer_generation":a["aborter_generation"],
        "retirement_intent_sha256":sha(&bytes(&context)?),"storage_receipt_sha256":a["storage_receipt_sha256"],"archive_sha256":null,
        "partial":false,"volume_unmounted":true,"loop_detached":true,"backing_absent":true,"retained_storage":false,
        "job_consumed":true,"execution_eligible":false,"qualification_eligible":false,"model_requests":null});
    if v["receipt"] != expected || v["receipt_sha256"] != sha(&bytes(&expected)?) {
        return Err("unstarted retirement differs from original authority".into());
    }
    Ok(v)
}

fn closed(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.len() == fields.len() && fields.iter().all(|k| o.contains_key(*k)))
}
fn root_directory(value: &Value) -> bool {
    closed(value, &["device", "inode", "uid", "gid", "mode"])
        && value["device"].as_u64().is_some()
        && value["inode"].as_u64().is_some_and(|n| n > 0)
        && value["uid"] == 0
        && value["gid"] == 0
        && value["mode"] == 448
}

/// Validate the public storage claim against pre-dispatch operator pins. Root
/// separately reobserves its loop, backing descriptor and kernel mount state.
pub(crate) fn verify(
    value: &Value,
    source: &str,
    job: &str,
    worker: &str,
    formatter: &str,
    profile: &str,
) -> Result<(), String> {
    let (gib, inodes, format_inodes, base) = match profile {
        "native-v1" => (
            2_u64,
            65536_u64,
            65536_u64,
            "/var/lib/hol-gauntlet-rust/native-jobs",
        ),
        "build-v1" => (12, 262144, 261120, "/var/lib/hol-gauntlet/builds"),
        "dependency-v1" => (4, 131072, 131072, "/var/lib/hol-gauntlet/builds"),
        _ => return Err("closed bounded-storage profile required".into()),
    };
    let capacity = gib * 1024 * 1024 * 1024;
    let r = &value["receipt"];
    if !hex(source, 40)
        || !hex(job, 16)
        || !hex(worker, 64)
        || !hex(formatter, 64)
        || !closed(value, &["receipt_sha256", "receipt"])
        || value["receipt_sha256"] != sha(&bytes(r)?)
        || !closed(
            r,
            &[
                "schema",
                "source_sha",
                "job_id",
                "worker_generation",
                "profile",
                "limits",
                "backing",
                "filesystem",
                "loop",
                "mount",
                "namespace",
                "namespace_owner",
                "boot_id",
                "root_directory",
                "covered_directory",
                "mke2fs_sha256",
                "formatter",
                "storage_state",
                "execution_eligible",
                "qualification_eligible",
            ],
        )
        || r["schema"] != "hol-gauntlet-job-storage.v2"
        || r["source_sha"] != source
        || r["job_id"] != job
        || r["worker_generation"] != worker
        || r["mke2fs_sha256"] != formatter
        || r["profile"] != profile
        || r["storage_state"] != "retained-mounted-rw"
        || r["execution_eligible"] != false
        || r["qualification_eligible"] != false
        || r["limits"]
            != json!({"schema":"hol-gauntlet-job-storage-limits.v1","profile":profile,
            "bytes":capacity,"inodes":inodes,"format_inodes":format_inodes,"block_size":4096})
    {
        return Err("bounded storage differs from outside identity or exact finite limits".into());
    }
    let b = &r["backing"];
    let l = &r["loop"];
    let m = &r["mount"];
    let number = l["number"]
        .as_u64()
        .filter(|n| *n <= 0x0f_ffff)
        .ok_or("bounded Linux loop number required")?;
    // Linux's device encoding, independent of the macOS host's dev_t layout.
    let device = (number & 0xff) | (7 << 8) | ((number & !0xff) << 12);
    let mount_source = m["source"].as_str().is_some_and(|source| {
        source == format!("/dev/loop{number}")
            || source
                .strip_prefix("/proc/self/fd/")
                .and_then(|s| {
                    s.parse::<u32>()
                        .ok()
                        .filter(|n| *n > 2 && n.to_string() == s)
                })
                .is_some()
    });
    let mut uuid = Sha256::digest(bytes(
        &json!({"source":source,"job":job,"worker":worker,"profile":profile}),
    )?);
    uuid[6] = (uuid[6] & 15) | 64;
    uuid[8] = (uuid[8] & 63) | 128;
    let uuid = uuid[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let boot = r["boot_id"].as_str().unwrap_or("");
    let boot_valid = boot.len() == 36
        && boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b"0123456789abcdef".contains(&b)
            }
        });
    if !closed(
        b,
        &[
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "links",
            "bytes",
            "allocated_bytes",
        ],
    ) || b["device"].as_u64().is_none()
        || b["inode"].as_u64().is_none_or(|n| n == 0)
        || b["uid"] != 0
        || b["gid"] != 0
        || b["mode"] != 384
        || b["links"] != 1
        || b["bytes"] != capacity
        || b["allocated_bytes"].as_u64().is_none_or(|n| n < capacity)
        || r["filesystem"]
            != json!({"kind":"ext4","uuid":uuid,"block_size":4096,
            "blocks":capacity/4096,"inodes":format_inodes})
        || l != &json!({"number":number,"device":device,"backing_device":b["device"],
            "backing_inode":b["inode"],"offset":0,"bytes":capacity,"flags":4})
        || !closed(
            m,
            &[
                "id", "target", "device", "source", "private", "readonly", "nosuid", "nodev",
                "noatime",
            ],
        )
        || m["id"].as_u64().is_none_or(|n| n == 0)
        || m["target"] != format!("{base}/{job}")
        || m["device"] != format!("7:{number}")
        || !mount_source
        || m["private"] != true
        || m["readonly"] != false
        || m["nosuid"] != true
        || m["nodev"] != true
        || m["noatime"] != true
        || !boot_valid
        || !closed(&r["namespace"], &["device", "inode"])
        || r["namespace"]["device"].as_u64().is_none()
        || r["namespace"]["inode"].as_u64().is_none_or(|n| n == 0)
        || !root_directory(&r["root_directory"])
        || !root_directory(&r["covered_directory"])
        || r["root_directory"]["device"] != device
        || r["root_directory"]["inode"] != 2
        || r["covered_directory"]["device"] != b["device"]
        || !closed(
            &r["formatter"],
            &[
                "exit_code",
                "stdout_sha256",
                "stderr_sha256",
                "configuration_sha256",
            ],
        )
        || r["formatter"]["exit_code"] != 0
        || ["stdout_sha256", "stderr_sha256", "configuration_sha256"]
            .iter()
            .any(|k| !r["formatter"][*k].as_str().is_some_and(|s| hex(s, 64)))
        || r["formatter"]["configuration_sha256"]
            != "4a877aafc4c028c553448ee5dd03edc6775544fa609e41c213373c55951389cf"
    {
        return Err("bounded volume custody, allocation or kernel filesystem claim differs".into());
    }
    verify_namespace_owner(r, source, job, worker)?;
    Ok(())
}

fn verify_namespace_owner(r: &Value, source: &str, job: &str, worker: &str) -> Result<(), String> {
    let owner = &r["namespace_owner"];
    let process = &owner["process"];
    let cgroup = &owner["cgroup"];
    let original = &owner["original_namespace"];
    let started = owner["started_boottime_ns"].as_u64();
    let deadline = owner["deadline_boottime_ns"].as_u64();
    if !closed(
        owner,
        &[
            "schema",
            "source_sha",
            "job_id",
            "worker_generation",
            "owner_nonce_hex",
            "boot_id",
            "process",
            "executable_sha256",
            "cgroup",
            "namespace",
            "original_namespace",
            "started_boottime_ns",
            "deadline_boottime_ns",
            "state",
        ],
    ) || owner["schema"] != "hol-gauntlet-job-storage-namespace-owner.v1"
        || owner["source_sha"] != source
        || owner["job_id"] != job
        || owner["worker_generation"] != worker
        || !owner["owner_nonce_hex"]
            .as_str()
            .is_some_and(|s| hex(s, 32))
        || owner["boot_id"] != r["boot_id"]
        || owner["executable_sha256"] != worker
        || owner["namespace"] != r["namespace"]
        || owner["namespace"] == *original
        || owner["state"] != "retained"
        || !closed(process, &["pid", "start_ticks"])
        || process["pid"]
            .as_u64()
            .is_none_or(|n| !(2..=u32::MAX as u64).contains(&n))
        || process["start_ticks"].as_u64().is_none_or(|n| n == 0)
        || !closed(cgroup, &["path", "device", "inode"])
        || cgroup["path"] != format!("/system.slice/hol-gauntlet-rust-storage-owner-{job}")
        || cgroup["device"].as_u64().is_none()
        || cgroup["inode"].as_u64().is_none_or(|n| n == 0)
        || !closed(original, &["device", "inode"])
        || original["device"].as_u64().is_none()
        || original["inode"].as_u64().is_none_or(|n| n == 0)
        || started.is_none_or(|n| n == 0)
        || started.and_then(|n| n.checked_add(86_400_000_000_000)) != deadline
    {
        return Err("bounded storage namespace owner differs from original source/job/worker or finite lifetime".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn fixture(
    source: &str,
    job: &str,
    worker: &str,
    formatter: &str,
    profile: &str,
) -> Value {
    let (gib, inodes, format_inodes, base) = match profile {
        "native-v1" => (
            2_u64,
            65536_u64,
            65536_u64,
            "/var/lib/hol-gauntlet-rust/native-jobs",
        ),
        "build-v1" => (12, 262144, 261120, "/var/lib/hol-gauntlet/builds"),
        "dependency-v1" => (4, 131072, 131072, "/var/lib/hol-gauntlet/builds"),
        _ => panic!("closed test storage profile required"),
    };
    let mut uuid = Sha256::digest(
        bytes(&json!({"source":source,"job":job,"worker":worker,"profile":profile})).unwrap(),
    );
    uuid[6] = (uuid[6] & 15) | 64;
    uuid[8] = (uuid[8] & 63) | 128;
    let uuid = uuid[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let capacity = gib * 1024 * 1024 * 1024;
    let boot = "12345678-1234-1234-1234-123456789abc";
    let namespace = json!({"device":4,"inode":700});
    let owner = json!({"schema":"hol-gauntlet-job-storage-namespace-owner.v1","source_sha":source,"job_id":job,"worker_generation":worker,
        "owner_nonce_hex":"a".repeat(32),"boot_id":boot,"process":{"pid":102,"start_ticks":50},"executable_sha256":worker,
        "cgroup":{"path":format!("/system.slice/hol-gauntlet-rust-storage-owner-{job}"),"device":5,"inode":401},
        "namespace":namespace,"original_namespace":{"device":4,"inode":600},"started_boottime_ns":1,"deadline_boottime_ns":86_400_000_000_001_u64,"state":"retained"});
    let receipt = json!({"schema":"hol-gauntlet-job-storage.v2","source_sha":source,"job_id":job,"worker_generation":worker,"profile":profile,
        "limits":{"schema":"hol-gauntlet-job-storage-limits.v1","profile":profile,"bytes":capacity,"inodes":inodes,"format_inodes":format_inodes,"block_size":4096},
        "backing":{"device":21,"inode":80,"uid":0,"gid":0,"mode":384,"links":1,"bytes":capacity,"allocated_bytes":capacity},
        "filesystem":{"kind":"ext4","uuid":uuid,"block_size":4096,"blocks":capacity/4096,"inodes":format_inodes},
        "loop":{"number":3,"device":1795,"backing_device":21,"backing_inode":80,"offset":0,"bytes":capacity,"flags":4},
        "mount":{"id":42,"target":format!("{base}/{job}"),"device":"7:3","source":"/dev/loop3","private":true,"readonly":false,"nosuid":true,"nodev":true,"noatime":true},
        "namespace":namespace,"namespace_owner":owner,"boot_id":boot,
        "root_directory":{"device":1795,"inode":2,"uid":0,"gid":0,"mode":448},"covered_directory":{"device":21,"inode":51,"uid":0,"gid":0,"mode":448},
        "mke2fs_sha256":formatter,"formatter":{"exit_code":0,"stdout_sha256":"1".repeat(64),"stderr_sha256":"2".repeat(64),"configuration_sha256":"4a877aafc4c028c553448ee5dd03edc6775544fa609e41c213373c55951389cf"},
        "storage_state":"retained-mounted-rw","execution_eligible":false,"qualification_eligible":false});
    json!({"receipt_sha256":sha(&bytes(&receipt).unwrap()),"receipt":receipt})
}

pub(in crate::native_operation::preparation) fn require_not_aborted(
    j: &Journal,
    job: &str,
) -> Result<(), String> {
    let prefix = format!("{job}.native-initialize-abort-");
    for (n, row) in rustix::fs::Dir::read_from(&j.root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if n > 4098 {
            return Err("initialization abort journal bound".into());
        }
        if row
            .map_err(|e| e.to_string())?
            .file_name()
            .to_bytes()
            .starts_with(prefix.as_bytes())
        {
            return Err("native initialization abort consumes this job permanently".into());
        }
    }
    j.stable()
}
pub(super) fn abort_records(j: &Journal, job: &str, unreleased: bool) -> Result<Value, String> {
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
    ];
    let prefix = format!("{job}.");
    let mut out = serde_json::Map::new();
    for (n, row) in rustix::fs::Dir::read_from(&j.root)
        .map_err(|e| e.to_string())?
        .enumerate()
    {
        if n > 4098 {
            return Err("initialization abort journal bound".into());
        }
        let row = row.map_err(|e| e.to_string())?;
        let name = row
            .file_name()
            .to_str()
            .map_err(|_| "abort filename UTF8")?;
        if !name.starts_with(&prefix) {
            continue;
        }
        if unreleased && Journal::name(job, "dispatch").as_deref() == Ok(name) {
            out.insert("dispatch".into(), json!(sha(&j.read(job, "dispatch")?)));
            continue;
        }
        if let Some(s) = allowed
            .iter()
            .find(|s| Journal::name(job, s).as_deref() == Ok(name))
        {
            out.insert((*s).into(), json!(sha(&j.read(job, s)?)));
            continue;
        }
        if ["intent", "dispatch", "return", "result"]
            .iter()
            .any(|s| Journal::name(job, &format!("initialize-abort-{s}")).as_deref() == Ok(name))
        {
            continue;
        }
        if name
            .strip_prefix(&format!("{job}.native-initialize-abort-frame-"))
            .and_then(|s| s.strip_suffix(".json"))
            .is_some_and(|s| hex(s, 64))
        {
            continue;
        }
        return Err(
            "run, prelaunch, provision, turn or unknown state blocks initialization abort".into(),
        );
    }
    j.stable()?;
    Ok(Value::Object(out))
}
