//! Inert disposal of an original prepared Live job that was never dispatched.
//! Only fixed public records leave the volume; seeds are never copied/exported.
use super::{
    admission, initialization, lifecycle, linux, resources, retain, JobStoragePins,
    JobStorageProfile,
};
use crate::{NativeJobExecution, RunReservationJournal};
use gauntlet_contracts::WorkerRequest;
use serde_json::{json, Value};
use std::{os::fd::OwnedFd, path::Path};

const SNAPSHOT: &str = "prepared-live-abort-snapshot.json";
pub(crate) const INTENT: &str = "prepared-live-abort-intent.json";
const AUTHORITY: &str = "hol-gauntlet-native-prepared-live-storage-authority.v1";
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
const RECORDS: [(&str, &str, usize); 6] = [
    ("initialization", "prepared-live-initialization.raw", 24576),
    ("declaration", "prepared-live-declaration.raw", 8192),
    ("preparation", "prepared-live-preparation.raw", 49152),
    ("normal_preparation", "prepared-live-normal.raw", 8192),
    ("live_prepared", "prepared-live-prepared.raw", 8192),
    ("world_initial", "prepared-live-world.raw", 65536),
];
fn text<'a>(p: &'a Value, key: &str) -> &'a str {
    p[key].as_str().unwrap_or("")
}
fn valid_pins(p: &Value) -> Result<(), String> {
    if p.as_object().is_none_or(|o| o.len() != FIELDS.len())
        || FIELDS.iter().any(|key| {
            !crate::hex(
                text(p, key),
                if *key == "source_sha" {
                    40
                } else if *key == "job_id" {
                    16
                } else {
                    64
                },
            )
        })
    {
        return Err("closed original prepared Live abort pins required".into());
    }
    Ok(())
}
fn parse(args: &[String]) -> Result<Value, String> {
    if args.len() != 14
        || !matches!(
            args[1].as_str(),
            "--abort-native-prepared-live-storage-v1" | "--read-native-prepared-live-abort-v1"
        )
    {
        return Err("fixed prepared Live abort arguments required".into());
    }
    let mut value = json!({});
    for (key, raw) in FIELDS.into_iter().zip(&args[2..]) {
        value[key] = json!(raw);
    }
    valid_pins(&value)?;
    Ok(value)
}
fn pins(p: &Value) -> JobStoragePins<'_> {
    JobStoragePins {
        source_sha: text(p, "source_sha"),
        job_id: text(p, "job_id"),
        worker_generation: text(p, "worker_generation"),
        mke2fs_sha256: text(p, "mke2fs_sha256"),
    }
}
fn read(slot: &OwnedFd, name: &str, bound: usize) -> Result<Option<Vec<u8>>, String> {
    crate::feature_files::read(slot, name, (0, 0), 0o600, bound)
}
fn decode(raw: &[u8]) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(raw).map_err(|_| "prepared Live abort JSON")?;
    if linux::canonical(&v)? != raw {
        return Err("canonical prepared Live abort evidence required".into());
    }
    Ok(v)
}
fn public_records(copies: &[Vec<u8>]) -> Result<Value, String> {
    if copies.len() != RECORDS.len() {
        return Err("closed public Live abort inventory required".into());
    }
    let records: serde_json::Map<String, Value> = RECORDS
        .iter()
        .zip(copies)
        .map(|((name, _, bound), raw)| {
            if raw.len() > *bound {
                return Err("public Live abort record exceeds fixed bound".to_owned());
            }
            Ok((
                (*name).into(),
                json!({"sha256":linux::sha(raw),"bytes":raw.len()}),
            ))
        })
        .collect::<Result<_, _>>()?;
    Ok(Value::Object(records))
}
fn check_snapshot(p: &Value, initial: &Value, s: &Value, copies: &[Vec<u8>]) -> Result<(), String> {
    valid_pins(p)?;
    let records = public_records(copies)?;
    let expected = json!({"schema":"hol-gauntlet-native-prepared-live-abort-snapshot.v1","pins":p,
        "workspace":initial["workspace"],"world_before":s["world_before"],"public_records":records,
        "model_requests":null,"exit_code":null});
    if copies.len() != 6 || *s != expected {
        return Err("prepared Live abort snapshot changed".into());
    }
    for (index, key) in [
        "initialization_sha256",
        "deployment_digest",
        "preparation_sha256",
        "normal_preparation_receipt_sha256",
        "live_prepared_sha256",
    ]
    .into_iter()
    .enumerate()
    {
        if linux::sha(&copies[index]) != text(p, key) {
            return Err("retained public prepared Live record changed".into());
        }
    }
    let live = decode(&copies[4])?;
    let world = &s["world_before"];
    let database = &world["database"];
    if live.as_object().is_none_or(|o| o.len() != 13)
        || live["schema"] != "hol-gauntlet-native-live-prepared.v2"
        || [
            "source_sha",
            "job_id",
            "deployment_digest",
            "worker_generation",
            "preparation_sha256",
            "normal_preparation_receipt_sha256",
        ]
        .iter()
        .any(|k| live[*k] != p[*k])
        || world.as_object().is_none_or(|o| o.len() != 7)
        || world["live_prepared_sha256"] != p["live_prepared_sha256"]
        || world["world_snapshot_sha256"] != live["world_initial_sha256"]
        || world["world_snapshot_sha256"] != linux::sha(&copies[5])
        || world["world_receipt_count"] != 0
        || [
            "world_key_retained",
            "cleanup_key_retained",
            "live_private_inventory_exact",
        ]
        .iter()
        .any(|k| world[*k] != true)
        || database.as_object().is_none_or(|o| o.len() != 6)
        || database["device"] != initial["job_directory"]["device"]
        || database["inode"].as_u64().is_none_or(|v| v == 0)
        || database["uid"] != 0
        || database["gid"] != 0
        || database["mode"] != 0o600
        || database["links"] != 1
    {
        return Err("unused original World and private inventory required".into());
    }
    decode(&copies[5])?;
    Ok(())
}
fn checked_snapshot(p: &Value, slot: &OwnedFd) -> Result<Value, String> {
    valid_pins(p)?;
    let initial = initialization(
        &pins(p),
        text(p, "initialization_sha256"),
        text(p, "storage_receipt_sha256"),
    )?;
    let raw = read(slot, SNAPSHOT, 8192)?.ok_or("original prepared Live abort snapshot absent")?;
    let s = decode(&raw)?;
    let mut copies = Vec::new();
    for (_, name, bound) in RECORDS {
        copies.push(read(slot, name, bound)?.ok_or("retained public Live abort record absent")?);
    }
    check_snapshot(p, &initial, &s, &copies)?;
    Ok(s)
}
fn capture(p: &Value) -> Result<(Value, Vec<Vec<u8>>), String> {
    let request=WorkerRequest::parse(json!({"schema":"hol-gauntlet-worker-request.v1","action":"run",
        "source_sha":p["source_sha"],"job_id":p["job_id"],"deployment_digest":p["deployment_digest"]}).to_string().as_bytes()).map_err(|e|e.to_string())?;
    let (job, preparation) = crate::native_job_io::load(&request, text(p, "worker_generation"))?;
    if !matches!(job.execution, NativeJobExecution::HostPinnedLive { .. })
        || job.preparation_sha256 != text(p, "preparation_sha256")
        || preparation.podman_sha256 != text(p, "podman_sha256")
    {
        return Err("prepared Live abort differs from original declaration/preparation".into());
    }
    let (raw, initial) = crate::native_initialize::checked_job_initialization(
        text(p, "source_sha"),
        text(p, "job_id"),
        text(p, "worker_generation"),
        false,
    )?;
    if linux::sha(&raw) != text(p, "initialization_sha256") {
        return Err("original Live initialization changed".into());
    }
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    admission::closed_inventory(
        &root,
        &[
            "workspace",
            "preparation.v1.json",
            "mcp-world.db",
            "live-private",
        ],
    )?;
    let workspace = crate::feature_files::open_directory(&root, "workspace", (10001, 10001))?;
    admission::closed_inventory(&workspace, &[])?;
    let (world_before, world) = crate::native_live_prepare::verify_unreleased_snapshot(
        &job,
        text(p, "deployment_digest"),
        text(p, "live_prepared_sha256"),
    )?;
    let live = crate::native_live_prepare::retained(&job, text(p, "deployment_digest"))?;
    let declarations = crate::open_root_owned_public_directory(Path::new(
        crate::native_job_spec::NATIVE_DEPLOYMENTS,
    ))
    .map_err(|e| e.to_string())?;
    let receipts = crate::open_root_owned_public_directory(Path::new(
        "/var/lib/hol-gauntlet-rust/native-initialization",
    ))
    .map_err(|e| e.to_string())?;
    let copies = vec![
        raw,
        crate::feature_files::required(
            &declarations,
            &format!("{}.json", text(p, "deployment_digest")),
            (0, 0),
            0o600,
            8192,
        )?,
        crate::feature_files::required(&root, "preparation.v1.json", (0, 0), 0o600, 49152)?,
        crate::feature_files::required(
            &receipts,
            &format!("{}.preparation.json", job.job_id),
            (0, 0),
            0o600,
            8192,
        )?,
        live.raw,
        linux::canonical(&world)?,
    ];
    let records = public_records(&copies)?;
    let s = json!({"schema":"hol-gauntlet-native-prepared-live-abort-snapshot.v1","pins":p,
        "workspace":initial["workspace"],"world_before":world_before,"public_records":records,"model_requests":null,"exit_code":null});
    check_snapshot(p, &initial, &s, &copies)?;
    admission::closed_inventory(
        &root,
        &[
            "workspace",
            "preparation.v1.json",
            "mcp-world.db",
            "live-private",
        ],
    )?;
    Ok((s, copies))
}
pub(super) fn authority_mode(
    a: &Value,
    p: &JobStoragePins<'_>,
    profile: JobStorageProfile,
    storage: Option<&str>,
    archive: Option<&str>,
) -> Result<bool, String> {
    if a["schema"] != AUTHORITY {
        return Ok(false);
    }
    if profile != JobStorageProfile::Native
        || archive.is_some()
        || storage != a["storage_receipt_sha256"].as_str()
        || a.as_object().is_none_or(|o| o.len() != 5)
        || [
            "initialization_sha256",
            "storage_receipt_sha256",
            "snapshot_sha256",
            "podman_sha256",
        ]
        .iter()
        .any(|k| !a[*k].as_str().is_some_and(|s| crate::hex(s, 64)))
    {
        return Err("closed prepared Live abort authority required".into());
    }
    let slot = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(p.job_id))
        .map_err(|e| e.to_string())?;
    let intent = read(&slot, INTENT, 8192)?.ok_or("original prepared Live abort intent absent")?;
    let original = decode(&intent)?;
    if original["schema"] != "hol-gauntlet-native-prepared-live-abort-intent.v1"
        || original.as_object().is_none_or(|o| o.len() != 2)
    {
        return Err("exact original prepared Live abort intent required".into());
    }
    let selected = &original["pins"];
    if selected["source_sha"] != p.source_sha
        || selected["job_id"] != p.job_id
        || selected["worker_generation"] != p.worker_generation
        || selected["mke2fs_sha256"] != p.mke2fs_sha256
        || selected["initialization_sha256"] != a["initialization_sha256"]
        || selected["storage_receipt_sha256"] != a["storage_receipt_sha256"]
        || selected["podman_sha256"] != a["podman_sha256"]
    {
        return Err("prepared Live abort authority differs from original pins".into());
    }
    let snapshot = checked_snapshot(selected, &slot)?;
    if linux::sha(&linux::canonical(&snapshot)?) != a["snapshot_sha256"] {
        return Err("prepared Live abort snapshot authority changed".into());
    }
    Ok(true)
}
pub fn abort_prepared_native_live_storage(args: &[String]) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let p = parse(args)?;
    crate::verify_running_binary(text(&p, "aborter_generation")).map_err(|e| e.to_string())?;
    let epoch = crate::native_worker::interruption_epoch();
    let _scope = super::super::super::owner::scope()?;
    let pin = pins(&p);
    initialization(
        &pin,
        text(&p, "initialization_sha256"),
        text(&p, "storage_receipt_sha256"),
    )?;
    let slot =
        crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(pin.job_id))
            .map_err(|e| e.to_string())?;
    let publish = args[1] == "--abort-native-prepared-live-storage-v1";
    let intent = linux::canonical(
        &json!({"schema":"hol-gauntlet-native-prepared-live-abort-intent.v1","pins":p}),
    )?;
    if read(&slot, INTENT, 8192)?.is_some_and(|old| old != intent) {
        return Err("original prepared Live abort intent changed".into());
    }
    if read(&slot, SNAPSHOT, 8192)?.is_none() {
        if !publish {
            return Err("prepared Live abort read cannot create a snapshot".into());
        }
        let j = RunReservationJournal::open_root_owned(Path::new(
            crate::builder_image_context::RUST_STATE,
        ))
        .map_err(|e| e.to_string())?;
        let active = j.acquire_active_lease().map_err(|e| e.to_string())?;
        let python =
            crate::builder_image_context::python_worker_lock().map_err(|e| e.to_string())?;
        resources(&pin, text(&p, "podman_sha256"), &j)?;
        let (snapshot, copies) = capture(&p)?;
        super::epoch_unchanged(epoch)?;
        retain(&slot, INTENT, &intent)?;
        for ((_, name, _), raw) in RECORDS.iter().zip(&copies) {
            retain(&slot, name, raw)?;
        }
        retain(&slot, SNAPSHOT, &linux::canonical(&snapshot)?)?;
        active.verify(&j.root).map_err(|e| e.to_string())?;
        crate::builder_image_context::verify_python_lock(&python).map_err(|e| e.to_string())?;
    }
    if read(&slot, INTENT, 8192)?.as_deref() != Some(intent.as_slice()) {
        return Err("original prepared Live abort intent missing".into());
    }
    let snapshot = checked_snapshot(&p, &slot)?;
    let authority = json!({"schema":AUTHORITY,"initialization_sha256":p["initialization_sha256"],
        "storage_receipt_sha256":p["storage_receipt_sha256"],"snapshot_sha256":linux::sha(&linux::canonical(&snapshot)?),"podman_sha256":p["podman_sha256"]});
    super::epoch_unchanged(epoch)?;
    let raw = super::super::super::retire::retire(
        &pin,
        JobStorageProfile::Native,
        authority,
        Some(text(&p, "storage_receipt_sha256")),
        None,
        text(&p, "aborter_generation"),
        publish,
        || {
            super::epoch_unchanged(epoch)?;
            if super::super::super::retire::mount_row(&JobStorageProfile::Native.root(pin.job_id)?)?
                .is_some()
                && capture(&p)?.0 != snapshot
            {
                return Err("original prepared Live changed after snapshot".into());
            }
            Ok(())
        },
    )?;
    super::epoch_unchanged(epoch)?;
    linux::canonical(
        &json!({"schema":"hol-gauntlet-native-prepared-live-abort-result.v1","snapshot":snapshot,"receipt":decode(&raw)?,"receipt_sha256":linux::sha(&raw)}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Vec<Vec<u8>>) {
        let mut p = json!({});
        for key in FIELDS {
            p[key] = json!("a".repeat(if key == "source_sha" {
                40
            } else if key == "job_id" {
                16
            } else {
                64
            }));
        }
        let initial = json!({"workspace":{"device":7,"inode":20},"job_directory":{"device":7}});
        let mut copies = vec![
            linux::canonical(&initial).unwrap(),
            b"{}".to_vec(),
            b"{}".to_vec(),
            b"{}".to_vec(),
        ];
        for (index, key) in [
            "initialization_sha256",
            "deployment_digest",
            "preparation_sha256",
            "normal_preparation_receipt_sha256",
        ]
        .into_iter()
        .enumerate()
        {
            p[key] = json!(linux::sha(&copies[index]));
        }
        let world = linux::canonical(&json!({"records":[]})).unwrap();
        let live = json!({"schema":"hol-gauntlet-native-live-prepared.v2","source_sha":p["source_sha"],"job_id":p["job_id"],
            "deployment_digest":p["deployment_digest"],"worker_generation":p["worker_generation"],"preparation_sha256":p["preparation_sha256"],
            "normal_preparation_receipt_sha256":p["normal_preparation_receipt_sha256"],"role":"feature-ai-protected","cell_id":"source-cell",
            "spec_sha256":"b".repeat(64),"world_public_key_hex":"c".repeat(64),"world_initial_sha256":linux::sha(&world),"cleanup_public_key_hex":"d".repeat(64)});
        copies.push(linux::canonical(&live).unwrap());
        p["live_prepared_sha256"] = json!(linux::sha(&copies[4]));
        copies.push(world);
        let records = public_records(&copies).unwrap();
        let s = json!({"schema":"hol-gauntlet-native-prepared-live-abort-snapshot.v1","pins":p,"workspace":initial["workspace"],
            "world_before":{"live_prepared_sha256":p["live_prepared_sha256"],"world_snapshot_sha256":linux::sha(&copies[5]),"world_receipt_count":0,
            "database":{"device":7,"inode":21,"uid":0,"gid":0,"mode":0o600,"links":1},
            "world_key_retained":true,"cleanup_key_retained":true,"live_private_inventory_exact":true},
            "public_records":records,"model_requests":null,"exit_code":null});
        (p, initial, s, copies)
    }
    #[test]
    fn preserved_snapshot_refuses_used_foreign_or_rewritten_state() {
        let (p, initial, s, copies) = fixture();
        check_snapshot(&p, &initial, &s, &copies).unwrap();
        for (pointer, bad) in [
            ("/world_before/world_receipt_count", json!(1)),
            ("/world_before/database/device", json!(8)),
            ("/world_before/live_private_inventory_exact", json!(false)),
            ("/workspace/inode", json!(99)),
            ("/model_requests", json!(0)),
            ("/exit_code", json!(0)),
            ("/public_records/preparation/sha256", json!("0".repeat(64))),
        ] {
            let mut changed = s.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(
                check_snapshot(&p, &initial, &changed, &copies).is_err(),
                "{pointer}"
            );
        }
        for index in 0..copies.len() {
            let mut changed = copies.clone();
            changed[index].push(b' ');
            assert!(check_snapshot(&p, &initial, &s, &changed).is_err());
        }
    }
    #[test]
    fn read_and_resume_require_closed_original_generation_and_full_pins() {
        let (p, _, _, _) = fixture();
        let mut args = vec![
            "worker".into(),
            "--read-native-prepared-live-abort-v1".into(),
        ];
        for key in FIELDS {
            args.push(text(&p, key).into());
        }
        assert_eq!(parse(&args).unwrap(), p);
        for index in 2..args.len() {
            let mut changed = args.clone();
            changed[index] = "not-a-pin".into();
            assert!(parse(&changed).is_err());
        }
        args[1] = "--abort-native-initialization-v1".into();
        assert!(parse(&args).is_err());
        let mut extra = p.clone();
        extra["extra"] = json!("refuse");
        assert!(valid_pins(&extra).is_err());
    }
}
