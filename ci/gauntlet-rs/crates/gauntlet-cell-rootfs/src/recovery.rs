//! Recovery of a journaled image after all product processes have disappeared.
//! Live/uncertain services, profiles or mounts require a different repair path.
use crate::image_process::{run, Operation};
use crate::supervisor_cleanup::absent;
use crate::{fs_input, hash, CellPreparation, Result, RootfsSpec, SupervisorSpec};
use serde_json::{json, Value};
use std::path::Path;

struct Retained {
    system: crate::declarations::System,
    facts: Value,
}

fn retained(spec: &CellPreparation) -> Result<Retained> {
    retained_history(spec, false)
}

fn retained_history(spec: &CellPreparation, closed: bool) -> Result<Retained> {
    crate::kernel_process::root_proc()?;
    fs_input::directory(&spec.stage)?;
    let image_raw = fs_input::read(
        &spec.stage.join("native-image-events.v1.jsonl"),
        64 * 1024 * 1024,
    )?;
    let image = crate::recovery_protocol::events(&image_raw)?;
    // The closed profile is read-only and never confers mount ownership. The
    // historical repair profile still accepts exactly its four pending rows.
    if image.len() != if closed { 6 } else { 4 }
        || image[0]["kind"] != "image-reserved"
        || image[0]["data"]
            != json!({"image_id":spec.image_id,"podman_sha256":spec.podman_sha256,"stage":spec.stage})
        || image[1]["kind"] != "image-acquiring"
        || image[1]["data"] != json!({"image_id":spec.image_id})
        || image[2]["kind"] != "image-mounted"
        || image[3]["kind"] != "image-cell-launch-pending"
        || image[3]["data"] != json!({"image_id":spec.image_id})
    {
        return Err("retained image history does not authorize quiescent recovery".into());
    }
    if closed {
        crate::recovery_protocol::closed_image(&image, &spec.image_id)?;
    }
    let raw = fs_input::read(&spec.stage.join("native-rootfs.v1.json"), 8192)?;
    let rootfs = RootfsSpec::parse(&raw, &hash(&raw))?;
    if rootfs.stage != spec.stage
        || rootfs.artifact_manifest_sha256 != spec.artifact_manifest_sha256
        || rootfs.initializer_sha256 != spec.initializer_sha256
    {
        return Err("retained rootfs differs from native job preparation".into());
    }
    let system_raw = fs_input::pinned(
        &spec.stage.join("system.json"),
        4096,
        &rootfs.system_spec_sha256,
    )?;
    let system = crate::declarations::System::parse(&system_raw)?;
    let image_record = json!({"image_id":spec.image_id,"root":system.root,"device":system.device,"inode":system.inode});
    if image[2]["data"] != image_record {
        return Err("retained image mount differs from rootfs declaration".into());
    }
    let runtime_raw = fs_input::pinned(
        &spec.stage.join("runtime.json"),
        8192,
        &rootfs.runtime_spec_sha256,
    )?;
    let runtime: Value = serde_json::from_slice(&runtime_raw).map_err(|e| e.to_string())?;
    let task_raw = fs_input::pinned(
        &spec.stage.join("task-mounts.json"),
        32768,
        &rootfs.task_spec_sha256,
    )?;
    let tasks: Value = serde_json::from_slice(&task_raw).map_err(|e| e.to_string())?;
    if runtime != spec.runtime() || tasks != spec.task_mounts {
        return Err("retained task/runtime declarations changed".into());
    }
    let supervisor_raw = fs_input::read(&spec.stage.join("native-supervisor.v1.json"), 8192)?;
    let supervisor = SupervisorSpec::parse(&supervisor_raw, &hash(&supervisor_raw))?;
    let value: Value = serde_json::from_slice(&supervisor_raw).map_err(|e| e.to_string())?;
    if value != spec.supervisor(&hash(&raw))? {
        return Err("retained supervisor differs from preparation".into());
    }
    let events_raw = fs_input::read(
        &spec.stage.join("native-supervisor-events.v1.jsonl"),
        64 * 1024 * 1024,
    )?;
    let records = crate::recovery_protocol::events(&events_raw)?;
    if closed {
        crate::recovery_protocol::closed_supervisor(&records)?;
    }
    let first = &records[0];
    let profile = first["data"]["profile"]
        .as_str()
        .ok_or("retained profile missing")?;
    let cgroup = supervisor.cgroup_path(profile)?;
    if first["kind"] != "prepared"
        || first["data"]["cgroup"] != cgroup.to_string_lossy().as_ref()
        || first["data"]["rootfs_declaration_sha256"] != hash(&raw)
        || first["data"]["supervisor_declaration_sha256"] != hash(&supervisor_raw)
        || first["data"]["constructor_sha256"] != supervisor.constructor_sha256
        || first["data"]["execution_eligible"] != false
    {
        return Err("retained supervisor ownership differs from native job".into());
    }
    if !absent(&cgroup)? {
        return Err("product cgroup remains; quiescent repair refused".into());
    }
    if let Some(slice) = spec.job_slice() {
        if !absent(&Path::new("/sys/fs/cgroup").join(slice))? {
            return Err("product slice remains; quiescent repair refused".into());
        }
    }
    let mounts = String::from_utf8(crate::supervisor_io::kernel_file(
        Path::new("/proc/self/mountinfo"),
        2 * 1024 * 1024,
    )?)
    .map_err(|_| "mountinfo UTF-8")?;
    let target = spec
        .stage
        .join("rootfs")
        .to_string_lossy()
        .replace('\\', "\\134")
        .replace(' ', "\\040");
    if mounts.lines().any(|line| {
        line.split_ascii_whitespace()
            .nth(4)
            .is_some_and(|p| p == target || p.starts_with(&(target.clone() + "/")))
    }) {
        return Err("product rootfs mount remains; quiescent repair refused".into());
    }
    let profiles = String::from_utf8(crate::supervisor_io::kernel_file(
        Path::new("/sys/kernel/security/apparmor/profiles"),
        1024 * 1024,
    )?)
    .map_err(|_| "AppArmor inventory UTF-8")?;
    if profiles
        .lines()
        .any(|s| s.split_ascii_whitespace().next() == Some(profile))
    {
        return Err("product profile remains; quiescent repair refused".into());
    }
    let tree = gauntlet_evidence::inventory_tree(
        &spec.runtime_prefix,
        gauntlet_evidence::TreeKind::InstalledPrefix,
    )
    .map_err(|e| e.to_string())?;
    if tree.digest != spec.runtime_tree_digest {
        return Err("runtime changed before recovery".into());
    }
    Ok(Retained {
        system,
        facts: json!({"image_events_sha256":hash(&image_raw),"supervisor_events_sha256":hash(&events_raw),
        "rootfs_declaration_sha256":hash(&raw),"supervisor_declaration_sha256":hash(&supervisor_raw),"profile":profile,
        "product_cgroup_absent":true,"product_slice_absent":true,"rootfs_mount_absent":true,"apparmor_profile_absent":true,
        "runtime_tree_digest":tree.digest,"image_id":spec.image_id}),
    })
}

pub fn verify_quiescent_preparation(spec: &CellPreparation) -> Result<Value> {
    let retained = retained(spec)?;
    crate::require_image_lease_absent(&spec.image_id, &spec.podman_sha256)?;
    Ok(retained.facts)
}

/// Select only after the full retained declarations, chain, custody and live
/// quiescence checks. Selection alone never grants image mount ownership.
pub fn native_preparation_image_history(
    spec: &CellPreparation,
) -> Result<crate::NativeImageHistory> {
    let raw = fs_input::read(
        &spec.stage.join("native-image-events.v1.jsonl"),
        64 * 1024 * 1024,
    )?;
    let records = crate::recovery_protocol::events(&raw)?;
    let history = crate::recovery_protocol::image_history(&records)?;
    retained_history(spec, history == crate::NativeImageHistory::Closed)?;
    Ok(history)
}

/// Already-closed SDK attempts need no image mutation. Require the complete
/// release/cleanup history and all current absence/custody checks afresh.
pub fn verify_closed_native_preparation(spec: &CellPreparation) -> Result<Value> {
    let mut retained = retained_history(spec, true)?;
    crate::require_image_lease_absent(&spec.image_id, &spec.podman_sha256)?;
    retained.facts["image_history"] = json!("already-closed-v1");
    Ok(retained.facts)
}

pub fn recover_quiescent_preparation(spec: &CellPreparation) -> Result<Value> {
    let original = retained(spec)?;
    let mut audit = crate::supervisor_journal::Journal::create_recovery(&spec.stage)?;
    audit.append("recovery-quiescent", original.facts.clone())?;
    let id = crate::image_protocol::image_id(&spec.image_id)?;
    let active =
        Path::new("/var/lib/hol-gauntlet-rust/cell-image-leases").join(format!("{id}.active.json"));
    let mut pointer_sha256 = None;
    if !absent(&active)? {
        let (lock, digest) =
            crate::image_lock::ImageLock::reopen_for_recovery(&spec.image_id, &spec.stage)?;
        let mounted = crate::image_protocol::mounted(
            &run(&spec.podman_sha256, Operation::Inventory, &spec.image_id)?,
            &spec.image_id,
        )?;
        if let Some(root) = mounted {
            if root != original.system.root {
                return Err("mounted image belongs to a different lease".into());
            }
            let fd = fs_input::directory(&root)?;
            let info = rustix::fs::fstat(&fd).map_err(|e| e.to_string())?;
            if info.st_dev != original.system.device || info.st_ino != original.system.inode {
                return Err("owned image mount identity changed".into());
            }
            if retained(spec)?.facts != original.facts {
                return Err("recovery inputs changed before unmount".into());
            }
            lock.verify()?;
            audit.append(
                "recovery-image-unmount-pending",
                json!({"image_id":spec.image_id,"active_pointer_sha256":digest}),
            )?;
            run(&spec.podman_sha256, Operation::Unmount, &spec.image_id)?;
        }
        if crate::image_protocol::mounted(
            &run(&spec.podman_sha256, Operation::Inventory, &spec.image_id)?,
            &spec.image_id,
        )?
        .is_some()
        {
            return Err("recovered image remains mounted".into());
        }
        lock.complete()?;
        pointer_sha256 = Some(digest);
    }
    let facts = verify_quiescent_preparation(spec)?;
    if facts != original.facts {
        return Err("retained evidence changed during recovery".into());
    }
    audit.append("recovery-cleanup", json!({"quiescent":facts,"image_unmounted":true,"active_pointer_absent":true,"execution_eligible":false}))?;
    Ok(
        json!({"quiescent":facts,"active_pointer_sha256":pointer_sha256,"image_unmounted":true,"active_pointer_absent":true}),
    )
}
