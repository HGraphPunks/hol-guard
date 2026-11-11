//! Root mounts finite tmpfs before Podman binds it. Podman4.9's option parser
//! cannot carry nr_inodes; original kernel mounts/receipts remain authoritative.
use super::linux::{temporary_identity as identity, temporary_mount as mount_row};
use super::{lifecycle, linux, JobStoragePins, JobStorageProfile};
use rustix::fs::{fstat, openat, Mode, OFlags};
use serde_json::{json, Value};
use std::{
    ffi::CString,
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scope {
    Sdk,
    Mcp,
    Build,
    Dependency,
}
impl Scope {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Sdk => "sdk",
            Self::Mcp => "mcp",
            Self::Build => "build",
            Self::Dependency => "dependency",
        }
    }
    fn profile(self) -> JobStorageProfile {
        match self {
            Self::Sdk | Self::Mcp => JobStorageProfile::Native,
            Self::Build => JobStorageProfile::Build,
            Self::Dependency => JobStorageProfile::Dependency,
        }
    }
    fn limits(self) -> Vec<(&'static str, u64, u64)> {
        if matches!(self, Self::Sdk | Self::Mcp) {
            super::tmpfs_limits().to_vec()
        } else {
            vec![("/dev/shm", 67108864, 16384)]
        }
    }
    pub(crate) fn source(profile: JobStorageProfile) -> Result<Self, String> {
        match profile {
            JobStorageProfile::Build => Ok(Self::Build),
            JobStorageProfile::Dependency => Ok(Self::Dependency),
            _ => Err("closed source temporary profile required".into()),
        }
    }
}
fn name(target: &str) -> &str {
    match target {
        "/tmp" => "tmp",
        "/var/tmp" => "var-tmp",
        "/run" => "run",
        "/dev/shm" => "shm",
        _ => unreachable!(),
    }
}
fn path(job: &str, scope: Scope) -> PathBuf {
    Path::new(lifecycle::BASE)
        .join(job)
        .join("temporary")
        .join(scope.name())
}
fn read(root: &OwnedFd, name: &str) -> Result<Option<Value>, String> {
    crate::feature_files::read(root, name, (0, 0), 0o600, 24576)?
        .map(|raw| {
            let value: Value =
                serde_json::from_slice(&raw).map_err(|_| "temporary storage record JSON")?;
            if linux::canonical(&value)? != raw {
                return Err("canonical temporary storage record required".into());
            }
            Ok(value)
        })
        .transpose()
}
fn write(root: &OwnedFd, name: &str, value: &Value) -> Result<(), String> {
    crate::feature_files::write(root, name, &linux::canonical(value)?, (0, 0), 0o600)
}
fn volume(job: &str, scope: Scope, cleanup: bool) -> Result<(OwnedFd, Value), String> {
    if !crate::hex(job, 16) {
        return Err("exact temporary storage job required".into());
    }
    if cleanup {
        super::owner::cleanup_access(job)?;
    } else {
        super::owner::enter(job)?;
    }
    let slot = crate::open_root_owned_public_directory(&Path::new(lifecycle::BASE).join(job))
        .map_err(|e| e.to_string())?;
    let value = read(&slot, lifecycle::RECEIPT)?.ok_or("original bounded volume receipt absent")?;
    let p = JobStoragePins {
        source_sha: value["source_sha"]
            .as_str()
            .ok_or("temporary source pin absent")?,
        job_id: job,
        worker_generation: value["worker_generation"]
            .as_str()
            .ok_or("temporary worker pin absent")?,
        mke2fs_sha256: value["mke2fs_sha256"]
            .as_str()
            .ok_or("temporary formatter pin absent")?,
    };
    linux::pins_valid(&p)?;
    if value["profile"] != scope.profile().as_str()
        || value["namespace"] != linux::namespace()?
        || value["boot_id"] != linux::boot()?
    {
        return Err("temporary original volume/namespace profile differs".into());
    }
    if !cleanup {
        let original = lifecycle::JobVolume::read(&p, scope.profile())?;
        if original.value != value {
            return Err("temporary storage original volume differs".into());
        }
    }
    Ok((slot, value))
}
fn open(root: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    openat(
        root,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())
}
fn context(job: &str, scope: Scope, storage: &Value) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-job-temporary-intent.v1","job_id":job,"scope":scope.name(),"storage_receipt_sha256":linux::sha(&linux::canonical(storage)?),
        "source_sha":storage["source_sha"],"worker_generation":storage["worker_generation"],"namespace":linux::namespace()?,"boot_id":linux::boot()?,
        "limits":scope.limits().into_iter().map(|(target,bytes,inodes)|json!({"target":target,"bytes":bytes,"inodes":inodes})).collect::<Vec<_>>()}),
    )
}
fn verify_context(
    root: &OwnedFd,
    job: &str,
    scope: Scope,
    storage: &Value,
) -> Result<Value, String> {
    let intent =
        read(root, "intent.json")?.ok_or("original temporary intent absent; retain unknown")?;
    let mut expected = context(job, scope, storage)?;
    expected["covered"] = intent["covered"].clone();
    if intent != expected {
        return Err("temporary original source/storage/namespace binding differs".into());
    }
    Ok(intent)
}
pub(crate) fn create(job: &str, scope: Scope) -> Result<Vec<String>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let (slot, storage) = volume(job, scope, false)?;
    let base = crate::feature_files::directory(&slot, "temporary", (0, 0), false)?;
    let root = crate::feature_files::directory(&base, scope.name(), (0, 0), true)?;
    let mut covered = serde_json::Map::new();
    for (target, _, _) in scope.limits() {
        let fd = crate::feature_files::directory(&root, name(target), (0, 0), true)?;
        let s = fstat(&fd).map_err(|e| e.to_string())?;
        covered.insert(
            name(target).into(),
            json!({"device":s.st_dev,"inode":s.st_ino}),
        );
    }
    let mut intent = context(job, scope, &storage)?;
    intent["covered"] = Value::Object(covered);
    write(&root, "intent.json", &intent)?;
    let mounted = (|| {
        for (target, bytes, inodes) in scope.limits() {
            if crate::native_worker::cancellation_requested() {
                return Err("temporary allocation cancelled".into());
            }
            let destination = path(job, scope).join(name(target));
            linux::require_private_ancestor(&destination)?;
            if mount_row(&destination)?.is_some() {
                return Err("fresh temporary target already mounted".into());
            }
            let source = format!("hol-gauntlet-{job}-{}-{}", scope.name(), name(target));
            let src = CString::new(source.clone()).unwrap();
            let dst = CString::new(destination.to_str().unwrap()).unwrap();
            let options = CString::new(format!(
                "size={bytes},nr_inodes={inodes},mode=1777,uid=0,gid=0"
            ))
            .unwrap();
            // Fixed fresh private namespace targets only; never remount global Root.
            if unsafe {
                libc::mount(
                    src.as_ptr(),
                    dst.as_ptr(),
                    c"tmpfs".as_ptr(),
                    libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    options.as_ptr().cast(),
                )
            } != 0
            {
                return Err("fresh bounded temporary mount failed".into());
            }
            let fd = open(&root, name(target))?;
            let row = mount_row(&destination)?.ok_or("fresh temporary mount absent")?;
            if row["source"] != source {
                return Err("temporary kernel source identity differs".into());
            }
            write(
                &root,
                &format!("{}.json", name(target)),
                &json!({"intent_sha256":linux::sha(&linux::canonical(&intent)?),"mount":row,"identity":identity(&fd,bytes,inodes)?}),
            )?;
        }
        write(
            &root,
            "complete.json",
            &json!({"schema":"hol-gauntlet-job-temporary-complete.v1","intent_sha256":linux::sha(&linux::canonical(&intent)?)}),
        )
    })();
    if let Err(error) = mounted {
        return Err(format!(
            "{error}; temporary intent retained for original pinned cleanup"
        ));
    }
    verify(job, scope, None)?;
    let mut args = vec!["--read-only-tmpfs=false".into()];
    for (target, _, _) in scope.limits() {
        args.extend([
            "--volume".into(),
            format!(
                "{}:{target}:rw,rprivate,nosuid,nodev,noexec",
                path(job, scope).join(name(target)).display()
            ),
        ]);
    }
    Ok(args)
}
pub(crate) fn verify(job: &str, scope: Scope, container: Option<&Value>) -> Result<(), String> {
    inspect(job, scope, container).map(|_| ())
}
fn inspect(job: &str, scope: Scope, container: Option<&Value>) -> Result<Value, String> {
    let (_, storage) = volume(job, scope, false)?;
    let root =
        crate::open_root_owned_public_directory(&path(job, scope)).map_err(|e| e.to_string())?;
    let intent = verify_context(&root, job, scope, &storage)?;
    let digest = linux::sha(&linux::canonical(&intent)?);
    if read(&root, "closed.json")?.is_some()
        || read(&root, "complete.json")?
            != Some(
                json!({"schema":"hol-gauntlet-job-temporary-complete.v1","intent_sha256":digest}),
            )
    {
        return Err("temporary mount publication is partial or consumed".into());
    }
    let task = container
        .filter(|v| v["State"]["Running"] == true)
        .map(|v| {
            let pid = v["State"]["Pid"]
                .as_u64()
                .filter(|p| *p > 1 && *p <= u32::MAX as u64)
                .ok_or("temporary container PID absent")?;
            crate::linux_process::HeldProcessRoot::open(pid as u32)
        })
        .transpose()?;
    let mut filesystems = serde_json::Map::new();
    for (target, bytes, inodes) in scope.limits() {
        let receipt = read(&root, &format!("{}.json", name(target)))?
            .ok_or("original temporary mount receipt absent")?;
        let fd = open(&root, name(target))?;
        if receipt["intent_sha256"] != digest
            || receipt["mount"]
                != mount_row(&path(job, scope).join(name(target)))?
                    .ok_or("original temporary mount absent")?
            || receipt["identity"] != identity(&fd, bytes, inodes)?
        {
            return Err("original temporary mount identity or capacity changed".into());
        }
        if let Some(v) = container {
            let rows = v["Mounts"]
                .as_array()
                .ok_or("actual temporary bind inventory absent")?
                .iter()
                .filter(|r| r["Destination"] == target)
                .collect::<Vec<_>>();
            if rows.len() != 1
                || rows[0]["Type"] != "bind"
                || rows[0]["RW"] != true
                || rows[0]["Propagation"] != "rprivate"
                || rows[0]["Source"]
                    != path(job, scope)
                        .join(name(target))
                        .to_string_lossy()
                        .as_ref()
            {
                return Err("container temporary bind differs from original mount".into());
            }
        }
        if let Some(task) = &task {
            let fd = open(&task.root, &target[1..])?;
            let inside = identity(&fd, bytes, inodes)?;
            if [
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
                "filesystem",
                "bytes",
                "inodes",
            ]
            .iter()
            .any(|k| inside[*k] != receipt["identity"][*k])
            {
                return Err("inside/outside temporary filesystem identity differs".into());
            }
            filesystems.insert(target.into(), json!({"outside":receipt,"inside":inside}));
        }
    }
    Ok(
        json!({"schema":"hol-gauntlet-job-temporary-inside.v1","intent_sha256":digest,
        "container_id":container.map(|v|v["Id"].clone()),
        "task":task.as_ref().map(|t|t.observation()).transpose()?,"filesystems":filesystems}),
    )
}
/// Called only by the original execution owner, never by a completed reader.
pub(crate) fn observe(job: &str, scope: Scope, container: &Value) -> Result<bool, String> {
    if !lifecycle::present(job)? {
        return Ok(true);
    }
    let observation = inspect(job, scope, Some(container))?;
    if observation["task"].is_null() {
        return Ok(false);
    }
    let root =
        crate::open_root_owned_public_directory(&path(job, scope)).map_err(|e| e.to_string())?;
    match read(&root, "inside.json")? {
        Some(old) if old == observation => Ok(true),
        Some(_) => Err("original temporary inside task observation changed".into()),
        None => {
            write(&root, "inside.json", &observation)?;
            Ok(true)
        }
    }
}
pub(crate) fn close(job: &str, scope: Scope) -> Result<(), String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    if !lifecycle::present(job)? {
        return Ok(());
    }
    super::owner::cleanup_access(job)?;
    if !path(job, scope).try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let (_, storage) = volume(job, scope, true)?;
    let root =
        crate::open_root_owned_public_directory(&path(job, scope)).map_err(|e| e.to_string())?;
    if read(&root, "intent.json")?.is_none() {
        return require_absent(job, scope);
    }
    let intent = verify_context(&root, job, scope, &storage)?;
    let digest = linux::sha(&linux::canonical(&intent)?);
    let mut errors = Vec::new();
    for (target, bytes, inodes) in scope.limits() {
        let outcome = (|| -> Result<(), String> {
            let destination = path(job, scope).join(name(target));
            if let Some(row) = mount_row(&destination)? {
                let receipt = read(&root, &format!("{}.json", name(target)))?
                    .ok_or("temporary mount has no original kernel receipt; retain unknown")?;
                let fd = open(&root, name(target))?;
                if receipt["intent_sha256"] != digest
                    || receipt["mount"] != row
                    || receipt["identity"] != identity(&fd, bytes, inodes)?
                {
                    return Err("temporary cleanup original identity differs".into());
                }
                drop(fd);
                let destination = CString::new(destination.to_str().unwrap()).unwrap();
                if unsafe { libc::umount2(destination.as_ptr(), 0) } != 0 {
                    return Err("original temporary unmount failed".into());
                }
            }
            if mount_row(&destination)?.is_some() {
                return Err("temporary mount remains after cleanup".into());
            }
            let s = fstat(open(&root, name(target))?).map_err(|e| e.to_string())?;
            if intent["covered"][name(target)] != json!({"device":s.st_dev,"inode":s.st_ino}) {
                return Err("temporary covered directory identity changed".into());
            }
            Ok(())
        })();
        if let Err(e) = outcome {
            errors.push(format!("{}: {e}", name(target)));
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let closed = json!({"schema":"hol-gauntlet-job-temporary-closed.v1","intent_sha256":digest,"namespace":linux::namespace()?,"boot_id":linux::boot()?});
    match read(&root, "closed.json")? {
        Some(old) if old == closed => Ok(()),
        Some(_) => Err("temporary closure binding changed".into()),
        None => write(&root, "closed.json", &closed),
    }
}
pub(crate) fn require_absent(job: &str, scope: Scope) -> Result<(), String> {
    if !crate::hex(job, 16) {
        return Err("exact temporary job required".into());
    }
    if !lifecycle::present(job)? {
        return Ok(());
    }
    super::owner::cleanup_access(job)?;
    for (target, _, _) in scope.limits() {
        if mount_row(&path(job, scope).join(name(target)))?.is_some() {
            return Err("owned temporary mount remains".into());
        }
    }
    if path(job, scope).try_exists().map_err(|e| e.to_string())? {
        let root = crate::open_root_owned_public_directory(&path(job, scope))
            .map_err(|e| e.to_string())?;
        super::admission::closed_inventory(
            &root,
            &[
                "tmp",
                "var-tmp",
                "run",
                "shm",
                "intent.json",
                "complete.json",
                "inside.json",
                "closed.json",
                "tmp.json",
                "var-tmp.json",
                "run.json",
                "shm.json",
            ],
        )?;
        if read(&root, "intent.json")?.is_some() {
            let (_, storage) = volume(job, scope, true)?;
            let intent = verify_context(&root, job, scope, &storage)?;
            if read(&root, "closed.json")?
                != Some(json!({"schema":"hol-gauntlet-job-temporary-closed.v1",
                "intent_sha256":linux::sha(&linux::canonical(&intent)?),"namespace":linux::namespace()?,"boot_id":linux::boot()?}))
            {
                return Err(
                    "temporary publication/closure is unknown; explicit original cleanup required"
                        .into(),
                );
            }
        }
    }
    Ok(())
}
pub(crate) fn require_all_absent(job: &str) -> Result<(), String> {
    if !lifecycle::present(job)? {
        return Ok(());
    }
    super::owner::cleanup_access(job)?;
    let base = Path::new(lifecycle::BASE).join(job).join("temporary");
    if base.try_exists().map_err(|e| e.to_string())? {
        let root = crate::open_root_owned_public_directory(&base).map_err(|e| e.to_string())?;
        super::admission::closed_inventory(&root, &["sdk", "mcp", "build", "dependency"])?;
    }
    for scope in [Scope::Sdk, Scope::Mcp, Scope::Build, Scope::Dependency] {
        require_absent(job, scope)?;
    }
    Ok(())
}
