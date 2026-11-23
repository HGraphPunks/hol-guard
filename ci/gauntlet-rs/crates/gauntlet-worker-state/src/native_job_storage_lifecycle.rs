//! Durable fresh-volume custody. A partial allocation is consumed and cannot
//! be adopted or reformatted by a second initialize call.
use super::linux::{self, LoopDevice};
use super::{JobStoragePins, JobStorageProfile};
use crate::{ActiveLease, RunReservationJournal};
use rustix::fs::{fchmod, fchown, fstat, fsync, openat, statat, AtFlags, Mode, OFlags};
use serde_json::{json, Value};
use std::{
    fs::File,
    os::fd::{AsRawFd, OwnedFd},
    path::Path,
};

pub(crate) const BASE: &str = "/var/lib/hol-gauntlet-rust/job-volumes";
pub(crate) const RECEIPT: &str = "storage.json";
pub(crate) struct JobVolume {
    pub root: OwnedFd,
    pub slot: OwnedFd,
    pub backing: File,
    pub device: LoopDevice,
    pub raw: Vec<u8>,
    pub value: Value,
    pub profile: JobStorageProfile,
}
fn root_identity(fd: &OwnedFd) -> Result<Value, String> {
    crate::feature_files::private_directory(fd, (0, 0))?;
    let s = fstat(fd).map_err(|e| e.to_string())?;
    Ok(json!({"device":s.st_dev,"inode":s.st_ino,"uid":0,"gid":0,"mode":0o700}))
}
fn context(p: &JobStoragePins<'_>, profile: JobStorageProfile) -> Value {
    json!({"schema":"hol-gauntlet-job-storage-intent.v1","source_sha":p.source_sha,"job_id":p.job_id,
        "worker_generation":p.worker_generation,"mke2fs_sha256":p.mke2fs_sha256,"profile":profile.as_str(),"limits":profile.limits()})
}
fn parent(create: bool) -> Result<OwnedFd, String> {
    let base = crate::open_root_owned_public_directory(Path::new("/var/lib/hol-gauntlet-rust"))
        .map_err(|e| e.to_string())?;
    if create {
        crate::feature_files::directory(&base, "job-volumes", (0, 0), false)
    } else {
        crate::feature_files::open_directory(&base, "job-volumes", (0, 0))
    }
}
pub(crate) fn present(job: &str) -> Result<bool, String> {
    if super::owner::present(job)? {
        return Ok(true);
    }
    if !crate::hex(job, 16) {
        return Err("exact storage job ID required".into());
    }
    if !Path::new(BASE).try_exists().map_err(|e| e.to_string())? {
        return Ok(false);
    }
    let parent = parent(false)?;
    match statat(&parent, job, AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(e) => Err(e.to_string()),
        Ok(_) => Ok(true),
    }
}
pub(crate) fn require_absent(job: &str) -> Result<(), String> {
    if present(job)? {
        Err("bounded storage intent exists; v1 fallback/adoption refused".into())
    } else {
        Ok(())
    }
}
pub(crate) fn verify_binding(
    binding: &Value,
    source: &str,
    job: &str,
    generation: &str,
    profile: JobStorageProfile,
) -> Result<Value, String> {
    verify_binding_mode(binding, source, job, generation, profile, false)
}
pub(crate) fn verify_cleanup_binding(
    binding: &Value,
    source: &str,
    job: &str,
    generation: &str,
    profile: JobStorageProfile,
) -> Result<Value, String> {
    verify_binding_mode(binding, source, job, generation, profile, true)
}
fn verify_binding_mode(
    binding: &Value,
    source: &str,
    job: &str,
    generation: &str,
    profile: JobStorageProfile,
    cleanup: bool,
) -> Result<Value, String> {
    let receipt = &binding["receipt"];
    let raw = linux::canonical(receipt)?;
    if binding.as_object().is_none_or(|o| o.len() != 2)
        || binding["receipt_sha256"] != linux::sha(&raw)
    {
        return Err("exact original storage receipt/hash binding required".into());
    }
    let p = JobStoragePins {
        source_sha: source,
        job_id: job,
        worker_generation: generation,
        mke2fs_sha256: receipt["mke2fs_sha256"]
            .as_str()
            .ok_or("original formatter pin absent")?,
    };
    let volume = if cleanup {
        JobVolume::read_for_cleanup(&p, profile)?
    } else {
        JobVolume::read(&p, profile)?
    };
    if volume.raw != raw {
        return Err("original initialization/source storage differs from physical custody".into());
    }
    Ok(volume.binding())
}
fn lease(
    journal: &RunReservationJournal,
    active: &ActiveLease,
    python: &crate::builder_image_context::PythonWorkerLease,
) -> Result<(), String> {
    active.verify(&journal.root).map_err(|e| e.to_string())?;
    crate::builder_image_context::verify_python_lock(python).map_err(|e| e.to_string())?;
    super::owner::health()?;
    if crate::native_worker::cancellation_requested() {
        return Err("job volume allocation cancelled".into());
    }
    Ok(())
}
fn actual_filesystem(
    root: &OwnedFd,
    profile: JobStorageProfile,
    capacity: &Value,
) -> Result<(), String> {
    let mut s = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(root.as_raw_fd(), s.as_mut_ptr()) } != 0 {
        return Err("mounted filesystem capacity unavailable".into());
    }
    let s = unsafe { s.assume_init() };
    if s.f_type != 0xef53
        || s.f_bsize != 4096
        || s.f_blocks
            .checked_mul(4096)
            .is_none_or(|n| n > profile.bytes())
        || json!(s.f_files) != capacity["inodes"]
    {
        return Err("mounted kernel filesystem capacity differs from original bounded ext4".into());
    }
    Ok(())
}
impl JobVolume {
    pub(crate) fn create(
        p: &JobStoragePins<'_>,
        profile: JobStorageProfile,
        journal: &RunReservationJournal,
        active: &ActiveLease,
        python: &crate::builder_image_context::PythonWorkerLease,
    ) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        linux::pins_valid(p)?;
        crate::verify_running_binary(p.worker_generation).map_err(|e| e.to_string())?;
        lease(journal, active, python)?;
        crate::native_initialize::require_unstarted_job(journal, p.job_id)?;
        crate::native_job_io::require_no_unknown_jobs(journal)?;
        crate::dependency_state::require_idle()?;
        super::admission::require_complete()?;
        let program = linux::formatter(p.mke2fs_sha256)?;
        let parent = parent(true)?;
        if linux::available(&parent)? < profile.bytes() + linux::RESERVE {
            return Err("job volume lacks real backing space plus VM reserve".into());
        }
        let target = profile.root(p.job_id)?;
        let jobs = crate::open_root_owned_public_directory(
            target.parent().ok_or("fixed volume parent absent")?,
        )
        .map_err(|e| e.to_string())?;
        crate::feature_files::private_directory(&jobs, (0, 0))?;
        if !matches!(
            statat(&jobs, p.job_id, AtFlags::SYMLINK_NOFOLLOW),
            Err(rustix::io::Errno::NOENT)
        ) {
            return Err("fresh volume job destination already consumed".into());
        }
        let namespace_owner = super::owner::create(p, profile)?;
        linux::require_private_ancestor(&target)?;
        // Exclusive slot+intent precede backing allocation, formatter or mount.
        let slot = crate::feature_files::directory(&parent, p.job_id, (0, 0), true)?;
        crate::feature_files::write(
            &slot,
            "intent.json",
            &linux::canonical(&context(p, profile))?,
            (0, 0),
            0o600,
        )?;
        crate::feature_files::write(
            &slot,
            "origin.json",
            &linux::canonical(&json!({"namespace":linux::namespace()?,"boot_id":linux::boot()?}))?,
            (0, 0),
            0o600,
        )?;
        let covered = crate::feature_files::directory(&jobs, p.job_id, (0, 0), true)?;
        let covered_identity = root_identity(&covered)?;
        crate::feature_files::write(
            &slot,
            "covered.json",
            &linux::canonical(&covered_identity)?,
            (0, 0),
            0o600,
        )?;
        let fd = openat(
            &slot,
            "backing.ext4",
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| e.to_string())?;
        fchmod(&fd, Mode::from_bits_truncate(0o600)).map_err(|e| e.to_string())?;
        let backing = File::from(fd);
        backing
            .set_len(profile.bytes())
            .map_err(|e| e.to_string())?;
        let allocated = unsafe {
            libc::posix_fallocate(backing.as_raw_fd(), 0, profile.bytes() as libc::off_t)
        };
        if allocated != 0 {
            return Err("real one-use backing allocation failed; retain volume intent".into());
        }
        backing
            .sync_all()
            .and_then(|_| fsync(&slot).map_err(std::io::Error::from))
            .map_err(|e| e.to_string())?;
        let before = linux::backing_identity(&fstat(&backing).map_err(|e| e.to_string())?)?;
        if before["bytes"] != profile.bytes() || linux::available(&parent)? < linux::RESERVE {
            return Err("backing allocation differs or VM reserve exhausted".into());
        }
        lease(journal, active, python)?;
        let uuid = linux::uuid(p, profile)?;
        let formatter = linux::format(&slot, &backing, &program, profile, &uuid)?;
        linux::formatter(p.mke2fs_sha256)?;
        let filesystem = linux::read_capacity(&backing, profile, &uuid)?;
        linux::backing_identity(&fstat(&backing).map_err(|e| e.to_string())?)?;
        lease(journal, active, python)?;
        let device = LoopDevice::configure(&backing, profile.bytes())?;
        crate::feature_files::write(
            &slot,
            "allocation.json",
            &linux::canonical(
                &json!({"backing":linux::backing_identity(&fstat(&backing).map_err(|e|e.to_string())?)?,"loop":device.identity(&backing,profile.bytes())?,"namespace":linux::namespace()?,"boot_id":linux::boot()?}),
            )?,
            (0, 0),
            0o600,
        )?;
        device.mount(&target)?;
        let root = crate::open_root_owned_public_directory(&target).map_err(|e| e.to_string())?;
        fchown(
            &root,
            Some(rustix::process::Uid::ROOT),
            Some(rustix::process::Gid::ROOT),
        )
        .and_then(|_| fchmod(&root, Mode::from_bits_truncate(0o700)))
        .and_then(|_| fsync(&root))
        .map_err(|e| e.to_string())?;
        // Remove only mke2fs's newly created, empty recovery directory. No
        // historical directory or caller-selected child is eligible here.
        let lost = crate::feature_files::open_directory(&root, "lost+found", (0, 0))?;
        if fstat(&lost).map_err(|e| e.to_string())?.st_ino != 11 {
            return Err("fresh ext4 recovery directory identity differs".into());
        }
        for entry in rustix::fs::Dir::read_from(&lost).map_err(|e| e.to_string())? {
            if !matches!(
                entry.map_err(|e| e.to_string())?.file_name().to_bytes(),
                b"." | b".."
            ) {
                return Err("fresh ext4 recovery directory is not empty".into());
            }
        }
        rustix::fs::unlinkat(&root, "lost+found", AtFlags::REMOVEDIR)
            .and_then(|_| fsync(&root))
            .map_err(|e| e.to_string())?;
        actual_filesystem(&root, profile, &filesystem)?;
        let value = json!({"schema":"hol-gauntlet-job-storage.v2","source_sha":p.source_sha,"job_id":p.job_id,"worker_generation":p.worker_generation,
            "profile":profile.as_str(),"limits":profile.limits(),"backing":linux::backing_identity(&fstat(&backing).map_err(|e|e.to_string())?)?,
            "filesystem":filesystem,"loop":device.identity(&backing,profile.bytes())?,"mount":linux::mount_snapshot(&target,&device.file)?,
            "namespace":linux::namespace()?,"boot_id":linux::boot()?,"root_directory":root_identity(&root)?,"covered_directory":covered_identity,
            "mke2fs_sha256":p.mke2fs_sha256,"formatter":formatter,"storage_state":"retained-mounted-rw","execution_eligible":false,"qualification_eligible":false,"namespace_owner":namespace_owner});
        let raw = linux::canonical(&value)?;
        lease(journal, active, python)?;
        crate::feature_files::write(&slot, RECEIPT, &raw, (0, 0), 0o600)?;
        let volume = Self {
            root,
            slot,
            backing,
            device,
            raw,
            value,
            profile,
        };
        volume.verify(p)?;
        Ok(volume)
    }
    pub(crate) fn read(p: &JobStoragePins<'_>, profile: JobStorageProfile) -> Result<Self, String> {
        Self::read_mode(p, profile, false)
    }
    pub(crate) fn read_for_cleanup(
        p: &JobStoragePins<'_>,
        profile: JobStorageProfile,
    ) -> Result<Self, String> {
        Self::read_mode(p, profile, true)
    }
    fn read_mode(
        p: &JobStoragePins<'_>,
        profile: JobStorageProfile,
        cleanup: bool,
    ) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        linux::pins_valid(p)?;
        let owner = if cleanup {
            super::owner::cleanup_receipt(p.job_id)?
        } else {
            super::owner::enter_pinned(p.source_sha, p.job_id, p.worker_generation)?;
            super::owner::receipt(p.job_id)?
        };
        let parent = parent(false)?;
        let slot = crate::feature_files::open_directory(&parent, p.job_id, (0, 0))?;
        let raw = crate::feature_files::required(&slot, RECEIPT, (0, 0), 0o600, 16384)?;
        if gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())? != raw {
            return Err("canonical original storage receipt required".into());
        }
        let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let backing = File::from(
            openat(
                &slot,
                "backing.ext4",
                OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        );
        let number = value["loop"]["number"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or("original volume loop identity absent")?;
        let device = LoopDevice::retained(number)?;
        let root = crate::open_root_owned_public_directory(&profile.root(p.job_id)?)
            .map_err(|e| e.to_string())?;
        let volume = Self {
            root,
            slot,
            backing,
            device,
            raw,
            value,
            profile,
        };
        volume.verify_with_owner(p, &owner)?;
        Ok(volume)
    }
    pub(crate) fn verify(&self, p: &JobStoragePins<'_>) -> Result<(), String> {
        self.verify_with_owner(p, &super::owner::receipt(p.job_id)?)
    }
    fn verify_with_owner(&self, p: &JobStoragePins<'_>, owner: &Value) -> Result<(), String> {
        linux::pins_valid(p)?;
        let fields = [
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
            "boot_id",
            "root_directory",
            "covered_directory",
            "mke2fs_sha256",
            "formatter",
            "storage_state",
            "execution_eligible",
            "qualification_eligible",
            "namespace_owner",
        ];
        if self.value.as_object().is_none_or(|o| {
            o.len() != fields.len() || fields.iter().any(|name| !o.contains_key(*name))
        }) || self.value["schema"] != "hol-gauntlet-job-storage.v2"
            || self.value["source_sha"] != p.source_sha
            || self.value["job_id"] != p.job_id
            || self.value["worker_generation"] != p.worker_generation
            || self.value["profile"] != self.profile.as_str()
            || self.value["limits"] != self.profile.limits()
            || self.value["mke2fs_sha256"] != p.mke2fs_sha256
            || self.value["storage_state"] != "retained-mounted-rw"
            || self.value["execution_eligible"] != false
            || self.value["qualification_eligible"] != false
            || self.value["namespace"] != linux::namespace()?
            || self.value["boot_id"] != linux::boot()?
            || self.value["root_directory"] != root_identity(&self.root)?
            || self.value["namespace_owner"] != *owner
            || self.value["formatter"]["exit_code"] != 0
            || self.value["formatter"]["configuration_sha256"] != linux::sha(linux::CONFIG)
        {
            return Err(
                "retained storage differs from original source/job/worker/profile custody".into(),
            );
        }
        if crate::feature_files::required(&self.slot, "intent.json", (0, 0), 0o600, 8192)?
            != linux::canonical(&context(p, self.profile))?
            || crate::feature_files::required(&self.slot, RECEIPT, (0, 0), 0o600, 16384)?
                != self.raw
            || crate::feature_files::required(&self.slot, "mke2fs.conf", (0, 0), 0o600, 8192)?
                != linux::CONFIG
        {
            return Err("immutable volume metadata changed".into());
        }
        let current = linux::backing_identity(&fstat(&self.backing).map_err(|e| e.to_string())?)?;
        for name in ["device", "inode", "uid", "gid", "mode", "links", "bytes"] {
            if current[name] != self.value["backing"][name] {
                return Err("original bounded backing inode changed".into());
            }
        }
        let visible = fstat(
            &openat(
                &self.slot,
                "backing.ext4",
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if visible.st_dev
            != current["device"]
                .as_u64()
                .ok_or("original backing device absent")?
            || visible.st_ino
                != current["inode"]
                    .as_u64()
                    .ok_or("original backing inode absent")?
        {
            return Err("visible original backing inode was replaced".into());
        }
        let uuid = linux::uuid(p, self.profile)?;
        let capacity = linux::read_capacity(&self.backing, self.profile, &uuid)?;
        if self.value["filesystem"] != capacity
            || self.value["loop"] != self.device.identity(&self.backing, self.profile.bytes())?
            || self.value["mount"]
                != linux::mount_snapshot(&self.profile.root(p.job_id)?, &self.device.file)?
        {
            return Err(
                "actual loop/mount/filesystem differs from original storage receipt".into(),
            );
        }
        actual_filesystem(&self.root, self.profile, &capacity)
    }
    pub(crate) fn binding(&self) -> Value {
        json!({"receipt_sha256":linux::sha(&self.raw),"receipt":self.value})
    }
}
