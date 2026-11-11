//! Kernel and fixed-system-utility boundary for fresh writable job volumes.
//! Nothing here imports candidate or SDK code into Root.
use super::{JobStoragePins, JobStorageProfile};
use rustix::fs::{fstat, open, openat, Mode, OFlags, Stat};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::fs::FileExt,
    path::Path,
};

#[path = "native_job_storage_format.rs"]
mod formatting;
pub(crate) use formatting::{format, formatter};

pub(crate) const CONFIG:&[u8]=b"[defaults]\nbase_features = sparse_super,large_file,filetype,dir_index,ext_attr\nblocksize = 4096\ninode_size = 256\ninode_ratio = 16384\nenable_periodic_fsck = 0\n[fs_types]\next4 = {\nfeatures = has_journal,extent,huge_file,flex_bg,metadata_csum,64bit,dir_nlink,extra_isize\n}\n";
pub(crate) const RESERVE: u64 = 12 * 1024 * 1024 * 1024;
pub(crate) const MKE2FS: &str = "/usr/sbin/mke2fs";
pub(crate) fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
pub(crate) fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    gauntlet_contracts::canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())
}
pub(crate) fn pins_valid(p: &JobStoragePins<'_>) -> Result<(), String> {
    if !crate::hex(p.source_sha, 40)
        || !crate::hex(p.job_id, 16)
        || !crate::hex(p.worker_generation, 64)
        || !crate::hex(p.mke2fs_sha256, 64)
    {
        return Err("exact outside job volume source/job/worker/formatter pins required".into());
    }
    Ok(())
}
pub(crate) fn uuid(p: &JobStoragePins<'_>, profile: JobStorageProfile) -> Result<String, String> {
    let mut raw = Sha256::digest(canonical(
        &json!({"source":p.source_sha,"job":p.job_id,"worker":p.worker_generation,"profile":profile.as_str()}),
    )?);
    raw[6] = (raw[6] & 15) | 64;
    raw[8] = (raw[8] & 63) | 128;
    Ok(raw[..16].iter().map(|b| format!("{b:02x}")).collect())
}
pub(crate) fn uuid_argument(raw: &str) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..]
    )
}
pub(crate) fn backing_identity(s: &Stat) -> Result<Value, String> {
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o177777 != 0o100600
        || s.st_nlink != 1
        || s.st_size < 0
        || s.st_blocks < 0
    {
        return Err("private ordinary Root backing-file custody required".into());
    }
    let allocated = (s.st_blocks as u64)
        .checked_mul(512)
        .ok_or("backing allocation overflow")?;
    if allocated < s.st_size as u64 {
        return Err("real backing allocation required; sparse reservation is incomplete".into());
    }
    Ok(
        json!({"device":s.st_dev,"inode":s.st_ino,"uid":0,"gid":0,"mode":0o600,"links":1,"bytes":s.st_size,"allocated_bytes":allocated}),
    )
}
pub(crate) fn available(fd: &OwnedFd) -> Result<u64, String> {
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(fd.as_raw_fd(), value.as_mut_ptr()) } != 0 {
        return Err("actual backing-filesystem capacity unavailable".into());
    }
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .ok_or("backing filesystem capacity overflow".into())
}
pub(crate) fn read_capacity(
    file: &File,
    profile: JobStorageProfile,
    uuid: &str,
) -> Result<Value, String> {
    let mut raw = [0; 1024];
    file.read_exact_at(&mut raw, 1024)
        .map_err(|e| e.to_string())?;
    super::ext4_capacity(&raw, profile, uuid)
}
pub(crate) fn namespace() -> Result<Value, String> {
    let fd = open(
        "/proc/thread-self/ns/mnt",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let s = fstat(&fd).map_err(|e| e.to_string())?;
    Ok(json!({"device":s.st_dev,"inode":s.st_ino}))
}
pub(crate) fn boot() -> Result<String, String> {
    let mut raw = Vec::new();
    File::open("/proc/sys/kernel/random/boot_id")
        .and_then(|f| f.take(65).read_to_end(&mut raw))
        .map_err(|e| e.to_string())?;
    let value = std::str::from_utf8(&raw)
        .map_err(|_| "kernel boot ID UTF8")?
        .trim();
    if value.len() != 36 {
        return Err("exact kernel boot ID required".into());
    }
    Ok(value.into())
}
pub(crate) fn mount_snapshot(target: &Path, device: &File) -> Result<Value, String> {
    let mut raw = Vec::new();
    File::open("/proc/thread-self/mountinfo")
        .and_then(|f| f.take(2 * 1024 * 1024 + 1).read_to_end(&mut raw))
        .map_err(|e| e.to_string())?;
    let s = fstat(device).map_err(|e| e.to_string())?;
    kernel_options(device)?;
    super::volume_mount(
        std::str::from_utf8(&raw).map_err(|_| "kernel mount inventory UTF8")?,
        target.to_str().ok_or("volume target UTF8")?,
        &format!("{}:{}", libc::major(s.st_rdev), libc::minor(s.st_rdev)),
    )
}

pub(crate) fn kernel_options(device: &File) -> Result<Value, String> {
    let block = fstat(device).map_err(|e| e.to_string())?;
    let number = libc::minor(block.st_rdev);
    if libc::major(block.st_rdev) != 7
        || number >= 4096
        || rustix::fs::FileType::from_raw_mode(block.st_mode) != rustix::fs::FileType::BlockDevice
    {
        return Err("original fixed loop device required for effective options".into());
    }
    let parent = crate::open_root_owned_public_directory(
        &Path::new("/proc/fs/ext4").join(format!("loop{number}")),
    )
    .map_err(|e| e.to_string())?;
    let fd = openat(
        &parent,
        "options",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_mode & 0o177777 != 0o100444
        || before.st_nlink != 1
    {
        return Err("effective ext4 options must be the fixed Root kernel file".into());
    }
    let mut file = File::from(fd);
    let mut raw = String::new();
    Read::by_ref(&mut file)
        .take(16385)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    let visible = rustix::fs::statat(&parent, "options", rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| e.to_string())?;
    if !crate::builder_candidate_source::same_file(
        &before,
        &fstat(&file).map_err(|e| e.to_string())?,
    ) || !crate::builder_candidate_source::same_file(&before, &visible)
        || !crate::builder_candidate_source::same_file(
            &block,
            &fstat(device).map_err(|e| e.to_string())?,
        )
    {
        return Err("original loop/options custody changed during measurement".into());
    }
    super::effective_ext4_options(&raw)?;
    Ok(
        json!({"schema":"hol-gauntlet-job-storage-kernel-options.v1","device":block.st_rdev,"options_sha256":sha(raw.as_bytes()),"options":raw.lines().collect::<Vec<_>>(),"errors":"remount-ro","discard":false}),
    )
}

// Linux UAPI layout and ioctl values, not an inferred userspace losetup parse:
// https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/loop.h
#[repr(C)]
#[derive(Clone, Copy)]
struct LoopInfo {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    key_size: u32,
    flags: u32,
    file_name: [u8; 64],
    crypt_name: [u8; 64],
    key: [u8; 32],
    init: [u64; 2],
}
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo,
    reserved: [u64; 8],
}
pub(crate) struct LoopDevice {
    pub file: File,
    pub number: u32,
}
impl LoopDevice {
    fn open(number: u32) -> Result<Self, String> {
        if number >= 4096 {
            return Err("bounded loop device index required".into());
        }
        let fd = open(
            format!("/dev/loop{number}"),
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let s = fstat(&fd).map_err(|e| e.to_string())?;
        if s.st_mode & 0o170000 != 0o060000
            || s.st_uid != 0
            || s.st_mode & 0o7007 != 0
            || s.st_nlink != 1
            || libc::major(s.st_rdev) != 7
            || libc::minor(s.st_rdev) != number
        {
            return Err("ordinary Root loop device identity required".into());
        }
        Ok(Self {
            file: File::from(fd),
            number,
        })
    }
    pub(crate) fn configure(backing: &File, bytes: u64) -> Result<Self, String> {
        let control = open(
            "/dev/loop-control",
            OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let s = fstat(&control).map_err(|e| e.to_string())?;
        if s.st_uid != 0
            || s.st_mode & 0o170000 != 0o020000
            || s.st_mode & 0o7007 != 0
            || s.st_nlink != 1
            || libc::major(s.st_rdev) != 10
            || libc::minor(s.st_rdev) != 237
        {
            return Err("fixed Root loop-control device required".into());
        }
        let number = unsafe { libc::ioctl(control.as_raw_fd(), 0x4c82) };
        if !(0..4096).contains(&number) {
            return Err("fresh loop device allocation unavailable".into());
        }
        // GET_FREE runs once. Only wait for udev's fixed node to appear;
        // never allocate another number or reuse an existing association.
        let path = format!("/dev/loop{number}");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !Path::new(&path).try_exists().map_err(|e| e.to_string())? {
            if std::time::Instant::now() >= deadline {
                return Err("fresh loop node did not appear".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let device = Self::open(number as u32)?;
        let mut info: LoopInfo = unsafe { std::mem::zeroed() };
        info.sizelimit = bytes;
        info.flags = 4;
        let config = LoopConfig {
            fd: backing.as_raw_fd() as u32,
            block_size: 4096,
            info,
            reserved: [0; 8],
        };
        // One atomic configuration. EBUSY/uncertainty fails without retry/reuse.
        if unsafe { libc::ioctl(device.file.as_raw_fd(), 0x4c0a, &config) } != 0 {
            return Err("one-use atomic loop configuration failed".into());
        }
        device.identity(backing, bytes)?;
        Ok(device)
    }
    pub(crate) fn retained(number: u32) -> Result<Self, String> {
        Self::open(number)
    }
    pub(crate) fn identity(&self, backing: &File, bytes: u64) -> Result<Value, String> {
        let mut info: LoopInfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(self.file.as_raw_fd(), 0x4c05, &mut info) } != 0 {
            return Err("original loop association unavailable".into());
        }
        let s = fstat(backing).map_err(|e| e.to_string())?;
        let d = fstat(&self.file).map_err(|e| e.to_string())?;
        if info.device != s.st_dev
            || info.inode != s.st_ino
            || info.rdevice != 0
            || info.offset != 0
            || info.sizelimit != bytes
            || info.number != self.number
            || info.encrypt_type != 0
            || info.key_size != 0
            || info.flags != 4
        {
            return Err("loop association differs from original bounded backing inode".into());
        }
        Ok(
            json!({"number":self.number,"device":d.st_rdev,"backing_device":info.device,"backing_inode":info.inode,"offset":0,"bytes":bytes,"flags":4}),
        )
    }
    pub(crate) fn mount(&self, target: &Path) -> Result<(), String> {
        require_private_ancestor(target)?;
        let source = CString::new(format!("/proc/self/fd/{}", self.file.as_raw_fd())).unwrap();
        let target = CString::new(target.to_str().ok_or("volume target UTF8")?)
            .map_err(|_| "volume target NUL")?;
        if unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                c"ext4".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOATIME,
                c"errors=remount-ro,nodiscard".as_ptr().cast(),
            )
        } != 0
        {
            return Err("fresh bounded ext4 mount failed".into());
        }
        if unsafe {
            libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_PRIVATE | libc::MS_REC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err("fresh volume mount propagation could not be isolated".into());
        }
        Ok(())
    }
    pub(crate) fn detach(&self) -> Result<(), String> {
        if unsafe { libc::ioctl(self.file.as_raw_fd(), 0x4c01) } != 0 {
            return Err("original loop detach failed".into());
        }
        Ok(())
    }
    pub(crate) fn detached(&self) -> Result<bool, String> {
        let mut info: LoopInfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(self.file.as_raw_fd(), 0x4c05, &mut info) } == 0 {
            return Ok(false);
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO) {
            Ok(true)
        } else {
            Err("loop status uncertain during retirement".into())
        }
    }
    pub(crate) fn references(&self, backing: &Stat) -> Result<bool, String> {
        self.references_identity(backing.st_dev, backing.st_ino)
    }
    pub(crate) fn references_identity(&self, device: u64, inode: u64) -> Result<bool, String> {
        let mut info: LoopInfo = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(self.file.as_raw_fd(), 0x4c05, &mut info) } == 0 {
            return Ok(info.device == device && info.inode == inode);
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENXIO) {
            Ok(false)
        } else {
            Err("loop backing association uncertain".into())
        }
    }
}
pub(crate) fn require_private_ancestor(target: &Path) -> Result<(), String> {
    let mut raw = String::new();
    File::open("/proc/thread-self/mountinfo")
        .map_err(|e| e.to_string())?
        .take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    super::private_ancestor(&raw, target.to_str().ok_or("fixed storage target UTF8")?)
}

fn temporary_rows() -> Result<String, String> {
    let mut raw = String::new();
    File::open("/proc/thread-self/mountinfo")
        .map_err(|e| e.to_string())?
        .take(2 * 1024 * 1024 + 1)
        .read_to_string(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > 2 * 1024 * 1024 {
        return Err("temporary mount inventory bound exceeded".into());
    }
    Ok(raw)
}
pub(crate) fn temporary_mount(target: &Path) -> Result<Option<Value>, String> {
    parse_temporary_mount(&temporary_rows()?, target)
}
fn parse_temporary_mount(raw: &str, target: &Path) -> Result<Option<Value>, String> {
    let mut found = None;
    for line in raw.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or("temporary mount inventory malformed")?;
        let a = left.split_ascii_whitespace().collect::<Vec<_>>();
        let b = right.split_ascii_whitespace().collect::<Vec<_>>();
        if a.len() < 6 || b.len() != 3 {
            return Err("temporary mount inventory fields malformed".into());
        }
        if a[4] != target.to_str().ok_or("temporary path UTF8")? {
            continue;
        }
        if found.is_some() || a.len() != 6 {
            return Err("temporary mount is duplicated or not private".into());
        }
        let opts = a[5].split(',').collect::<std::collections::BTreeSet<_>>();
        if !["rw", "nosuid", "nodev", "noexec"]
            .iter()
            .all(|s| opts.contains(s))
            || opts.contains("ro")
            || b[0] != "tmpfs"
            || a[3] != "/"
        {
            return Err("temporary mount protections or type differ".into());
        }
        found = Some(
            json!({"id":a[0],"parent":a[1],"device":a[2],"root":a[3],"target":a[4],"options":a[5],"filesystem":b[0],"source":b[1],"super_options":b[2]}),
        );
    }
    Ok(found)
}
pub(crate) fn temporary_identity(fd: &OwnedFd, bytes: u64, inodes: u64) -> Result<Value, String> {
    let s = fstat(fd).map_err(|e| e.to_string())?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: successful fstatfs fills the entire supplied structure.
    if unsafe { libc::fstatfs(fd.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
        return Err("temporary statfs unavailable".into());
    }
    let fs = unsafe { fs.assume_init() };
    let capacity = i128::from(fs.f_bsize)
        .checked_mul(i128::from(fs.f_blocks))
        .ok_or("temporary capacity overflow")?;
    if s.st_uid != 0
        || s.st_gid != 0
        || s.st_mode & 0o177777 != 0o041777
        || fs.f_type != 0x01021994
        || capacity <= 0
        || capacity > i128::from(bytes)
        || fs.f_files == 0
        || i128::from(fs.f_files) > i128::from(inodes)
        || fs.f_flags & 14 != 14
        || fs.f_flags & 1 != 0
    {
        return Err("actual temporary byte/inode/protection limits differ".into());
    }
    Ok(
        json!({"device":s.st_dev,"inode":s.st_ino,"uid":0,"gid":0,"mode":0o1777,"filesystem":fs.f_type,"bytes":capacity,"inodes":fs.f_files,"flags":fs.f_flags}),
    )
}
#[cfg(test)]
mod temporary_tests {
    use super::*;
    #[test]
    fn tmpfs_kernel_row_requires_private_security_flags_and_a_unique_mount() {
        let target =
            Path::new("/var/lib/hol-gauntlet-rust/job-volumes/0123456789abcdef/temporary/sdk/tmp");
        let row=format!("357 52 0:123 / {} rw,nosuid,nodev,noexec,relatime - tmpfs hol-gauntlet-0123456789abcdef-sdk-tmp rw,size=16384k,nr_inodes=4096",target.display());
        let value = parse_temporary_mount(&row, target).unwrap().unwrap();
        assert_eq!(value["source"], "hol-gauntlet-0123456789abcdef-sdk-tmp");
        for raw in [
            row.replace(",noexec", ""),
            row.replace(",nodev", ""),
            row.replace(" - ", " shared:1 - "),
            format!("{row}\n{row}"),
        ] {
            assert!(parse_temporary_mount(&raw, target).is_err());
        }
    }
}
