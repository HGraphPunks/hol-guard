//! Private inert prefix materialization. Only the Linux Root caller may
//! publish it after checking source/terminal custody, leases and tree hashes.
use crate::dependency_archive_read::{
    inspect_dependency_archive, DependencyArchivePins, DependencyArchiveProof,
};
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, openat, statat, symlinkat, AtFlags, FileType, Mode, OFlags,
};
use rustix::process::{getegid, geteuid};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::fd::OwnedFd;

pub(crate) const PREFIX: &str = "dependency-prefix";
pub(crate) const PARTIAL: &str = "dependency-prefix.partial";
pub(crate) const RECEIPT: &str = "dependency-prefix.v1.json";
const SITE: &str = "lib/python3.12/site-packages";

fn directory(root: &OwnedFd, relative: &str) -> Result<OwnedFd, String> {
    let mut fd = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    for part in relative.split('/') {
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.contains('\\')
            || part.len() > 255
            || part.chars().any(char::is_control)
        {
            return Err("unsafe dependency directory component".into());
        }
        let created = match mkdirat(&fd, part, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
            Ok(()) => true,
            Err(rustix::io::Errno::EXIST) => false,
            Err(e) => return Err(e.to_string()),
        };
        let child = openat(
            &fd,
            part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        if created {
            fchmod(&child, Mode::from_bits_truncate(0o755)).map_err(|e| e.to_string())?;
            fsync(&child)
                .and_then(|_| fsync(&fd))
                .map_err(|e| e.to_string())?;
        }
        let info = fstat(&child).map_err(|e| e.to_string())?;
        let visible = statat(&fd, part, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if info.st_uid != geteuid().as_raw()
            || info.st_gid != getegid().as_raw()
            || info.st_mode & 0o7777 != 0o755
            || !crate::dependency_prefix_meta::same(&info, &visible)
        {
            return Err("dependency output directory changed or has unsafe metadata".into());
        }
        fd = child;
    }
    Ok(fd)
}

fn ordinary_file(
    directory: &OwnedFd,
    name: &str,
    input: &mut impl Read,
    expected: u64,
) -> Result<(), String> {
    let fd = openat(
        directory,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "exclusive dependency output unavailable")?;
    let mut file = File::from(fd);
    let mut count = 0u64;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = input
            .read(&mut buffer)
            .map_err(|_| "dependency member CRC/read failed during materialization")?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|n| *n <= expected)
            .ok_or("dependency member grew during materialization")?;
        file.write_all(&buffer[..n]).map_err(|e| e.to_string())?;
        hash.update(&buffer[..n]);
    }
    if count != expected {
        return Err("dependency output size differs".into());
    }
    fchmod(&file, Mode::from_bits_truncate(0o644)).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let held = fstat(&file).map_err(|e| e.to_string())?;
    let fd = openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut readback = File::from(fd);
    let before = fstat(&readback).map_err(|e| e.to_string())?;
    let mut observed = Sha256::new();
    let mut bytes = 0u64;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != geteuid().as_raw()
        || before.st_gid != getegid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o644
        || before.st_size as u64 != expected
        || !crate::dependency_prefix_meta::same(&held, &before)
    {
        return Err("dependency output metadata differs on readback".into());
    }
    loop {
        let n = readback.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        bytes += n as u64;
        if bytes > expected {
            return Err("dependency output grew on readback".into());
        }
        observed.update(&buffer[..n]);
    }
    let after = fstat(&readback).map_err(|e| e.to_string())?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if bytes != expected
        || observed.finalize() != hash.finalize()
        || !crate::dependency_prefix_meta::same(&before, &after)
        || !crate::dependency_prefix_meta::same(&before, &visible)
    {
        return Err("dependency output byte/custody readback differs".into());
    }
    fsync(directory).map_err(|e| e.to_string())
}

pub(crate) fn write_private_prefix(
    parent: &OwnedFd,
    raw: &[u8],
    pins: &DependencyArchivePins<'_>,
) -> Result<(OwnedFd, DependencyArchiveProof), String> {
    let metadata = fstat(parent).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Directory
        || metadata.st_uid != geteuid().as_raw()
        || metadata.st_gid != getegid().as_raw()
        || metadata.st_mode & 0o7777 != 0o700
    {
        return Err("private dependency job parent required".into());
    }
    let proof = inspect_dependency_archive(raw, pins)?;
    for name in [PREFIX, PARTIAL, RECEIPT] {
        match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err("dependency prefix slot already consumed".into()),
        }
    }
    mkdirat(parent, PARTIAL, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    fsync(parent).map_err(|e| e.to_string())?;
    let target = openat(
        parent,
        PARTIAL,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    fchmod(&target, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    directory(&target, SITE)?;
    let bin = directory(&target, "bin")?;
    for (name, link) in [
        ("python3.12", "/usr/bin/python3.12"),
        ("python3", "python3.12"),
        ("python", "python3.12"),
    ] {
        symlinkat(link, &bin, name).map_err(|e| e.to_string())?;
    }
    fsync(&bin).map_err(|e| e.to_string())?;
    let config=b"home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12\nexecutable = /usr/bin/python3.12\n";
    ordinary_file(
        &target,
        "pyvenv.cfg",
        &mut config.as_slice(),
        config.len() as u64,
    )?;
    let mut zip = zip::ZipArchive::new(Cursor::new(raw)).map_err(|e| e.to_string())?;
    for (relative, size) in &proof.files {
        let full = format!("{SITE}/{relative}");
        let (parents, name) = full
            .rsplit_once('/')
            .ok_or("dependency output path missing")?;
        let parent = directory(&target, parents)?;
        let mut entry = zip
            .by_name(&format!("site-packages/{relative}"))
            .map_err(|e| e.to_string())?;
        if entry.size() != *size {
            return Err("validated dependency member changed".into());
        }
        ordinary_file(&parent, name, &mut entry, *size)?;
    }
    fsync(&target)
        .and_then(|_| fsync(parent))
        .map_err(|e| e.to_string())?;
    Ok((target, proof))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn real_export_materializes_without_pth_execution_and_replay_is_inert() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let test_root = rustix::fs::open(
            &base,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        // macOS temporary directories can inherit a different parent GID.
        rustix::fs::fchown(&test_root, None, Some(getegid())).unwrap();
        let source = base.join("site");
        std::fs::create_dir(&source).unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o700)).unwrap();
        let sentinel = base.join("must-not-execute");
        let payload = format!(
            "import pathlib; pathlib.Path({:?}).write_text('executed')\n",
            sentinel.to_str().unwrap()
        );
        std::fs::write(source.join("malicious.pth"), &payload).unwrap();
        std::fs::write(source.join("binary.bin"), b"\0\xffbytes").unwrap();
        let output = base.join("dependencies.zip");
        let binding = serde_json::json!({"job_id":"0123456789abcdef","source_sha":"a".repeat(40),"pyproject_sha256":"b".repeat(64),"uv_lock_sha256":"c".repeat(64),"wheel_only_install":true});
        crate::native_dependency_archive::archive_dependencies(&source, &output, &binding).unwrap();
        let raw = std::fs::read(&output).unwrap();
        let digest = format!("{:x}", Sha256::digest(&raw));
        let pins = DependencyArchivePins {
            job_id: "0123456789abcdef",
            source_sha: &"a".repeat(40),
            archive_sha256: &digest,
            pyproject_sha256: &"b".repeat(64),
            uv_lock_sha256: &"c".repeat(64),
        };
        let parent = rustix::fs::open(
            &base,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .unwrap();
        let wrong = DependencyArchivePins {
            archive_sha256: &"0".repeat(64),
            ..pins
        };
        assert!(write_private_prefix(&parent, &raw, &wrong).is_err());
        assert!(!base.join(PARTIAL).exists());
        let (_held, proof) = write_private_prefix(&parent, &raw, &pins).unwrap();
        assert_eq!(proof.files.len(), 2);
        assert!(!sentinel.exists());
        assert_eq!(
            std::fs::read(base.join(PARTIAL).join(SITE).join("malicious.pth")).unwrap(),
            payload.as_bytes()
        );
        assert_eq!(
            std::fs::read(base.join(PARTIAL).join(SITE).join("binary.bin")).unwrap(),
            b"\0\xffbytes"
        );
        assert!(write_private_prefix(&parent, &raw, &pins).is_err());
        assert!(!sentinel.exists());
        assert_eq!(
            std::fs::read_link(base.join(PARTIAL).join("bin/python3.12")).unwrap(),
            std::path::Path::new("/usr/bin/python3.12")
        );
    }
}
