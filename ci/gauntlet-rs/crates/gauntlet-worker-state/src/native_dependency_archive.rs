//! Bound and freeze an unprivileged dependency environment as ordinary data.

use rustix::fs::{fstat, open, openat, statat, AtFlags, Dir, FileType, Mode, OFlags};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zip::write::SimpleFileOptions;

const MAX_ARCHIVE: u64 = 256 * 1024 * 1024;
const MAX_DECODED: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

struct CappedFile {
    file: File,
    position: u64,
}

impl Write for CappedFile {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > MAX_ARCHIVE.saturating_sub(self.position) {
            return Err(std::io::Error::other("dependency archive byte bound"));
        }
        let count = self.file.write(bytes)?;
        self.position += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

impl Seek for CappedFile {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let next = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.file.metadata()?.len()) + i128::from(offset),
        };
        if !(0..=i128::from(MAX_ARCHIVE)).contains(&next) {
            return Err(std::io::Error::other("dependency archive seek bound"));
        }
        let next = next as u64;
        self.file.seek(SeekFrom::Start(next))?;
        self.position = next;
        Ok(next)
    }
}

fn same(left: &rustix::fs::Stat, right: &rustix::fs::Stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_uid == right.st_uid
        && left.st_gid == right.st_gid
        && left.st_mode == right.st_mode
        && left.st_nlink == right.st_nlink
        && left.st_size == right.st_size
        && left.st_mtime == right.st_mtime
        && left.st_mtime_nsec == right.st_mtime_nsec
        && left.st_ctime == right.st_ctime
        && left.st_ctime_nsec == right.st_ctime_nsec
}

fn names(directory: &OwnedFd) -> Result<Vec<String>, String> {
    let mut result = Vec::new();
    for entry in Dir::read_from(directory).map_err(|_| "dependency directory unavailable")? {
        let entry = entry.map_err(|_| "dependency directory unreadable")?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let name = std::str::from_utf8(raw).map_err(|_| "dependency path is not UTF-8")?;
        if name.is_empty()
            || name.contains('\\')
            || name.chars().any(char::is_control)
            || result.len() >= MAX_ENTRIES
        {
            return Err("unsafe or excessive dependency paths".to_owned());
        }
        result.push(name.to_owned());
    }
    result.sort();
    Ok(result)
}

struct Inventory {
    visited: usize,
    files: usize,
    bytes: u64,
    hash: Sha256,
}

fn visit(
    directory: &OwnedFd,
    prefix: &str,
    depth: usize,
    zip: &mut zip::ZipWriter<CappedFile>,
    inventory: &mut Inventory,
) -> Result<(), String> {
    if depth > 128 {
        return Err("dependency path depth exceeded".to_owned());
    }
    let before = fstat(directory).map_err(|_| "dependency directory metadata unavailable")?;
    if before.st_uid != geteuid().as_raw() || before.st_mode & 0o022 != 0 {
        return Err("dependency directory ownership or mode differs".to_owned());
    }
    let listed = names(directory)?;
    for name in &listed {
        inventory.visited += 1;
        if inventory.visited > MAX_ENTRIES {
            return Err("dependency object count exceeded".to_owned());
        }
        let fd = openat(
            directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "ordinary dependency objects required")?;
        let stat = fstat(&fd).map_err(|_| "dependency metadata unavailable")?;
        if stat.st_uid != geteuid().as_raw() || stat.st_mode & 0o7022 != 0 {
            return Err("dependency object ownership or mode differs".to_owned());
        }
        let path = format!("{prefix}/{name}");
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => visit(&fd, &path, depth + 1, zip, inventory)?,
            FileType::RegularFile => {
                if stat.st_nlink != 1 || stat.st_size < 0 {
                    return Err("ordinary single-link dependency file required".to_owned());
                }
                inventory.files += 1;
                inventory.bytes = inventory
                    .bytes
                    .checked_add(stat.st_size as u64)
                    .ok_or("dependency size overflow")?;
                if inventory.files > MAX_ENTRIES || inventory.bytes > MAX_DECODED {
                    return Err("dependency inventory bounds exceeded".to_owned());
                }
                zip.start_file(
                    &path,
                    SimpleFileOptions::default()
                        .compression_method(zip::CompressionMethod::Deflated)
                        .unix_permissions(0o644),
                )
                .map_err(|_| "dependency ZIP entry failed")?;
                inventory.hash.update((path.len() as u64).to_be_bytes());
                inventory.hash.update(path.as_bytes());
                inventory.hash.update((stat.st_size as u64).to_be_bytes());
                let mut file = File::from(fd);
                let mut copied = 0u64;
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let count = file
                        .read(&mut buffer)
                        .map_err(|_| "dependency file read failed")?;
                    if count == 0 {
                        break;
                    }
                    copied += count as u64;
                    if copied > stat.st_size as u64 {
                        return Err("dependency file grew during capture".to_owned());
                    }
                    zip.write_all(&buffer[..count])
                        .map_err(|_| "bounded dependency ZIP write failed")?;
                    inventory.hash.update(&buffer[..count]);
                }
                let after = fstat(&file).map_err(|_| "dependency readback unavailable")?;
                let visible = statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| "dependency file disappeared")?;
                if copied != stat.st_size as u64 || !same(&stat, &after) || !same(&stat, &visible) {
                    return Err("dependency file changed during capture".to_owned());
                }
            }
            _ => return Err("dependency links and special objects are refused".to_owned()),
        }
    }
    let after = fstat(directory).map_err(|_| "dependency directory readback unavailable")?;
    if !same(&before, &after) || names(directory)? != listed {
        return Err("dependency directory changed during capture".to_owned());
    }
    Ok(())
}

pub(crate) fn archive_dependencies(
    site: &Path,
    output_path: &Path,
    binding: &Value,
) -> Result<Value, String> {
    if !site.is_absolute() || site.canonicalize().ok().as_deref() != Some(site) {
        return Err("canonical dependency directory required".to_owned());
    }
    if !output_path.is_absolute() || output_path.starts_with(site) {
        return Err("separate absolute dependency output required".to_owned());
    }
    let directory = open(
        site,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "dependency site directory unavailable")?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(output_path)
        .map_err(|_| "exclusive dependency ZIP unavailable")?;
    let mut zip = zip::ZipWriter::new(CappedFile { file, position: 0 });
    let mut inventory = Inventory {
        visited: 0,
        files: 0,
        bytes: 0,
        hash: Sha256::new(),
    };
    visit(&directory, "site-packages", 0, &mut zip, &mut inventory)?;
    if inventory.files == 0 {
        return Err("empty dependency environment refused".to_owned());
    }
    let mut report = binding.clone();
    report["schema"] = json!("hol-gauntlet-native-dependency-export.v1");
    report["files"] = json!(inventory.files);
    report["decoded_bytes"] = json!(inventory.bytes);
    report["entry_bytes_sha256"] = json!(format!("{:x}", inventory.hash.finalize()));
    report["artifact_admitted"] = json!(false);
    report["execution_eligible"] = json!(false);
    report["model_requests"] = json!(0);
    zip.start_file(
        "dependency-export.v1.json",
        SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o644),
    )
    .map_err(|_| "dependency manifest entry failed")?;
    zip.write_all(report.to_string().as_bytes())
        .map_err(|_| "dependency manifest write failed")?;
    let mut output = zip.finish().map_err(|_| "dependency ZIP finish failed")?;
    output
        .file
        .sync_all()
        .map_err(|_| "dependency ZIP fsync failed")?;
    let before = fstat(&output.file).map_err(|_| "dependency ZIP metadata unavailable")?;
    output
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| "dependency ZIP seek failed")?;
    let mut hash = Sha256::new();
    std::io::copy(&mut output.file, &mut hash).map_err(|_| "dependency ZIP hash failed")?;
    let after = fstat(&output.file).map_err(|_| "dependency ZIP readback unavailable")?;
    let visible = statat(rustix::fs::CWD, output_path, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "dependency ZIP disappeared")?;
    if !same(&before, &after)
        || !same(&before, &visible)
        || before.st_uid != geteuid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o777 != 0o600
        || before.st_size < 0
        || before.st_size as u64 > MAX_ARCHIVE
    {
        return Err("dependency ZIP changed during hash".to_owned());
    }
    let parent = open(
        output_path
            .parent()
            .ok_or("dependency export parent unavailable")?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "dependency export parent unavailable")?;
    rustix::fs::fsync(parent).map_err(|_| "dependency export directory fsync failed")?;
    report["archive_sha256"] = json!(format!("{:x}", hash.finalize()));
    report["archive_bytes"] = json!(before.st_size);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn captures_binary_files_and_manifest_without_executing_package_content_and_refuses_replay() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let site = root.join("site");
        std::fs::create_dir(&site).unwrap();
        std::fs::create_dir(site.join("nested")).unwrap();
        std::fs::write(site.join("nested/bytes.bin"), b"a\0\xff\n").unwrap();
        std::fs::write(
            site.join("untrusted.pth"),
            format!(
                "import pathlib; pathlib.Path({:?}).touch()\n",
                root.join("unexpected-execution").to_str().unwrap()
            ),
        )
        .unwrap();
        let path = root.join("dependencies.zip");
        let binding = json!({"job_id":"0123456789abcdef","source_sha":"a".repeat(40),"wheel_only_install":true});
        let report = archive_dependencies(&site, &path, &binding).unwrap();
        assert_eq!(report["files"], 2);
        assert_eq!(report["execution_eligible"], false);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            report["archive_sha256"],
            format!("{:x}", Sha256::digest(&bytes))
        );
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).unwrap();
        assert_eq!(zip.len(), 3);
        let mut binary = Vec::new();
        zip.by_name("site-packages/nested/bytes.bin")
            .unwrap()
            .read_to_end(&mut binary)
            .unwrap();
        assert_eq!(binary, b"a\0\xff\n");
        assert!(!root.join("unexpected-execution").exists());
        assert!(archive_dependencies(&site, &path, &binding).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
    }

    #[test]
    fn linked_input_objects_and_linked_site_roots_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let site = root.join("site");
        std::fs::create_dir(&site).unwrap();
        let outside = root.join("outside");
        std::fs::write(&outside, b"never imported").unwrap();
        symlink(&outside, site.join("foreign")).unwrap();
        assert!(archive_dependencies(&site, &root.join("symlink.zip"), &json!({})).is_err());
        let alias = root.join("alias");
        symlink(&site, &alias).unwrap();
        assert!(archive_dependencies(&alias, &root.join("alias.zip"), &json!({})).is_err());
        assert!(!root.join("alias.zip").exists());
        let linked = root.join("linked");
        std::fs::create_dir(&linked).unwrap();
        std::fs::hard_link(outside, linked.join("foreign")).unwrap();
        assert!(archive_dependencies(&linked, &root.join("hardlink.zip"), &json!({})).is_err());
    }

    #[test]
    fn out_of_bounds_seek_and_write_never_move_or_extend_the_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bounded");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let mut bounded = CappedFile { file, position: 0 };
        bounded.write_all(b"a").unwrap();
        assert!(bounded.seek(SeekFrom::Start(MAX_ARCHIVE + 1)).is_err());
        assert!(bounded.seek(SeekFrom::Current(-2)).is_err());
        assert!(bounded.seek(SeekFrom::End(i64::MAX)).is_err());
        assert_eq!(bounded.file.stream_position().unwrap(), 1);
        bounded.seek(SeekFrom::Start(MAX_ARCHIVE)).unwrap();
        assert!(bounded.write_all(b"x").is_err());
        assert_eq!(bounded.file.metadata().unwrap().len(), 1);
    }
}
