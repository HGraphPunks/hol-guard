//! Descriptor-bound, bounded tar/gzip writer for a freshly fetched bare repo.

use crate::local_source_prepare::LocalSourcePrepareError as Error;
use crate::private_jobs::same_file;
use flate2::{Compression, GzBuilder};
use rustix::fs::{fstat, fsync, openat, statat, AtFlags, Dir, FileType, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;

const MAX_COMPRESSED: u64 = 256 * 1024 * 1024;
const MAX_DECODED: u64 = 512 * 1024 * 1024;

struct CappedWriter {
    file: File,
    written: u64,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > MAX_COMPRESSED - self.written {
            return Err(io::Error::other("compressed source bound"));
        }
        let count = self.file.write(bytes)?;
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn names(directory: &OwnedFd) -> Result<Vec<String>, Error> {
    let mut names = Vec::new();
    for entry in Dir::read_from(directory).map_err(|_| Error::Io)? {
        let entry = entry.map_err(|_| Error::Io)?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let name = std::str::from_utf8(raw).map_err(|_| Error::UnsafeObjects)?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
            return Err(Error::UnsafeObjects);
        }
        names.push(name.to_owned());
        if names.len() > 100_000 {
            return Err(Error::TooLarge);
        }
    }
    names.sort();
    Ok(names)
}

fn visit<W: Write>(
    directory: &OwnedFd,
    prefix: &str,
    owner: u32,
    tar: &mut tar::Builder<W>,
    totals: &mut (usize, u64),
    depth: usize,
) -> Result<(), Error> {
    if depth > 32 {
        return Err(Error::TooLarge);
    }
    let before = fstat(directory).map_err(|_| Error::Io)?;
    if before.st_uid != owner || before.st_mode & 0o022 != 0 {
        return Err(Error::UnsafeObjects);
    }
    let listed = names(directory)?;
    for name in &listed {
        totals.0 += 1;
        if totals.0 > 100_000 {
            return Err(Error::TooLarge);
        }
        let fd = openat(
            directory,
            name.as_str(),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| Error::UnsafeObjects)?;
        let stat = fstat(&fd).map_err(|_| Error::Io)?;
        if stat.st_uid != owner || stat.st_mode & 0o022 != 0 {
            return Err(Error::UnsafeObjects);
        }
        let path = format!("{prefix}/{name}");
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => visit(&fd, &path, owner, tar, totals, depth + 1)?,
            FileType::RegularFile => {
                if stat.st_nlink != 1 || stat.st_size < 0 {
                    return Err(Error::UnsafeObjects);
                }
                totals.1 = totals
                    .1
                    .checked_add(stat.st_size as u64)
                    .ok_or(Error::TooLarge)?;
                if totals.1 > MAX_DECODED {
                    return Err(Error::TooLarge);
                }
                // FETCH_HEAD can contain local path names. Only the fresh repo's
                // self-contained graph and minimal configuration are exported.
                if path == "repository.git/FETCH_HEAD" {
                    continue;
                }
                let mut header = tar::Header::new_gnu();
                header.set_size(stat.st_size as u64);
                header.set_mode(0o600);
                header.set_uid(0);
                header.set_gid(0);
                header.set_mtime(0);
                header.set_cksum();
                let mut file = File::from(fd);
                tar.append_data(&mut header, &path, (&mut file).take(stat.st_size as u64))
                    .map_err(|_| Error::Io)?;
                let after = fstat(&file).map_err(|_| Error::Io)?;
                let visible = statat(directory, name.as_str(), AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| Error::Changed)?;
                if !same_file(&stat, &after) || !same_file(&stat, &visible) {
                    return Err(Error::Changed);
                }
            }
            _ => return Err(Error::UnsafeObjects),
        }
    }
    let after = fstat(directory).map_err(|_| Error::Io)?;
    if !same_file(&before, &after) || names(directory)? != listed {
        return Err(Error::Changed);
    }
    Ok(())
}

pub(crate) fn pack_local_source(job: &OwnedFd, owner: u32) -> Result<(String, u64), Error> {
    let root = openat(
        job,
        "repository.git",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| Error::UnsafeObjects)?;
    let output = openat(
        job,
        "source.tar.gz",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| Error::Io)?;
    let gzip = GzBuilder::new().mtime(0).write(
        CappedWriter {
            file: File::from(output),
            written: 0,
        },
        Compression::default(),
    );
    let mut tar = tar::Builder::new(gzip);
    visit(&root, "repository.git", owner, &mut tar, &mut (0, 0), 0)?;
    let gzip = tar.into_inner().map_err(|_| Error::Io)?;
    let mut output = gzip.finish().map_err(|_| Error::Io)?;
    output.file.sync_all().map_err(|_| Error::Io)?;
    fsync(job).map_err(|_| Error::Io)?;
    let before = fstat(&output.file).map_err(|_| Error::Io)?;
    if before.st_uid != owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size as u64 != output.written
    {
        return Err(Error::UnsafeObjects);
    }
    output
        .file
        .seek(SeekFrom::Start(0))
        .map_err(|_| Error::Io)?;
    let mut hash = Sha256::new();
    io::copy(&mut output.file, &mut hash).map_err(|_| Error::Io)?;
    let after = fstat(&output.file).map_err(|_| Error::Io)?;
    let visible =
        statat(job, "source.tar.gz", AtFlags::SYMLINK_NOFOLLOW).map_err(|_| Error::Changed)?;
    if !same_file(&before, &after) || !same_file(&before, &visible) {
        return Err(Error::Changed);
    }
    Ok((format!("{:x}", hash.finalize()), output.written))
}
