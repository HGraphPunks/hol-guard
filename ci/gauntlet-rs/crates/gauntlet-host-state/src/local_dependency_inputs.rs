//! One-use dependency capsule from an exact, already verified Git source graph.
//! No checkout, package import, installer, VM or provider starts on the host.

use crate::fixed_process::run_fixed_clean;
use crate::private_jobs::{child_directory, same_file, state_root};
use crate::verify_retained_source_archive_commit;
use rustix::fs::{
    fchmod, fstat, fsync, mkdirat, open, openat, statat, AtFlags, FileType, Mode, OFlags,
};
use rustix::process::geteuid;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use std::time::Duration;

fn write_verified(directory: &OwnedFd, name: &str, bytes: &[u8]) -> Result<(), String> {
    let fd = openat(
        directory,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(bytes).map_err(|e| e.to_string())?;
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let before = fstat(&file).map_err(|e| e.to_string())?;
    if before.st_uid != geteuid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || before.st_size as usize != bytes.len()
    {
        return Err("host capsule write custody differs".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash).map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || hash.finalize()[..] != Sha256::digest(bytes)[..]
    {
        return Err("host capsule readback differs".into());
    }
    Ok(())
}

fn git(repository: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>, String> {
    let mut argv = vec![
        "/usr/bin/git".into(),
        "-C".into(),
        repository
            .to_str()
            .ok_or("canonical local repository required")?
            .into(),
    ];
    for setting in [
        "core.hooksPath=/dev/null",
        "credential.helper=",
        "gc.auto=0",
        "maintenance.auto=false",
    ] {
        argv.extend(["-c".into(), setting.into()]);
    }
    argv.extend(args.iter().map(|s| (*s).to_owned()));
    run_fixed_clean(
        &argv,
        Duration::from_secs(30),
        limit,
        1500,
        &[
            ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_CONFIG_COUNT", "0"),
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_NO_LAZY_FETCH", "1"),
            ("GIT_TERMINAL_PROMPT", "0"),
        ],
    )
    .map_err(|_| "bounded dependency Git object read failed".into())
}

fn project_inputs(repository: &Path, source: &str) -> Result<[Vec<u8>; 2], String> {
    if !repository.is_absolute()
        || repository.canonicalize().ok().as_deref() != Some(repository)
        || !repository.is_dir()
        || !gauntlet_contracts::is_git_sha(source)
    {
        return Err("canonical repository and exact dependency commit required".into());
    }
    if git(repository, &["cat-file", "-t", source], 32)? != b"commit\n" {
        return Err("dependency source must identify a commit".into());
    }
    let args = [
        "ls-tree",
        "-z",
        "--full-tree",
        source,
        "--",
        "pyproject.toml",
        "uv.lock",
    ];
    let tree = git(repository, &args, 4096)?;
    let mut objects = BTreeMap::new();
    for line in tree.split(|b| *b == 0).filter(|line| !line.is_empty()) {
        let line = std::str::from_utf8(line).map_err(|_| "dependency tree is not UTF-8")?;
        let (head, path) = line
            .split_once('\t')
            .ok_or("dependency source tree malformed")?;
        let fields = head.split(' ').collect::<Vec<_>>();
        if fields.len() != 3
            || fields[0] != "100644"
            || fields[1] != "blob"
            || !gauntlet_contracts::is_git_sha(fields[2])
            || !matches!(path, "pyproject.toml" | "uv.lock")
            || objects.insert(path, fields[2]).is_some()
        {
            return Err("exact ordinary dependency source blobs required".into());
        }
    }
    if objects.len() != 2 {
        return Err("both dependency source blobs required".into());
    }
    let mut result: [Vec<u8>; 2] = std::array::from_fn(|_| Vec::new());
    for (index, path) in ["pyproject.toml", "uv.lock"].iter().enumerate() {
        result[index] = git(
            repository,
            &["cat-file", "blob", objects[path]],
            4 * 1024 * 1024,
        )?;
        if result[index].is_empty() {
            return Err("empty dependency source input refused".into());
        }
    }
    if git(repository, &args, 4096)? != tree {
        return Err("dependency source tree changed during read".into());
    }
    Ok(result)
}

fn static_arm64(raw: &[u8]) -> bool {
    if raw.len() < 64
        || &raw[..4] != b"\x7fELF"
        || raw[4] != 2
        || raw[5] != 1
        || raw[6] != 1
        || raw[18..20] != [183, 0]
        || !matches!(u16::from_le_bytes(raw[16..18].try_into().unwrap()), 2 | 3)
        || u32::from_le_bytes(raw[20..24].try_into().unwrap()) != 1
        || u16::from_le_bytes(raw[52..54].try_into().unwrap()) != 64
    {
        return false;
    }
    let offset = u64::from_le_bytes(raw[32..40].try_into().unwrap());
    let size = u16::from_le_bytes(raw[54..56].try_into().unwrap()) as u64;
    let count = u16::from_le_bytes(raw[56..58].try_into().unwrap()) as u64;
    if offset < 64
        || size != 56
        || count == 0
        || count > 1024
        || offset
            .checked_add(size * count)
            .is_none_or(|end| end > raw.len() as u64)
    {
        return false;
    }
    let kinds = (0..count)
        .map(|index| {
            let begin = (offset + index * size) as usize;
            u32::from_le_bytes(raw[begin..begin + 4].try_into().unwrap())
        })
        .collect::<Vec<_>>();
    kinds.contains(&1) && !kinds.contains(&3)
}

fn exporter(path: &Path, expected: &str) -> Result<Vec<u8>, String> {
    if !path.is_absolute()
        || path.canonicalize().ok().as_deref() != Some(path)
        || expected.len() != 64
        || !expected
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("canonical exporter and exact SHA-256 required".into());
    }
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "exporter input unavailable")?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != geteuid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o7022 != 0
        || !(64..=16 * 1024 * 1024).contains(&before.st_size)
    {
        return Err("owned ordinary exporter required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible =
        statat(rustix::fs::CWD, path, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || raw.len() as i64 != before.st_size
        || format!("{:x}", Sha256::digest(&raw)) != expected
        || !static_arm64(&raw)
    {
        return Err("exporter changed, is not static ARM64 ELF, or differs from pin".into());
    }
    Ok(raw)
}

/// Add a distinct one-use capsule under an existing source slot. The source
/// archive/ref/graph is independently reverified before any capsule mutation.
pub fn prepare_local_dependency_inputs(
    state: &Path,
    job: &str,
    source_archive: &str,
    repository: &Path,
    source: &str,
    exporter_path: &Path,
    exporter_sha256: &str,
) -> Result<Value, String> {
    verify_retained_source_archive_commit(
        state,
        job,
        source_archive,
        source,
        &format!("refs/heads/local-{source}"),
    )
    .map_err(|e| e.to_string())?;
    let owner = geteuid().as_raw();
    let root = state_root(state, owner).map_err(|e| e.to_string())?;
    let private = child_directory(&root, "private", owner).map_err(|e| e.to_string())?;
    let builds = child_directory(&private, "local-builds", owner).map_err(|e| e.to_string())?;
    let slot = child_directory(&builds, job, owner).map_err(|e| e.to_string())?;
    match statat(&slot, "dependency-inputs", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => {}
        _ => return Err("host dependency input slot already consumed".into()),
    }
    let [project, lock] = project_inputs(repository, source)?;
    let binary = exporter(exporter_path, exporter_sha256)?;
    let hashes = [&project, &lock, &binary].map(|bytes| format!("{:x}", Sha256::digest(bytes)));
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in ["pyproject.toml", "uv.lock", "gauntlet-dependency-exporter"]
        .into_iter()
        .zip([project, lock, binary])
    {
        zip.start_file(
            name,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(0o644),
        )
        .map_err(|e| e.to_string())?;
        zip.write_all(&bytes).map_err(|e| e.to_string())?;
    }
    let raw = zip.finish().map_err(|e| e.to_string())?.into_inner();
    if raw.is_empty() || raw.len() > 32 * 1024 * 1024 {
        return Err("bounded dependency capsule required".into());
    }
    let report = json!({"schema":"hol-gauntlet-host-dependency-inputs.v1","job_id":job,"source_sha":source,"source_archive_sha256":source_archive,
        "payload_sha256":format!("{:x}",Sha256::digest(&raw)),"payload_bytes":raw.len(),"pyproject_sha256":hashes[0],"uv_lock_sha256":hashes[1],"exporter_sha256":hashes[2],"git_graph_verified":true,"execution_eligible":false,"model_requests":0});
    mkdirat(
        &slot,
        "dependency-inputs",
        Mode::RUSR | Mode::WUSR | Mode::XUSR,
    )
    .map_err(|_| "host dependency input slot consumed or creation failed")?;
    fsync(&slot).map_err(|e| e.to_string())?;
    let output = child_directory(&slot, "dependency-inputs", owner).map_err(|e| e.to_string())?;
    fchmod(&output, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    write_verified(&output, "inputs.zip", &raw)?;
    verify_retained_source_archive_commit(
        state,
        job,
        source_archive,
        source,
        &format!("refs/heads/local-{source}"),
    )
    .map_err(|e| e.to_string())?;
    write_verified(
        &output,
        "preparation.v1.json",
        &gauntlet_contracts::canonicalize(report.to_string().as_bytes())
            .map_err(|e| e.to_string())?,
    )?;
    fsync(&output).map_err(|e| e.to_string())?;
    fsync(&slot).map_err(|e| e.to_string())?;
    Ok(report)
}
