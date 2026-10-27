//! Inert fixed fixture preparation and independent held-file readback.
use crate::{fs_input, hash, CellPreparation, Result};
use rustix::fs::{
    fchmod, fchown, fstat, fsync, mkdirat, openat, statat, AtFlags, Dir, FileType, Mode, OFlags,
};
use rustix::process::{Gid, Uid};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;

const FIXTURE: &str = include_str!("../../../adapters/native_contained_control_v1.py.txt");
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

fn workspace(spec: &CellPreparation) -> Result<OwnedFd> {
    let declaration = &spec.task_mounts["workspace"];
    let source = std::path::Path::new(
        declaration["source"]
            .as_str()
            .ok_or("workspace source required")?,
    );
    let root = std::path::Path::new(
        declaration["custody_root"]
            .as_str()
            .ok_or("workspace custody root required")?,
    );
    if source.parent() != Some(root)
        || source.file_name().and_then(|s| s.to_str()) != Some("workspace")
    {
        return Err("fixed native worker workspace required".into());
    }
    let root = fs_input::directory(root)?;
    let fd = openat(&root, "workspace", DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
    let info = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(info.st_mode) != FileType::Directory
        || info.st_uid != 10001
        || info.st_gid != 10001
        || declaration["device"] != info.st_dev
        || declaration["inode"] != info.st_ino
        || declaration["mode"] != info.st_mode & 0o7777
        || info.st_mode & 0o7777 != 0o700
    {
        return Err("native fixture physical workspace differs from outside pins".into());
    }
    Ok(fd)
}

pub(crate) fn seed(spec: &CellPreparation) -> Result<Value> {
    crate::require_outside_root()?;
    let root = workspace(spec)?;
    for item in Dir::read_from(&root).map_err(|e| e.to_string())? {
        let item = item.map_err(|e| e.to_string())?;
        if !matches!(item.file_name().to_bytes(), b"." | b"..") {
            return Err("native fixture workspace is already consumed".into());
        }
    }
    mkdirat(&root, "tests", Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    let tests = openat(&root, "tests", DIRECTORY, Mode::empty()).map_err(|e| e.to_string())?;
    let fd = openat(
        &tests,
        "test_control.py",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(FIXTURE.as_bytes())
        .map_err(|e| e.to_string())?;
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    fchown(
        &file,
        Some(Uid::from_raw(10001)),
        Some(Gid::from_raw(10001)),
    )
    .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let before = fstat(&file).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut copied = Vec::new();
    Read::by_ref(&mut file)
        .take(32769)
        .read_to_end(&mut copied)
        .map_err(|e| e.to_string())?;
    let visible =
        statat(&tests, "test_control.py", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if copied != FIXTURE.as_bytes()
        || before.st_uid != 10001
        || before.st_gid != 10001
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != 0o600
        || !fs_input::same(&before, &visible)
        || !fs_input::same(&before, &fstat(&file).map_err(|e| e.to_string())?)
    {
        return Err("native fixture readback or custody differs".into());
    }
    fchmod(&tests, Mode::RUSR | Mode::WUSR | Mode::XUSR).map_err(|e| e.to_string())?;
    fchown(
        &tests,
        Some(Uid::from_raw(10001)),
        Some(Gid::from_raw(10001)),
    )
    .map_err(|e| e.to_string())?;
    fsync(&tests)
        .and_then(|_| fsync(&root))
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"schema":"hol-gauntlet-native-contained-fixture.v1","source":"deterministic_probes.FIXTURES.success@62aa7ba7",
        "file":"tests/test_control.py","sha256":hash(FIXTURE.as_bytes()),"bytes":FIXTURE.len(),"uid":10001,"gid":10001,"product_code_executed":false}),
    )
}

pub(crate) fn effect(spec: &CellPreparation) -> Result<Value> {
    let workspace = workspace(spec)?;
    let fd = openat(
        &workspace,
        "native-contained.txt",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 10001
        || before.st_gid != 10001
        || before.st_nlink != 1
        || before.st_mode & 0o022 != 0
        || before.st_size != 20
    {
        return Err("held Native contained effect custody differs".into());
    }
    let mut raw = Vec::new();
    let mut file = File::from(fd);
    Read::by_ref(&mut file)
        .take(1024)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw != b"private plane effect"
        || !fs_input::same(&before, &fstat(&file).map_err(|e| e.to_string())?)
    {
        return Err("held Native contained effect bytes changed".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-held-native-effect.v1","path":"native-contained.txt","bytes":raw.len(),"sha256":hash(&raw),
        "device":before.st_dev,"inode":before.st_ino,"uid":before.st_uid,"gid":before.st_gid,"guard_causality_verified":false}),
    )
}
