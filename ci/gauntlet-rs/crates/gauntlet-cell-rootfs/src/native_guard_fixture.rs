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
const SDK_FIXTURE: &str = include_str!("../../../adapters/native_contained_control_v2.py.txt");
const DIRECTORY: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

pub(crate) fn workspace(spec: &CellPreparation) -> Result<OwnedFd> {
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

pub fn seed(spec: &CellPreparation) -> Result<Value> {
    seed_fixed(
        spec,
        FIXTURE,
        "hol-gauntlet-native-contained-fixture.v1",
        "deterministic_probes.FIXTURES.success@62aa7ba7",
    )
}

pub fn seed_sdk(spec: &CellPreparation) -> Result<Value> {
    seed_fixed(spec, SDK_FIXTURE, "hol-gauntlet-native-contained-fixture.v2",
        "native_contained_control_v2.py.txt; unchanged success assertions with retained Node/npm diagnostics")
}

/// V6 controls also exercise the installed read-only planner. Its project
/// root must be recognized independently of the benign workspace route.
pub fn seed_control(spec: &CellPreparation) -> Result<Value> {
    project_marker(spec, seed_sdk(spec)?)
}

pub fn seed_boundary(spec: &CellPreparation) -> Result<Value> {
    let root = spec.stage.parent().ok_or("boundary job root required")?;
    let path = root.join("controller-canary.txt");
    let extra = include_str!("../../../adapters/native_boundary_control_v1.py.txt").replace(
        "HOL_CONTROLLER_CANARY_JSON",
        &serde_json::to_string(&path).map_err(|e| e.to_string())?,
    );
    let body = format!("{SDK_FIXTURE}\n{extra}");
    let fixture = seed_fixed(spec, &body, "hol-gauntlet-native-contained-fixture.v4",
        "native_contained_control_v2.py.txt + native_boundary_control_v1.py.txt; fixed outside job canary")?;
    let mut fixture = project_marker(spec, fixture)?;
    fixture["schema"] = json!("hol-gauntlet-native-contained-fixture.v4");
    Ok(fixture)
}

fn project_marker(spec: &CellPreparation, mut fixture: Value) -> Result<Value> {
    let root = workspace(spec)?;
    let marker = b"[pytest]\ntestpaths = tests\n";
    let fd = openat(
        &root,
        "pytest.ini",
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(marker).map_err(|e| e.to_string())?;
    fchmod(&file, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    fchown(
        &file,
        Some(Uid::from_raw(10001)),
        Some(Gid::from_raw(10001)),
    )
    .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let held = fstat(&file).map_err(|e| e.to_string())?;
    let visible =
        statat(&root, "pytest.ini", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(128)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw != marker
        || held.st_nlink != 1
        || held.st_uid != 10001
        || held.st_gid != 10001
        || held.st_mode & 0o7777 != 0o600
        || !fs_input::same(&held, &visible)
        || !fs_input::same(&held, &fstat(&file).map_err(|e| e.to_string())?)
    {
        return Err("native control project marker custody differs".into());
    }
    fsync(&root).map_err(|e| e.to_string())?;
    fixture["schema"] = json!("hol-gauntlet-native-contained-fixture.v3");
    fixture["project_marker"] = json!({"file":"pytest.ini","sha256":hash(marker),
        "bytes":marker.len(),"uid":held.st_uid,"gid":held.st_gid,"mode":0o600,
        "device":held.st_dev,"inode":held.st_ino});
    Ok(fixture)
}

pub fn seed_lifecycle(spec: &CellPreparation, role: crate::NativeControlRole) -> Result<Value> {
    let lifecycle = crate::native_lifecycle_spec::NativeLifecycleSpec::new(&spec.stage, role)?;
    let fixture=seed_fixed(spec,&lifecycle.fixture(),"hol-gauntlet-native-contained-fixture.v6",
        "native_lifecycle_parent_v2.py.txt + native_lifecycle_child_v2.py.txt; unprivileged detached fixture with retained child errors")?;
    let mut fixture = project_marker(spec, fixture)?;
    fixture["schema"] = json!("hol-gauntlet-native-contained-fixture.v6");
    fixture["lifecycle_role"] = json!(role.as_str());
    fixture["detached_token"] = json!(lifecycle.token);
    fixture["detached_code_sha256"] = json!(hash(lifecycle.code.as_bytes()));
    Ok(fixture)
}

fn seed_fixed(spec: &CellPreparation, fixture: &str, schema: &str, source: &str) -> Result<Value> {
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
    file.write_all(fixture.as_bytes())
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
    if copied != fixture.as_bytes()
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
    Ok(json!({"schema":schema,"source":source,
        "file":"tests/test_control.py","sha256":hash(fixture.as_bytes()),"bytes":fixture.len(),"uid":10001,"gid":10001,"product_code_executed":false}))
}

pub fn effect(spec: &CellPreparation) -> Result<Value> {
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
