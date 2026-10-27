//! File readiness is joined to a held kernel child before timeout or cancel.
use crate::declarations::TaskMount;
use crate::native_lifecycle_kernel::HeldLifecycleChild;
use crate::native_lifecycle_spec::NativeLifecycleSpec;
use crate::{hash, CapturedProcess, NativeCell, NativeControlRole, Result};
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags, Stat};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    time::Instant,
};

pub(crate) struct NativeLifecycleControl {
    task: TaskMount,
    spec: NativeLifecycleSpec,
    file: Option<(File, Stat, Vec<u8>)>,
    ready: Option<Value>,
    child: Option<HeldLifecycleChild>,
    started: Instant,
    requested: bool,
}
fn absent(task: &TaskMount, name: &str) -> Result<()> {
    let workspace = crate::native_binding_fixture::workspace(task)?;
    if !matches!(
        statat(&workspace, name, AtFlags::SYMLINK_NOFOLLOW),
        Err(rustix::io::Errno::NOENT)
    ) {
        return Err(format!(
            "fresh absent synthetic lifecycle path required: {name}"
        ));
    }
    Ok(())
}
pub fn verify_closed(
    preparation: &crate::CellPreparation,
    role: NativeControlRole,
    control: &Value,
) -> Result<Value> {
    let spec = NativeLifecycleSpec::new(&preparation.stage, role)?;
    if control["status"] != "passed"
        || control["role"] != role.as_str()
        || control["detached_child_dead"] != true
    {
        return Err("closed lifecycle requires the actual held-child termination".into());
    }
    let workspace = crate::native_guard_fixture::workspace(preparation)?;
    let fd = openat(
        &workspace,
        "detached-ready.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    let before = fstat(&file).map_err(|e| e.to_string())?;
    let expected = &control["ready_file"];
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != 10001
        || before.st_gid != 10001
        || before.st_mode & 0o7777 != 0o600
        || before.st_nlink != 1
        || !(1..=4096).contains(&before.st_size)
        || expected["device"] != before.st_dev
        || expected["inode"] != before.st_ino
    {
        return Err("quiescent lifecycle readiness custody differs".into());
    }
    let mut raw = Vec::new();
    Read::by_ref(&mut file)
        .take(4097)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let visible = statat(&workspace, "detached-ready.json", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|e| e.to_string())?;
    crate::native_guard_fixture::workspace(preparation)?;
    if !crate::fs_input::same(&before, &visible)
        || !crate::fs_input::same(&before, &fstat(&file).map_err(|e| e.to_string())?)
        || expected["sha256"] != hash(&raw)
        || expected["bytes"] != raw.len()
        || spec.ready(&raw)? != control["ready"]
    {
        return Err("quiescent lifecycle readiness generation differs".into());
    }
    if !matches!(
        statat(
            &workspace,
            "late-detached-effect.txt",
            AtFlags::SYMLINK_NOFOLLOW
        ),
        Err(rustix::io::Errno::NOENT)
    ) {
        return Err("quiescent late lifecycle effect is present or unavailable".into());
    }
    Ok(
        json!({"schema":"hol-gauntlet-native-closed-lifecycle.v1","ready_sha256":hash(&raw),"late_effect_absent":true,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

impl NativeLifecycleControl {
    pub fn new(cell: &NativeCell, role: NativeControlRole) -> Result<Self> {
        let spec = NativeLifecycleSpec::new(&cell.inputs.spec.stage, role)?;
        let task = cell.inputs.tasks[0].clone();
        for name in [
            "detached-ready.json",
            "detached-ready.pending",
            "late-detached-effect.txt",
        ] {
            absent(&task, name)?;
        }
        Ok(Self {
            task,
            spec,
            file: None,
            ready: None,
            child: None,
            started: Instant::now(),
            requested: false,
        })
    }
    fn read_ready(&mut self) -> Result<()> {
        let workspace = crate::native_binding_fixture::workspace(&self.task)?;
        let fd = match openat(
            &workspace,
            "detached-ready.json",
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(e) => return Err(e.to_string()),
        };
        let mut file = File::from(fd);
        let s = fstat(&file).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(s.st_mode) != FileType::RegularFile
            || s.st_uid != 10001
            || s.st_gid != 10001
            || s.st_mode & 0o7777 != 0o600
            || s.st_nlink != 1
            || !(1..=4096).contains(&s.st_size)
        {
            return Err("private lifecycle ready-file custody differs".into());
        }
        let mut raw = Vec::new();
        Read::by_ref(&mut file)
            .take(4097)
            .read_to_end(&mut raw)
            .map_err(|e| e.to_string())?;
        let ready = self.spec.ready(&raw)?;
        let visible = statat(&workspace, "detached-ready.json", AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|e| e.to_string())?;
        if !crate::fs_input::same(&s, &visible)
            || !crate::fs_input::same(&s, &fstat(&file).map_err(|e| e.to_string())?)
            || raw.len() as i64 != s.st_size
        {
            return Err("lifecycle ready generation changed while being read".into());
        }
        self.file = Some((file, s, raw));
        self.ready = Some(ready);
        Ok(())
    }
    pub fn observe(&mut self, cell: &NativeCell, handle: &str) -> Result<()> {
        if self.ready.is_none() {
            self.read_ready()?;
        }
        if self.child.is_none() {
            if let Some(ready) = &self.ready {
                self.child = HeldLifecycleChild::find(cell, handle, &self.spec, ready)?;
            }
        }
        if self.child.is_some() && self.spec.role == NativeControlRole::Cancel {
            self.requested = true;
            return Err(
                "controller requested product-cell cancellation after held detached readiness"
                    .into(),
            );
        }
        Ok(())
    }
    pub fn finish(mut self, cell: &NativeCell, captured: &Result<CapturedProcess>) -> Value {
        let mut child_dead = None;
        let mut late_absent = None;
        let checked = (|| -> Result<()> {
            let child = self
                .child
                .as_ref()
                .ok_or("actual detached child was not observed before control termination")?;
            child_dead = Some(!child.is_alive()?);
            if child_dead != Some(true) {
                return Err("held detached child survived the lifecycle termination".into());
            }
            match self.spec.role {
                NativeControlRole::Timeout
                    if captured.as_ref().is_ok_and(|c| c.returncode == 124)
                        && !cell.cleanup_complete() => {}
                NativeControlRole::Cancel
                    if self.requested && captured.is_err() && cell.cleanup_complete() => {}
                _ => {
                    return Err(
                        "actual Native timeout/controller cancellation outcome differs".into(),
                    )
                }
            }
            let (file, s, raw) = self
                .file
                .as_mut()
                .ok_or("held lifecycle readiness missing")?;
            let workspace = crate::native_binding_fixture::workspace(&self.task)?;
            let visible = statat(&workspace, "detached-ready.json", AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|e| e.to_string())?;
            if !crate::fs_input::same(s, &visible)
                || !crate::fs_input::same(s, &fstat(&*file).map_err(|e| e.to_string())?)
            {
                return Err("held lifecycle readiness replaced after control".into());
            }
            file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
            let mut after = Vec::new();
            Read::by_ref(file)
                .take(4097)
                .read_to_end(&mut after)
                .map_err(|e| e.to_string())?;
            if &after != raw {
                return Err("held lifecycle readiness bytes changed".into());
            }
            absent(&self.task, "late-detached-effect.txt")?;
            late_absent = Some(true);
            Ok(())
        })();
        let error = checked.err();
        json!({"schema":"hol-gauntlet-native-detached-lifecycle.v1","role":self.spec.role.as_str(),"status":if error.is_none(){"passed"}else{"failed"},"error":error,
            "ready":self.ready,"ready_file":self.file.as_ref().map(|(_,s,raw)|json!({"file":"detached-ready.json","sha256":hash(raw),"bytes":raw.len(),
                "device":s.st_dev,"inode":s.st_ino,"uid":s.st_uid,"gid":s.st_gid,"mode":s.st_mode & 0o7777})),
            "detached_child":self.child.as_ref().map(|c|&c.observation),"detached_child_dead":child_dead,
            "cancel_requested_after_kernel_readiness":self.requested,"product_cell_closed":cell.cleanup_complete(),
            "capture_exit_code":captured.as_ref().ok().map(|v|v.returncode),"capture_error":captured.as_ref().err(),
            "late_effect_absent":late_absent,"elapsed_ms":self.started.elapsed().as_millis(),
            "execution_eligible":false,"guard_causality_verified":false,"model_requests":0})
    }
}
