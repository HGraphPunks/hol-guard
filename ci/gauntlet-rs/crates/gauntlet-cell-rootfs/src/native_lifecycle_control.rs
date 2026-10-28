//! Ready-file input is joined to a held kernel child in its actual overlay.
use crate::declarations::TaskMount;
use crate::native_lifecycle_kernel::HeldLifecycleChild;
use crate::native_lifecycle_ready::HeldLifecycleReady;
use crate::native_lifecycle_spec::NativeLifecycleSpec;
use crate::{hash, CapturedProcess, NativeCell, NativeControlRole, Result};
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use std::time::Instant;

pub(crate) struct NativeLifecycleControl {
    task: TaskMount,
    spec: NativeLifecycleSpec,
    ready: Option<HeldLifecycleReady>,
    child: Option<HeldLifecycleChild>,
    started: Instant,
    requested: bool,
    finished: Option<Value>,
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
            ready: None,
            child: None,
            started: Instant::now(),
            requested: false,
            finished: None,
        })
    }
    pub fn observe(&mut self, cell: &NativeCell, handle: &str) -> Result<()> {
        if self.child.is_none() {
            self.child = HeldLifecycleChild::find(cell, handle, &self.spec)?;
        }
        if let Some(child) = &self.child {
            if self.ready.is_none() {
                self.ready = HeldLifecycleReady::read(&child.workspace, &self.spec)?;
            }
            if let Some(ready) = self.ready.as_mut() {
                if ready.ready["pid"] != child.observation["namespace_pid"] {
                    return Err("ready claim does not name the independently held child".into());
                }
                ready.recheck_with_liveness(|| Ok(!child.is_alive()?))?;
                let alive = child.is_alive()?;
                if self.spec.role == NativeControlRole::Cancel && alive {
                    self.requested = true;
                    return Err("controller requested product-cell cancellation after held detached readiness".into());
                }
            }
        }
        Ok(())
    }
    pub fn finish(&mut self, cell: &NativeCell, captured: &Result<CapturedProcess>) -> Value {
        let mut child_dead = None;
        let mut ready_file = None;
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
            let ready = self
                .ready
                .as_mut()
                .ok_or("held lifecycle readiness missing")?;
            ready_file = Some(ready.recheck(true)?);
            Ok(())
        })();
        let error = checked.err();
        let value = json!({"schema":"hol-gauntlet-native-detached-lifecycle.v2","role":self.spec.role.as_str(),
            "status":if error.is_none(){"passed"}else{"failed"},"error":error,
            "ready":self.ready.as_ref().map(|r|&r.ready),"ready_file":ready_file,
            "detached_child":self.child.as_ref().map(|c|&c.observation),"detached_child_dead":child_dead,
            "cancel_requested_after_kernel_readiness":self.requested,"product_cell_closed":cell.cleanup_complete(),
            "capture_exit_code":captured.as_ref().ok().map(|c|c.returncode),"capture_error":captured.as_ref().err(),
            "late_effect_absent":ready_file.as_ref().map(|v|v["late_effect_absent"].clone()),
            "elapsed_ms":self.started.elapsed().as_millis(),"execution_eligible":false,
            "guard_causality_verified":false,"model_requests":0});
        self.finished = Some(value.clone());
        value
    }
    pub fn verify_closed(
        &mut self,
        preparation: &crate::CellPreparation,
        role: NativeControlRole,
        control: &Value,
    ) -> Result<Value> {
        let spec = NativeLifecycleSpec::new(&preparation.stage, role)?;
        if self.finished.as_ref() != Some(control)
            || control["status"] != "passed"
            || spec.token != self.spec.token
        {
            return Err("closed lifecycle requires this exact held successful control".into());
        }
        if self
            .child
            .as_ref()
            .ok_or("held lifecycle child missing")?
            .is_alive()?
        {
            return Err("held lifecycle child alive after cleanup".into());
        }
        let ready = self
            .ready
            .as_mut()
            .ok_or("held lifecycle ready missing")?
            .recheck(true)?;
        crate::native_guard_fixture::workspace(preparation)?;
        for name in [
            "detached-ready.json",
            "detached-ready.pending",
            "late-detached-effect.txt",
        ] {
            absent(&self.task, name)?;
        }
        Ok(json!({"schema":"hol-gauntlet-native-closed-lifecycle.v2",
            "control_sha256":hash(&gauntlet_contracts::canonicalize(control.to_string().as_bytes()).map_err(|e|e.to_string())?),
            "ready_file":ready,"detached_child_dead":true,"late_effect_absent":true,
            "physical_lower_lifecycle_paths_absent":true,"execution_eligible":false,
            "guard_causality_verified":false,"model_requests":0}))
    }
}
