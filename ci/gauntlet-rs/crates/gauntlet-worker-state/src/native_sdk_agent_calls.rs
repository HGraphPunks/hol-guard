//! Fixed SDK and negative-control launches inside the owned agent.
use super::*;
use std::io::Read;
pub(super) fn read(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > limit {
        return Err("SDK kernel read bound".into());
    }
    Ok(raw)
}
impl NativeSdkAgent {
    pub(super) fn check(&self, value: &Value, running: bool) -> Result<(String, u32), String> {
        if self.commands.is_cleanup() {
            return Err("cleanup consumed this agent; no further execution".into());
        }
        crate::native_job_storage::native::check(&self.job, value, running)?;
        self.check_shape(value, running)
    }
    pub(super) fn check_for_cleanup(
        &self,
        value: &Value,
        running: bool,
    ) -> Result<(String, u32), String> {
        if !self.commands.is_cleanup() || self.cid.as_deref() != value["Id"].as_str() {
            return Err("cleanup requires the original retained full container CID".into());
        }
        crate::native_job_storage::native::check_for_cleanup(&self.job, value, running)?;
        crate::native_sdk_agent_spec::check_retained_cleanup_task(value, self.kernel.as_ref())?;
        self.check_shape(value, running)
    }
    fn check_shape(&self, value: &Value, running: bool) -> Result<(String, u32), String> {
        if self.live {
            check_live_inspection(
                value,
                &self.name,
                &self.job,
                &self.nonce,
                &self.mounts,
                running,
            )
        } else if self.mcp {
            check_mcp_inspection(
                value,
                &self.name,
                &self.job,
                &self.nonce,
                &self.mounts,
                running,
            )
        } else {
            check_inspection(
                value,
                &self.name,
                &self.job,
                &self.nonce,
                &self.mounts,
                running,
            )
        }
    }

    pub(crate) fn prepare_live(
        job: &str,
        spec: &CellPreparation,
        assets: &VerifiedNativeSdkAssets,
        sockets: &NativeSdkSockets,
        public: &NativeSdkPublic,
        mcp: &mut crate::NativeMcpSockets,
    ) -> Result<Self, String> {
        let mut agent = Self::prepare_mcp(job, spec, assets, sockets, public, mcp)?;
        agent.live = true;
        agent.mounts.insert(
            "/runtime/live-model".into(),
            (
                sockets.model_directory()?.to_string_lossy().into_owned(),
                false,
            ),
        );
        Ok(agent)
    }
    pub(crate) fn launch_live_model_bridge(
        &mut self,
        source: &str,
        worker: &str,
        budget: &str,
        cancel: &AtomicBool,
    ) -> Result<RootChild, String> {
        if !crate::hex(source, 40) || !crate::hex(worker, 64) || !crate::hex(budget, 64) {
            return Err("fixed live model bridge pins required".into());
        }
        let value = self.inspect(cancel)?;
        self.check(&value, true)?;
        self.commands.spawn(
            false,
            &strings(&[
                "exec",
                "--interactive",
                self.cid.as_ref().ok_or("SDK CID absent")?,
                "/runtime/public/gauntlet-vm-worker",
                "--live-model-http-bridge-v1",
                source,
                &self.job,
                worker,
                budget,
            ]),
        )
    }
    pub(crate) fn launch_live_sdk(&mut self, cancel: &AtomicBool) -> Result<RootChild, String> {
        self.launch_selected_sdk(cancel)
    }
    fn launch_selected_sdk(&mut self, cancel: &AtomicBool) -> Result<RootChild, String> {
        let value = self.inspect(cancel)?;
        self.check(&value, true)?;
        if !self.entrypoint.sealed() {
            return Err("fresh SDK launch requires sealed startup profile".into());
        }
        let mut args = strings(&[
            "exec",
            "--interactive",
            "--workdir=/runtime/public",
            self.cid.as_ref().ok_or("SDK CID absent")?,
            "/usr/bin/env",
            "-i",
        ]);
        args.extend(
            crate::native_sdk_peer::STARTUP_ENV
                .into_iter()
                .map(|(k, v)| format!("{k}={v}")),
        );
        args.extend(self.entrypoint.arguments());
        self.commands.spawn(false, &args)
    }
    pub(crate) fn boundary_canary_positive(
        &mut self,
        expected: &str,
        cancel: &AtomicBool,
    ) -> Result<Value, String> {
        if !crate::hex(expected, 64) {
            return Err("fixed SDK canary digest required".into());
        }
        let inspected = self.inspect(cancel)?;
        self.check(&inspected, true)?;
        let argv = strings(&["exec","--interactive",self.cid.as_ref().ok_or("SDK CID absent")?,
            "/usr/bin/python3","-I","-B","-c",
            "import os,hashlib;from pathlib import Path;assert os.geteuid()==10001;print(hashlib.sha256(Path('/runtime/agent/agent-canary.txt').read_bytes()).hexdigest())"]);
        let captured = self.commands.run(false, &argv, 10, cancel)?;
        if captured.status.code() != Some(0)
            || captured.stdout != format!("{expected}\n").as_bytes()
            || !captured.stderr.is_empty()
        {
            return Err("SDK boundary canary positive visibility failed".into());
        }
        Ok(
            json!({"command":argv,"exit_code":0,"stdout_sha256":format!("{:x}",Sha256::digest(&captured.stdout)),
            "stderr_sha256":format!("{:x}",Sha256::digest(&captured.stderr)),"canary_sha256":expected,
            "unprivileged_adapter":true,"execution_eligible":false}),
        )
    }
    pub(crate) fn launch_sdk(&mut self, cancel: &AtomicBool) -> Result<RootChild, String> {
        self.launch_selected_sdk(cancel)
    }
    pub(crate) fn launch_peer_probe(&mut self) -> Result<RootChild, String> {
        self.commands.spawn(
            false,
            &strings(&[
                "exec",
                "--interactive",
                self.cid.as_ref().ok_or("SDK CID absent")?,
                "/usr/bin/python3",
                "-I",
                "-B",
                "/runtime/public/same_uid_peer_probe.py",
            ]),
        )
    }

    pub(crate) fn launch_mcp_peer_probe(&mut self) -> Result<RootChild, String> {
        if !self.mcp {
            return Err("MCP peer probe requires its explicit agent profile".into());
        }
        self.commands.spawn(
            false,
            &strings(&[
                "exec",
                "--interactive",
                self.cid.as_ref().ok_or("SDK CID absent")?,
                "/usr/bin/python3",
                "-I",
                "-B",
                "/runtime/public/same_uid_mcp_peer_probe.py",
            ]),
        )
    }
}
