//! Normal unprivileged installed-product entrypoints.
use super::*;
impl NativeMcpAgent {
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
        let check = if self.live {
            check_live_inspection
        } else {
            check_inspection
        };
        check(
            value,
            &self.name,
            &self.job,
            &self.nonce,
            &self.mounts,
            running,
        )
    }

    pub(crate) fn submit_live_prompt(&mut self, cancel: &AtomicBool) -> Result<Value, String> {
        self.public.verify()?;
        let python = self
            .prefix
            .join("bin/python")
            .to_string_lossy()
            .into_owned();
        let argv = vec![
            "exec".into(),
            "--interactive".into(),
            self.cid.as_ref().ok_or("MCP CID absent")?.clone(),
            "/bin/sh".into(),
            "-c".into(),
            "exec \"$@\" < /product/public/live-prompt.json".into(),
            "gauntlet-live-prompt".into(),
            python,
            "-I".into(),
            "-B".into(),
            "-m".into(),
            "codex_plugin_scanner.cli".into(),
            "guard".into(),
            "hook".into(),
            "--json".into(),
            "--harness".into(),
            "omp".into(),
            "--guard-home".into(),
            "/product/guard".into(),
            "--home".into(),
            "/product/home".into(),
            "--workspace".into(),
            "/product/home/project".into(),
        ];
        let output = self.commands.run(false, &argv, 45, cancel)?;
        self.public.verify()?;
        let response = gauntlet_evidence::normalize_native_hook_response(
            &output.stdout,
            i64::from(
                output
                    .status
                    .code()
                    .ok_or("actual live prompt process exit unavailable")?,
            ),
            Some("UserPromptSubmit"),
        )
        .map_err(|e| e.to_string())?;
        Ok(
            json!({"schema":"hol-gauntlet-native-live-mcp-prompt.v1","argv":argv,"exit_code":output.status.code(),
            "stdout_sha256":format!("{:x}",Sha256::digest(&output.stdout)),"stderr_sha256":format!("{:x}",Sha256::digest(&output.stderr)),
            "response":response,"product_claims_authenticated":false,"execution_eligible":false}),
        )
    }
    pub fn identity_and_daemon(
        &mut self,
        pins: &gauntlet_cell_rootfs::NativeGuardPins,
        cancel: &AtomicBool,
    ) -> Result<Value, String> {
        let value = self.inspect(cancel)?;
        self.check(&value, true)?;
        self.public.verify()?;
        let python = self
            .prefix
            .join("bin/python")
            .to_string_lossy()
            .into_owned();
        let cid = self.cid.as_ref().ok_or("MCP CID absent")?.clone();
        let raw = self.command(
            false,
            vec![
                "exec".into(),
                "--interactive".into(),
                cid.clone(),
                python.clone(),
                "-I".into(),
                "-B".into(),
                "/product/public/native_mcp_identity_v1.py".into(),
            ],
            45,
            cancel,
        )?;
        let raw = gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())?;
        let claim: Value = serde_json::from_slice(&raw).map_err(|_| "MCP identity JSON")?;
        if claim["available"] != true
            || claim["compatible"] != true
            || claim["installed"] != true
            || claim["manifest"]["source_sha"] != pins.source_sha
            || claim["capabilities"]["build_sha"] != pins.source_sha
            || claim["package_version"] != pins.package_version
            || claim["manifest"]["package_version"] != pins.package_version
            || claim["capabilities"]["runtime_version"] != pins.package_version
            || claim["runtime_sha256"] != pins.native_sha256
            || claim["manifest"]["runtime_sha256"] != pins.native_sha256
            || claim["prefix"] != self.prefix.to_string_lossy().as_ref()
        {
            return Err("MCP product identity claim differs from outside pins".into());
        }
        self.command(
            false,
            vec![
                "exec".into(),
                "--interactive".into(),
                cid,
                python,
                "-I".into(),
                "-m".into(),
                "codex_plugin_scanner.cli".into(),
                "guard".into(),
                "daemon".into(),
                "ensure".into(),
                "--guard-home".into(),
                "/product/guard".into(),
                "--home".into(),
                "/product/home".into(),
            ],
            45,
            cancel,
        )?;
        Ok(json!({"claim":claim,"product_claims_authenticated":false,"execution_eligible":false}))
    }
    pub fn launch_proxy(
        &mut self,
        family: gauntlet_mcp_service::Family,
        cancel: &AtomicBool,
    ) -> Result<crate::NativeMcpProxyClient, String> {
        let value = self.inspect(cancel)?;
        self.check(&value, true)?;
        self.public.verify()?;
        crate::NativeMcpProxyClient::spawn(
            &mut self.commands,
            self.cid.as_ref().ok_or("MCP CID absent")?,
            &self.prefix,
            family,
        )
    }
    pub fn public_observation(&self) -> Value {
        self.public.observation()
    }
    pub fn prefix(&self) -> &Path {
        &self.prefix
    }
    pub fn proxy_argv(&self, family: gauntlet_mcp_service::Family) -> Vec<String> {
        crate::native_mcp_command::proxy_argv(&self.prefix, family)
    }
    pub fn bootstrap_argv(&self, family: gauntlet_mcp_service::Family) -> Vec<String> {
        vec![
            self.prefix
                .join("bin/python")
                .to_string_lossy()
                .into_owned(),
            "-I".into(),
            "-B".into(),
            "/product/public/native_mcp_proxy_v1.py".into(),
            family.name().into(),
        ]
    }
}
