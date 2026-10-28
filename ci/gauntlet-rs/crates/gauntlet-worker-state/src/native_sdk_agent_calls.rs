//! Fixed SDK and negative-control launches inside the owned agent.
use super::*;
impl NativeSdkAgent {
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
        let value = self.inspect(cancel)?;
        self.check(&value, true)?;
        self.commands.spawn(
            false,
            &strings(&[
                "exec",
                "--interactive",
                self.cid.as_ref().ok_or("SDK CID absent")?,
                "/runtime/bun",
                "/runtime/public/private_cell_sdk_conformance.ts",
                "/runtime/public/episode.json",
            ]),
        )
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
