//! Fixed SDK and negative-control launches inside the owned agent.
use super::*;
impl NativeSdkAgent {
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
