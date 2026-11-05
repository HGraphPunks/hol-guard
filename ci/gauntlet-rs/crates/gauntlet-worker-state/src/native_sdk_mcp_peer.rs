//! MCP relay descendants of the already bound, actual Bun SDK process.
use super::*;
use gauntlet_mcp_service::Family;
use sha2::Digest;
use std::sync::Arc;

pub struct NativeSdkMcpPeer {
    owner: Arc<NativeSdkPeer>,
    peer: NativeSdkRequestPeer,
    python: File,
    executable: OwnedFd,
    executable_stat: Stat,
    executable_sha256: String,
    argv: Vec<u8>,
    family: Family,
}
impl NativeSdkPeer {
    pub fn authenticate_mcp(
        self: &Arc<Self>,
        socket: &UnixStream,
        family: Family,
    ) -> Result<NativeSdkMcpPeer, String> {
        self.recheck()?;
        let peer = self.authenticate(socket, true)?;
        let root = openat(
            &self.agent.snapshot.process,
            "root",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let python = openat(
            &root,
            "usr/bin/python3.12",
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let python = File::from(python);
        let outside = fstat(&python).map_err(|e| e.to_string())?;
        let (executable, executable_stat, executable_sha256) =
            crate::staging_product_process::executable(&peer.snapshot.process)?;
        if outside.st_uid != 0
            || outside.st_gid != 0
            || outside.st_nlink != 1
            || outside.st_mode & 0o022 != 0
            || !same_executable(&outside, &executable_stat)
        {
            return Err(
                "SDK MCP relay executable differs from the held readonly image interpreter".into(),
            );
        }
        let argv = [
            "/usr/bin/python3".to_owned(),
            "/runtime/public/service_relay.py".into(),
            "--socket".into(),
            format!("/runtime/resources/{}.sock", family.name()),
        ]
        .iter()
        .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
        .collect();
        let result = NativeSdkMcpPeer {
            owner: self.clone(),
            peer,
            python,
            executable,
            executable_stat,
            executable_sha256,
            argv,
            family,
        };
        result.recheck(socket)?;
        Ok(result)
    }
}
impl NativeSdkMcpPeer {
    pub fn recheck(&self, socket: &UnixStream) -> Result<(), String> {
        self.owner.recheck()?;
        self.peer.recheck(socket)?;
        bind_sdk_relay_to_ancestor_ineligible(socket, &self.peer.held, &self.owner.pin)?;
        let current = openat(
            &self.peer.snapshot.process,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        for s in [
            fstat(&current),
            fstat(&self.executable),
            fstat(&self.python),
        ] {
            if !same_executable(&self.executable_stat, &s.map_err(|e| e.to_string())?) {
                return Err("SDK MCP interpreter inode changed".into());
            }
        }
        if read_at(&self.peer.snapshot.process, "cmdline", 16384)? != self.argv {
            return Err("SDK MCP relay argv changed".into());
        }
        self.peer.recheck(socket)
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-mcp-peer.v1","family":self.family.name(),"peer":self.peer.observation(),
            "executable_sha256":self.executable_sha256,"argv_sha256":format!("{:x}",sha2::Sha256::digest(&self.argv)),
            "fixed_relay_argv_verified":true,"sdk_ancestry_rechecked":true,
            "guard_causality_verified":false,"execution_eligible":false})
    }
}
