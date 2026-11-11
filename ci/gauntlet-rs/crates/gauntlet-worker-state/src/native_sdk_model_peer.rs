//! Authenticate the fixed Rust HTTP bridge in the held SDK namespace.
use super::*;
use crate::staging_machine_observer::observe_sdk_executable;
use sha2::Digest;

pub(crate) struct NativeSdkModelPeer {
    agent: NativeSdkBoundary,
    snapshot: Snapshot,
    peer: HeldSdkWirePeer,
    program: File,
    program_stat: Stat,
    argv: Vec<u8>,
    generation: String,
}
impl NativeSdkModelPeer {
    pub(crate) fn bind(
        socket: &UnixStream,
        agent: NativeSdkBoundary,
        program: &File,
        source: &str,
        job: &str,
        generation: &str,
        budget: &str,
    ) -> Result<Self, String> {
        agent.snapshot.recheck()?;
        let (pin, peer) =
            observe_sdk_relay_peer_in_cgroup_ineligible(socket, &agent.snapshot.pin.cgroup)?;
        let snapshot = Snapshot::new(&pin, &agent.snapshot.label)?;
        if snapshot.namespace_values() != agent.snapshot.namespace_values() {
            return Err("model bridge escaped held SDK namespaces".into());
        }
        let program_stat = fstat(program).map_err(|e| e.to_string())?;
        if program_stat.st_uid != 0
            || program_stat.st_gid != 0
            || program_stat.st_nlink != 1
            || program_stat.st_mode & 0o177777 != 0o100555
        {
            return Err("immutable SDK model bridge artifact required".into());
        }
        let observed = observe_sdk_executable(&ContainerProcessIdentity {
            container_id: agent.container_id.clone(),
            pid: pin.pid,
            start_ticks: pin.start_ticks,
            cgroup: pin.cgroup.clone(),
        })
        .ok_or("model bridge executable observation missing")?;
        if observed.executable_sha256 != generation {
            return Err("SDK model bridge differs from outside worker bytes".into());
        }
        let argv = [
            "/runtime/public/gauntlet-vm-worker",
            "--live-model-http-bridge-v1",
            source,
            job,
            generation,
            budget,
        ]
        .iter()
        .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
        .collect();
        let bound = Self {
            agent,
            snapshot,
            peer,
            program: program.try_clone().map_err(|e| e.to_string())?,
            program_stat,
            argv,
            generation: generation.into(),
        };
        bound.recheck(socket)?;
        Ok(bound)
    }
    pub(crate) fn recheck(&self, socket: &UnixStream) -> Result<(), String> {
        self.agent.snapshot.recheck()?;
        self.peer.recheck(socket)?;
        self.snapshot.recheck()?;
        let current = openat(
            &self.snapshot.process,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        for info in [fstat(&current), fstat(&self.program)] {
            if !same_executable(&self.program_stat, &info.map_err(|e| e.to_string())?) {
                return Err("SDK model bridge inode changed".into());
            }
        }
        if read_at(&self.snapshot.process, "cmdline", 16384)? != self.argv {
            return Err("SDK model bridge argv changed".into());
        }
        self.peer.recheck(socket)
    }
    pub(crate) fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-model-peer.v1","identity":self.snapshot.value(),
            "worker_generation":self.generation,"argv_sha256":format!("{:x}",sha2::Sha256::digest(&self.argv)),
            "fixed_executable_inode_verified":true,"execution_eligible":false})
    }
}
