//! Outside kernel identities for the UID10005 Native MCP plane. A process
//! match never supplies a Guard decision or authenticates product self-report.
use crate::sdk_wire_peer::{
    ancestor_chain, authenticate_fixed_peer, parent_link, peer_credentials,
};
use crate::staging_product_process::{alive, executable, read_at, same_executable};
use crate::{HeldSdkWirePeer, SdkWirePeerPin};
use rustix::fs::{fstat, open, openat, FileType, Mode, OFlags, Stat};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, os::fd::OwnedFd, os::unix::net::UnixStream, sync::Arc};

#[path = "native_mcp_peer_snapshot.rs"]
mod kernel;
use kernel::Snapshot;

pub(crate) fn label(name: &str) -> Result<String, String> {
    let tail = name
        .strip_prefix("hol-gauntlet-mcp-")
        .ok_or("fixed MCP profile required")?;
    let (job, nonce) = tail.split_once('-').ok_or("MCP job/nonce required")?;
    if !crate::hex(job, 16) || !crate::hex(nonce, 32) {
        return Err("fresh MCP profile required".into());
    }
    Ok(format!("{name} (unconfined)"))
}
fn checked_label(expected: &str, observed: &str) -> Result<String, String> {
    let declared = expected.strip_prefix("crun//&").unwrap_or(expected);
    let name = declared
        .strip_suffix(" (unconfined)")
        .ok_or("MCP template mode differs")?;
    if label(name)? != declared
        || (observed != expected
            && (expected != declared || observed != format!("crun//&{declared}")))
    {
        return Err("MCP process full LSM label differs".into());
    }
    Ok(observed.into())
}
fn checked_status(raw: &[u8], pid: u32) -> Result<BTreeMap<String, String>, String> {
    crate::native_sdk_peer::checked_status_for_uid(raw, pid, 10005)
}

pub struct NativeMcpBoundary {
    snapshot: Snapshot,
    container: String,
}
impl NativeMcpBoundary {
    pub fn observe(
        container: &str,
        pin: &SdkWirePeerPin,
        declared_label: &str,
        product_actor: &Value,
    ) -> Result<Arc<Self>, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        if !crate::hex(container, 64) {
            return Err("fixed MCP container ID required".into());
        }
        let name = declared_label
            .strip_suffix(" (unconfined)")
            .ok_or("MCP template mode required")?;
        if label(name)? != declared_label {
            return Err("MCP profile differs".into());
        }
        let job = name
            .strip_prefix("hol-gauntlet-mcp-")
            .unwrap()
            .split_once('-')
            .unwrap()
            .0;
        let scope = format!("/holgauntletrust{job}.slice/libpod-{container}.scope");
        if pin.cgroup != scope && pin.cgroup != format!("{scope}/container") {
            return Err("MCP CID/job cgroup differs".into());
        }
        let snapshot = Snapshot::new(pin, declared_label)?;
        if snapshot.status["NSpid"].split_ascii_whitespace().last() != Some("1")
            || read_at(&snapshot.process, "cmdline", 1024)? != b"/usr/bin/sleep\x00240\x00"
        {
            return Err("MCP boundary is not the fresh fixed namespace init".into());
        }
        for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup"] {
            let own = open(
                format!("/proc/self/ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let own = fstat(&own).map_err(|e| e.to_string())?;
            let own = format!("{}:{}", own.st_dev, own.st_ino);
            let actual = &snapshot.namespaces[name].1;
            if actual == &own
                || product_actor["namespaces"][name]
                    .as_str()
                    .is_none_or(|product| actual == product)
            {
                return Err("MCP shares a private Root/product namespace".into());
            }
        }
        Ok(Arc::new(Self {
            snapshot,
            container: container.into(),
        }))
    }
    pub fn recheck(&self) -> Result<(), String> {
        self.snapshot.recheck()
    }
    pub fn python(&self) -> Result<File, String> {
        self.recheck()?;
        // Follow exactly the held init's kernel root link. The readonly fixed
        // image supplies this interpreter; the host's Python inode may differ.
        let root = openat(
            &self.snapshot.process,
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
        self.recheck()?;
        Ok(File::from(python))
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-boundary.v1","container_id":self.container,
            "identity":self.snapshot.value(),"execution_eligible":false})
    }
}

pub struct NativeMcpProcess {
    agent: Arc<NativeMcpBoundary>,
    snapshot: Snapshot,
    outside: File,
    executable: OwnedFd,
    executable_stat: Stat,
    executable_sha256: String,
    argv: Vec<u8>,
    gate: Option<(UnixStream, HeldSdkWirePeer)>,
}
fn argv_bytes(argv: &[String]) -> Result<Vec<u8>, String> {
    if argv.is_empty() || argv.len() > 64 || argv.iter().any(|s| s.contains('\0') || s.len() > 4096)
    {
        return Err("bounded literal MCP argv required".into());
    }
    let raw = argv
        .iter()
        .flat_map(|s| s.as_bytes().iter().copied().chain([0]))
        .collect::<Vec<_>>();
    if raw.len() > 16384 {
        return Err("MCP argv byte bound".into());
    }
    Ok(raw)
}
impl NativeMcpProcess {
    /// The Root owner supplies the tuple it observed in its owned cgroup, the
    /// held source executable and expected argv. No product JSON is authority.
    pub fn observe(
        agent: Arc<NativeMcpBoundary>,
        pin: &SdkWirePeerPin,
        outside: &File,
        argv: &[String],
    ) -> Result<Self, String> {
        agent.recheck()?;
        if pin.pid == agent.snapshot.pin.pid || pin.cgroup != agent.snapshot.pin.cgroup {
            return Err("distinct MCP process in the owned cgroup required".into());
        }
        let snapshot = Snapshot::new(pin, &agent.snapshot.label)?;
        if snapshot.namespace_values() != agent.snapshot.namespace_values() {
            return Err("MCP process namespaces differ from measured init".into());
        }
        let outside_stat = fstat(outside).map_err(|e| e.to_string())?;
        if FileType::from_raw_mode(outside_stat.st_mode) != FileType::RegularFile
            || outside_stat.st_uid != 0
            || outside_stat.st_gid != 0
            || outside_stat.st_nlink != 1
            || outside_stat.st_mode & 0o022 != 0
            || outside_stat.st_mode & 0o111 == 0
        {
            return Err("Root-owned immutable MCP executable required".into());
        }
        let (executable, executable_stat, executable_sha256) = executable(&snapshot.process)?;
        if !same_executable(&outside_stat, &executable_stat) {
            return Err("MCP executable differs from held outside inode".into());
        }
        let process = Self {
            agent,
            snapshot,
            outside: outside.try_clone().map_err(|e| e.to_string())?,
            executable,
            executable_stat,
            executable_sha256,
            argv: argv_bytes(argv)?,
            gate: None,
        };
        process.recheck()?;
        Ok(process)
    }
    pub fn bind(
        gate: UnixStream,
        agent: Arc<NativeMcpBoundary>,
        outside: &File,
        argv: &[String],
    ) -> Result<Self, String> {
        let (pid, uid, gid) = peer_credentials(&gate)?;
        if (uid, gid) != (10005, 10005) {
            return Err("MCP gate peer must be UID/GID10005".into());
        }
        let cgroup = agent.snapshot.pin.cgroup.clone();
        let (start_ticks, _) = parent_link(pid, &cgroup)?;
        let pin = SdkWirePeerPin {
            pid,
            start_ticks,
            cgroup,
        };
        let held = authenticate_fixed_peer(&gate, &pin, 10005, 10005)?;
        let mut process = Self::observe(agent, &pin, outside, argv)?;
        process.gate = Some((gate, held));
        process.recheck()?;
        Ok(process)
    }
    pub fn recheck(&self) -> Result<(), String> {
        self.agent.recheck()?;
        self.snapshot.recheck()?;
        if let Some((gate, held)) = &self.gate {
            held.recheck(gate)?;
        }
        let current = openat(
            &self.snapshot.process,
            "exe",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        for stat in [
            fstat(&current),
            fstat(&self.executable),
            fstat(&self.outside),
        ] {
            if !same_executable(&self.executable_stat, &stat.map_err(|e| e.to_string())?) {
                return Err("MCP executable changed".into());
            }
        }
        if read_at(&self.snapshot.process, "cmdline", 16384)? != self.argv {
            return Err("MCP argv changed".into());
        }
        self.snapshot.recheck()
    }
    /// A declared unprivileged bootstrap may exec the normal CLI with the
    /// same interpreter. The owner must observe that exact new argv first.
    pub fn observe_exec(&mut self, argv: &[String]) -> Result<(), String> {
        self.snapshot.recheck()?;
        let expected = argv_bytes(argv)?;
        if read_at(&self.snapshot.process, "cmdline", 16384)? != expected {
            return Err("MCP expected exec has not occurred".into());
        }
        let old = std::mem::replace(&mut self.argv, expected);
        if let Err(error) = self.recheck() {
            self.argv = old;
            return Err(error);
        }
        Ok(())
    }
    pub fn authenticate_descendant(
        &self,
        socket: &UnixStream,
        outside: &File,
        argv: &[String],
    ) -> Result<NativeMcpRequestPeer, String> {
        self.recheck()?;
        let (pid, uid, gid) = peer_credentials(socket)?;
        if (uid, gid) != (10005, 10005) {
            return Err("MCP relay peer must be UID/GID10005".into());
        }
        let (start_ticks, _) = parent_link(pid, &self.snapshot.pin.cgroup)?;
        let pin = SdkWirePeerPin {
            pid,
            start_ticks,
            cgroup: self.snapshot.pin.cgroup.clone(),
        };
        let held = authenticate_fixed_peer(socket, &pin, 10005, 10005)?;
        let first = ancestor_chain(&pin, &self.snapshot.pin)?;
        let process = Self::observe(self.agent.clone(), &pin, outside, argv)?;
        let second = ancestor_chain(&pin, &self.snapshot.pin)?;
        if first != second {
            return Err("MCP relay ancestry changed".into());
        }
        held.recheck(socket)?;
        self.recheck()?;
        Ok(NativeMcpRequestPeer {
            held,
            process,
            ancestor: self.snapshot.pin.clone(),
            hops: first.len() - 1,
        })
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-process.v1","identity":self.snapshot.value(),
            "executable_sha256":self.executable_sha256,"argv_sha256":format!("{:x}",Sha256::digest(&self.argv)),
            "held_executable_and_argv_verified":true,"socket_peer_bound":self.gate.is_some(),
            "product_claims_authenticated":false,"guard_causality_verified":false,"execution_eligible":false})
    }
}
pub struct NativeMcpRequestPeer {
    held: HeldSdkWirePeer,
    process: NativeMcpProcess,
    ancestor: SdkWirePeerPin,
    hops: usize,
}
impl NativeMcpRequestPeer {
    pub fn recheck(&self, socket: &UnixStream) -> Result<(), String> {
        self.held.recheck(socket)?;
        self.process.recheck()?;
        let first = ancestor_chain(&self.process.snapshot.pin, &self.ancestor)?;
        if first.len() != self.hops + 1
            || first != ancestor_chain(&self.process.snapshot.pin, &self.ancestor)?
        {
            return Err("MCP request ancestry changed".into());
        }
        self.held.recheck(socket)
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-mcp-request-peer.v1","process":self.process.observation(),
            "ancestor_pid":self.ancestor.pid,"ancestor_start_ticks":self.ancestor.start_ticks,
            "hops":self.hops,"peer_authenticated":true,"guard_causality_verified":false,"execution_eligible":false})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mcp_saved_ids_and_sdk_profile_cannot_be_interchanged() {
        let raw="Uid: 10005 10005 10005 10005\nGid: 10005 10005 10005 10005\nGroups: 10005\nNoNewPrivs: 1\nSeccomp: 2\nSeccomp_filters: 1\nNSpid: 42 1\nCapAmb: 0000000000000000\nCapBnd: 0000000000000000\nCapEff: 0000000000000000\nCapInh: 0000000000000000\nCapPrm: 0000000000000000\n";
        assert!(checked_status(raw.as_bytes(), 42).is_ok());
        assert!(crate::native_sdk_peer::checked_status(raw.as_bytes(), 42).is_err());
        assert!(checked_status(raw.replace("10005", "10001").as_bytes(), 42).is_err());
        for changed in [
            raw.replace("10005 10005 10005 10005", "10005 10005 0 10005"),
            raw.replace("Groups: 10005", "Groups: 10005 0"),
            raw.replace("Seccomp: 2", "Seccomp: 0"),
            raw.replace("CapBnd: 0000000000000000", "CapBnd: 0000000000000001"),
            format!("{raw}Uid: 10005 10005 10005 10005\n"),
        ] {
            assert!(checked_status(changed.as_bytes(), 42).is_err());
        }
        assert!(crate::native_sdk_peer::checked_status_for_uid(raw.as_bytes(), 42, 0).is_err());
    }
    #[test]
    fn mcp_labels_require_the_exact_job_nonce_mode_and_runtime_stack() {
        let name = format!("hol-gauntlet-mcp-{}-{}", "a".repeat(16), "b".repeat(32));
        let label = label(&name).unwrap();
        let stacked = format!("crun//&{label}");
        assert_eq!(checked_label(&label, &stacked).unwrap(), stacked);
        assert!(checked_label(&stacked, &label).is_err());
        for changed in [
            label.replace("mcp-", "sdk-"),
            label.replace("unconfined", "enforce"),
            format!("other//&{label}"),
            format!("crun//&crun//&{label}"),
        ] {
            assert!(checked_label(&label, &changed).is_err());
        }
    }
}
