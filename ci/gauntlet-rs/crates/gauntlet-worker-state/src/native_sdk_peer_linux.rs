//! Held pidfds, executable inode and namespace descriptors for one actual SDK.
use super::{checked_status, sdk_cgroup, sdk_process_label};
use crate::linux_process::observe_process;
use crate::sdk_wire_peer::{
    authenticate_sdk_relay_peer_ineligible, bind_sdk_relay_to_ancestor_ineligible,
    observe_sdk_relay_peer_in_cgroup_ineligible, HeldSdkWirePeer, SdkWirePeerPin,
};
use crate::staging_machine_observer::{observe_sdk_executable, ContainerProcessIdentity};
use crate::staging_product_process::{alive, read_at, same_executable};
use rustix::fs::{fstat, open, openat, Mode, OFlags, Stat};
use rustix::process::{pidfd_open, Pid, PidfdFlags};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

#[path = "native_sdk_mcp_peer.rs"]
mod mcp;
pub use mcp::NativeSdkMcpPeer;

struct Snapshot {
    pin: SdkWirePeerPin,
    process: OwnedFd,
    pidfd: OwnedFd,
    namespaces: BTreeMap<String, (OwnedFd, String)>,
    status: BTreeMap<String, String>,
    label: String,
}

impl Snapshot {
    fn new(pin: &SdkWirePeerPin, label: &str) -> Result<Self, String> {
        observe_process(pin.pid, pin.start_ticks, &pin.cgroup)
            .map_err(|_| "SDK process differs from outside tuple")?;
        let pid = Pid::from_raw(i32::try_from(pin.pid).map_err(|_| "SDK PID overflow")?)
            .ok_or("SDK PID invalid")?;
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(|e| e.to_string())?;
        let process = open(
            format!("/proc/{}", pin.pid),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        let status = checked_status(&read_at(&process, "status", 16384)?, pin.pid)?;
        let current = String::from_utf8(read_at(&process, "attr/current", 4096)?)
            .map_err(|_| "SDK LSM label UTF-8")?;
        let label = sdk_process_label(label, current.trim())?;
        let mut namespaces = BTreeMap::new();
        for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup", "user"] {
            let fd = openat(
                &process,
                format!("ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let s = fstat(&fd).map_err(|e| e.to_string())?;
            namespaces.insert(name.into(), (fd, format!("{}:{}", s.st_dev, s.st_ino)));
        }
        let snapshot = Self {
            pin: pin.clone(),
            process,
            pidfd,
            namespaces,
            status,
            label,
        };
        snapshot.recheck()?;
        Ok(snapshot)
    }
    fn recheck(&self) -> Result<(), String> {
        alive(&self.pidfd)?;
        observe_process(self.pin.pid, self.pin.start_ticks, &self.pin.cgroup)
            .map_err(|_| "SDK PID/start/cgroup changed")?;
        if checked_status(&read_at(&self.process, "status", 16384)?, self.pin.pid)? != self.status
            || String::from_utf8(read_at(&self.process, "attr/current", 4096)?)
                .map_err(|_| "SDK label UTF-8")?
                .trim()
                != self.label
        {
            return Err("SDK IDs/capabilities/filter/label changed".into());
        }
        for (name, (held, expected)) in &self.namespaces {
            let visible = openat(
                &self.process,
                format!("ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            for fd in [held, &visible] {
                let s = fstat(fd).map_err(|e| e.to_string())?;
                if format!("{}:{}", s.st_dev, s.st_ino) != *expected {
                    return Err("SDK namespace changed".into());
                }
            }
        }
        alive(&self.pidfd)
    }
    fn namespace_values(&self) -> BTreeMap<String, String> {
        self.namespaces
            .iter()
            .map(|(n, (_, v))| (n.clone(), v.clone()))
            .collect()
    }
    fn value(&self) -> Value {
        json!({"pid":self.pin.pid,"start_ticks":self.pin.start_ticks,"cgroup":self.pin.cgroup,
            "status":self.status,"namespaces":self.namespace_values(),"lsm_label":self.label,"pidfd_held":true})
    }
}

pub struct NativeSdkBoundary {
    snapshot: Snapshot,
    container_id: String,
}

impl NativeSdkBoundary {
    /// The Root agent owner obtains this tuple from its own fresh container.
    pub fn observe(
        container_id: &str,
        pin: &SdkWirePeerPin,
        label: &str,
        product_actor: &Value,
    ) -> Result<Self, String> {
        gauntlet_cell_rootfs::require_outside_root()?;
        sdk_cgroup(container_id, label, &pin.cgroup)?;
        let snapshot = Snapshot::new(pin, label)?;
        let ids = snapshot.status["NSpid"]
            .split_ascii_whitespace()
            .collect::<Vec<_>>();
        if ids.last() != Some(&"1")
            || read_at(&snapshot.process, "cmdline", 1024)? != b"/usr/bin/sleep\x00240\x00"
        {
            return Err("SDK boundary is not the fixed freshly launched namespace init".into());
        }
        for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup"] {
            let own = open(
                format!("/proc/self/ns/{name}"),
                OFlags::RDONLY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let s = fstat(&own).map_err(|e| e.to_string())?;
            let own = format!("{}:{}", s.st_dev, s.st_ino);
            let actual = &snapshot.namespaces[name].1;
            let product = product_actor["namespaces"][name]
                .as_str()
                .ok_or("outside product namespace unavailable")?;
            if *actual == own || actual == product {
                return Err("SDK shares Root or product private namespace".into());
            }
        }
        Ok(Self {
            snapshot,
            container_id: container_id.into(),
        })
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-agent-boundary.v1","container_id":self.container_id,
            "identity":self.snapshot.value(),"execution_eligible":false})
    }
}

pub struct NativeSdkPeer {
    gate: UnixStream,
    pin: SdkWirePeerPin,
    peer: HeldSdkWirePeer,
    snapshot: Snapshot,
    agent: NativeSdkBoundary,
    executable: File,
    executable_stat: Stat,
    bun: File,
    executable_sha256: String,
    argv_sha256: String,
}

impl NativeSdkPeer {
    pub fn bind(
        gate: UnixStream,
        agent: NativeSdkBoundary,
        bun: &File,
        bun_sha256: &str,
    ) -> Result<Self, String> {
        agent.snapshot.recheck()?;
        if !crate::hex(bun_sha256, 64) {
            return Err("outside Bun digest required".into());
        }
        let outside = fstat(bun).map_err(|e| e.to_string())?;
        if outside.st_uid != 0
            || outside.st_gid != 0
            || outside.st_nlink != 1
            || outside.st_mode & 0o7777 != 0o555
        {
            return Err("immutable Root Bun file custody required".into());
        }
        let (pin, peer) =
            observe_sdk_relay_peer_in_cgroup_ineligible(&gate, &agent.snapshot.pin.cgroup)?;
        if pin.pid == agent.snapshot.pin.pid {
            return Err("SDK must be a distinct exec from its container init".into());
        }
        let snapshot = Snapshot::new(&pin, &agent.snapshot.label)?;
        if snapshot.namespace_values() != agent.snapshot.namespace_values() {
            return Err("SDK escaped its measured agent namespaces".into());
        }
        let sampled = observe_sdk_executable(&ContainerProcessIdentity {
            container_id: agent.container_id.clone(),
            pid: pin.pid,
            start_ticks: pin.start_ticks,
            cgroup: pin.cgroup.clone(),
        })
        .ok_or("fixed actual SDK executable/argv unavailable")?;
        if sampled.executable_sha256 != bun_sha256 {
            return Err("actual SDK Bun bytes differ from outside pin".into());
        }
        let executable = File::open(format!("/proc/{}/exe", pin.pid)).map_err(|e| e.to_string())?;
        let executable_stat = fstat(&executable).map_err(|e| e.to_string())?;
        if !same_executable(&outside, &executable_stat) {
            return Err("SDK executable is not the held frozen Bun inode".into());
        }
        let bound = Self {
            gate,
            pin,
            peer,
            snapshot,
            agent,
            executable,
            executable_stat,
            bun: bun.try_clone().map_err(|e| e.to_string())?,
            executable_sha256: sampled.executable_sha256,
            argv_sha256: sampled.argv_sha256,
        };
        bound.recheck()?;
        Ok(bound)
    }
    pub fn recheck(&self) -> Result<(), String> {
        self.agent.snapshot.recheck()?;
        self.peer.recheck(&self.gate)?;
        self.snapshot.recheck()?;
        let current =
            File::open(format!("/proc/{}/exe", self.pin.pid)).map_err(|e| e.to_string())?;
        for file in [&current, &self.executable, &self.bun] {
            if !same_executable(
                &self.executable_stat,
                &fstat(file).map_err(|e| e.to_string())?,
            ) {
                return Err("SDK held/visible executable inode changed".into());
            }
        }
        let raw = read_at(&self.snapshot.process, "cmdline", 1024)?;
        if raw!=b"/runtime/bun\x00/runtime/public/private_cell_sdk_conformance.ts\x00/runtime/public/episode.json\x00" {
            return Err("SDK command changed after pre-import binding".into())
        }
        Ok(())
    }
    pub fn authenticate(
        &self,
        socket: &UnixStream,
        execution_descendant: bool,
    ) -> Result<NativeSdkRequestPeer, String> {
        self.recheck()?;
        let (pin, held) = if execution_descendant {
            observe_sdk_relay_peer_in_cgroup_ineligible(socket, &self.pin.cgroup)?
        } else {
            (
                self.pin.clone(),
                authenticate_sdk_relay_peer_ineligible(socket, &self.pin)?,
            )
        };
        let ancestry = if execution_descendant {
            Some(bind_sdk_relay_to_ancestor_ineligible(socket, &held, &self.pin)?.to_json())
        } else {
            None
        };
        let snapshot = Snapshot::new(&pin, &self.snapshot.label)?;
        if snapshot.namespace_values() != self.snapshot.namespace_values() {
            return Err("SDK request peer escaped bound namespaces".into());
        }
        held.recheck(socket)?;
        self.recheck()?;
        Ok(NativeSdkRequestPeer {
            held,
            snapshot,
            ancestry,
        })
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-executable-peer.v1","identity":self.snapshot.value(),
            "agent":self.agent.observation(),"executable_sha256":self.executable_sha256,"argv_sha256":self.argv_sha256,
            "kernel_peer_authenticated":true,"bun_executable_pinned":true,"fixed_entrypoint_argv_verified":true,
            "entrypoint_bytes_verified":false,"bound_before_sdk_import":false,
            "sdk_source_pinned":false,"guard_causality_verified":false,"execution_eligible":false})
    }
}

pub struct NativeSdkRequestPeer {
    held: HeldSdkWirePeer,
    snapshot: Snapshot,
    ancestry: Option<Value>,
}
impl NativeSdkRequestPeer {
    pub fn recheck(&self, socket: &UnixStream) -> Result<(), String> {
        self.held.recheck(socket)?;
        self.snapshot.recheck()
    }
    pub fn observation(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-sdk-request-peer.v1","identity":self.snapshot.value(),
            "ancestry":self.ancestry,"peer_authenticated":true,"execution_eligible":false})
    }
}
