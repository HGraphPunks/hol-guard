//! Authenticate the fixed Rust HTTP bridge in the held SDK namespace.
use super::*;
use crate::staging_product_process::executable;
use sha2::Digest;

fn verify_bridge_executable(
    process: &OwnedFd,
    expected: &Stat,
    generation: &str,
    argv: &[u8],
) -> Result<(), String> {
    if read_at(process, "cmdline", 16384)? != argv {
        return Err("SDK model bridge argv changed".into());
    }
    // The peer is the fixed Rust bridge, not a Bun SDK entrypoint. Hash its
    // actual held executable without applying a different program's argv gate.
    let (_held, observed, digest) = executable(process)?;
    if digest != generation || !same_executable(expected, &observed) {
        return Err("SDK model bridge differs from outside worker bytes or inode".into());
    }
    if read_at(process, "cmdline", 16384)? != argv {
        return Err("SDK model bridge argv changed while hashing".into());
    }
    Ok(())
}

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
        verify_bridge_executable(
            &bound.snapshot.process,
            &bound.program_stat,
            &bound.generation,
            &bound.argv,
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn live_elf_copy_executes_only_after_its_writer_is_closed() {
        use std::{
            io::Read,
            os::fd::AsRawFd,
            process::{Command, Stdio},
            time::{Duration, Instant},
        };
        let temp = tempfile::tempdir().unwrap();
        let root = open(
            temp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let path = temp.path().join("gauntlet-vm-worker");
        let mut writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::io::copy(&mut File::open("/proc/self/exe").unwrap(), &mut writer).unwrap();
        writer.sync_all().unwrap();
        rustix::fs::fchmod(&writer, Mode::from_bits_truncate(0o555)).unwrap();
        let original = fstat(&writer).unwrap();
        let command = || {
            let mut c = Command::new(&path);
            c.arg("--list")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            c
        };
        match command().spawn() {
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::ETXTBSY)),
            Ok(mut child) => {
                let _ = child.kill();
                child.wait().unwrap();
                panic!("writable ELF unexpectedly executed");
            }
        }
        let mut reader = crate::native_sdk_public::readonly_live_bridge(&root, writer).unwrap();
        assert!(same_executable(&original, &fstat(&reader).unwrap()));
        // SAFETY: F_GETFL only observes flags on this live owned descriptor.
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY);
        let mut raw = Vec::new();
        reader.read_to_end(&mut raw).unwrap();
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(&raw)),
            executable(
                &open(
                    format!("/proc/{}", std::process::id()),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                    Mode::empty()
                )
                .unwrap()
            )
            .unwrap()
            .2
        );
        let mut child = command().spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("sealed inert ELF listing timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn rust_bridge_identity_is_not_restricted_to_bun_but_keeps_exact_bytes_inode_and_argv() {
        let process = open(
            format!("/proc/{}", std::process::id()),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let argv = read_at(&process, "cmdline", 16384).unwrap();
        assert!(!argv.starts_with(b"/runtime/bun\0"));
        let (_held, stat, digest) = executable(&process).unwrap();
        verify_bridge_executable(&process, &stat, &digest, &argv).unwrap();
        assert!(verify_bridge_executable(&process, &stat, &"0".repeat(64), &argv).is_err());
        let mut changed = stat;
        changed.st_ino = changed.st_ino.wrapping_add(1);
        assert!(verify_bridge_executable(&process, &changed, &digest, &argv).is_err());
        let mut changed = argv;
        changed.extend_from_slice(b"foreign\0");
        assert!(verify_bridge_executable(&process, &stat, &digest, &changed).is_err());
    }
}
