//! Actual service/profile teardown after an exhausted evidence filesystem.
use super::*;
use crate::declarations::{Runtime, System};
use crate::{NetworkProfile, StateProfile};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::process::{Command, Stdio};

struct Mount(PathBuf);
impl Drop for Mount {
    fn drop(&mut self) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(self.0.as_os_str().as_bytes()).unwrap();
        // SAFETY: this test owns this mount in its dedicated mount namespace.
        assert_eq!(unsafe { libc::umount2(path.as_ptr(), 0) }, 0);
    }
}

fn cell(stage: &Path, prefix: &Path) -> NativeCell {
    let directory = || crate::fs_input::directory(prefix).unwrap();
    let mut pins = BTreeMap::new();
    for path in [
        "/usr/bin/systemctl",
        "/usr/sbin/apparmor_parser",
        "/usr/bin/nsenter",
    ] {
        pins.insert(path.into(), crate::hash(&fs::read(path).unwrap()));
    }
    let profile = format!("hol-product-cell-{}", crate::nonce().unwrap());
    let spec = SupervisorSpec {
        rootfs_declaration: stage.join("native-rootfs.v1.json"),
        rootfs_sha256: "a".repeat(64),
        constructor: "/opt/hol-gauntlet/test/gauntlet-cell-rootfs".into(),
        constructor_sha256: "b".repeat(64),
        wall_seconds: 30,
        cpu: CpuProfile::Quota,
        job_slice: None,
        host_helpers: pins,
        image_interpreter_sha256: None,
        outside_observer_sha256: None,
        process_events: false,
        native_stdio_sha256: None,
        native_pipe_transport: false,
    };
    NativeCell {
        cgroup: spec.cgroup_path(&profile).unwrap(),
        inputs: Inputs {
            spec: RootfsSpec {
                stage: stage.into(),
                initializer_sha256: "a".repeat(64),
                artifact_manifest_sha256: "b".repeat(64),
                system_spec_sha256: "c".repeat(64),
                task_spec_sha256: "d".repeat(64),
                runtime_spec_sha256: "e".repeat(64),
                idmap_runtime: "ubuntu2404-controller-v1".into(),
                state: StateProfile::Memory,
                network: NetworkProfile::UnixOnly,
                native_wire_sha256: None,
            },
            system: System {
                root: prefix.into(),
                device: 0,
                inode: 0,
                workspace: "/runtime/home/project".into(),
            },
            runtime: Runtime {
                prefix: prefix.into(),
                mountpoint: "/runtime/guard".into(),
                tree_digest: gauntlet_evidence::inventory_tree(
                    prefix,
                    gauntlet_evidence::TreeKind::InstalledPrefix,
                )
                .unwrap()
                .digest,
            },
            tasks: Vec::new(),
            stage: crate::fs_input::directory(stage).unwrap(),
            image: directory(),
            prefix: directory(),
            public: directory(),
            native_wire: None,
        },
        spec,
        profile,
        cpu: None,
        actor: None,
        children: BTreeMap::new(),
        output_counts: BTreeMap::new(),
        client: None,
        cancelled: Arc::new(AtomicBool::new(false)),
        journal: Journal::create(stage).unwrap(),
        process: None,
        errors: None,
        loaded: false,
        service_started: false,
        service_observed: false,
        closed: false,
        image: None,
        image_interpreter: None,
        process_events: None,
        process_events_result: None,
        process_events_journaled: false,
        native_wire: None,
        native_wire_result: None,
        declaration_sha256: "a".repeat(64),
        actor_sha256: "b".repeat(64),
    }
}

#[test]
#[ignore = "Root-only owned ARM VM; starts a bounded trusted sleep helper and empty AppArmor profile"]
fn full_journal_still_stops_owned_service_and_removes_owned_profile_without_cleanup_credit() {
    assert_eq!(rustix::process::geteuid().as_raw(), 0);
    // Namespace changes stay on this dedicated test thread.
    std::thread::spawn(|| {
        // SAFETY: no task is running on this fresh test-owned mount namespace.
        assert_eq!(unsafe { libc::unshare(libc::CLONE_NEWNS) }, 0);
        crate::mounts::mount(
            None,
            Path::new("/"),
            None,
            libc::MS_REC | libc::MS_PRIVATE,
            None,
        )
        .unwrap();
        let temp = tempfile::tempdir_in("/run").unwrap();
        let stage = temp.path().join("stage");
        let prefix = temp.path().join("prefix");
        fs::create_dir(&stage).unwrap();
        fs::create_dir(&prefix).unwrap();
        fs::write(prefix.join("inert-marker"), b"no candidate code\n").unwrap();
        crate::mounts::tmpfs(
            &stage,
            libc::MS_NOSUID | libc::MS_NODEV,
            "mode=0700",
            128 * 1024,
            128,
        )
        .unwrap();
        let mount = Mount(stage.clone());
        let mut cell = cell(&stage, &prefix);
        let profile_file = stage.join("native-cell.apparmor");
        fs::write(&profile_file, format!("profile {} {{ }}\n", cell.profile)).unwrap();
        cell.run_helper(
            "/usr/sbin/apparmor_parser",
            &[
                "--replace".into(),
                profile_file.to_string_lossy().into_owned(),
            ],
            Duration::from_secs(10),
        )
        .unwrap();
        cell.loaded = true;
        assert!(absent(&cell.cgroup).unwrap());
        cell.service_started = true;
        let namespace = super::launch::held_private_mount_namespace()
            .unwrap()
            .unwrap();
        let namespace_info = rustix::fs::fstat(&namespace).unwrap();
        let profile_info = fs::metadata(&profile_file).unwrap();
        let entry = super::launch::mount_namespace_entry(&cell.spec, Some(&namespace)).unwrap();
        let mut command = Command::new("/usr/bin/systemd-run");
        command
            .args(["--quiet", "--wait", "--pipe", "--collect"])
            .arg(format!("--unit={}", cell.profile))
            .args([
                "--property=NoNewPrivileges=yes",
                // Opening a full-capability Root parent's held namespace FD
                // requires ptrace-read permission before joining that namespace.
                "--property=CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SYS_PTRACE",
                "--property=MemoryMax=16M",
                "--property=MemorySwapMax=0",
                "--property=TasksMax=2",
                "--property=CPUQuota=10%",
                "--property=RuntimeMaxSec=30",
                "--property=KillMode=control-group",
                "--property=PrivateNetwork=yes",
            ])
            .args(entry)
            .args([
                "/usr/bin/sleep",
                "25",
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        cell.process = Some(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(5);
        let sleep_present = || {
            fs::read_to_string(cell.cgroup.join("cgroup.procs"))
                .ok()
                .is_some_and(|raw| {
                    raw.split_ascii_whitespace().any(|pid| {
                        fs::read_link(format!("/proc/{pid}/exe")).ok().as_deref()
                            == Some(Path::new("/usr/bin/sleep"))
                            && fs::metadata(format!("/proc/{pid}/ns/mnt")).is_ok_and(|s|
                                (s.dev(), s.ino()) == (namespace_info.st_dev, namespace_info.st_ino))
                            // Observe the private-only file through the service's actual root.
                            && fs::metadata(format!("/proc/{pid}/root{}", profile_file.display()))
                                .is_ok_and(|s| (s.dev(), s.ino()) == (profile_info.dev(), profile_info.ino()))
                    })
                })
        };
        while !sleep_present() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !sleep_present() {
            use std::io::Read;
            let process = cell.process.as_mut().unwrap();
            let status = process.try_wait().unwrap();
            let mut errors = String::new();
            if status.is_some() {
                process.stderr.take().unwrap().take(4096).read_to_string(&mut errors).unwrap();
            }
            panic!("actual sleep did not inherit the private namespace/marker: {status:?}; {errors}");
        }
        assert!(!absent(&cell.cgroup).unwrap());
        assert!(!fs::read_to_string(cell.cgroup.join("cgroup.procs"))
            .unwrap()
            .trim()
            .is_empty());
        cell.service_observed = true;
        let mut filler = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(stage.join("owned-test-filler"))
            .unwrap();
        let error = loop {
            if let Err(error) = filler.write_all(&[0; 4096]) {
                break error;
            }
        };
        assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
        assert!(cell.journal.append("exhaustion", json!({})).is_err());
        assert!(cell.close().is_err());
        assert!(!cell.cleanup_complete());
        assert!(absent(&cell.cgroup).unwrap());
        assert!(cell.process.as_mut().unwrap().try_wait().unwrap().is_some());
        let profiles = fs::read_to_string("/sys/kernel/security/apparmor/profiles").unwrap();
        assert!(!profiles
            .lines()
            .any(|line| line.split_ascii_whitespace().next() == Some(cell.profile.as_str())));
        assert!(!cell.loaded);
        assert!(cell.journal.binding().is_err());
        drop(cell);
        drop(filler);
        // The fixture owns these disposable files and its private tmpfs only.
        fs::remove_file(stage.join("owned-test-filler")).unwrap();
        drop(mount);
    })
    .join()
    .unwrap();
}
