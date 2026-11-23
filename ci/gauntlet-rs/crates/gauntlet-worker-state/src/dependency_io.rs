//! Descriptor-bound inert inputs and one-use output capture. No package byte
//! is imported or executed while Root reads or publishes these files.
//! The same retained group owns dependency resource creators and the client.
use crate::builder_candidate_source::same_file;
pub(crate) use crate::dependency_completion::report_finalization;
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{
    fchmod, fstat, fsync, openat, renameat_with, statat, AtFlags, FileType, Mode, OFlags,
    RenameFlags,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

pub(crate) fn error_detail(error: &str) -> serde_json::Value {
    let end = (0..=error.len().min(1024))
        .rev()
        .find(|n| error.is_char_boundary(*n))
        .unwrap_or(0);
    serde_json::json!({"sha256":format!("{:x}",Sha256::digest(error.as_bytes())),
        "bytes":error.len(),"prefix":&error[..end],"truncated":end<error.len()})
}

pub(crate) fn read(
    dir: &OwnedFd,
    name: &str,
    owner: u32,
    mode: u32,
    maximum: u64,
) -> Result<Vec<u8>, String> {
    let fd = openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_gid != owner
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != mode
        || before.st_size <= 0
        || before.st_size as u64 > maximum
    {
        return Err("dependency file metadata differs".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(dir, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after)
        || !same_file(&before, &visible)
        || raw.len() as i64 != before.st_size
    {
        return Err("dependency file changed while reading".into());
    }
    Ok(raw)
}

pub(crate) fn verify_inputs(job: &OwnedFd, intent: &DependencyRunIntent) -> Result<(), String> {
    let p = &intent.pins;
    let pins = crate::native_dependency_inputs::NativeDependencyInputPins {
        job: p.text("job_id"),
        source: p.text("source_sha"),
        source_archive: p.text("source_archive_sha256"),
        payload_sha256: p.text("capsule_sha256"),
        payload_bytes: p.capsule_bytes(),
        project_sha256: p.text("pyproject_sha256"),
        lock_sha256: p.text("uv_lock_sha256"),
        exporter_sha256: p.text("exporter_sha256"),
        generation: p.text("capture_worker_sha256"),
    };
    let bytes = crate::builder_candidate_source::verify_captured_source(job, pins.source_archive)
        .map_err(|e| e.to_string())?;
    crate::native_dependency_capture::source_receipt(job, &pins, bytes)?;
    let raw = read(job, "dependency-inputs.zip", 0, 0o444, 32 * 1024 * 1024)?;
    crate::native_dependency_inputs::decode_inputs(&raw, &pins)?;
    let directory = openat(
        job,
        "dependency-inputs",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    crate::native_dependency_capture::verify_extracted_inputs(&directory, &pins)?;
    let original = crate::native_job_storage::source::verify(
        pins.job,
        job,
        Some(crate::JobStorageProfile::Dependency),
    )?;
    let name = if original.is_some() {
        "capture.v2.json"
    } else {
        "capture.v1.json"
    };
    if crate::feature_files::read(
        &directory,
        if original.is_some() {
            "capture.v1.json"
        } else {
            "capture.v2.json"
        },
        (0, 0),
        0o600,
        8192,
    )?
    .is_some()
    {
        return Err("mixed dependency capture versions refused".into());
    }
    let receipt = read(&directory, name, 0, 0o600, 8192)?;
    let mut body = pins.receipt();
    if let Some(original) = original {
        body["schema"] = serde_json::json!("hol-gauntlet-native-dependency-inputs.v2");
        body["storage_receipt_sha256"] = original["storage"]["receipt_sha256"].clone();
    }
    let expected =
        gauntlet_contracts::canonicalize(body.to_string().as_bytes()).map_err(|e| e.to_string())?;
    if receipt != expected
        || format!("{:x}", Sha256::digest(&receipt)) != p.text("capture_receipt_sha256")
    {
        return Err("dependency capture receipt differs from outside intent".into());
    }
    let held = fstat(&directory).map_err(|e| e.to_string())?;
    let visible =
        statat(job, "dependency-inputs", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&held, &visible) {
        return Err("dependency input directory replaced".into());
    }
    Ok(())
}

pub(crate) fn captured(job: &OwnedFd) -> Result<Option<(u64, String)>, String> {
    match statat(job, "dependencies.zip", AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(e) => Err(e.to_string()),
        Ok(_) => {
            let raw = read(job, "dependencies.zip", 0, 0o444, 256 * 1024 * 1024)?;
            Ok(Some((
                raw.len() as u64,
                format!("{:x}", Sha256::digest(raw)),
            )))
        }
    }
}

pub(crate) fn capture_output(job: &OwnedFd) -> Result<(u64, String), String> {
    let dir = openat(
        job,
        "export",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&dir).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::Directory
        || before.st_uid != 65532
        || before.st_gid != 65532
        || before.st_mode & 0o7777 != 0o700
    {
        return Err("private unprivileged dependency export required".into());
    }
    let raw = read(&dir, "dependencies.zip", 65532, 0o600, 256 * 1024 * 1024)?;
    let fd = openat(
        job,
        "dependencies.receiving",
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| "dependency output already consumed or unavailable")?;
    fchmod(&fd, Mode::RUSR | Mode::WUSR).map_err(|e| e.to_string())?;
    let mut file = File::from(fd);
    file.write_all(&raw)
        .and_then(|_| file.sync_all())
        .map_err(|_| "dependency output copy commit uncertain")?;
    fchmod(&file, Mode::RUSR | Mode::RGRP | Mode::ROTH).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    let digest = format!("{:x}", Sha256::digest(&raw));
    if read(job, "dependencies.receiving", 0, 0o444, 256 * 1024 * 1024)? != raw
        || read(&dir, "dependencies.zip", 65532, 0o600, 256 * 1024 * 1024)? != raw
    {
        return Err("dependency output differs on independent readback".into());
    }
    let after = fstat(&dir).map_err(|e| e.to_string())?;
    let visible = statat(job, "export", AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if !same_file(&before, &after) || !same_file(&before, &visible) {
        return Err("dependency export directory changed".into());
    }
    renameat_with(
        job,
        "dependencies.receiving",
        job,
        "dependencies.zip",
        RenameFlags::NOREPLACE,
    )
    .map_err(|_| "dependency output publication uncertain")?;
    fsync(job).map_err(|_| "dependency output directory commit uncertain")?;
    if read(job, "dependencies.zip", 0, 0o444, 256 * 1024 * 1024)? != raw {
        return Err("published dependency output changed".into());
    }
    Ok((raw.len() as u64, digest))
}

/// Retain helper custody before loading policy or creating a container.
pub(crate) fn prepare_creators(
    job: &OwnedFd,
    intent: &DependencyRunIntent,
    started: &str,
) -> Result<crate::builder_cgroup::OwnedCandidateCgroup, String> {
    let id = intent.pins.text("job_id");
    let binding = intent.digest()?;
    let mut group =
        crate::builder_cgroup::OwnedCandidateCgroup::create(id).map_err(|e| e.to_string())?;
    let retained = (|| {
        group.retain_candidate(job, id, &binding)?;
        let raw = read(job, "candidate-client-cgroup.v1.json", 0, 0o600, 2048)?;
        crate::builder_candidate_receipt::write_root_canonical_job_file(job, "dependency-creators-ready.v1.json",
            &serde_json::json!({"schema":"hol-gauntlet-native-dependency-creators-ready.v1","job_id":id,
              "intent_sha256":binding,"started_marker_sha256":started,"worker_generation":intent.pins.text("runner_binary_sha256"),
              "client_cgroup_receipt_sha256":format!("{:x}",Sha256::digest(raw))})).map(|_|()).map_err(|e|e.to_string())
    })();
    if let Err(error) = retained {
        group.kill().map_err(|e| e.to_string())?;
        group.drain_and_remove().map_err(|e| e.to_string())?;
        return Err(error);
    }
    Ok(group)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_contracts::DependencyRunPins;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::CommandExt;
    use std::time::{Duration, Instant};

    #[test]
    #[ignore = "requires outside Root and delegated cgroup v2; inert pre-exec helpers only"]
    fn prepared_helpers_join_retained_group_before_exec() {
        gauntlet_cell_rootfs::require_outside_root().unwrap();
        let mut random = [0u8; 8];
        SystemRandom::new().fill(&mut random).unwrap();
        let id: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let pins=DependencyRunPins::from_value(serde_json::json!({
          "job_id":id,"source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
          "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),
          "uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),
          "capture_receipt_sha256":"2".repeat(64),"controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef",
          "controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),
          "builder_image_id":format!("sha256:{}","6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),
          "slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),"runner_binary_sha256":"c".repeat(64)
        })).unwrap();
        let intent =
            DependencyRunIntent::new(pins, "/usr/bin/limactl", "fixture-vm", &"0".repeat(64))
                .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let slot = rustix::fs::open(
            temp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        let started = "d".repeat(64);
        // A torn staging file is preserved and cannot replace completion.
        let partial = "dependency-repair-staging-interrupted.json";
        crate::feature_files::write(&slot, partial, b"{", (0, 0), 0o600).unwrap();
        let journal_dir = tempfile::tempdir().unwrap();
        let journal = crate::RunReservationJournal::open(journal_dir.path()).unwrap();
        let body = gauntlet_contracts::canonicalize(
            br#"{"schema":"hol-gauntlet-native-dependency-repair.v3","fixture":true}"#,
        )
        .unwrap();
        let published = format!("{id}.dependency-repair.json");
        crate::dependency_creator_recovery::publish(&journal, &slot, &published, &body).unwrap();
        assert_eq!(
            crate::feature_files::required(&journal.root, &published, (0, 0), 0o600, 8192).unwrap(),
            body
        );
        assert!(
            crate::dependency_creator_recovery::publish(&journal, &slot, &published, &body)
                .is_err()
        );
        assert_eq!(
            crate::feature_files::required(&journal.root, &published, (0, 0), 0o600, 8192).unwrap(),
            body
        );
        assert_eq!(
            crate::feature_files::required(&slot, partial, (0, 0), 0o600, 8192).unwrap(),
            b"{"
        );
        let mut finalization = serde_json::json!({"schema":"hol-gauntlet-native-dependency-report-finalization.v1",
            "finalizer_generation":"e".repeat(64),"report_sha256":"f".repeat(64)});
        let torn = "dependency-report-finalization-0123456789abcdef.json";
        crate::feature_files::write(&slot, torn, b"{", (0, 0), 0o600).unwrap();
        assert!(report_finalization(&slot, &finalization, false).is_err());
        report_finalization(&slot, &finalization, true).unwrap();
        report_finalization(&slot, &finalization, false).unwrap();
        finalization["finalizer_generation"] = serde_json::Value::Null;
        report_finalization(&slot, &finalization, false).unwrap();
        finalization["report_sha256"] = serde_json::json!("0".repeat(64));
        assert!(report_finalization(&slot, &finalization, false).is_err());
        assert!(report_finalization(&slot, &finalization, true).is_err());
        assert_eq!(
            crate::feature_files::required(&slot, torn, (0, 0), 0o600, 8192).unwrap(),
            b"{"
        );
        let mut group = prepare_creators(&slot, &intent, &started).unwrap();
        let receipt = read(&slot, "candidate-client-cgroup.v1.json", 0, 0o600, 2048).unwrap();
        let ready = read(&slot, "dependency-creators-ready.v1.json", 0, 0o600, 2048).unwrap();
        let recovered =
            crate::dependency_creator_recovery::ready(&slot, &intent, &started).unwrap();
        assert_eq!(recovered.0, format!("{:x}", Sha256::digest(&ready)));
        assert_eq!(recovered.1, format!("{:x}", Sha256::digest(&receipt)));
        assert!(
            crate::dependency_creator_recovery::ready(&slot, &intent, &"e".repeat(64)).is_err()
        );
        let v: serde_json::Value = serde_json::from_slice(&ready).unwrap();
        assert_eq!(v["intent_sha256"], intent.digest().unwrap());
        assert_eq!(v["started_marker_sha256"], started);
        assert_eq!(
            v["client_cgroup_receipt_sha256"],
            format!("{:x}", Sha256::digest(&receipt))
        );
        assert!(
            crate::builder_cgroup::OwnedCandidateCgroup::reopen_candidate(
                &slot,
                &id,
                &"e".repeat(64)
            )
            .is_err()
        );
        let commands = [
            (
                crate::builder_policy::parser_command(
                    "--replace",
                    "/nonexistent/inert-policy",
                    Some(&group),
                )
                .unwrap(),
                true,
            ),
            (
                crate::dependency_podman::helper_command(
                    &["create".into(), "--help".into()],
                    Some(&group),
                )
                .unwrap(),
                true,
            ),
            (
                crate::builder_policy::parser_command(
                    "--replace",
                    "/nonexistent/inert-policy",
                    None,
                )
                .unwrap(),
                false,
            ),
        ];
        for (mut command, expected_placement) in commands {
            use std::os::fd::AsRawFd;
            let (mut receiver, sender) = std::os::unix::net::UnixStream::pair().unwrap();
            receiver
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            // SAFETY: only stack bytes and async-signal-safe getpid/write/kill after placement.
            unsafe {
                command.pre_exec(move || {
                    let pid = libc::getpid();
                    let raw = pid.to_ne_bytes();
                    if libc::write(sender.as_raw_fd(), raw.as_ptr().cast(), raw.len())
                        != raw.len() as isize
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::kill(pid, libc::SIGSTOP) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
            let child =
                std::thread::spawn(move || command.spawn().and_then(|mut child| child.wait()));
            let mut raw_pid = [0u8; 4];
            let received = receiver.read_exact(&mut raw_pid);
            if received.is_err() {
                let _ = group.kill();
                let _ = child.join();
                panic!("inert child handshake failed: {received:?}");
            }
            let pid = i32::from_ne_bytes(raw_pid);
            let held = rustix::process::pidfd_open(
                rustix::process::Pid::from_raw(pid).unwrap(),
                rustix::process::PidfdFlags::empty(),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            let observed = loop {
                let raw = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
                let stat = crate::linux_process::parse_proc_stat(&raw, pid as u32).unwrap();
                if stat.state == 'T' || Instant::now() >= deadline {
                    break stat;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            let own_image = std::fs::metadata("/proc/self/exe").unwrap();
            let child_image = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
            assert_eq!(observed.parent_pid, std::process::id());
            assert_eq!(
                (own_image.dev(), own_image.ino()),
                (child_image.dev(), child_image.ino())
            );
            let raw = std::fs::read(format!("/proc/{pid}/stat")).unwrap();
            let repeated = crate::linux_process::parse_proc_stat(&raw, pid as u32).unwrap();
            assert_eq!(repeated.start_ticks, observed.start_ticks);
            assert_eq!(repeated.parent_pid, std::process::id());
            let actual = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap();
            let placed = actual == format!("0::{}\n", group.path());
            if placed {
                group.kill().unwrap();
            } else {
                rustix::process::pidfd_send_signal(&held, rustix::process::Signal::KILL).unwrap();
            }
            let status = child.join().unwrap();
            assert_eq!(observed.state, 'T');
            assert_eq!(placed, expected_placement);
            assert!(status.is_err() || !status.unwrap().success());
            assert_eq!(
                receipt,
                read(&slot, "candidate-client-cgroup.v1.json", 0, 0o600, 2048).unwrap()
            );
            assert_eq!(
                ready,
                read(&slot, "dependency-creators-ready.v1.json", 0, 0o600, 2048).unwrap()
            );
        }
        group.drain_and_remove().unwrap();
        assert!(!std::path::Path::new(&format!("/sys/fs/cgroup{}", group.path())).exists());
    }
}
