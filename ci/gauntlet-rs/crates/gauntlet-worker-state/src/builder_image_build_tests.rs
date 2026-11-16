use super::*;
use crate::builder_context::derive_from_bytes;

fn inert_preparation_plan() -> (
    crate::builder_context::BuilderContextProof,
    BuilderImagePlan,
) {
    let context = derive_from_bytes(
        &"a".repeat(64),
        "0123456789abcdef",
        include_bytes!("../../../../gauntlet/control_plane/Builder.Dockerfile"),
        include_bytes!("../../../../gauntlet/control_plane/builder_entry.py"),
        include_bytes!("../../../../gauntlet/control_plane/build_artifact.py"),
        include_bytes!("../../../../gauntlet/control_plane/Builder.apparmor"),
    )
    .unwrap();
    let plan = fixed_builder_image_plan(
        &context,
        "0123456789abcdef",
        &"b".repeat(64),
        &"c".repeat(64),
    )
    .unwrap();
    (context, plan)
}

#[test]
#[ignore = "Root-only inert held-directory preparation; no container or candidate"]
fn bounded_builder_preparation_retains_partial_and_refuses_replay_or_tampering() {
    use crate::builder_image_context::{
        bounded_inputs, prepare_bounded_inputs, BuilderInputsState,
    };
    use std::os::unix::fs::PermissionsExt;
    gauntlet_cell_rootfs::require_outside_root().unwrap();
    let (context, plan) = inert_preparation_plan();
    let temp = tempfile::tempdir_in("/run").unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let job = crate::open_root_owned_public_directory(temp.path()).unwrap();
    let inspect = || bounded_inputs(&job, &plan, context.policy_sha256());
    assert_eq!(inspect().unwrap(), BuilderInputsState::Preparable);
    assert!(prepare_bounded_inputs(&job, &plan, &context, || Err(
        "owner lost before write".into()
    ))
    .is_err());
    assert_eq!(inspect().unwrap(), BuilderInputsState::Preparable);
    let interrupted = std::cell::Cell::new(false);
    let result = prepare_bounded_inputs(&job, &plan, &context, || {
        if [
            "Builder.Dockerfile",
            "builder_entry.py",
            "build_artifact.py",
        ]
        .iter()
        .all(|name| {
            temp.path()
                .join("builder-image-context")
                .join(name)
                .is_file()
        }) {
            interrupted.set(true);
            Err("owner lost between context and policy".into())
        } else {
            Ok(())
        }
    });
    assert_eq!(result, Err("owner lost between context and policy".into()));
    assert!(interrupted.get());
    assert!(temp
        .path()
        .join("builder-image-context/builder_entry.py")
        .is_file());
    assert!(!temp.path().join("Builder.apparmor").exists());
    assert!(inspect().is_err());
    assert!(prepare_bounded_inputs(&job, &plan, &context, || Ok(())).is_err());
    let complete = tempfile::tempdir_in("/run").unwrap();
    std::fs::set_permissions(complete.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let held = crate::open_root_owned_public_directory(complete.path()).unwrap();
    prepare_bounded_inputs(&held, &plan, &context, || Ok(())).unwrap();
    assert_eq!(
        bounded_inputs(&held, &plan, context.policy_sha256()).unwrap(),
        BuilderInputsState::Complete
    );
    let extra = complete.path().join("builder-image-context/unexpected");
    std::fs::write(&extra, b"not a declared builder input").unwrap();
    assert!(bounded_inputs(&held, &plan, context.policy_sha256()).is_err());
    std::fs::remove_file(extra).unwrap();
    let file = complete
        .path()
        .join("builder-image-context/builder_entry.py");
    std::fs::write(&file, b"changed pinned builder input").unwrap();
    assert!(bounded_inputs(&held, &plan, context.policy_sha256()).is_err());
    assert!(prepare_bounded_inputs(&held, &plan, &context, || Ok(())).is_err());
}

#[test]
#[ignore = "Root-only inert original-directory custody; no volume or workload"]
fn bounded_builder_preparation_checks_original_custody_before_creating_inputs() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    gauntlet_cell_rootfs::require_outside_root().unwrap();
    let (context, plan) = inert_preparation_plan();
    let temp = tempfile::tempdir_in("/run").unwrap();
    let visible = temp.path().join("job");
    std::fs::create_dir(&visible).unwrap();
    std::fs::set_permissions(&visible, std::fs::Permissions::from_mode(0o700)).unwrap();
    let held = crate::open_root_owned_public_directory(&visible).unwrap();
    let original = rustix::fs::fstat(&held).unwrap();
    let retained = temp.path().join("original");
    std::fs::rename(&visible, &retained).unwrap();
    std::fs::create_dir(&visible).unwrap();
    let recheck = || {
        let current = std::fs::symlink_metadata(&visible).map_err(|e| e.to_string())?;
        if current.dev() != original.st_dev || current.ino() != original.st_ino {
            return Err("original source mount/directory was replaced".into());
        }
        Ok(())
    };
    assert!(
        crate::builder_image_context::prepare_bounded_inputs(&held, &plan, &context, recheck)
            .is_err()
    );
    assert_eq!(std::fs::read_dir(&visible).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&retained).unwrap().count(), 0);
}

#[test]
#[ignore = "requires initialized idle Root worker; private inert journals only, no candidate"]
fn captured_builder_input_cannot_prepare_after_a_later_native_job_becomes_unknown() {
    use crate::builder_candidate_preflight::{BoundedCandidatePreparation, CandidateRuntimePins};
    use crate::candidate_host_anchor::HostCandidateRunAnchor;
    use std::os::unix::fs::PermissionsExt;
    gauntlet_cell_rootfs::require_outside_root().unwrap();
    let journal_dir = tempfile::tempdir_in("/var/lib").unwrap();
    let journal = crate::RunReservationJournal::open_root_owned(journal_dir.path()).unwrap();
    let lease = journal.acquire_active_lease().unwrap();
    crate::native_job_io::require_no_unknown_jobs(&journal).unwrap();
    let captured = tempfile::tempdir_in("/run").unwrap();
    let raw = b"previously retained inert source bytes";
    std::fs::write(captured.path().join("source.tar.gz"), raw).unwrap();
    std::fs::set_permissions(
        captured.path().join("source.tar.gz"),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    let job = crate::open_root_owned_public_directory(captured.path()).unwrap();
    let source = json!({"job_id":"0123456789abcdef","source_sha":"a".repeat(40),
        "source_archive_sha256":format!("{:x}",Sha256::digest(raw))});
    let request = gauntlet_contracts::WorkerRequest::parse(
        json!({
        "schema":"hol-gauntlet-worker-request.v1","action":"run","job_id":"fedcba9876543210",
        "source_sha":"a".repeat(40),"deployment_digest":"b".repeat(64)})
        .to_string()
        .as_bytes(),
    )
    .unwrap();
    journal
        .reserve_under_lease(
            &lease,
            &request,
            &"a".repeat(40),
            &"b".repeat(64),
            &"c".repeat(64),
        )
        .unwrap();
    let (context, plan) = inert_preparation_plan();
    let pin = "f".repeat(64);
    let runtime = CandidateRuntimePins::parse(&pin, &pin, &pin, &pin).unwrap();
    let anchor = HostCandidateRunAnchor::parse_with_tag(
        context.policy_sha256(),
        &pin,
        &pin,
        &pin,
        &pin,
        "v3.49.0",
    )
    .unwrap();
    // Source admission is a caller precondition. This inert regression proves
    // the later unknown refuses BEFORE any Source reinspection, helper or write.
    let error = BoundedCandidatePreparation {
        journal: &journal,
        job: &job,
        source: &source,
        context: &context,
        plan: &plan,
        runtime: &runtime,
        anchor: &anchor,
        controller_root: Path::new("/not-opened-before-admission"),
        tree_digest: &"a".repeat(64),
        image_id: &format!("sha256:{pin}"),
        version: "3.49.0",
        tag: "v3.49.0",
    }
    .consume_and_prepare(|| lease.verify(&journal.root).map_err(|e| e.to_string()))
    .unwrap_err();
    assert_eq!(error, "active or unknown prior job blocks new work");
    assert_eq!(
        std::fs::read(captured.path().join("source.tar.gz")).unwrap(),
        raw.as_slice()
    );
    assert_eq!(std::fs::read_dir(captured.path()).unwrap().count(), 1);
}

#[test]
fn build_argv_is_local_only_and_excludes_candidate_source() {
    let context = derive_from_bytes(
        &"a".repeat(64),
        "0123456789abcdef",
        include_bytes!("../../../../gauntlet/control_plane/Builder.Dockerfile"),
        include_bytes!("../../../../gauntlet/control_plane/builder_entry.py"),
        include_bytes!("../../../../gauntlet/control_plane/build_artifact.py"),
        include_bytes!("../../../../gauntlet/control_plane/Builder.apparmor"),
    )
    .unwrap();
    let plan = fixed_builder_image_plan(
        &context,
        "0123456789abcdef",
        &"b".repeat(64),
        &"c".repeat(64),
    )
    .unwrap();
    let argv = build_argv(&plan);
    assert!(argv.contains(&"--pull=never".to_owned()));
    assert!(argv.contains(&"--no-cache".to_owned()));
    assert!(!argv
        .iter()
        .any(|word| word.contains("source.tar.gz") || word == "--volume"));
    assert_eq!(
        argv.last().unwrap(),
        "/var/lib/hol-gauntlet/builds/0123456789abcdef/builder-image-context"
    );
}

#[test]
fn container_cleanup_requires_every_identity_field() {
    let job = "0123456789abcdef";
    let image = format!("sha256:{}", "a".repeat(64));
    let binding = "b".repeat(64);
    let label = "hol-gauntlet.candidate-intent";
    let original = json!({"Id":"c".repeat(64),"Name":format!("hol-gauntlet-build-{job}"),
        "Image":image,"Config":{"User":"65532:65532","Labels":{label:binding}}});
    let check = |v: &Value| {
        crate::dependency_podman::validated_container_identity(v, job, &image, label, &binding)
    };
    assert_eq!(check(&original).unwrap(), "c".repeat(64));
    for (key, value) in [
        ("Id", json!("c".repeat(63))),
        ("Name", json!("hol-gauntlet-build-fedcba9876543210")),
        ("Image", json!(format!("sha256:{}", "d".repeat(64)))),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        assert!(check(&changed).is_err(), "{key}");
    }
    let mut changed = original.clone();
    changed["Config"]["User"] = json!("0:0");
    assert!(check(&changed).is_err());
    changed = original.clone();
    changed["Config"]["Labels"][label] = json!("d".repeat(64));
    assert!(check(&changed).is_err());
    changed["Config"]["Labels"]
        .as_object_mut()
        .unwrap()
        .remove(label);
    assert!(check(&changed).is_err());
}

#[test]
#[ignore = "requires the owned ARM VM, Root, three leases and outside image/helper pins"]
fn candidate_timeout_stops_its_container_and_refuses_a_foreign_binding() {
    use crate::builder_candidate_process::{candidate_timeout_probe, CandidateProcessError};
    use crate::candidate_host_anchor::CandidateContainer;
    use std::os::unix::fs::PermissionsExt;
    gauntlet_cell_rootfs::require_outside_root().unwrap();
    let main = crate::RunReservationJournal::open_root_owned(Path::new(
        crate::builder_image_context::RUST_STATE,
    ))
    .unwrap();
    let lease = main.acquire_active_lease().unwrap();
    let legacy = crate::builder_image_context::python_worker_lock().unwrap();
    let features =
        crate::RunReservationJournal::open_root_owned(Path::new(crate::feature_state::STATE))
            .unwrap();
    let feature_lease = features.acquire_active_lease().unwrap();
    let image = std::env::var("HOL_GAUNTLET_VM_TEST_BUILDER_IMAGE").unwrap();
    let podman = std::env::var("HOL_GAUNTLET_VM_TEST_PODMAN_SHA256").unwrap();
    let parser = std::env::var("HOL_GAUNTLET_VM_TEST_APPARMOR_SHA256").unwrap();
    crate::builder_candidate_preflight::verify_file(
        "/usr/sbin/apparmor_parser",
        &parser,
        true,
        64 * 1024 * 1024,
    )
    .unwrap();
    let job = format!("c4{:014x}", std::process::id());
    let directory = tempfile::tempdir().unwrap().keep();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let slot = rustix::fs::open(
        &directory,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    let profile = format!("hol-gauntlet-build-{job}");
    assert!(crate::builder_policy::profile_absent(&profile).unwrap());
    let policy = directory.join("Builder.apparmor");
    std::fs::write(
        &policy,
        include_str!("../../../../gauntlet/control_plane/Builder.apparmor")
            .replace("HOL_GAUNTLET_BUILD_PROFILE", &profile),
    )
    .unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    crate::builder_policy::run_parser("--replace", policy.to_str().unwrap()).unwrap();
    let plan = crate::BuilderRunPlan {
        argv: vec![
            "/usr/bin/podman".into(),
            "run".into(),
            "--rm".into(),
            "--name".into(),
            format!("hol-gauntlet-build-{job}"),
            "--user=65532:65532".into(),
            "--cap-drop=ALL".into(),
            "--security-opt=no-new-privileges".into(),
            format!("--security-opt=apparmor={profile}"),
            "--memory=128m".into(),
            "--memory-swap=128m".into(),
            "--cpus=1".into(),
            "--pids-limit=16".into(),
            "--network=none".into(),
            "--ipc=private".into(),
            "--entrypoint=/bin/sleep".into(),
            image.clone(),
            "120".into(),
        ],
        job_id: job.clone(),
        source_archive_sha256: "a".repeat(64),
        execution_eligible: false,
    };
    let binding = "a".repeat(64);
    let foreign_binding = "b".repeat(64);
    let mut owned = CandidateContainer::new(&plan, &image, &podman, &binding).unwrap();
    let attached = owned.create(&slot).unwrap();
    let cid = attached.argv.last().unwrap();
    let receipt = std::fs::read(directory.join("candidate-container.v1.json")).unwrap();
    let seen = std::cell::RefCell::new(None);
    let still_owned = || {
        lease.verify(&main.root).unwrap();
        feature_lease.verify(&features.root).unwrap();
        crate::builder_image_context::verify_python_lock(&legacy).unwrap();
        Ok(())
    };
    let observe = |_, group: &str| {
        // The Root identity must be durable before the first child callback.
        let retained = crate::feature_files::required(
            &slot,
            "candidate-client-cgroup.v1.json",
            (0, 0),
            0o600,
            2048,
        )
        .unwrap();
        let retained: Value = serde_json::from_slice(&retained).unwrap();
        assert_eq!(retained["binding_sha256"], binding);
        assert_eq!(retained["job_id"], job);
        assert!(
            crate::builder_cgroup::OwnedCandidateCgroup::reopen_candidate(
                &slot,
                &job,
                &foreign_binding,
            )
            .is_err()
        );
        assert_eq!(
            group,
            format!("/system.slice/hol-gauntlet-rust-candidate-{job}")
        );
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            let raw =
                crate::dependency_podman::run(&podman, &["inspect".into(), cid.clone()]).unwrap();
            let rows: Vec<Value> = serde_json::from_slice(&raw).unwrap();
            if rows[0]["State"]["Running"] == true {
                let pid = rows[0]["State"]["Pid"].as_u64().unwrap() as u32;
                let base = std::path::PathBuf::from(format!("/proc/{pid}"));
                let status = std::fs::read_to_string(base.join("status")).unwrap();
                let fields: std::collections::BTreeMap<_, _> =
                    status.lines().filter_map(|s| s.split_once(':')).collect();
                assert_eq!(
                    fields["Uid"].split_whitespace().collect::<Vec<_>>(),
                    vec!["65532"; 4]
                );
                assert_eq!(
                    fields["Gid"].split_whitespace().collect::<Vec<_>>(),
                    vec!["65532"; 4]
                );
                assert_eq!(u64::from_str_radix(fields["CapEff"].trim(), 16).unwrap(), 0);
                assert_eq!(fields["NoNewPrivs"].trim(), "1");
                let ticks = crate::linux_process::parse_proc_stat(
                    &std::fs::read(base.join("stat")).unwrap(),
                    pid,
                )
                .unwrap()
                .start_ticks;
                assert!(std::fs::read_to_string(base.join("attr/current"))
                    .unwrap()
                    .contains(&profile));
                *seen.borrow_mut() = Some((pid, ticks, group.to_owned()));
                break;
            }
            assert!(
                Instant::now() < until,
                "inert candidate container did not start"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let foreign = CandidateContainer::new(&plan, &image, &podman, &foreign_binding).unwrap();
        assert!(foreign.drain().is_err());
        assert!(!crate::builder_candidate_process::container_id_absent(cid).unwrap());
        assert_eq!(
            std::fs::read(directory.join("candidate-container.v1.json")).unwrap(),
            receipt
        );
        Ok(())
    };
    assert_eq!(
        candidate_timeout_probe(
            &attached,
            &slot,
            &binding,
            &still_owned,
            &|| owned
                .drain()
                .map_err(|_| CandidateProcessError::CleanupUncertain),
            &observe
        ),
        Err(CandidateProcessError::TimedOut)
    );
    owned.drain().unwrap();
    let (pid, ticks, client_group) = seen.into_inner().unwrap();
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/stat")) {
        assert_ne!(
            crate::linux_process::parse_proc_stat(&raw, pid)
                .unwrap()
                .start_ticks,
            ticks
        );
    }
    crate::builder_policy::run_parser("--remove", policy.to_str().unwrap()).unwrap();
    assert!(crate::builder_policy::profile_absent(&profile).unwrap());
    assert!(!Path::new("/sys/fs/cgroup")
        .join(client_group.trim_start_matches('/'))
        .exists());
    assert_eq!(
        std::fs::read(directory.join("candidate-container.v1.json")).unwrap(),
        receipt
    );
    println!(
        "{}",
        json!({"schema":"hol-gauntlet-candidate-timeout-probe.v1","job_id":job,
        "container_id":cid,"init_pid":pid,"init_start_ticks":ticks,"client_cgroup":client_group,"timeout_observed":true,
        "foreign_binding_refused":true,"container_and_cgroups_absent":true,"profile_absent":true,
        "receipt_unchanged":true,"proof_directory":directory,"leases_held":3,"candidate_executed":false,
        "qualification_eligible":false,"model_requests":0,"model_tokens":0})
    );
}
