//! Explicit candidate operations shared by the primary host command and its
//! historical diagnostic entrypoints. The existing journals own all custody,
//! one-use dispatch, response validation and recovery authorization.

use crate::{
    prepare_local_source_archive_one_use, public_vm_operations, HostCandidateBuildPinJournal,
    HostCandidateBuildPins, VmCandidateBuildPlan, VmHostBoundCandidateRepairPlan,
    VmHostBoundCandidateResultPlan,
};
use serde_json::Value;
use std::path::Path;

pub const CANDIDATE_BUILD_USAGE: &str = "candidate commands:\nsource PRIVATE_STATE JOB_ID ABSOLUTE_REPOSITORY SOURCE_SHA\ntransfer PRIVATE_SOURCE_STATE PRIVATE_TRANSFER_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 CAPTURE_BINARY_SHA256 [--vm VM_NAME]\nrun PRIVATE_PIN_DIR JOB_ID SOURCE_SHA SOURCE_ARCHIVE_SHA256 VERSION TAG CONTROLLER_ROOT CONTROLLER_TREE_SHA256 UV_BASE_IMAGE_ID RUST_BASE_IMAGE_ID BUILDER_IMAGE_ID POLICY_SHA256 PODMAN_SHA256 SLIRP_SHA256 APPARMOR_PARSER_SHA256 SECCOMP_SHA256 RUNNER_BINARY_SHA256 RESULT_READER_BINARY_SHA256 READINESS_BINARY_SHA256 [--vm VM_NAME]\nread PRIVATE_PIN_DIR JOB_ID RESULT_SHA256 EXPORT_ARCHIVE_SHA256 [--vm VM_NAME]\nrepair PRIVATE_PIN_DIR JOB_ID REPAIR_BINARY_SHA256 [--vm VM_NAME]\nAll private state directories must already exist with mode 0700. All operations remain ineligible for execution admission and qualification.";

/// Parse the entire command before opening a journal or contacting the VM.
/// The private host nonce is never an operator argument or a public result.
pub fn run_candidate_build_command(args: &[String]) -> Result<Value, String> {
    let action = match (args.first().map(String::as_str), args.len()) {
        (Some("source"), 5) => "source",
        (Some("transfer"), 7) => "transfer",
        (Some("transfer"), 9) if args[7] == "--vm" => "transfer",
        (Some("run"), 20) => "run",
        (Some("run"), 22) if args[20] == "--vm" => "run",
        (Some("read"), 5) => "read",
        (Some("read"), 7) if args[5] == "--vm" => "read",
        (Some("repair"), 4) => "repair",
        (Some("repair"), 6) if args[4] == "--vm" => "repair",
        _ => return Err(CANDIDATE_BUILD_USAGE.into()),
    };
    if action == "source" {
        return prepare_local_source_archive_one_use(
            Path::new(&args[1]),
            &args[2],
            Path::new(&args[3]),
            &args[4],
        )
        .map_err(|e| e.to_string());
    }
    if action == "run" {
        return run(args);
    }
    if action == "transfer" {
        let operations =
            public_vm_operations(args.get(8).map(String::as_str)).map_err(|e| e.to_string())?;
        return transfer(args, &operations);
    }
    let vm_index = if action == "repair" { 5 } else { 6 };
    let operations =
        public_vm_operations(args.get(vm_index).map(String::as_str)).map_err(|e| e.to_string())?;
    let journal =
        HostCandidateBuildPinJournal::open(Path::new(&args[1])).map_err(|e| e.to_string())?;
    if action == "repair" {
        VmHostBoundCandidateRepairPlan::new(&operations, &journal, &args[2], &args[3])?
            .execute_repair(&journal)
    } else {
        VmHostBoundCandidateResultPlan::new(&operations, &journal, &args[2], &args[3], &args[4])
            .map_err(|e| e.to_string())?
            .execute_read_only()
            .map_err(|e| e.to_string())
    }
}

fn transfer(args: &[String], operations: &Value) -> Result<Value, String> {
    use crate::private_jobs::{read_regular_bytes, write_private_once};
    use gauntlet_contracts::canonicalize;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let hex = |value: &str, length| {
        value.len() == length
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !hex(&args[3], 16) || !hex(&args[4], 40) || !hex(&args[5], 64) || !hex(&args[6], 64) {
        return Err("exact source transfer job, commit, archive and worker pins required".into());
    }
    let config = crate::load_operations_bytes(operations.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    let (bytes, inventory) =
        crate::source_archive::verified_archive_bytes(Path::new(&args[1]), &args[3], &args[5])
            .map_err(|e| e.to_string())?;
    crate::source_archive_commit::verify_archive_commit_bytes(
        &args[3],
        &bytes,
        inventory,
        &args[4],
        &format!("refs/heads/local-{}", args[4]),
    )
    .map_err(|e| e.to_string())?;
    let journal =
        HostCandidateBuildPinJournal::open(Path::new(&args[2])).map_err(|e| e.to_string())?;
    let dispatch_name = format!("{}.candidate-source-dispatch.json", args[3]);
    let result_name = format!("{}.candidate-source-result.json", args[3]);
    let result_absent = || -> Result<(), String> {
        match rustix::fs::statat(
            journal.directory().map_err(|e| e.to_string())?,
            &result_name,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => Ok(()),
            _ => Err(
                "source transfer result already exists or is uncertain; preserve consumed job"
                    .into(),
            ),
        }
    };
    result_absent()?;
    let dispatch = canonicalize(
        json!({
            "schema":"hol-gauntlet-host-source-dispatch.v1", "job_id":args[3],
            "source_sha":args[4], "source_archive_sha256":args[5], "source_bytes":bytes.len(),
            "worker_generation":args[6], "limactl":config["limactl"], "vm":config["vm"],
            "retry_allowed":false, "execution_eligible":false,
        })
        .to_string()
        .as_bytes(),
    )
    .map_err(|e| e.to_string())?;
    write_private_once(
        journal.directory().map_err(|e| e.to_string())?,
        &dispatch_name,
        &dispatch,
    )?;
    let stable = || -> Result<(), String> {
        if read_regular_bytes(
            journal.directory().map_err(|e| e.to_string())?,
            &dispatch_name,
            rustix::process::geteuid().as_raw(),
        )
        .map_err(|e| e.to_string())?
            != dispatch
        {
            return Err("source transfer record changed; reconcile without retry".into());
        }
        Ok(())
    };
    stable()?;
    result_absent()?;
    let argv = vec![
        config["limactl"]
            .as_str()
            .ok_or("source transport missing")?
            .into(),
        "shell".into(),
        config["vm"].as_str().ok_or("source VM missing")?.into(),
        "--".into(),
        "sudo".into(),
        "-n".into(),
        format!(
            "/opt/hol-gauntlet/rust-native-dependency-worker-{}",
            args[6]
        ),
        "--capture-build-source".into(),
        args[3].clone(),
        args[4].clone(),
        args[5].clone(),
        bytes.len().to_string(),
        args[6].clone(),
    ];
    let raw = crate::stream_process::run_streamed(
        &argv,
        &bytes,
        std::time::Duration::from_secs(180),
        2048,
    )
    .map_err(|_| "source transfer uncertain; dispatch consumed, reconcile without retry")?;
    stable()?;
    let frame = raw
        .strip_suffix(b"\n")
        .filter(|v| !v.contains(&b'\n'))
        .ok_or("source capture response framing differs; dispatch consumed")?;
    if canonicalize(frame).map_err(|e| e.to_string())? != frame {
        return Err("source capture response is not canonical; dispatch consumed".into());
    }
    let value: Value = serde_json::from_slice(frame).map_err(|e| e.to_string())?;
    let expected = json!({"schema":"hol-gauntlet-native-source-capture.v1",
        "job_id":args[3], "source_sha":args[4], "source_archive_sha256":args[5],
        "source_bytes":bytes.len(), "worker_generation":args[6], "builder_executed":false,
        "execution_eligible":false, "model_requests":0});
    if value != expected {
        return Err("source capture response differs from outside pins; dispatch consumed".into());
    }
    let result = json!({"schema":"hol-gauntlet-host-source-transfer.v1",
        "capture":value, "source_graph_verified":true,
        "dispatch_sha256":format!("{:x}", Sha256::digest(&dispatch)),
        "candidate_executed":false, "execution_eligible":false});
    let result_raw = canonicalize(result.to_string().as_bytes()).map_err(|e| e.to_string())?;
    write_private_once(
        journal.directory().map_err(|e| e.to_string())?,
        &result_name,
        &result_raw,
    )?;
    stable()?;
    Ok(result)
}

fn run(args: &[String]) -> Result<Value, String> {
    let operations =
        public_vm_operations(args.get(21).map(String::as_str)).map_err(|e| e.to_string())?;
    let pins = HostCandidateBuildPins {
        job_id: args[2].clone(),
        source_sha: args[3].clone(),
        source_archive_sha256: args[4].clone(),
        version: args[5].clone(),
        tag: args[6].clone(),
        controller_root: args[7].clone(),
        controller_tree_sha256: args[8].clone(),
        uv_base_image_id: args[9].clone(),
        rust_base_image_id: args[10].clone(),
        builder_image_id: args[11].clone(),
        policy_sha256: args[12].clone(),
        podman_sha256: args[13].clone(),
        slirp4netns_sha256: args[14].clone(),
        apparmor_parser_sha256: args[15].clone(),
        seccomp_sha256: args[16].clone(),
        runner_binary_sha256: args[17].clone(),
        result_reader_binary_sha256: args[18].clone(),
    };
    let plan = VmCandidateBuildPlan::new(&operations, pins).map_err(|e| e.to_string())?;
    let journal =
        HostCandidateBuildPinJournal::open(Path::new(&args[1])).map_err(|e| e.to_string())?;
    plan.preflight_plan(&args[19])
        .map_err(|e| e.to_string())?
        .execute_read_only()
        .map_err(|e| e.to_string())?;
    plan.record_before_launch(&journal)
        .map_err(|e| e.to_string())?
        .execute_once(&journal)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;

    const JOB: &str = "4fc83e91ab520067";
    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        args: Vec<String>,
        operations: Value,
        response: Value,
    }
    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let repository = root.join("repo");
        fs::create_dir(&repository).unwrap();
        let git = |args: &[&str]| {
            let output = Command::new("/usr/bin/git")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("-C")
                .arg(&repository)
                .args([
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "user.name=Gauntlet fixture",
                    "-c",
                    "user.email=test@example.invalid",
                ])
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        git(&["init", "-q", "--template="]);
        fs::write(
            repository.join("README"),
            b"inert fixture, never executed\n",
        )
        .unwrap();
        git(&["add", "README"]);
        git(&["commit", "-qm", "source fixture"]);
        let source = git(&["rev-parse", "HEAD"]);
        for name in ["source", "journal"] {
            let path = root.join(name);
            fs::create_dir(&path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let report =
            prepare_local_source_archive_one_use(&root.join("source"), JOB, &repository, &source)
                .unwrap();
        let args = vec![
            "transfer".into(),
            root.join("source").to_str().unwrap().into(),
            root.join("journal").to_str().unwrap().into(),
            JOB.into(),
            source,
            report["source_archive_sha256"].as_str().unwrap().into(),
            "d".repeat(64),
        ];
        let response = json!({"schema":"hol-gauntlet-native-source-capture.v1",
            "job_id":JOB, "source_sha":args[4], "source_archive_sha256":args[5],
            "source_bytes":report["source_bytes"], "worker_generation":args[6],
            "builder_executed":false, "execution_eligible":false, "model_requests":0});
        let mut operations = public_vm_operations(Some("owned-transfer-fixture")).unwrap();
        operations["limactl"] = json!(root.join("limactl"));
        Fixture {
            _temp: temp,
            root,
            args,
            operations,
            response,
        }
    }
    fn transport(f: &Fixture, ending: &str) {
        let script = format!("#!/bin/sh\nprintf x >> \"$0.calls\"\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat > \"$0.input\"\n{ending}\n");
        let path = f.root.join("limactl");
        fs::write(&path, script).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn dispatch(f: &Fixture) -> PathBuf {
        f.root
            .join(format!("journal/{JOB}.candidate-source-dispatch.json"))
    }
    fn result(f: &Fixture) -> PathBuf {
        f.root
            .join(format!("journal/{JOB}.candidate-source-result.json"))
    }

    #[test]
    fn concurrent_transfer_delivers_exact_archive_once_and_restart_never_replays() {
        let f = fixture();
        transport(&f, &format!("printf '%s\\n' '{}'", f.response));
        let results = std::thread::scope(|scope| {
            let jobs: Vec<_> = (0..4)
                .map(|_| scope.spawn(|| transfer(&f.args, &f.operations)))
                .collect();
            jobs.into_iter()
                .map(|j| j.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(results.iter().filter(|v| v.is_ok()).count(), 1);
        assert_eq!(fs::read(f.root.join("limactl.calls")).unwrap(), b"x");
        assert_eq!(
            fs::read(f.root.join("limactl.input")).unwrap(),
            fs::read(
                f.root
                    .join(format!("source/private/local-builds/{JOB}/source.tar.gz"))
            )
            .unwrap()
        );
        let argv = fs::read_to_string(f.root.join("limactl.argv")).unwrap();
        assert_eq!(
            argv.lines().collect::<Vec<_>>(),
            vec![
                "shell",
                "owned-transfer-fixture",
                "--",
                "sudo",
                "-n",
                &format!(
                    "/opt/hol-gauntlet/rust-native-dependency-worker-{}",
                    f.args[6]
                ),
                "--capture-build-source",
                JOB,
                &f.args[4],
                &f.args[5],
                &f.response["source_bytes"].to_string(),
                &f.args[6]
            ]
        );
        let before = fs::read(dispatch(&f)).unwrap();
        let terminal = fs::read(result(&f)).unwrap();
        let value: Value = serde_json::from_slice(&terminal).unwrap();
        assert_eq!(value["capture"], f.response);
        assert_eq!(value["source_graph_verified"], true);
        assert_eq!(value["execution_eligible"], false);
        assert!(transfer(&f.args, &f.operations).is_err());
        let mut other_vm = f.operations.clone();
        other_vm["vm"] = json!("different-transfer-fixture");
        assert!(transfer(&f.args, &other_vm).is_err());
        assert_eq!(fs::read(f.root.join("limactl.calls")).unwrap(), b"x");
        assert_eq!(fs::read(dispatch(&f)).unwrap(), before);
        assert_eq!(fs::read(result(&f)).unwrap(), terminal);
    }

    #[test]
    fn uncertain_or_forged_capture_reply_consumes_dispatch_without_a_result() {
        for kind in ["transport", "wrong-generation", "extra-field", "framing"] {
            let f = fixture();
            let mut response = f.response.clone();
            if kind == "wrong-generation" {
                response["worker_generation"] = json!("a".repeat(64));
            }
            if kind == "extra-field" {
                response["passed"] = json!(true);
            }
            let ending = match kind {
                "transport" => "exit 7".into(),
                "framing" => format!("printf '%s\\n\\n' '{response}'"),
                _ => format!("printf '%s\\n' '{response}'"),
            };
            transport(&f, &ending);
            assert!(transfer(&f.args, &f.operations).is_err(), "{kind}");
            let before = fs::read(dispatch(&f)).unwrap();
            assert!(!result(&f).exists());
            assert!(transfer(&f.args, &f.operations).is_err());
            assert_eq!(fs::read(dispatch(&f)).unwrap(), before);
            assert_eq!(fs::read(f.root.join("limactl.calls")).unwrap(), b"x");
        }
    }

    #[test]
    fn wrong_source_or_archive_and_linked_input_refuse_before_dispatch() {
        for kind in ["source", "archive", "link"] {
            let mut f = fixture();
            transport(&f, "exit 7");
            match kind {
                "source" => f.args[4] = "f".repeat(40),
                "archive" => f.args[5] = "a".repeat(64),
                _ => {
                    let path = f
                        .root
                        .join(format!("source/private/local-builds/{JOB}/source.tar.gz"));
                    let saved = path.with_extension("saved");
                    fs::rename(&path, &saved).unwrap();
                    symlink(saved, path).unwrap();
                }
            }
            assert!(transfer(&f.args, &f.operations).is_err(), "{kind}");
            assert!(!dispatch(&f).exists());
            assert!(!f.root.join("limactl.calls").exists());
        }
    }

    #[test]
    fn orphan_partial_or_linked_transfer_records_never_contact_or_replace() {
        for (record, kind) in [
            ("dispatch", "partial"),
            ("dispatch", "symlink"),
            ("dispatch", "hardlink"),
            ("result", "partial"),
            ("result", "symlink"),
            ("result", "hardlink"),
        ] {
            let f = fixture();
            transport(&f, "exit 7");
            let saved = f.root.join("preserve");
            fs::write(&saved, b"preserve").unwrap();
            let marker = if record == "dispatch" {
                dispatch(&f)
            } else {
                result(&f)
            };
            match kind {
                "partial" => fs::write(&marker, b"").unwrap(),
                "symlink" => symlink(&saved, &marker).unwrap(),
                _ => fs::hard_link(&saved, &marker).unwrap(),
            }
            assert!(transfer(&f.args, &f.operations).is_err(), "{kind}");
            assert!(!f.root.join("limactl.calls").exists());
            assert_eq!(fs::read(saved).unwrap(), b"preserve");
            assert_eq!(
                fs::symlink_metadata(&marker)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                kind == "symlink"
            );
            if record == "dispatch" {
                assert!(!result(&f).exists());
            }
        }
    }
}
