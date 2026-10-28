//! Offline authentication of one public completion against the prior host pin.
//! Explicit options check binding, boundary, SDK/MCP or kernel artifact subsets. No execution,
//! repair, complete role scoring or qualification is performed.
use gauntlet_host_state::{HostControllerKeyPinJournal, HostPrelaunchIdentity};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

fn snapshot(s: &std::fs::Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        s.dev(),
        s.ino(),
        s.mode(),
        s.uid(),
        s.gid(),
        s.nlink(),
        s.len(),
        s.mtime(),
        s.mtime_nsec(),
        s.ctime(),
        s.ctime_nsec(),
    )
}
fn read_completion(path: &Path) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    let limit = gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT as u64;
    if !before.is_file() || before.nlink() != 1 || !(1..=limit).contains(&before.len()) {
        return Err("bounded single-link public completion file required".into());
    }
    let mut raw = Vec::new();
    (&file)
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if raw.len() as u64 != before.len() || snapshot(&before) != snapshot(&after) {
        return Err("public completion changed during read".into());
    }
    Ok(raw)
}
fn run() -> Result<(), String> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 9
        && !(args.len() == 14 && args[9] == "--process-artifacts")
        && !(args.len() == 12
            && matches!(
                args[9].as_str(),
                "--input-binding-artifacts" | "--boundary-artifacts" | "--mcp-artifacts"
            ))
    {
        return Err("usage: gauntlet-host-verify-native-control PRIVATE_PIN_DIRECTORY COMPLETION_JSON SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_SHA256 PREPARATION_SHA256 ROLE [--input-binding-artifacts|--boundary-artifacts|--mcp-artifacts PUBLIC_USTAR SHA256 | --process-artifacts PUBLIC_USTAR SHA256 INTERPRETER_SHA256 OBSERVER_SHA256]".into());
    }
    let journal =
        HostControllerKeyPinJournal::open(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let expected = HostPrelaunchIdentity {
        source_sha: args[3].clone(),
        job_id: args[4].clone(),
        deployment_digest: args[5].clone(),
        worker_generation: args[6].clone(),
    };
    let raw = read_completion(Path::new(&args[2]))?;
    let verified = journal
        .verify_native_completion(&raw, &expected, &args[7], &args[8])
        .map_err(|e| e.to_string())?;
    let mut output = serde_json::json!({"schema":"hol-gauntlet-offline-native-control-verification.v1",
        "completion_sha256":format!("{:x}",Sha256::digest(&raw)),"readback":verified.observation(),
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if args.len() == 12 {
        if args[9] == "--input-binding-artifacts" {
            output["schema"] =
                serde_json::json!("hol-gauntlet-offline-native-binding-artifact-verification.v1");
            output["binding_artifacts"] =
                verified.verify_input_binding_artifacts(Path::new(&args[10]), &args[11])?;
        } else if args[9] == "--boundary-artifacts" {
            output["schema"] =
                serde_json::json!("hol-gauntlet-offline-native-boundary-artifact-verification.v1");
            output["boundary_artifacts"] =
                verified.verify_boundary_artifacts(Path::new(&args[10]), &args[11])?;
        } else {
            output["schema"] =
                serde_json::json!("hol-gauntlet-offline-native-mcp-artifact-verification.v1");
            output["mcp_artifacts"] =
                verified.verify_mcp_artifacts(Path::new(&args[10]), &args[11])?;
        }
    }
    if args.len() == 14 {
        output["schema"] =
            serde_json::json!("hol-gauntlet-offline-native-process-artifact-verification.v1");
        output["process_artifacts"] = verified.verify_process_artifacts(
            Path::new(&args[10]),
            &args[11],
            &args[12],
            &args[13],
        )?;
    }
    println!("{output}");
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("offline native control verification refused: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completion_input_refuses_links_empty_and_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("completion.json");
        std::fs::write(&file, b"{}").unwrap();
        assert_eq!(read_completion(&file).unwrap(), b"{}");
        let link = temp.path().join("link.json");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_completion(&link).is_err());
        let hard = temp.path().join("hard.json");
        std::fs::hard_link(&file, &hard).unwrap();
        assert!(read_completion(&file).is_err());
        let empty = temp.path().join("empty.json");
        std::fs::write(&empty, b"").unwrap();
        assert!(read_completion(&empty).is_err());
        let large = temp.path().join("large.json");
        let created = std::fs::File::create(&large).unwrap();
        created
            .set_len(gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT as u64 + 1)
            .unwrap();
        assert!(read_completion(&large).is_err());
    }
}
