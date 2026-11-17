//! Offline authentication of one public completion against the prior host pin.
//! Explicit options check binding, boundary, SDK/MCP or kernel artifact subsets. No execution,
//! repair, complete role scoring or qualification is performed.
use gauntlet_host_state::{HostControllerKeyPinJournal, HostPrelaunchIdentity};
use serde_json::Value;
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
fn read_file(path: &Path, limit: u64, kind: &str) -> Result<Vec<u8>, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.nlink() != 1 || !(1..=limit).contains(&before.len()) {
        return Err(format!("bounded single-link {kind} file required"));
    }
    let mut raw = Vec::new();
    (&file)
        .take(limit + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if raw.len() as u64 != before.len() || snapshot(&before) != snapshot(&after) {
        return Err(format!("{kind} changed during read"));
    }
    Ok(raw)
}
fn read_completion(path: &Path) -> Result<Vec<u8>, String> {
    read_file(
        path,
        gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT as u64,
        "public completion",
    )
}
fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn read_storage(path: &Path, expected: &str) -> Result<Value, String> {
    if !is_sha256(expected) {
        return Err("outside original-storage SHA-256 required".into());
    }
    let raw = read_file(path, 8192, "original storage")?;
    if digest(&raw) != expected {
        return Err("original storage bytes differ from outside SHA-256".into());
    }
    // The strict parser refuses duplicate keys before serde_json sees them.
    let canonical = gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
    let receipt = value
        .get("receipt")
        .ok_or("original storage receipt required")?;
    let receipt_bytes =
        gauntlet_contracts::canonicalize(&serde_json::to_vec(receipt).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if value.as_object().is_none_or(|o| o.len() != 2)
        || !receipt.is_object()
        || value["receipt_sha256"] != digest(&receipt_bytes)
    {
        return Err("exact original storage wrapper and receipt digest required".into());
    }
    Ok(value)
}
struct Options<'a> {
    args: &'a [String],
    storage: Option<(&'a str, &'a str)>,
}
fn options(mut args: &[String]) -> Result<Options<'_>, String> {
    let storage = if args.len() >= 12 && args[args.len() - 3] == "--bounded-storage" {
        let last = args.len();
        if !is_sha256(&args[last - 1]) {
            return Err("outside original-storage SHA-256 required".into());
        }
        let storage = Some((args[last - 2].as_str(), args[last - 1].as_str()));
        args = &args[..last - 3];
        storage
    } else {
        None
    };
    if args.len() != 9
        && !(args.len() == 14
            && matches!(
                args[9].as_str(),
                "--process-artifacts"
                    | "--hook-artifacts"
                    | "--control-artifacts"
                    | "--readonly-artifacts"
            ))
        && !(args.len() == 12
            && matches!(
                args[9].as_str(),
                "--input-binding-artifacts" | "--boundary-artifacts" | "--mcp-artifacts"
            ))
    {
        return Err("usage: gauntlet-host-verify-native-control PRIVATE_PIN_DIRECTORY COMPLETION_JSON SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_SHA256 PREPARATION_SHA256 ROLE [--input-binding-artifacts|--boundary-artifacts|--mcp-artifacts PUBLIC_USTAR SHA256 | --process-artifacts|--hook-artifacts|--control-artifacts|--readonly-artifacts PUBLIC_USTAR SHA256 INTERPRETER_SHA256 OBSERVER_SHA256] [--bounded-storage ORIGINAL_STORAGE_JSON SHA256]".into());
    }
    Ok(Options { args, storage })
}
fn run() -> Result<(), String> {
    let command = std::env::args().collect::<Vec<_>>();
    let options = options(&command)?;
    let args = options.args;
    let storage = options
        .storage
        .map(|(path, pin)| read_storage(Path::new(path), pin))
        .transpose()?;
    let journal =
        HostControllerKeyPinJournal::open(Path::new(&args[1])).map_err(|e| e.to_string())?;
    let expected = HostPrelaunchIdentity {
        source_sha: args[3].clone(),
        job_id: args[4].clone(),
        deployment_digest: args[5].clone(),
        worker_generation: args[6].clone(),
    };
    let raw = read_completion(Path::new(&args[2]))?;
    let verified = match &storage {
        Some(storage) => journal
            .verify_native_bounded_completion(&raw, &expected, &args[7], &args[8], None, storage),
        None => journal.verify_native_completion(&raw, &expected, &args[7], &args[8]),
    }
    .map_err(|e| e.to_string())?;
    let mut output = serde_json::json!({"schema":"hol-gauntlet-offline-native-control-verification.v1",
        "completion_sha256":digest(&raw),"readback":verified.observation(),
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
    if let Some((_, pin)) = options.storage {
        output["original_storage_input"] = serde_json::json!({"raw_sha256":pin,
            "pin_source":"explicit-separate-file-and-sha256","outside_pin_provenance_verified":false});
        output["qualification_eligible"] = serde_json::json!(false);
    }
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
    if args.len() == 14 && args[9] == "--process-artifacts" {
        output["schema"] =
            serde_json::json!("hol-gauntlet-offline-native-process-artifact-verification.v1");
        output["process_artifacts"] = verified.verify_process_artifacts(
            Path::new(&args[10]),
            &args[11],
            &args[12],
            &args[13],
        )?;
    }
    if args.len() == 14 && args[9] == "--hook-artifacts" {
        output["schema"] =
            serde_json::json!("hol-gauntlet-offline-native-hook-artifact-verification.v1");
        output["hook_artifacts"] = verified.verify_hook_artifacts(
            Path::new(&args[10]),
            &args[11],
            &args[12],
            &args[13],
        )?;
    }
    if args.len() == 14 && args[9] == "--control-artifacts" {
        output["schema"] =
            serde_json::json!("hol-gauntlet-offline-native-control-artifact-verification.v1");
        output["control_artifacts"] = verified.verify_control_artifacts(
            Path::new(&args[10]),
            &args[11],
            &args[12],
            &args[13],
        )?;
    }
    if args.len() == 14 && args[9] == "--readonly-artifacts" {
        output["schema"] =
            serde_json::json!("hol-gauntlet-offline-native-readonly-artifact-verification.v1");
        output["readonly_artifacts"] = verified.verify_readonly_artifacts(
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

    fn command(extra: &[&str]) -> Vec<String> {
        let mut args = [
            "verify",
            "private-pins",
            "completion.json",
            "source",
            "job",
            "deployment",
            "worker",
            "preparation",
            "readonly-utility",
        ]
        .map(str::to_owned)
        .to_vec();
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        args
    }

    #[test]
    fn storage_option_is_final_and_preserves_every_original_artifact_form() {
        let mut forms = vec![Vec::new()];
        for flag in [
            "--input-binding-artifacts",
            "--boundary-artifacts",
            "--mcp-artifacts",
        ] {
            forms.push(vec![flag, "artifacts.tar", "archive-sha"]);
        }
        for flag in [
            "--process-artifacts",
            "--hook-artifacts",
            "--control-artifacts",
            "--readonly-artifacts",
        ] {
            forms.push(vec![
                flag,
                "artifacts.tar",
                "archive-sha",
                "python",
                "observer",
            ]);
        }
        let pin = "a".repeat(64);
        for form in forms {
            let old = command(&form);
            assert!(options(&old).unwrap().storage.is_none());
            let mut bounded = old.clone();
            bounded.extend([
                "--bounded-storage".into(),
                "storage.json".into(),
                pin.clone(),
            ]);
            let parsed = options(&bounded).unwrap();
            assert_eq!(parsed.args, old);
            assert_eq!(parsed.storage, Some(("storage.json", pin.as_str())));
        }
        for extra in [
            vec!["--bounded-storage"],
            vec!["--bounded-storage", "storage.json"],
            vec!["--bounded-storage", "storage.json", "not-a-sha"],
            vec![
                "--bounded-storage",
                "storage.json",
                pin.as_str(),
                "--mcp-artifacts",
                "a",
                "b",
            ],
            vec![
                "--bounded-storage",
                "storage.json",
                pin.as_str(),
                "--bounded-storage",
                "other.json",
                pin.as_str(),
            ],
        ] {
            assert!(options(&command(&extra)).is_err());
        }
    }

    fn storage_bytes(receipt: Value) -> Vec<u8> {
        let raw = gauntlet_contracts::canonicalize(&serde_json::to_vec(&receipt).unwrap()).unwrap();
        gauntlet_contracts::canonicalize(
            &serde_json::to_vec(
                &serde_json::json!({"receipt":receipt,"receipt_sha256":digest(&raw)}),
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn storage_input_requires_exact_outside_bytes_and_closed_duplicate_free_wrapper() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("original-storage.json");
        let receipt = serde_json::json!({"source_sha":"original","profile":"native-v1"});
        let raw = storage_bytes(receipt.clone());
        std::fs::write(&path, &raw).unwrap();
        let outside = digest(&raw);
        assert_eq!(read_storage(&path, &outside).unwrap()["receipt"], receipt);
        assert!(read_storage(&path, &"b".repeat(64)).is_err());
        assert!(read_storage(&path, "invalid").is_err());

        // Rehashing a substitute's inner receipt cannot change the outside pin.
        let substitute =
            storage_bytes(serde_json::json!({"source_sha":"substitute","profile":"native-v1"}));
        std::fs::write(&path, &substitute).unwrap();
        assert!(read_storage(&path, &outside).is_err());

        let duplicate = format!(
            "{{\"receipt\":{{}},\"receipt\":{{}},\"receipt_sha256\":\"{}\"}}",
            digest(b"{}")
        );
        std::fs::write(&path, duplicate.as_bytes()).unwrap();
        assert!(read_storage(&path, &digest(duplicate.as_bytes())).is_err());
        for bad in [
            serde_json::json!({"receipt":receipt,"receipt_sha256":"b".repeat(64)}),
            serde_json::json!({"receipt":{},"receipt_sha256":digest(b"{}"),"extra":true}),
            serde_json::json!({"receipt":null,"receipt_sha256":digest(b"null")}),
        ] {
            let bytes = serde_json::to_vec(&bad).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(read_storage(&path, &digest(&bytes)).is_err());
        }
    }

    #[test]
    fn storage_input_refuses_links_empty_and_oversized_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("storage.json");
        let raw = storage_bytes(serde_json::json!({}));
        std::fs::write(&path, &raw).unwrap();
        let pin = digest(&raw);
        let link = temp.path().join("symlink.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_storage(&link, &pin).is_err());
        let hard = temp.path().join("hardlink.json");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(read_storage(&path, &pin).is_err());
        let empty = temp.path().join("empty.json");
        std::fs::write(&empty, b"").unwrap();
        assert!(read_storage(&empty, &digest(b"")).is_err());
        let large = temp.path().join("large.json");
        std::fs::File::create(&large)
            .unwrap()
            .set_len(8193)
            .unwrap();
        assert!(read_storage(&large, &pin).is_err());
    }

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
