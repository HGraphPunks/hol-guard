//! Outside authorization binds recovery to the observed preparation or reservation.
use crate::dependency_intent::DependencyIntentJournal;
use crate::fixed_process::run_fixed_intent;
use crate::private_jobs::{read_regular_bytes, write_private_once};
use gauntlet_contracts::DependencyRunIntent;
use rustix::fs::{statat, AtFlags};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RepairPins {
    pub started: String,
    pub generation: String,
    pub preparation: Option<String>,
}
pub(crate) fn observed_started(public: &Value) -> &Value {
    public
        .get("expected_started_marker_sha256")
        .unwrap_or(&public["started_marker_sha256"])
}
impl DependencyIntentJournal {
    pub(crate) fn repair_pins(
        &self,
        intent: &DependencyRunIntent,
    ) -> Result<Option<RepairPins>, String> {
        let name = format!(
            "{}.dependency-repair-authorized.json",
            intent.pins.text("job_id")
        );
        match statat(&self.root, name.as_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(e) => return Err(e.to_string()),
            Ok(_) => {}
        }
        let raw = read_regular_bytes(&self.root, &name, self.owner).map_err(|e| e.to_string())?;
        let (started, generation) =
            gauntlet_contracts::parse_dependency_repair_authorization(intent, &raw)?;
        let preparation =
            gauntlet_contracts::dependency_preparation_authorization_state(intent, &raw)?;
        Ok(Some(RepairPins {
            started,
            generation,
            preparation,
        }))
    }
    pub(crate) fn check_repair_view(public: &Value, auth: &RepairPins) -> Result<(), String> {
        if observed_started(public).as_str() != Some(auth.started.as_str())
            || public["repair_generation"] != auth.generation
            || public
                .get("preparation_state_sha256")
                .and_then(Value::as_str)
                != auth.preparation.as_deref()
        {
            return Err("dependency recovery differs from outside authorization".into());
        }
        Ok(())
    }
    pub(crate) fn repaired(
        &self,
        intent: &DependencyRunIntent,
        reader: &str,
        read: bool,
    ) -> Result<Value, String> {
        let auth = self
            .repair_pins(intent)?
            .ok_or("dependency cleanup has no outside authorization")?;
        gauntlet_contracts::dependency_repair_authorization(intent, &auth.started, reader)?;
        if !read && reader != auth.generation {
            return Err("dependency mutator differs from authorization".into());
        }
        let mut argv = vec![
            intent.limactl.clone(),
            "shell".into(),
            intent.vm.clone(),
            "--".into(),
            "sudo".into(),
            "-n".into(),
            format!("/opt/hol-gauntlet/rust-native-dependency-worker-{reader}"),
            if read {
                "--read-native-dependency-repair".into()
            } else {
                "--repair-owned-native-dependencies".into()
            },
            intent.pins.text("job_id").into(),
            intent.digest()?,
            auth.started.clone(),
            intent.pins.text("runner_binary_sha256").into(),
            reader.into(),
        ];
        let mut input = Vec::new();
        if let Some(preparation) = auth.preparation.as_ref().filter(|_| !read) {
            input = intent.bytes()?;
            argv.extend([preparation.clone(), input.len().to_string()]);
        }
        let raw = run_fixed_intent(&argv, &input, Duration::from_secs(120), 32769, 8192).map_err(
            |e| format!("dependency recovery unavailable; workload cannot retry: {e:?}"),
        )?;
        let frame = raw
            .strip_suffix(b"\n")
            .ok_or("canonical dependency recovery response required")?;
        let mut public = gauntlet_contracts::verify_dependency_recovery_reply(
            intent,
            &auth.started,
            &auth.generation,
            reader,
            frame,
        )?;
        // A finalized original report has no repair generation, and is available
        // only under the historical reservation authorization, never a snapshot.
        if public.get("repair_generation").is_some() {
            Self::check_repair_view(&public, &auth)?;
        } else if auth.preparation.is_some() {
            return Err("preparation authorization cannot finalize a report".into());
        }
        self.stable()?;
        if self.read(intent.pins.text("job_id"))? != *intent
            || self.repair_pins(intent)? != Some(auth.clone())
        {
            return Err("dependency recovery authorization or intent changed".into());
        }
        if read {
            public["retained_result_reconciled"] = json!(true);
            public["reader_generation"] = json!(reader);
        } else {
            self.retain_view(
                &format!(
                    "{}.dependency-repair-result.json",
                    intent.pins.text("job_id")
                ),
                &public,
            )?;
        }
        if public.to_string().contains(&intent.nonce) {
            return Err("private dependency value appeared in readback".into());
        }
        if self.read(intent.pins.text("job_id"))? != *intent
            || self.repair_pins(intent)? != Some(auth)
        {
            return Err("dependency recovery pins changed after readback".into());
        }
        Ok(public)
    }

    pub fn repair(
        &self,
        job: &str,
        started: &str,
        generation: &str,
        vm: Option<&str>,
    ) -> Result<Value, String> {
        let intent = self.read(job)?;
        if vm.is_some_and(|v| v != intent.vm) {
            return Err("dependency repair requires the original VM".into());
        }
        let mut encoded =
            gauntlet_contracts::dependency_repair_authorization(&intent, started, generation)?;
        let auth = match self.repair_pins(&intent)? {
            None => {
                let observed = self.reconcile_read_only(job, generation, vm)?;
                if observed["status"] != "unknown" || observed_started(&observed) != started {
                    return Err("dependency reservation differs or is already complete; cleanup not authorized".into());
                }
                let preparation = observed
                    .get("preparation_state_sha256")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Some(state) = &preparation {
                    if generation != intent.pins.text("runner_binary_sha256") {
                        return Err(
                            "preparation retirement requires the original pinned worker".into()
                        );
                    }
                    encoded = gauntlet_contracts::dependency_preparation_authorization(
                        &intent, started, generation, state,
                    )?;
                }
                write_private_once(
                    &self.root,
                    &format!("{job}.dependency-repair-authorized.json"),
                    &encoded,
                )?;
                RepairPins {
                    started: started.into(),
                    generation: generation.into(),
                    preparation,
                }
            }
            Some(auth) => {
                if auth.started != started || auth.generation != generation {
                    return Err("retained dependency repair authorization differs".into());
                }
                auth
            }
        };
        if self.repair_pins(&intent)? != Some(auth) {
            return Err("dependency repair authorization commit uncertain".into());
        }
        self.repaired(&intent, generation, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gauntlet_contracts::{DependencyPreparationState, DependencyRunPins};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn partial_preparation_requires_durable_snapshot_authorization_and_exact_framed_intent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let transport = root.join("limactl");
        let job = "0123456789abcdef";
        let pins = DependencyRunPins::from_value(json!({
            "job_id":job,"source_sha":"a".repeat(40),"source_archive_sha256":"b".repeat(64),
            "capsule_sha256":"c".repeat(64),"capsule_bytes":1551712,"pyproject_sha256":"d".repeat(64),
            "uv_lock_sha256":"e".repeat(64),"exporter_sha256":"f".repeat(64),"capture_worker_sha256":"1".repeat(64),
            "capture_receipt_sha256":"2".repeat(64),"controller_root":"/opt/hol-gauntlet/controller-0123456789abcdef",
            "controller_tree_sha256":"3".repeat(64),"uv_base_image_id":"4".repeat(64),"rust_base_image_id":"5".repeat(64),
            "builder_image_id":format!("sha256:{}", "6".repeat(64)),"policy_sha256":"7".repeat(64),"podman_sha256":"8".repeat(64),
            "slirp4netns_sha256":"9".repeat(64),"apparmor_parser_sha256":"a".repeat(64),"seccomp_sha256":"b".repeat(64),"runner_binary_sha256":"c".repeat(64)
        })).unwrap();
        let mut operations = crate::public_vm_operations(None).unwrap();
        operations["limactl"] = json!(transport);
        let journal = DependencyIntentJournal::open(&root).unwrap();
        let intent = journal.record(pins, &operations).unwrap();
        let state = DependencyPreparationState::inspect(
            &intent,
            Some(b"{"),
            Some(&"a".repeat(64)),
            None,
            None,
        )
        .unwrap();
        let generation = "c".repeat(64);
        let unknown = String::from_utf8(state.unknown(&intent, &generation).unwrap()).unwrap();
        let retired = String::from_utf8(state.retired(&intent, &generation).unwrap()).unwrap();
        let auth = root.join(format!("{job}.dependency-repair-authorized.json"));
        let script = format!("#!/bin/sh\n/bin/cat > \"$0.input\"\ncase \"$*\" in\n*--repair-owned-native-dependencies*)\n[ -s '{}' ] || exit 9\n/bin/cat \"$0.input\" > \"$0.repaired-input\"\nprintf '%s' \"$*\" > \"$0.args\"\n: > \"$0.retired\";;\n*--read-native-dependencies*)\nif [ ! -e \"$0.retired\" ]; then\n/bin/cat <<'UNKNOWN'\n{unknown}\nUNKNOWN\nexit 0\nfi;;\nesac\n/bin/cat <<'RETIRED'\n{retired}\nRETIRED\n", auth.display());
        std::fs::write(&transport, script).unwrap();
        std::fs::set_permissions(&transport, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(journal
            .repair(job, &"f".repeat(64), &generation, None)
            .is_err());
        assert!(!auth.exists() && !root.join("limactl.retired").exists());
        let public = journal
            .repair(job, &state.expected_started_sha256, &generation, None)
            .unwrap();
        assert_eq!(public["schema"], "hol-gauntlet-host-dependency-repair.v3");
        assert_eq!(public["status"], "aborted");
        assert!(!public.to_string().contains(&intent.nonce));
        assert_eq!(
            std::fs::read(root.join("limactl.repaired-input")).unwrap(),
            intent.bytes().unwrap()
        );
        let args = std::fs::read_to_string(root.join("limactl.args")).unwrap();
        assert!(args.ends_with(&format!(
            "{} {}",
            state.sha256,
            intent.bytes().unwrap().len()
        )));
        let original_auth = std::fs::read(&auth).unwrap();
        assert_eq!(
            gauntlet_contracts::dependency_preparation_authorization_state(&intent, &original_auth)
                .unwrap(),
            Some(state.sha256.clone())
        );
        assert!(journal.execute_once(&intent).is_err());
        assert!(!root
            .join(format!("{job}.dependency-dispatch.json"))
            .exists());
        let reopened = DependencyIntentJournal::open(&root).unwrap();
        assert_eq!(
            reopened
                .repair(job, &state.expected_started_sha256, &generation, None)
                .unwrap(),
            public
        );
        let read = reopened
            .reconcile_read_only(job, &generation, None)
            .unwrap();
        assert_eq!(read["retained_result_reconciled"], true);
        assert_eq!(std::fs::read(&auth).unwrap(), original_auth);
        let wrong = gauntlet_contracts::dependency_preparation_authorization(
            &intent,
            &state.expected_started_sha256,
            &generation,
            &"f".repeat(64),
        )
        .unwrap();
        std::fs::write(&auth, wrong).unwrap();
        assert!(reopened
            .reconcile_read_only(job, &generation, None)
            .is_err());
        assert!(reopened
            .repair(job, &state.expected_started_sha256, &generation, None)
            .is_err());
    }
}
