//! Normal native operations retain their VM identity before dispatch. Only the
//! new operational journal is inspected; historical worker records are not read.
use crate::private_jobs::{
    read_regular_bytes_bounded, same_file, state_root, write_private_once_bounded,
};
use crate::{HostControllerKeyPinJournal, HostNativeControlReadback, HostPrelaunchIdentity};
use gauntlet_contracts::{canonicalize, is_git_sha, NATIVE_HOST_PINNED_COMPLETION_LIMIT};
use rustix::fs::{
    flock, fstat, openat, statat, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags,
};
use rustix::{io::Errno, process::geteuid};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    os::fd::OwnedFd,
    path::{Path, PathBuf},
};

#[path = "candidate_artifact_operation.rs"]
pub(crate) mod artifact;
pub use artifact::{run_source_artifact_command, SOURCE_ARTIFACT_USAGE};
#[path = "native_transport_context.rs"]
pub(crate) mod context;
#[path = "live_campaign_operation.rs"]
pub(crate) mod live;
#[path = "native_preparation_operation.rs"]
mod preparation;
#[cfg(test)]
pub(crate) use preparation::job_storage_fixture;
pub(crate) use preparation::verify_storage as verify_job_storage;
#[path = "native_public_export.rs"]
mod public_export;
pub(crate) use artifact::observe_build_job;
pub use live::{run_live_campaign_command, LIVE_CAMPAIGN_USAGE};
pub(crate) use transport::observe_native_job;
#[path = "native_operation_transport.rs"]
mod transport;

const LIMIT: u64 = NATIVE_HOST_PINNED_COMPLETION_LIMIT as u64;
pub const NATIVE_OPERATION_USAGE: &str = "deterministic commands:\ninitialize PRIVATE_0700_JOURNAL VM LIMA_SHA256 SOURCE_SHA JOB_ID WORKER_SHA256 [MKE2FS_SHA256] SSH_HOME LIMA_HOME\ninitialize-read PRIVATE_JOURNAL JOB_ID INITIALIZATION_INTENT_SHA256\ninitialize-abort|initialize-abort-unreleased PRIVATE_JOURNAL JOB_ID INITIALIZATION_INTENT_SHA256 INITIALIZATION_RECEIPT_SHA256 STORAGE_SHA256 PODMAN_SHA256 ABORTER_SHA256\ninitialize-abort-read|initialize-abort-resume PRIVATE_JOURNAL JOB_ID ABORT_INTENT_SHA256\nrecord PRIVATE_0700_JOURNAL VM LIMA_SHA256 SOURCE_SHA JOB_ID DEPLOYMENT_SHA256 WORKER_SHA256 PREPARATION_SHA256 ROLE INTERPRETER_SHA256 OBSERVER_SHA256 SSH_HOME LIMA_HOME\nprepare PRIVATE_JOURNAL JOB_ID INTENT_SHA256 PRIVATE_BUNDLE_JSON BUNDLE_SHA256\nprepare-read PRIVATE_JOURNAL JOB_ID INTENT_SHA256\nrun|read PRIVATE_JOURNAL JOB_ID INTENT_SHA256\nreport PRIVATE_JOURNAL JOB_ID INTENT_SHA256 [PRIVATE_ARTIFACT_USTAR ARCHIVE_SHA256]\nretire PRIVATE_JOURNAL JOB_ID INTENT_SHA256 RETIRER_SHA256\nretire-read|retire-resume PRIVATE_JOURNAL JOB_ID INTENT_SHA256\nrepair PRIVATE_JOURNAL JOB_ID INTENT_SHA256 REPAIR_SHA256 [--never-released]\nExecution uses the retained original VM and one-use dispatch. Unknown work blocks new runs. Reports distinguish producer status, independent judgment and qualification. Artifact USTARs stay private (0700 parent/0600 file); stdout contains hashes and sanitized judgments.";

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn bytes(value: &Value) -> Result<Vec<u8>, String> {
    canonicalize(value.to_string().as_bytes()).map_err(|e| e.to_string())
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

#[derive(Clone, PartialEq, Eq)]
struct Intent(Value);
impl Intent {
    fn parse(raw: &[u8]) -> Result<Self, String> {
        let value: Value = serde_json::from_slice(raw).map_err(|_| "native intent JSON invalid")?;
        let live = value["schema"] == "hol-gauntlet-host-native-live-intent.v1";
        let mut fields = vec![
            "schema",
            "job_id",
            "source_sha",
            "deployment_digest",
            "worker_generation",
            "preparation_sha256",
            "role",
            "vm",
            "limactl",
            "lima_sha256",
            "interpreter_sha256",
            "observer_sha256",
            "transport_context",
        ];
        if live {
            fields.push("live");
        }
        let text = |key: &str| value[key].as_str().unwrap_or("");
        let vm = text("vm");
        if raw != bytes(&value)?
            || value.as_object().is_none_or(|v| {
                v.len() != fields.len() || fields.iter().any(|k| !v.contains_key(*k))
            })
            || (!live && text("schema") != "hol-gauntlet-host-native-intent.v1")
            || !hex(text("job_id"), 16)
            || !is_git_sha(text("source_sha"))
            || ![
                "deployment_digest",
                "worker_generation",
                "preparation_sha256",
                "lima_sha256",
                "interpreter_sha256",
                "observer_sha256",
            ]
            .iter()
            .all(|k| hex(text(k), 64))
            || !(if live {
                matches!(
                    text("role"),
                    "feature-ai-unprotected" | "feature-ai-protected"
                )
            } else {
                matches!(
                    text("role"),
                    "success"
                        | "input-binding"
                        | "injection"
                        | "boundary"
                        | "timeout"
                        | "cancel"
                        | "readonly-utility"
                )
            })
            || !vm.starts_with("hol-")
            || vm.len() > 96
            || !vm
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            || text("limactl") != "/opt/homebrew/bin/limactl"
        {
            return Err("closed native intent and exact outside pins required".into());
        }
        context::TransportContext::parse(&value["transport_context"])?;
        if value["transport_context"]["vm"] != value["vm"] {
            return Err("native intent Lima instance differs".into());
        }
        if live {
            live::validate_intent(&value)?;
        }
        Ok(Self(value))
    }
    fn is_live(&self) -> bool {
        self.0["schema"] == "hol-gauntlet-host-native-live-intent.v1"
    }
    fn declaration_version(&self) -> (&'static str, &'static str) {
        if self.is_live() {
            (
                "hol-gauntlet-native-worker-job.v9",
                "native-host-pinned-live-omp-v1",
            )
        } else if self.text("role") == "readonly-utility" {
            (
                "hol-gauntlet-native-worker-job.v8",
                "native-host-pinned-readonly-hook-v1",
            )
        } else {
            (
                "hol-gauntlet-native-worker-job.v7",
                "native-host-pinned-control-v1",
            )
        }
    }
    fn text(&self, k: &str) -> &str {
        self.0[k].as_str().expect("validated intent")
    }
    fn job(&self) -> &str {
        self.text("job_id")
    }
    fn raw(&self) -> Result<Vec<u8>, String> {
        bytes(&self.0)
    }
    fn digest(&self) -> Result<String, String> {
        Ok(sha(&self.raw()?))
    }
    fn expected(&self) -> HostPrelaunchIdentity {
        HostPrelaunchIdentity {
            job_id: self.job().into(),
            source_sha: self.text("source_sha").into(),
            deployment_digest: self.text("deployment_digest").into(),
            worker_generation: self.text("worker_generation").into(),
        }
    }
}

struct Journal {
    root: OwnedFd,
    path: PathBuf,
    owner: u32,
    lease: Option<OwnedFd>,
}
impl Journal {
    fn open(path: &Path) -> Result<Self, String> {
        let owner = geteuid().as_raw();
        Ok(Self {
            root: state_root(path, owner).map_err(|e| e.to_string())?,
            path: path.into(),
            owner,
            lease: None,
        })
    }
    fn stable(&self) -> Result<(), String> {
        let visible = state_root(&self.path, self.owner).map_err(|e| e.to_string())?;
        let a = fstat(&self.root).map_err(|e| e.to_string())?;
        let b = fstat(&visible).map_err(|e| e.to_string())?;
        if (a.st_dev, a.st_ino, a.st_uid, a.st_mode) != (b.st_dev, b.st_ino, b.st_uid, b.st_mode) {
            return Err("native host journal replaced".into());
        }
        if let Some(fd) = &self.lease {
            let held = fstat(fd).map_err(|e| e.to_string())?;
            let visible = statat(
                &self.root,
                "native-operation.lock",
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(|_| "native owner lock replaced")?;
            if !same_file(&held, &visible)
                || held.st_uid != self.owner
                || held.st_nlink != 1
                || held.st_mode & 0o777 != 0o600
                || held.st_size != 0
            {
                return Err("native owner lock replaced or changed".into());
            }
        }
        Ok(())
    }
    fn lock(&mut self) -> Result<(), String> {
        self.stable()?;
        let name = "native-operation.lock";
        let fd = openat(
            &self.root,
            name,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| "native host lock unavailable")?;
        let held = fstat(&fd).map_err(|e| e.to_string())?;
        let visible =
            statat(&self.root, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if !same_file(&held, &visible)
            || FileType::from_raw_mode(held.st_mode) != FileType::RegularFile
            || held.st_uid != self.owner
            || held.st_mode & 0o777 != 0o600
            || held.st_nlink != 1
            || held.st_size != 0
        {
            return Err("native host lock unsafe".into());
        }
        flock(&fd, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| "another native operation owns the journal")?;
        self.lease = Some(fd);
        self.stable()?;
        Ok(())
    }
    fn name(job: &str, suffix: &str) -> Result<String, String> {
        if !hex(job, 16)
            || suffix.is_empty()
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("closed native host record name required".into());
        }
        Ok(format!("{job}.native-{suffix}.json"))
    }
    fn read(&self, job: &str, suffix: &str) -> Result<Vec<u8>, String> {
        self.stable()?;
        let raw =
            read_regular_bytes_bounded(&self.root, &Self::name(job, suffix)?, self.owner, LIMIT)
                .map_err(|e| e.to_string())?;
        self.stable()?;
        Ok(raw)
    }
    fn absent(&self, job: &str, suffix: &str) -> Result<bool, String> {
        self.stable()?;
        match statat(
            &self.root,
            Self::name(job, suffix)?.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(Errno::NOENT) => Ok(true),
            Ok(_) => Ok(false),
            Err(_) => Err("native record existence uncertain".into()),
        }
    }
    fn write(&self, job: &str, suffix: &str, raw: &[u8]) -> Result<(), String> {
        self.stable()?;
        write_private_once_bounded(&self.root, &Self::name(job, suffix)?, raw, LIMIT)?;
        self.stable()
    }
    fn retain(&self, job: &str, suffix: &str, raw: &[u8]) -> Result<(), String> {
        if self.absent(job, suffix)? {
            self.write(job, suffix, raw)
        } else if self.read(job, suffix)? == raw {
            Ok(())
        } else {
            Err("native retained record differs; preserve uncertain state".into())
        }
    }
    fn intent(&self, job: &str) -> Result<Intent, String> {
        let intent = Intent::parse(&self.read(job, "intent")?)?;
        if intent.job() != job {
            return Err("native intent job differs".into());
        }
        Ok(intent)
    }
    fn dispatch_raw(intent: &Intent) -> Result<Vec<u8>, String> {
        bytes(
            &json!({"schema":"hol-gauntlet-host-native-dispatch.v1","job_id":intent.job(),"intent_sha256":intent.digest()?,"retry_allowed":false}),
        )
    }
    fn require_dispatch(&self, intent: &Intent) -> Result<(), String> {
        if self.intent(intent.job())? != *intent
            || self.read(intent.job(), "dispatch")? != Self::dispatch_raw(intent)?
        {
            return Err("native intent or dispatch changed".into());
        }
        Ok(())
    }
    fn verify(&self, intent: &Intent, raw: &[u8]) -> Result<HostNativeControlReadback, String> {
        if intent.is_live() {
            return live::verify_completion(self, intent, raw);
        }
        preparation::verify_completion(self, intent, raw)
    }
    fn require_idle(&self) -> Result<(), String> {
        let mut count = 0;
        for entry in Dir::read_from(&self.root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .to_str()
                .map_err(|_| "native journal name invalid")?;
            public_export::verify_retirement_idle_record(self, name)?;
            if preparation::verify_idle_record(self, name)? {
                continue;
            }
            live::verify_idle_record(self, name)?;
            if let Some(job) = name.strip_suffix(".native-dispatch.json") {
                count += 1;
                if count > 4096 {
                    return Err("native journal exceeds job bound".into());
                }
                let intent = self.intent(job)?;
                self.require_dispatch(&intent)?;
                if !self.absent(job, "repair-intent")? {
                    if intent.is_live() {
                        live::verify_retained_repair(self, &intent)?;
                    } else {
                        transport::verify_retained_repair(self, &intent)?;
                    }
                } else {
                    self.verify(&intent, &self.read(job, "completion")?)
                        .map_err(|_| "unknown native job blocks new dispatch")?;
                }
            }
        }
        self.stable()
    }
    fn observe(&self, intent: &Intent, operation: &str, raw: &[u8]) -> Result<Value, String> {
        self.require_dispatch(intent)?;
        let frame = raw.strip_suffix(b"\n").unwrap_or(raw);
        // Even a malformed bounded return remains private evidence. A failed
        // verifier cannot turn it into a completion or authorize another run.
        if operation == "run" {
            self.write(intent.job(), "return", frame)?;
        }
        if bytes(
            &serde_json::from_slice::<Value>(frame)
                .map_err(|_| "native completion JSON invalid")?,
        )? != frame
        {
            return Err("canonical native completion required; job remains unknown".into());
        }
        let verified = self.verify(intent, frame)?;
        self.require_dispatch(intent)?;
        self.retain(intent.job(), "completion", frame)?;
        Ok(
            json!({"schema":if intent.is_live() {"hol-gauntlet-host-live-result.v1"}else{"hol-gauntlet-host-deterministic-result.v1"},"operation":operation,
            "job_id":intent.job(),"source_sha":intent.text("source_sha"),"intent_sha256":intent.digest()?,
            "completion_sha256":sha(frame),"readback":verified.observation(),"independent_judgment":null,
            "next_operation":"report","execution_eligible":false,"qualification_eligible":false,"model_requests":verified.observation()["model_requests"]}),
        )
    }
}

/// Parse the complete operation before opening private state or contacting Lima.
pub fn run_native_operation_command(args: &[String]) -> Result<Value, String> {
    if args
        .first()
        .is_some_and(|s| matches!(s.as_str(), "retire" | "retire-read" | "retire-resume"))
    {
        return public_export::run_retirement_command(args);
    }
    if args.first().is_some_and(|v| {
        matches!(
            v.as_str(),
            "initialize"
                | "initialize-read"
                | "initialize-abort"
                | "initialize-abort-unreleased"
                | "initialize-abort-read"
                | "initialize-abort-resume"
                | "prepare"
                | "prepare-read"
        )
    }) {
        return preparation::run_command(args);
    }
    let action = match (args.first().map(String::as_str), args.len()) {
        (Some("record"), 14) => "record",
        (Some(action @ ("run" | "read")), 4) => action,
        (Some("report"), 4 | 6) => "report",
        (Some("repair"), 5) => "repair",
        (Some("repair"), 6) if args[5] == "--never-released" => "repair",
        _ => return Err(NATIVE_OPERATION_USAGE.into()),
    };
    let record = if action == "record" {
        Some(Intent::parse(&bytes(
            &json!({"schema":"hol-gauntlet-host-native-intent.v1","vm":args[2],"limactl":"/opt/homebrew/bin/limactl",
            "lima_sha256":args[3],"source_sha":args[4],"job_id":args[5],"deployment_digest":args[6],"worker_generation":args[7],
            "preparation_sha256":args[8],"role":args[9],"interpreter_sha256":args[10],"observer_sha256":args[11],
            "transport_context":context::TransportContext::from_paths(Path::new(&args[12]),Path::new(&args[13]),&args[2])?.value()}),
        )?)?)
    } else {
        if !hex(&args[2], 16)
            || !hex(&args[3], 64)
            || (action == "repair" && !hex(&args[4], 64))
            || (action == "report"
                && args.len() == 6
                && (!Path::new(&args[4]).is_absolute() || !hex(&args[5], 64)))
        {
            return Err("exact native job/intent/artifact pins required".into());
        }
        None
    };
    let mut journal = Journal::open(Path::new(&args[1]))?;
    journal.lock()?;
    if let Some(intent) = record {
        for suffix in ["dispatch", "completion", "repair-intent", "repair"] {
            if !journal.absent(intent.job(), suffix)? {
                return Err("orphan native state blocks recording".into());
            }
        }
        if !matches!(
            HostControllerKeyPinJournal::open(&journal.path)
                .map_err(|e| e.to_string())?
                .read(intent.job()),
            Err(crate::HostKeyPinError::Missing)
        ) {
            return Err("existing or uncertain host pin blocks native recording".into());
        }
        journal.write(intent.job(), "intent", &intent.raw()?)?;
        return Ok(
            json!({"schema":"hol-gauntlet-host-deterministic-record.v1","job_id":intent.job(),"source_sha":intent.text("source_sha"),
            "intent_sha256":intent.digest()?,"next_operation":"prepare","execution_eligible":false,"qualification_eligible":false}),
        );
    }
    let intent = journal.intent(&args[2])?;
    if intent.is_live() {
        return Err("live intent requires the explicit live campaign command".into());
    }
    if intent.digest()? != args[3] {
        return Err("outside native intent digest differs".into());
    }
    match action {
        "run" => {
            preparation::require_prepared(&journal, &intent)?;
            journal.require_idle()?;
            for suffix in ["return", "completion", "repair-intent", "repair"] {
                if !journal.absent(intent.job(), suffix)? {
                    return Err("orphan native result blocks dispatch".into());
                }
            }
            let mut lima = transport::Lima::open(&intent)?;
            journal.write(intent.job(), "dispatch", &Journal::dispatch_raw(&intent)?)?;
            journal.require_dispatch(&intent)?;
            let raw = transport::execute(&journal, &intent, &mut lima, true)?;
            journal.observe(&intent, "run", &raw)
        }
        "read" => {
            journal.require_dispatch(&intent)?;
            if !journal.absent(intent.job(), "repair-intent")? {
                return transport::read_repair(&journal, &intent);
            }
            let mut lima = transport::Lima::open(&intent)?;
            let raw = transport::execute(&journal, &intent, &mut lima, false)?;
            journal.observe(&intent, "read", &raw)
        }
        "repair" => transport::repair(&journal, &intent, &args[4], args.len() == 6),
        "report" => public_export::report(&journal, &intent, args),
        _ => unreachable!(),
    }
}

#[cfg(test)]
#[path = "native_operation_tests.rs"]
mod tests;
