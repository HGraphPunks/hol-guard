//! Passive Rust observer plus an optional loopback dashboard in the same
//! process. Closing the process closes both ownership and its listening socket.

use crate::lifecycle_files::nonce;
use crate::observer_collect::{now_ms, Samplers};
use crate::observer_public::ObserverPublic;
use crate::{compose_observer_snapshot, HostLifecycleError as Error, HostLifecycleStore};
use gauntlet_dashboard::{http, snapshot::PublicRoot};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

pub(crate) fn operation_projection(
    reference: Value,
    state: &str,
    phase: &str,
    authority: Option<String>,
    completion: Option<String>,
    model: Option<u64>,
    exit: Option<i64>,
) -> Value {
    json!({"reference":reference,"state":state,"phase":phase,"result":{"authority_sha256":authority,"completion_sha256":completion,
        "model_requests":model,"exit_code":exit,"execution_eligible":false,"qualification_eligible":false}})
}

fn attachment_name(job: &str) -> Result<String, Error> {
    if !crate::lifecycle_document::hex(job, 16) {
        return Err(Error::InvalidState);
    }
    Ok(format!("{job}.normal-job-binding.json"))
}
fn canonical(v: &Value) -> Result<Vec<u8>, Error> {
    gauntlet_contracts::canonicalize(v.to_string().as_bytes()).map_err(|_| Error::InvalidState)
}
fn digest(raw: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(raw))
}
fn observe(kind: &str, journal: &Path, job: &str, intent: &str) -> Result<Value, Error> {
    let v = match kind {
        "native" => crate::native_operation::observe_native_job(journal, job, intent),
        "bounded-build" => crate::native_operation::observe_build_job(journal, job, intent),
        _ => return Err(Error::InvalidState),
    }
    .map_err(|_| Error::InvalidState)?;
    let r = &v["reference"];
    if !crate::lifecycle_document::valid_projection(&v)
        || r["job_id"] != job
        || r["operation"] != kind
        || r["intent_sha256"] != intent
        || !r["source_sha"]
            .as_str()
            .is_some_and(gauntlet_contracts::is_git_sha)
    {
        return Err(Error::InvalidState);
    }
    Ok(v)
}
fn attachment_public(job: &Value) -> Value {
    json!({"schema":"hol-gauntlet-host-job-attachment.v1","job_id":job["id"],"kind":job["kind"],"source_sha":job["sha"],
        "attachment_sha256":job["attachment_sha256"],"phase":job["phase"],"state":job["state"],"result":job["result"],
        "execution_eligible":false,"qualification_eligible":false})
}
impl HostLifecycleStore {
    /// Attach metadata ownership only. The original workflow keeps every pin,
    /// process, dispatch and recovery authority; this method sends no request.
    pub fn attach_job(
        &self,
        kind: &str,
        journal: &Path,
        job: &str,
        intent: &str,
        now: u64,
    ) -> Result<Value, Error> {
        if !crate::lifecycle_document::hex(intent, 64) {
            return Err(Error::InvalidState);
        }
        let projected = observe(kind, journal, job, intent)?;
        let directory = crate::native_operation::context::snapshot(journal)
            .map_err(|_| Error::UnsafeDirectory)?;
        let binding = json!({"schema":"hol-gauntlet-host-job-attachment-binding.v1","instance_id":self.instance,"operation":kind,
            "job_id":job,"intent_sha256":intent,"journal":directory,"reference":projected["reference"]});
        let raw = canonical(&binding)?;
        let hash = digest(&raw);
        let name = attachment_name(job)?;
        self.files.stable()?;
        match rustix::fs::statat(
            self.files.directory()?,
            name.as_str(),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        ) {
            Err(rustix::io::Errno::NOENT) => {
                let mut f = self.files.create(&name)?;
                f.write_all(&raw)
                    .and_then(|_| f.sync_all())
                    .map_err(|_| Error::CommitUncertain)?;
                rustix::fs::fsync(self.files.directory()?).map_err(|_| Error::CommitUncertain)?;
            }
            Ok(_) => {}
            Err(_) => return Err(Error::UnsafeFile),
        }
        if self.files.read_named(&name, 65536)? != raw {
            return Err(Error::Changed);
        }
        self.transact(now,|document|{
            let jobs=document["jobs"].as_array_mut().ok_or(Error::InvalidState)?;
            if let Some(old)=jobs.iter().find(|v|v["id"]==job) {
                if old["attachment_sha256"]!=hash {return Err(Error::DuplicateJob);}
                return Ok(());
            }
            if jobs.iter().filter(|v|crate::lifecycle_document::normal_job(v)).count()>=16 {return Err(Error::TooLarge);}
            jobs.push(json!({"id":job,"kind":if kind=="native" {"normal-native"}else{"normal-build"},"tag":null,"sha":projected["reference"]["source_sha"],
                "state":projected["state"],"phase":projected["phase"],"created_at_ms":now,"updated_at_ms":now,"reason":"Verified original Rust workflow observation",
                "deployment_digest":projected["reference"]["deployment_digest"],"attachment_sha256":hash,"result":projected["result"]}));
            document["schema"]=json!(crate::lifecycle_document::ATTACHED_SCHEMA);
            Ok(())
        })?;
        self.refresh_job(job, &hash, now)
    }
    /// Reobserve only the originally attached private journal. Inconsistent
    /// files become unknown; no replacement source or worker is adopted.
    pub fn refresh_job(&self, job: &str, expected: &str, now: u64) -> Result<Value, Error> {
        if !crate::lifecycle_document::hex(expected, 64) {
            return Err(Error::InvalidState);
        }
        let (_, document) = self.read()?;
        let row = document["jobs"]
            .as_array()
            .ok_or(Error::InvalidState)?
            .iter()
            .find(|r| r["id"] == job && crate::lifecycle_document::normal_job(r))
            .ok_or(Error::InvalidState)?;
        if row["attachment_sha256"] != expected {
            return Err(Error::Changed);
        }
        let observed = (|| -> Result<Value, Error> {
            let raw = self.files.read_named(&attachment_name(job)?, 65536)?;
            let a: Value = serde_json::from_slice(&raw).map_err(|_| Error::InvalidState)?;
            if digest(&raw) != expected
                || canonical(&a)? != raw
                || a.as_object().is_none_or(|o| o.len() != 7)
                || a["schema"] != "hol-gauntlet-host-job-attachment-binding.v1"
                || a["instance_id"] != self.instance
                || a["job_id"] != job
            {
                return Err(Error::Changed);
            }
            let path = a["journal"]["path"].as_str().ok_or(Error::InvalidState)?;
            if crate::native_operation::context::snapshot(Path::new(path))
                .map_err(|_| Error::Changed)?
                != a["journal"]
            {
                return Err(Error::Changed);
            }
            let v = observe(
                a["operation"].as_str().ok_or(Error::InvalidState)?,
                Path::new(path),
                job,
                a["intent_sha256"].as_str().ok_or(Error::InvalidState)?,
            )?;
            let expected_kind = match a["operation"].as_str() {
                Some("native") => "normal-native",
                Some("bounded-build") => "normal-build",
                _ => return Err(Error::Changed),
            };
            if v["reference"] != a["reference"]
                || v["reference"]["source_sha"] != row["sha"]
                || v["reference"]["deployment_digest"] != row["deployment_digest"]
                || row["kind"] != expected_kind
            {
                return Err(Error::Changed);
            }
            Ok(v)
        })()
        .unwrap_or_else(|_| {
            operation_projection(
                Value::Null,
                "unknown",
                "reconciliation-required",
                None,
                None,
                None,
                None,
            )
        });
        self.transact(now,|document|{
            let row=document["jobs"].as_array_mut().ok_or(Error::InvalidState)?.iter_mut().find(|r|r["id"]==job).ok_or(Error::InvalidState)?;
            if row["attachment_sha256"]!=expected {return Err(Error::Changed);}
            if ["state","phase","result"].iter().any(|k|row[*k]!=observed[*k]) {
                for k in ["state","phase","result"] {row[k]=observed[k].clone();}
                row["updated_at_ms"]=json!(now);row["reason"]=json!("Verified original Rust workflow observation; inconsistent evidence requires original reconciliation");
            }
            Ok(attachment_public(row))
        })
    }
    pub(crate) fn refresh_attached_jobs(&self, now: u64) -> Result<(), Error> {
        let (_, document) = self.read()?;
        let jobs = document["jobs"].as_array().ok_or(Error::InvalidState)?;
        for row in jobs
            .iter()
            .filter(|r| crate::lifecycle_document::normal_job(r))
        {
            self.refresh_job(
                row["id"].as_str().ok_or(Error::InvalidState)?,
                row["attachment_sha256"]
                    .as_str()
                    .ok_or(Error::InvalidState)?,
                now,
            )?;
        }
        Ok(())
    }
}

fn queue_observed_releases(store: &HostLifecycleStore, observations: &Value) -> Result<(), Error> {
    let Some(rows) = observations["releases"].as_array() else {
        return Ok(());
    };
    let status = store.status(now_ms()?)?;
    let jobs = status["jobs"].as_array().ok_or(Error::InvalidState)?;
    for row in rows {
        let (Some(tag), Some(sha)) = (row["tag"].as_str(), row["sha"].as_str()) else {
            continue;
        };
        if jobs.iter().any(|job| job["tag"] == tag) {
            continue;
        }
        // Existing tuple/source binding remains immutable. Moved tags are
        // reported by the public projection and never replace a retained job.
        match store.enqueue_release(&nonce()?[..16], tag, sha, now_ms()?) {
            Ok(_) | Err(Error::SourceMoved) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn run_passive_observer(
    store: &HostLifecycleStore,
    expected_config: &str,
    volume: &Path,
    port: Option<u16>,
    once: bool,
    shutdown: &AtomicBool,
) -> Result<Value, Error> {
    let config = store.read_observer_configuration(expected_config)?;
    // Bind before taking an observer lease or recovering jobs. A busy port
    // cannot interrupt an existing listener or claim ownership of its state.
    let listener = port
        .map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)))
        .transpose()
        .map_err(|_| Error::DashboardUnavailable)?;
    if let Some(listener) = &listener {
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::DashboardUnavailable)?;
    }
    let lease = crate::start_observer_bounded(store)?;
    let public = ObserverPublic::open(&lease)?;
    let root = PublicRoot::open(&public.path(&lease)?).map_err(|_| Error::DashboardUnavailable)?;
    if let Some(listener) = &listener {
        println!(
            "{}",
            json!({"service":"hol-gauntlet-dashboard","instance_id":store.instance,
            "url":format!("http://127.0.0.1:{}",listener.local_addr().map_err(|_|Error::DashboardUnavailable)?.port()),
            "configuration_sha256":config.sha256,"mode":"passive","execution_eligible":false})
        );
        io::stdout().flush().map_err(|_| Error::Io)?;
    }
    let (sender, receiver) = mpsc::channel();
    let mut samplers = Samplers::new(sender);
    let mut observations = json!({"releases":[]});
    let started = Instant::now();
    let mut next_metrics = Duration::ZERO;
    let mut next_sources = Duration::ZERO;
    let mut next_heartbeat = Duration::ZERO;
    let mut next_publication = Duration::ZERO;
    let metrics_interval = Duration::from_secs(
        config.operations["telemetry_seconds"]
            .as_u64()
            .ok_or(Error::InvalidObserverConfig)?,
    );
    let source_interval = Duration::from_secs(
        config.operations["poll_seconds"]
            .as_u64()
            .ok_or(Error::InvalidObserverConfig)?,
    );
    let result = (|| {
        loop {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let now = now_ms()?;
            let status = match store.status(now) {
                Ok(value) => value,
                Err(Error::Busy) => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) => return Err(error),
            };
            if status["stop_requested"] == true {
                break;
            }
            match store.read_observer_configuration(expected_config) {
                Ok(_) => {}
                Err(Error::Busy) => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) => return Err(error),
            }
            let elapsed = started.elapsed();
            let mut updated = false;
            for update in receiver.try_iter() {
                samplers.apply(update, &mut observations)?;
                updated = true;
            }
            if elapsed >= next_heartbeat {
                match lease.heartbeat(now_ms()?) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                };
                next_heartbeat = elapsed + Duration::from_secs(5);
            }
            if elapsed >= next_publication || updated {
                match queue_observed_releases(store, &observations) {
                    Ok(()) => {}
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                };
            }
            if elapsed >= next_publication || updated {
                let current = match store.status(now_ms()?) {
                    Ok(value) => value,
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                };
                match public.publish(
                    &lease,
                    &compose_observer_snapshot(&config, &current, &observations, now_ms()?)?,
                ) {
                    Ok(()) => {}
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                }
                next_publication = elapsed + Duration::from_secs(5);
            }
            if once
                && next_metrics != Duration::ZERO
                && next_sources != Duration::ZERO
                && samplers.telemetry_idle()
                && samplers.sources_idle()
            {
                break;
            }
            if elapsed >= next_metrics
                && samplers.telemetry_idle()
                && (!once || next_metrics == Duration::ZERO)
            {
                samplers.telemetry(config.clone(), volume.to_owned());
                next_metrics = elapsed + metrics_interval;
            }
            if elapsed >= next_sources
                && samplers.sources_idle()
                && (!once || next_sources == Duration::ZERO)
            {
                samplers.sources(config.clone());
                next_sources = elapsed + source_interval;
            }
            if let Some(listener) = &listener {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if http::handle(stream, &root).is_err() {
                            eprintln!("dashboard request failed");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Error::DashboardUnavailable),
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();
    // Cancel and join every owned read-only sampler before releasing the
    // observer lease, on normal shutdown and error paths alike.
    drop(samplers);
    let final_now = now_ms()?;
    let mut status = store.status(final_now)?;
    status["observer"]["status"] = json!("stopped");
    let stopped = compose_observer_snapshot(&config, &status, &observations, final_now)?;
    let publication = public.publish(&lease, &stopped);
    let finish = lease.finish(now_ms()?);
    result?;
    publication?;
    finish?;
    Ok(stopped)
}

impl HostLifecycleStore {
    pub fn published_observer_snapshot(
        &self,
        expected_config: &str,
        now: u64,
    ) -> Result<Value, Error> {
        let config = self.read_observer_configuration(expected_config)?;
        let root =
            PublicRoot::open(&self.files.public_path()).map_err(|_| Error::DashboardUnavailable)?;
        if root.identity().as_deref() != Some(self.instance.as_str()) {
            return Err(Error::Changed);
        }
        let value = root.snapshot(now as f64 / 1000.0);
        if value["instance_id"] != self.instance
            || value["observer"]["configuration_sha256"] != config.sha256
        {
            return Err(Error::Changed);
        }
        self.files.stable()?;
        Ok(value)
    }
}
