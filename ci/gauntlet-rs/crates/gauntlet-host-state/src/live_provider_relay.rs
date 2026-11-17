//! Foreground provider owner. Restarts never adopt or replay old dispatched work.
use super::assets::Assets;
use super::custody::Journal;
use super::{adapter::Adapter, bytes, http, idle, inference::Inference, num, sha, Intent};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
static CANCEL: AtomicBool = AtomicBool::new(false);
static SIGNAL_OWNER: AtomicBool = AtomicBool::new(false);
pub(super) fn cancelled() -> bool {
    CANCEL.load(Ordering::Acquire)
}
extern "C" fn cancel(_signal: libc::c_int) {
    CANCEL.store(true, Ordering::Release);
}
struct Signals {
    old: Vec<(i32, libc::sigaction)>,
}
impl Signals {
    fn install() -> Result<Self, String> {
        if SIGNAL_OWNER
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("provider signal owner already active".into());
        }
        CANCEL.store(false, Ordering::Release);
        let mut guard = Self { old: Vec::new() };
        for signal in [libc::SIGINT, libc::SIGTERM] {
            // SAFETY: plain signal action stores only a lock-free atomic flag.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut old: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = cancel as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            if unsafe { libc::sigaction(signal, &action, &mut old) } != 0 {
                return Err("provider signal custody unavailable".into());
            }
            guard.old.push((signal, old));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, old) in &self.old {
            unsafe {
                libc::sigaction(*signal, old, std::ptr::null_mut());
            }
        }
        SIGNAL_OWNER.store(false, Ordering::Release);
    }
}
pub(super) fn validate_request(intent: &Intent, value: &Value) -> Result<(), String> {
    super::inference::validate(intent, value).map(|_| ())
}
fn summary(
    intent: &Intent,
    state: &str,
    quota: Option<&Value>,
    cleanup: Value,
) -> Result<Value, String> {
    Ok(
        json!({"schema":"hol-gauntlet-rust-provider-operation.v1","state":state,"source_sha":intent.text("source_sha")?,"provider_job_id":intent.text("provider_job_id")?,"binding_sha256":intent.digest()?,"quota_known_tokens":quota.and_then(|q|q.get("known_tokens")),"quota_remaining_tokens":quota.and_then(|q|q.get("remaining_tokens")),"quota_halted":quota.and_then(|q|q.get("halted")),"cleanup":cleanup,"restart_allowed":false,"execution_eligible":false,"qualification_eligible":false}),
    )
}
pub(super) fn read(journal: &Journal, intent: &Intent) -> Result<Value, String> {
    if journal.exists("provider-terminal.json")? {
        let terminal = journal.json("provider-terminal.json")?;
        if terminal["schema"] != "hol-gauntlet-rust-provider-terminal.v1"
            || terminal["binding_sha256"] != intent.digest()?
            || !matches!(
                terminal["state"].as_str(),
                Some("stopped" | "failed" | "uncertain")
            )
        {
            return Err("provider terminal binding invalid".into());
        }
        return summary(
            intent,
            terminal["state"].as_str().unwrap_or("uncertain"),
            terminal.get("quota"),
            terminal["cleanup"].clone(),
        );
    }
    if !journal.exists("provider-dispatch.json")? {
        if super::lifetime::consumed(intent)? {
            return summary(intent, "uncertain", None, Value::Null);
        }
        return summary(
            intent,
            "prepared",
            Some(&intent.0["quota_at_prepare"]),
            Value::Null,
        );
    }
    match http::client(journal, intent, "GET", "/v1/hol-gauntlet/status", None) {
        Ok(value) => {
            if value["binding_sha256"] != intent.digest()?
                || value["source_sha"] != intent.spec()["source_sha"]
                || value["provider_job_id"] != intent.spec()["provider_job_id"]
            {
                return Err("provider owner status binding differs".into());
            }
            Ok(value)
        }
        Err(_) => summary(intent, "uncertain", None, Value::Null),
    }
}
pub(super) fn serve(journal: &mut Journal, intent: &Intent) -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("owned macOS MLX provider required".into());
    }
    journal.lock()?;
    if journal.exists("provider-dispatch.json")? || journal.exists("provider-stop.json")? {
        return Err("provider dispatch already consumed; read retained state".into());
    }
    let assets = Assets::capture_spec(intent.spec())?;
    if assets.facts != intent.0["asset_custody"]
        || assets.directories != intent.0["asset_directory_custody"]
    {
        return Err("prepared numerical asset custody changed".into());
    }
    let quota = intent.snapshot()?;
    idle(&quota, intent.spec())?;
    if quota != intent.0["quota_at_prepare"] {
        return Err("provider quota progressed after immutable preparation".into());
    }
    super::lifetime::previous_listeners_absent()?;
    let lifetime = super::lifetime::Lifetime::claim(journal, intent)?;
    let digest = intent.digest()?;
    let _signals = Signals::install()?;
    journal.put("provider-dispatch.json",&json!({"schema":"hol-gauntlet-rust-provider-dispatch.v1","binding_sha256":digest,"owner_pid":std::process::id(),"one_use":true}))?;
    let listener = http::listener(journal, &digest)?;
    let mut numerical = match Adapter::spawn(intent, journal, &assets) {
        Ok(adapter) => adapter,
        Err(_) => {
            drop(listener);
            journal.put("provider-terminal.json",&json!({"schema":"hol-gauntlet-rust-provider-terminal.v1","binding_sha256":digest,"state":"uncertain","failure_code":"numerical-startup-incomplete","cleanup":null,"quota":intent.snapshot().ok()}))?;
            return read(journal, intent);
        }
    };
    journal.put("provider-ready.json",&json!({"schema":"hol-gauntlet-rust-provider-readiness.v1","binding_sha256":digest,"child_record_sha256":sha(&journal.read("provider-child.json")?),"asset_custody_sha256":sha(&bytes(&assets.facts)?),"quota_sha256":sha(&bytes(&quota)?),"model_loaded":true,"qualification_eligible":false}))?;
    let mut inference = Inference::new();
    let started = Instant::now();
    let outcome = (|| -> Result<(), String> {
        loop {
            if cancelled()
                || journal.stop_requested(&digest)?
                || started.elapsed() >= Duration::from_secs(3000)
            {
                return Ok(());
            }
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                Err(_) => return Err("provider listener failed".into()),
            };
            let request = match http::request(&mut stream) {
                Ok(value) => value,
                Err(_) => {
                    let _ = http::reply(
                        &mut stream,
                        400,
                        &json!({"error":"invalid-provider-request"}),
                        None,
                    );
                    continue;
                }
            };
            if http::authenticate(&request, journal, intent).is_err() {
                let _ = http::reply(
                    &mut stream,
                    403,
                    &json!({"error":"provider-authentication-failed"}),
                    None,
                );
                continue;
            }
            let auth = Some((&request, &*journal, intent));
            match (request.method.as_str(), request.path.as_str()) {
                ("GET", "/v1/models") => http::reply(
                    &mut stream,
                    200,
                    &json!({"object":"list","data":[{"id":super::MODEL,"object":"model"}]}),
                    auth,
                )?,
                ("GET", "/v1/benchmark-quota") => {
                    http::reply(&mut stream, 200, &intent.status(intent.snapshot()?)?, auth)?
                }
                ("GET", "/v1/hol-gauntlet/status") => http::reply(
                    &mut stream,
                    200,
                    &summary(intent, "ready", Some(&intent.snapshot()?), Value::Null)?,
                    auth,
                )?,
                ("POST", "/v1/chat/completions") => {
                    let value = super::parse(&request.body)?;
                    validate_request(intent, &value)?;
                    match inference.complete_bounded(
                        intent,
                        journal,
                        &assets,
                        &mut numerical,
                        &value,
                        http::model_deadline(&request)?,
                    ) {
                        Ok(reply) => http::reply(&mut stream, 200, &reply, auth)?,
                        Err(error) => {
                            let _ = http::reply(
                                &mut stream,
                                409,
                                &json!({"error":"provider-attempt-incomplete","qualification_eligible":false}),
                                auth,
                            );
                            return Err(error);
                        }
                    }
                }
                _ => http::reply(
                    &mut stream,
                    400,
                    &json!({"error":"unsupported-provider-route"}),
                    auth,
                )?,
            }
        }
    })();
    drop(listener);
    let cleanup = numerical.stop(journal).ok().and_then(|mut cleanup| {
        journal.remove_socket(&digest).ok().map(|()| {
            cleanup["private_socket_removed"] = json!(true);
            cleanup
        })
    });
    let final_quota = intent.snapshot().ok();
    let state = if cleanup.is_none() {
        "uncertain"
    } else if outcome.is_err() {
        "failed"
    } else {
        "stopped"
    };
    journal.put("provider-terminal.json",&json!({"schema":"hol-gauntlet-rust-provider-terminal.v1","binding_sha256":digest,"state":state,"failure_code":outcome.err().map(|_|"provider-owner-incomplete"),"cleanup":cleanup,"quota":final_quota,"completed_requests":inference.requests,"known_job_tokens":inference.tokens,"qualification_eligible":false}))?;
    if cleanup.is_some() {
        lifetime.finish(journal, intent)?;
    }
    // Reconcile the retained final journal; never create an empty replacement.
    if let Some(quota) = final_quota {
        if num(&quota, "known_tokens")? < num(&intent.0["quota_at_prepare"], "known_tokens")? {
            return Err("provider quota regressed".into());
        }
    }
    read(journal, intent)
}
