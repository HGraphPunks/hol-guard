//! Retained lifetime ownership is independent of the caller's artifact journal.
//! These private sidecars never replace quota config, events or allowance state.
use super::{custody::Journal, text, Intent};
use serde_json::{json, Value};
use std::path::Path;
pub(super) fn previous_listeners_absent() -> Result<(), String> {
    for port in [8001, 8002] {
        let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        match std::net::TcpStream::connect_timeout(&address, std::time::Duration::from_millis(200))
        {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {}
            _ => {
                return Err(
                    "existing or uncertain local model listener prevents a new numerical owner"
                        .into(),
                )
            }
        }
    }
    Ok(())
}

fn name(spec: &Value) -> Result<String, String> {
    Ok(format!(
        "rust-provider-{}.dispatch.json",
        text(spec, "provider_job_id")?
    ))
}
fn quota(spec: &Value) -> Result<Journal, String> {
    Journal::open(Path::new(text(spec, "quota_root")?))
}
pub(super) fn available(spec: &Value) -> Result<(), String> {
    let journal = quota(spec)?;
    if journal.exists("rust-provider-active.json")? {
        return Err("previous provider ownership unresolved; new model operations blocked".into());
    }
    if journal.exists(&name(spec)?)? {
        return Err("approved provider job already consumed in retained lifetime".into());
    }
    Ok(())
}
pub(super) fn consumed(intent: &Intent) -> Result<bool, String> {
    let journal = quota(intent.spec())?;
    Ok(journal.exists("rust-provider-active.json")? || journal.exists(&name(intent.spec())?)?)
}
pub(super) struct Lifetime {
    quota: Journal,
    claim: Value,
}
impl Lifetime {
    pub fn claim(local: &Journal, intent: &Intent) -> Result<Self, String> {
        let mut quota = quota(intent.spec())?;
        quota.lock()?;
        if quota.exists("rust-provider-active.json")? || quota.exists(&name(intent.spec())?)? {
            return Err("provider lifetime active or approved job already consumed".into());
        }
        let claim = json!({"schema":"hol-gauntlet-rust-provider-global-dispatch.v1","source_sha":intent.text("source_sha")?,"provider_job_id":intent.text("provider_job_id")?,"source_authorization_sha256":intent.0["source_authorization_sha256"],"binding_sha256":intent.digest()?,"artifact_journal":local.identity()?,"one_use":true});
        // A partial marker also blocks. Persist global ownership before local
        // dispatch, socket creation, state creation, or numerical process spawn.
        quota.put("rust-provider-active.json", &claim)?;
        quota.put(&name(intent.spec())?, &claim)?;
        Ok(Self { quota, claim })
    }
    pub fn finish(&self, local: &Journal, intent: &Intent) -> Result<(), String> {
        let terminal = local.json("provider-terminal.json")?;
        if terminal["schema"] != "hol-gauntlet-rust-provider-terminal.v1"
            || terminal["binding_sha256"] != intent.digest()?
            || terminal["cleanup"]["owned_process_group_stopped"] != true
            || terminal["cleanup"]["child_reaped"] != true
            || terminal["cleanup"]["private_socket_removed"] != true
            || local.identity()? != self.claim["artifact_journal"]
        {
            return Err(
                "verified original provider cleanup required before lifetime release".into(),
            );
        }
        self.quota.put(&format!("rust-provider-{}.terminal.json",intent.text("provider_job_id")?),&json!({"schema":"hol-gauntlet-rust-provider-global-terminal.v1","claim":self.claim,"terminal_sha256":super::sha(&local.read("provider-terminal.json")?),"qualification_eligible":false}))?;
        self.quota.clear_provider_active(&self.claim)
    }
}
