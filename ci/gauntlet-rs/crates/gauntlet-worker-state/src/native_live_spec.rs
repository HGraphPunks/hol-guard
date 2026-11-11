//! A closed live profile selects source-owned cells, never a caller command.
use crate::native_live_model::NativeLiveModelPins;
use serde_json::{json, Value};

pub const FEATURE_AI_BASELINE: &str = "episode-a9344653386e0c30b3bd63437f283047";
pub const FEATURE_AI_PROTECTED: &str = "episode-406531b0394f2bfaba126c5ec3ddfadb";
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) const EPISODE_SECONDS: u64 = 900;
pub(crate) const PREPARATION_SECONDS: u64 = 990;
#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) const ACTIVE_SECONDS: u64 = 1080;

#[cfg(any(all(target_os = "linux", target_arch = "aarch64"), test))]
pub(crate) fn initial_snapshot(spec: &Value) -> Result<Value, String> {
    let mut initial = spec["initial_snapshot"].clone();
    let records = initial["records"]
        .as_array_mut()
        .ok_or("source-selected live records absent")?;
    if records.iter().any(|row| row["id"].as_str().is_none()) {
        return Err("source-selected live record identity absent".into());
    }
    records.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(initial)
}

#[derive(Clone, Debug)]
pub struct NativeLiveJob {
    pub cell_id: String,
    pub spec_sha256: String,
    pub model: NativeLiveModelPins,
}
impl NativeLiveJob {
    pub fn parse(value: &Value) -> Result<Self, String> {
        if value.as_object().is_none_or(|o| {
            o.len() != 4
                || !["schema", "cell_id", "spec_sha256", "model"]
                    .iter()
                    .all(|n| o.contains_key(*n))
        }) || value["schema"] != "hol-gauntlet-native-live-omp-job.v1"
            || !matches!(
                value["cell_id"].as_str(),
                Some(FEATURE_AI_BASELINE | FEATURE_AI_PROTECTED)
            )
            || value["spec_sha256"]
                .as_str()
                .is_none_or(|s| !crate::hex(s, 64))
        {
            return Err("fixed source-selected live OMP cell required".into());
        }
        Ok(Self {
            cell_id: value["cell_id"].as_str().unwrap().into(),
            spec_sha256: value["spec_sha256"].as_str().unwrap().into(),
            model: NativeLiveModelPins::parse(&value["model"])?,
        })
    }
    pub fn protected(&self) -> bool {
        self.cell_id == FEATURE_AI_PROTECTED
    }
    pub fn role(&self) -> &'static str {
        if self.protected() {
            "feature-ai-protected"
        } else {
            "feature-ai-unprotected"
        }
    }
    pub fn to_json(&self) -> Value {
        json!({"schema":"hol-gauntlet-native-live-omp-job.v1","cell_id":self.cell_id,"spec_sha256":self.spec_sha256,"model":self.model.to_json()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_world_uses_the_actual_sqlite_snapshot_order_and_source_budget() {
        let spec = gauntlet_evidence::feature_ai_support_spec().unwrap();
        assert_eq!(
            spec["execution_budget"],
            json!({"episode_seconds":EPISODE_SECONDS,"preparation_wall_seconds":PREPARATION_SECONDS,"worker_active_seconds":ACTIVE_SECONDS})
        );
        let initial = initial_snapshot(&spec).unwrap();
        let key = ring::signature::Ed25519KeyPair::from_seed_unchecked(&[37; 32]).unwrap();
        let mut world = gauntlet_world::World::initialize(
            rusqlite::Connection::open_in_memory().unwrap(),
            &initial.to_string(),
            key,
        )
        .unwrap();
        assert_eq!(world.snapshot().unwrap(), initial);
        assert!(world.receipts().unwrap().is_empty());
        assert_ne!(spec["initial_snapshot"]["records"], initial["records"]);
    }
    #[test]
    fn live_selection_is_closed_and_does_not_reuse_deterministic_roles() {
        let mut value = json!({"schema":"hol-gauntlet-native-live-omp-job.v1","cell_id":FEATURE_AI_BASELINE,"spec_sha256":"b".repeat(64),"model":{"schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":"c".repeat(16),"budget_digest":"d".repeat(64),"model_id":crate::native_live_model::MODEL,"max_turns":32,"token_limit":100_000}});
        let job = NativeLiveJob::parse(&value).unwrap();
        assert!(!job.protected());
        assert_eq!(job.role(), "feature-ai-unprotected");
        value["cell_id"] = json!(FEATURE_AI_PROTECTED);
        assert!(NativeLiveJob::parse(&value).unwrap().protected());
        for cell in ["input-binding", "readonly-utility", "caller-scenario"] {
            value["cell_id"] = json!(cell);
            assert!(NativeLiveJob::parse(&value).is_err());
        }
        value["cell_id"] = json!(FEATURE_AI_BASELINE);
        value["command"] = json!("anything");
        assert!(NativeLiveJob::parse(&value).is_err());
    }
}
