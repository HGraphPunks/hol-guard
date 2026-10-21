//! Read-only opening of a source-bound local executor conformance package.
//! Signed producer reports are inspected, never promoted to a Guard verdict.

use crate::crypto::{decode_hex, is_sha256, sha256};
use crate::payload::exact_keys;
use crate::{verify_control_reported_tail, verify_native_review_summary, EvidenceError, Result};
use gauntlet_contracts::canonicalize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
const ROLES: [&str; 5] = ["boundary", "cancel", "input-binding", "success", "timeout"];
const REQUIREMENTS: [&str; 12] = [
    "identity",
    "separation",
    "task-custody",
    "readonly-inputs",
    "network",
    "syscalls-devices",
    "proc-paths",
    "resources",
    "input-output-replay",
    "timeout",
    "cancellation",
    "cleanup",
];

// The exact Python local_executor_conformance.EXECUTION_SOURCES set at the
// integration source pin. Additions require a reviewed schema/source update.
pub const EXECUTION_SOURCES: [&str; 50] = [
    "builtin_hook_supervisor.py",
    "contained_exec_relay.py",
    "contained_output_binding.py",
    "contained_request_file.py",
    "developer_product_runtime.py",
    "developer_sdk_gate.py",
    "developer_pilot.py",
    "developer_pilot_services.py",
    "developer_resources.py",
    "private_cell_factory.py",
    "private_cell_hook_plane.py",
    "product_cell_actor.py",
    "product_cell_idmap.py",
    "product_cell_image.py",
    "product_cell_layout.py",
    "product_cell_protocol.py",
    "product_cell_supervisor.py",
    "product_cell_system.py",
    "product_cell_task_mounts.py",
    "product_exec_gate.py",
    "product_vm_network.py",
    "product_vm_rootfs.py",
    "product_vm_seccomp.py",
    "native_product_container.py",
    "native_builtin_plane.py",
    "native_mcp_supervisor.py",
    "mcp_task_context.py",
    "service_supervisor.py",
    "mcp_server.py",
    "mcp_protocol_profiles.py",
    "mcp_protocol_campaign.py",
    "developer_budget.py",
    "developer_model_relay.py",
    "mcp_agent_profile.py",
    "runtime_bundle.py",
    "vm_bridge_frames.py",
    "vm_bridge_io.py",
    "vm_bridge_rpc.py",
    "vm_product_operations.py",
    "product_version.py",
    "private_cell_readiness.py",
    "release_mcp_entry.py",
    "release_hook_entry.py",
    "builtin_guard_bridge.ts",
    "private_cell_sdk_conformance.ts",
    "developer_omp_episode.ts",
    "mcp_agent_surfaces.ts",
    "service_relay.py",
    "product_vm.apparmor",
    "product_vm_seccomp_oci_v1.json",
];

const INVALID: EvidenceError = EvidenceError::Invalid("invalid local conformance package");
const SOURCE: EvidenceError =
    EvidenceError::Invalid("execution source differs from outside controller tree");
const CONTROL: EvidenceError = EvidenceError::Invalid("control differs from pinned package anchor");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalConformancePackageShadow {
    pub package_sha256: String,
    pub source_count: usize,
    pub role_session_ids: BTreeMap<String, String>,
    pub public_inputs_verified: bool,
    pub execution_eligible: bool,
}

impl LocalConformancePackageShadow {
    pub fn to_json(&self) -> Value {
        json!({
            "schema":"hol-gauntlet-local-conformance-package-shadow.v1",
            "package_sha256":self.package_sha256,
            "execution_source_count":self.source_count,
            "control_roles":self.role_session_ids.keys().collect::<Vec<_>>(),
            "distinct_signed_sessions":self.role_session_ids.len(),
            "native_review_summaries_recomputed":self.role_session_ids.len(),
            "public_inputs_verified":self.public_inputs_verified,
            "signed_openings_checked":true,
            "independent_kernel_sdk_effects_verified":false,
            "qualification_eligible":false,
            "execution_eligible":false,
        })
    }
}

fn canonical_value(value: &Value) -> Result<Vec<u8>> {
    canonicalize(&serde_json::to_vec(value).map_err(|_| INVALID)?).map_err(|_| INVALID)
}

fn exact_set(value: &Value, names: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == names.len() && names.iter().all(|name| object.contains_key(*name))
    })
}

fn verify_review(review: &Value) -> Result<()> {
    if !exact_keys(
        review,
        &[
            "schema",
            "reviewer_role",
            "verdict",
            "requirements",
            "document",
            "document_sha256",
        ],
    ) || review["schema"] != "local-executor-equivalence-review.v1"
        || review["reviewer_role"] != "implementation-author"
        || review["verdict"] != "scoped-local-conformance"
        || !exact_set(&review["requirements"], &REQUIREMENTS)
    {
        return Err(EvidenceError::Invalid(
            "local security-equivalence review missing",
        ));
    }
    let requirements = review["requirements"].as_object().ok_or(INVALID)?;
    if !requirements.values().all(|value| {
        value
            .as_str()
            .is_some_and(|text| !text.is_empty() && text.len() <= 4096)
    }) {
        return Err(EvidenceError::Invalid(
            "local security-equivalence review missing",
        ));
    }
    let document = review["document"].as_str().ok_or(INVALID)?;
    if document.len() > 65_536
        || !is_sha256(review["document_sha256"].as_str().unwrap_or(""))
        || sha256(document.as_bytes()) != review["document_sha256"]
    {
        return Err(EvidenceError::Invalid(
            "local security-equivalence review digest differs",
        ));
    }
    Ok(())
}

/// Compare the whole package with *outside* pins and open its five signed
/// records. The source hashes must be read from a separately pinned controller
/// tree, and `expected_runtime` must be derived from an outside-pinned config.
/// The existing control tail does not authenticate SDK, Native or kernel effects.
pub fn verify_local_conformance_package_ineligible(
    raw: &[u8],
    outside_package_sha256: &str,
    expected_runtime: &Value,
    observed_platform: &Value,
    outside_source_hashes: &BTreeMap<String, String>,
    observed_public_assets: Option<&Value>,
) -> Result<LocalConformancePackageShadow> {
    if raw.is_empty()
        || raw.len() > MAX_PACKAGE_BYTES
        || !is_sha256(outside_package_sha256)
        || sha256(raw) != outside_package_sha256
    {
        return Err(EvidenceError::Invalid(
            "conformance bytes differ from outside pin",
        ));
    }
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let package: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    if !exact_keys(
        &package,
        &[
            "schema",
            "scope",
            "qualification_eligible",
            "platform",
            "runtime",
            "public_assets",
            "execution_sources",
            "review",
            "controls",
        ],
    ) || package["schema"] != "local-executor-conformance.v1"
        || package["scope"] != "local-diagnostic-only"
        || package["qualification_eligible"] != false
    {
        return Err(EvidenceError::Invalid(
            "explicit local-only conformance required",
        ));
    }
    if &package["platform"] != observed_platform || &package["runtime"] != expected_runtime {
        return Err(EvidenceError::Invalid(
            "platform or runtime differs from outside pins",
        ));
    }
    let sources = package["execution_sources"].as_object().ok_or(SOURCE)?;
    if !exact_set(&package["execution_sources"], &EXECUTION_SOURCES)
        || outside_source_hashes.len() != EXECUTION_SOURCES.len()
        || EXECUTION_SOURCES.iter().any(|name| {
            let package_digest = sources.get(*name).and_then(Value::as_str);
            let outside_digest = outside_source_hashes.get(*name).map(String::as_str);
            package_digest.is_none_or(|digest| !is_sha256(digest) || Some(digest) != outside_digest)
        })
    {
        return Err(SOURCE);
    }
    verify_review(&package["review"])?;
    if !exact_set(&package["controls"], &ROLES)
        || !exact_set(&package["public_assets"], &["sdk", "bun"])
    {
        return Err(INVALID);
    }
    let mut role_session_ids = BTreeMap::new();
    let mut sessions = BTreeSet::new();
    for role in ROLES {
        let row = &package["controls"][role];
        if !exact_keys(row, &["public_key", "record", "record_digest"]) {
            return Err(CONTROL);
        }
        let key_text = row["public_key"].as_str().ok_or(CONTROL)?;
        if !is_sha256(key_text) {
            return Err(CONTROL);
        }
        let key = decode_hex(key_text, 32).map_err(|_| CONTROL)?;
        let record = &row["record"];
        let record_digest = row["record_digest"]
            .as_str()
            .filter(|text| is_sha256(text))
            .ok_or(CONTROL)?;
        let record_raw = canonical_value(record)?;
        if sha256(&record_raw) != record_digest
            || record["public_input_assets_before"] != package["public_assets"]
        {
            return Err(CONTROL);
        }
        let tail = verify_control_reported_tail(&record_raw, role, &key, expected_runtime)?;
        let reviews = verify_native_review_summary(&tail.session.signed.builtin)?;
        if reviews["review_complete"] != (role != "cancel")
            || (role == "cancel"
                && tail.session.signed.builtin["review_summary"]["missing_required_post_call_ids"]
                    != json!(["sdk-contained-control"]))
        {
            return Err(EvidenceError::Invalid(
                "control Native review status differs from role",
            ));
        }
        let session_id = tail.session.session_id;
        if !sessions.insert(session_id.clone()) {
            return Err(EvidenceError::Invalid(
                "conformance roles must be distinct runs",
            ));
        }
        role_session_ids.insert(role.to_owned(), session_id);
    }
    if let Some(assets) = observed_public_assets {
        if assets["sdk"] != package["public_assets"]["sdk"]
            || ["sha256", "size", "mode"]
                .iter()
                .any(|field| assets["bun"][*field] != package["public_assets"]["bun"][*field])
        {
            return Err(EvidenceError::Invalid(
                "actual SDK/Bun differs from conformance",
            ));
        }
    }
    Ok(LocalConformancePackageShadow {
        package_sha256: outside_package_sha256.to_owned(),
        source_count: sources.len(),
        role_session_ids,
        public_inputs_verified: observed_public_assets.is_some(),
        execution_eligible: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn structural_fixture() -> (Value, BTreeMap<String, String>, Value, Value) {
        let sources: BTreeMap<String, String> = EXECUTION_SOURCES
            .iter()
            .map(|name| ((*name).to_owned(), "0".repeat(64)))
            .collect();
        let requirements: BTreeMap<String, String> = REQUIREMENTS
            .iter()
            .map(|name| ((*name).to_owned(), "reviewed".to_owned()))
            .collect();
        let runtime = json!({"source_sha":"outside"});
        let platform = json!({"machine":"aarch64"});
        let package = json!({
            "schema":"local-executor-conformance.v1",
            "scope":"local-diagnostic-only",
            "qualification_eligible":false,
            "platform":platform,
            "runtime":runtime,
            "public_assets":{"sdk":{},"bun":{}},
            "execution_sources":sources,
            "review":{
                "schema":"local-executor-equivalence-review.v1",
                "reviewer_role":"implementation-author",
                "verdict":"scoped-local-conformance",
                "requirements":requirements,
                "document":"reviewed",
                "document_sha256":sha256(b"reviewed"),
            },
            "controls":{},
        });
        (package, sources, runtime, platform)
    }

    fn inspect_fixture(
        package: &Value,
        sources: &BTreeMap<String, String>,
        runtime: &Value,
        platform: &Value,
    ) -> Result<LocalConformancePackageShadow> {
        let raw = canonical_value(package).unwrap();
        verify_local_conformance_package_ineligible(
            &raw,
            &sha256(&raw),
            runtime,
            platform,
            sources,
            None,
        )
    }

    #[test]
    fn exact_source_and_role_sets_are_frozen() {
        assert_eq!(EXECUTION_SOURCES.len(), 50);
        assert_eq!(EXECUTION_SOURCES.iter().collect::<BTreeSet<_>>().len(), 50);
        assert_eq!(ROLES.iter().collect::<BTreeSet<_>>().len(), 5);
    }

    #[test]
    fn bounded_reader_refuses_digest_and_ambiguous_json() {
        let raw = br#"{"schema":"x","schema":"y"}"#;
        assert!(verify_local_conformance_package_ineligible(
            raw,
            &sha256(raw),
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            None
        )
        .is_err());
        assert!(verify_local_conformance_package_ineligible(
            b"{}",
            &"0".repeat(64),
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            None
        )
        .is_err());
        assert!(verify_local_conformance_package_ineligible(
            &vec![b' '; MAX_PACKAGE_BYTES + 1],
            &"0".repeat(64),
            &json!({}),
            &json!({}),
            &BTreeMap::new(),
            None
        )
        .is_err());
    }

    #[test]
    fn package_cannot_choose_runtime_source_set_review_or_roles() {
        let (mut package, sources, runtime, platform) = structural_fixture();
        assert_eq!(
            inspect_fixture(&package, &sources, &runtime, &platform)
                .unwrap_err()
                .to_string(),
            INVALID.to_string()
        );
        package["runtime"]["source_sha"] = json!("candidate-chosen");
        assert!(inspect_fixture(&package, &sources, &runtime, &platform)
            .unwrap_err()
            .to_string()
            .contains("outside pins"));
        package["runtime"] = runtime.clone();
        package["execution_sources"][EXECUTION_SOURCES[0]] = json!("1".repeat(64));
        assert_eq!(
            inspect_fixture(&package, &sources, &runtime, &platform)
                .unwrap_err()
                .to_string(),
            SOURCE.to_string()
        );
        package["execution_sources"][EXECUTION_SOURCES[0]] = json!("0".repeat(64));
        package["review"]["document"] = json!("changed");
        assert!(inspect_fixture(&package, &sources, &runtime, &platform)
            .unwrap_err()
            .to_string()
            .contains("review digest"));
    }
}
