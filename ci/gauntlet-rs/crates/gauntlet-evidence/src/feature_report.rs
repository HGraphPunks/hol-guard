//! Independently check every fixed group's XML/log bytes against a v2 report.
//! Files are requested by fixed names; their custody and execution provenance
//! must be established by the outside caller, never inferred here.
use crate::crypto::sha256;
use crate::{verify_feature_junit_v2, EvidenceError, Result, MAX_FEATURE_JUNIT_BYTES};
use gauntlet_contracts::{canonicalize, fixed_feature_catalog, FeatureExecutorSpec};
use serde_json::{json, Value};

const INVALID: EvidenceError =
    EvidenceError::Invalid("feature report v2 differs from fixed inputs or artifacts");
const GROUP_FIELDS: [&str; 12] = [
    "id",
    "label",
    "tests",
    "evidence_kind",
    "attempted",
    "status",
    "counts",
    "exit_code",
    "elapsed_millis",
    "junit_sha256",
    "log_sha256",
    "reason",
];

fn check(ok: bool) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(INVALID)
    }
}
fn fields(value: &Value, keys: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|row| row.len() == keys.len() && keys.iter().all(|key| row.contains_key(*key)))
}

pub(crate) fn aggregate(statuses: impl IntoIterator<Item = impl AsRef<str>>) -> &'static str {
    let mut failed = false;
    let mut incomplete = false;
    for status in statuses {
        match status.as_ref() {
            "passed" => {}
            "failed" => failed = true,
            "incomplete" => incomplete = true,
            _ => return "invalid-evidence",
        }
    }
    if failed {
        "failed"
    } else if incomplete {
        "incomplete"
    } else {
        "passed"
    }
}

/// `read` must return only the requested ordinary artifact within its bound,
/// or `None` when absent. This reader starts no test, package or model process.
pub fn verify_feature_report_v2(
    spec: &FeatureExecutorSpec,
    raw: &[u8],
    mut read: impl FnMut(&str, usize) -> Result<Option<Vec<u8>>>,
) -> Result<Value> {
    check(!raw.is_empty() && raw.len() <= 128 * 1024)?;
    let canonical = canonicalize(raw).map_err(|_| INVALID)?;
    let report: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
    check(fields(
        &report,
        &[
            "schema",
            "audit_id",
            "source_sha",
            "version",
            "wheel_sha256",
            "native_sha256",
            "node_version",
            "catalog_sha256",
            "feature_executor_sha256",
            "source_compiler_sha256",
            "evidence_kind",
            "status",
            "groups",
            "model_requests",
            "model_tokens",
            "qualification_eligible",
        ],
    ))?;
    check(
        report["schema"] == "hol-gauntlet-feature-contracts.v2"
            && report["node_version"] == "v22.22.2"
            && report["evidence_kind"] == "mixed-source-installed-contract"
            && report["model_requests"].as_u64() == Some(0)
            && report["model_tokens"].as_u64() == Some(0)
            && report["qualification_eligible"] == false,
    )?;
    for key in [
        "audit_id",
        "source_sha",
        "version",
        "wheel_sha256",
        "native_sha256",
        "catalog_sha256",
    ] {
        check(report[key] == spec.text(key))?;
    }
    check(report["feature_executor_sha256"] == spec.text("executor_sha256"))?;
    check(
        report["source_compiler_sha256"]
            .as_str()
            .is_some_and(crate::crypto::is_sha256),
    )?;
    let catalog = fixed_feature_catalog().map_err(|_| INVALID)?;
    let rows = report["groups"].as_array().ok_or(INVALID)?;
    check(rows.len() == catalog.len())?;
    let mut checked = Vec::new();
    let mut total_bytes = 0usize;
    for (group, row) in catalog.iter().zip(rows) {
        check(fields(row, &GROUP_FIELDS))?;
        let expected = group.to_json();
        for key in ["id", "label", "tests", "evidence_kind"] {
            check(row[key] == expected[key])?;
        }
        let xml = read(&format!("{}.xml", group.id()), MAX_FEATURE_JUNIT_BYTES)?;
        let log = read(&format!("{}.log", group.id()), 8 * 1024 * 1024)?;
        check(
            xml.as_ref()
                .is_none_or(|v| v.len() <= MAX_FEATURE_JUNIT_BYTES)
                && log.as_ref().is_none_or(|v| v.len() <= 8 * 1024 * 1024),
        )?;
        total_bytes += xml.as_ref().map_or(0, Vec::len) + log.as_ref().map_or(0, Vec::len);
        check(total_bytes <= 336 * 1024 * 1024)?;
        let attempted = row["attempted"].as_bool().ok_or(INVALID)?;
        let (counts, status) = if !attempted {
            check(
                xml.is_none()
                    && log.is_none()
                    && row["exit_code"].is_null()
                    && row["elapsed_millis"].as_u64() == Some(0)
                    && row["junit_sha256"].is_null()
                    && row["log_sha256"].is_null()
                    && row["reason"] == "declared-source-test-missing",
            )?;
            (Value::Null, "invalid-evidence")
        } else {
            let log = log.as_ref().ok_or(INVALID)?;
            check(row["log_sha256"] == sha256(log) && row["reason"].is_null())?;
            let code = row["exit_code"]
                .as_i64()
                .filter(|c| (-255..=255).contains(c))
                .ok_or(INVALID)? as i32;
            check(row["elapsed_millis"].as_u64().is_some_and(|n| n <= 660_000))?;
            let result = if let Some(xml) = &xml {
                check(row["junit_sha256"] == sha256(xml))?;
                verify_feature_junit_v2(xml).ok()
            } else {
                check(row["junit_sha256"].is_null())?;
                None
            };
            result.map_or((Value::Null, "invalid-evidence"), |value| {
                (value.to_json(), value.status(code))
            })
        };
        check(row["counts"] == counts && row["status"] == status)?;
        checked.push(json!({"id":group.id(),"evidence_kind":group.evidence_kind(),"status":status,
            "counts":counts,"attempted":attempted,"xml_bytes":xml.as_ref().map(Vec::len),"log_bytes":log.as_ref().map(Vec::len)}));
    }
    let status = aggregate(
        checked
            .iter()
            .map(|row| row["status"].as_str().expect("computed status")),
    );
    check(report["status"] == status)?;
    Ok(
        json!({"schema":"hol-gauntlet-feature-report-readback.v2","audit_id":spec.text("audit_id"),
        "source_sha":spec.text("source_sha"),"spec_sha256":spec.digest(),"report_sha256":sha256(raw),
        "status":status,"fixed_groups_checked":checked.len(),"groups":checked,"artifact_bytes_checked":total_bytes,
        "counts_independently_recomputed":true,"execution_provenance_authenticated":false,
        "qualification_eligible":false,"execution_eligible":false,"model_requests":0,"model_tokens":0}),
    )
}
