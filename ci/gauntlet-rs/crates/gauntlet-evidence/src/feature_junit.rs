//! Bounded JUnit v2 observation. Count actual cases and outcomes independently;
//! aggregate suite attributes cannot manufacture tests or conceal failures.
use crate::{EvidenceError, Result};
use roxmltree::{Document, Node, ParsingOptions};
use serde_json::{json, Value};

pub const MAX_FEATURE_JUNIT_BYTES: usize = 4 * 1024 * 1024;
const INVALID: EvidenceError = EvidenceError::Invalid("invalid bounded feature JUnit v2");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FeatureJunitCounts {
    pub tests: u64,
    pub failures: u64,
    pub errors: u64,
    pub skipped: u64,
}
impl FeatureJunitCounts {
    pub fn to_json(self) -> Value {
        json!({"tests":self.tests,"failures":self.failures,"errors":self.errors,"skipped":self.skipped})
    }
    pub fn status(self, exit_code: i32) -> &'static str {
        if self.tests == 0 {
            "invalid-evidence"
        } else if self.failures > 0 || self.errors > 0 || exit_code != 0 {
            "failed"
        } else if self.skipped > 0 {
            "incomplete"
        } else {
            "passed"
        }
    }
    fn add(&mut self, other: Self) -> Result<()> {
        self.tests = self.tests.checked_add(other.tests).ok_or(INVALID)?;
        self.failures = self.failures.checked_add(other.failures).ok_or(INVALID)?;
        self.errors = self.errors.checked_add(other.errors).ok_or(INVALID)?;
        self.skipped = self.skipped.checked_add(other.skipped).ok_or(INVALID)?;
        Ok(())
    }
}

fn count(value: Option<&str>) -> Result<u64> {
    match value {
        None => Ok(0),
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => value
            .parse::<u64>()
            .ok()
            .filter(|n| *n <= 200_000)
            .ok_or(INVALID),
        _ => Err(INVALID),
    }
}
fn declared(node: Node<'_, '_>) -> Result<FeatureJunitCounts> {
    Ok(FeatureJunitCounts {
        tests: count(node.attribute("tests"))?,
        failures: count(node.attribute("failures"))?,
        errors: count(node.attribute("errors"))?,
        skipped: count(node.attribute("skipped"))?,
    })
}
fn named(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace().is_none() && node.tag_name().name() == name
}
fn suite(node: Node<'_, '_>) -> Result<FeatureJunitCounts> {
    if !named(node, "testsuite") {
        return Err(INVALID);
    }
    let mut measured = FeatureJunitCounts::default();
    for child in node.children().filter(Node::is_element) {
        if matches!(
            child.tag_name().name(),
            "properties" | "system-out" | "system-err"
        ) && child.tag_name().namespace().is_none()
        {
            continue;
        }
        if !named(child, "testcase") {
            return Err(INVALID);
        }
        measured.tests += 1;
        for outcome in child.children().filter(Node::is_element) {
            if outcome.tag_name().namespace().is_some() {
                return Err(INVALID);
            }
            match outcome.tag_name().name() {
                "failure" => measured.failures += 1,
                "error" => measured.errors += 1,
                "skipped" => measured.skipped += 1,
                "properties" | "system-out" | "system-err" => {}
                _ => return Err(INVALID),
            }
        }
    }
    if declared(node)? != measured {
        return Err(INVALID);
    }
    Ok(measured)
}

/// This explicitly versioned reader rejects unsupported nesting, namespaces,
/// non-UTF8 input and dishonest or negative counters. It resolves no external
/// entities. The caller separately binds XML bytes to the isolated run.
pub fn verify_feature_junit_v2(raw: &[u8]) -> Result<FeatureJunitCounts> {
    if raw.is_empty() || raw.len() > MAX_FEATURE_JUNIT_BYTES {
        return Err(INVALID);
    }
    let text = std::str::from_utf8(raw).map_err(|_| INVALID)?;
    let document = Document::parse_with_options(
        text,
        ParsingOptions {
            allow_dtd: false,
            nodes_limit: 200_000,
            entity_resolver: None,
        },
    )
    .map_err(|_| INVALID)?;
    if document
        .descendants()
        .any(|node| node.ancestors().take(66).count() > 65)
    {
        return Err(INVALID);
    }
    let root = document.root_element();
    if named(root, "testsuite") {
        return suite(root);
    }
    if !named(root, "testsuites") {
        return Err(INVALID);
    }
    let mut total = FeatureJunitCounts::default();
    let mut suites = 0;
    for child in root.children().filter(Node::is_element) {
        total.add(suite(child)?)?;
        suites += 1;
    }
    if suites == 0 {
        return Err(INVALID);
    }
    // pytest normally omits root counters; if supplied, they must agree too.
    if ["tests", "failures", "errors", "skipped"]
        .iter()
        .any(|key| root.attribute(*key).is_some())
        && declared(root)? != total
    {
        return Err(INVALID);
    }
    Ok(total)
}
