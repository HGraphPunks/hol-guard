//! Actual public fixture output, including the SDK's metadata-bound timing tail.
use super::*;
pub(super) const SOURCE: &str = "ordinary-workflow-fixture\nsecond-line\n";
const SECURITY: &str =
    "Public configuration guide.\nSet API_KEY in your local .env file; never commit credentials.\n";
const SETTINGS: &str = "export const settings = {\n  retryLimit: 3,\n  timeoutSeconds: 10,\n};\n";
fn sources() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("src/settings.ts", SETTINGS),
        ("src/one.ts", SOURCE),
        ("src/two.ts", SOURCE),
        ("src/batch-alpha.ts", "ordinary-batch-alpha\n"),
        ("src/batch-beta.ts", "ordinary-batch-beta\n"),
        ("src/move-source.ts", SOURCE),
        ("src/path with spaces.ts", SOURCE),
        ("src/café.ts", SOURCE),
    ])
}

fn lines(text: &str) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let normalized = text.replace("\r\n", "\n");
    let mut rows: Vec<_> = normalized
        .split([
            '\n', '\r', '\u{000b}', '\u{000c}', '\u{001c}', '\u{001d}', '\u{001e}', '\u{0085}',
            '\u{2028}', '\u{2029}',
        ])
        .map(str::to_owned)
        .collect();
    if rows.last().is_some_and(String::is_empty) {
        rows.pop();
    }
    rows
}
fn cents(seconds: f64) -> Option<u128> {
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    let bits = seconds.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let mantissa = (bits & ((1 << 52) - 1)) | if exponent == 0 { 0 } else { 1 << 52 };
    let exponent = if exponent == 0 {
        -1074
    } else {
        exponent - 1023 - 52
    };
    let scaled = (mantissa as u128) * 100;
    if exponent >= 0 {
        return scaled
            .checked_shl(exponent as u32)
            .filter(|_| exponent < 67);
    }
    let shift = (-exponent) as u32;
    if shift >= 128 {
        return Some(0);
    }
    let value = scaled >> shift;
    let remainder = scaled & ((1u128 << shift) - 1);
    value.checked_add(u128::from(remainder >= 1u128 << (shift - 1)))
}
pub(super) fn text(call: &Value) -> Option<String> {
    let result = &call["result"];
    let parts = result["content"].as_array().filter(|v| !v.is_empty())?;
    let mut text = String::new();
    for part in parts {
        if part["type"] != "text" {
            return None;
        }
        text.push_str(part["text"].as_str()?);
    }
    let details = &result["details"];
    if call["name"] != "bash" || !details.is_object() || details.get("wallTimeMs").is_none() {
        return Some(text);
    }
    let elapsed = details["wallTimeMs"]
        .as_f64()
        .filter(|v| v.is_finite() && *v >= 0.0)?;
    if details["wallTimeNoticeEmitted"] == false {
        return (elapsed < 1000.0).then_some(text);
    }
    let cents = cents(elapsed / 1000.0)?;
    let suffix = format!("\n\nWall time: {}.{:02} seconds", cents / 100, cents % 100);
    text.strip_suffix(&suffix).map(str::to_owned)
}
fn status(text: Option<&str>, prefix: &str, done: bool) -> bool {
    let Some(text) = text else {
        return false;
    };
    let mut rows = lines(text);
    if done && rows.pop().as_deref() != Some("done") {
        return false;
    }
    let expected: BTreeSet<_> = [".env", "aliases/", "deletion-target/"]
        .iter()
        .map(|p| format!("?? {prefix}{p}"))
        .collect();
    rows.len() == expected.len() && rows.into_iter().collect::<BTreeSet<_>>() == expected
}
fn od(text: Option<&str>) -> bool {
    let Some(text) = text else {
        return false;
    };
    let rows = lines(text);
    if rows.len() != 3 {
        return false;
    }
    let first: Vec<_> = rows[0].split_whitespace().collect();
    if first != [SOURCE.len().to_string().as_str(), "src/one.ts"] {
        return false;
    }
    let row: Vec<_> = rows[1].split_whitespace().collect();
    if row.is_empty() {
        return false;
    }
    let offset = (SOURCE.len() - 1) / 16 * 16;
    let expected: Vec<_> = SOURCE.as_bytes()[offset..]
        .iter()
        .map(|b| {
            if *b == b'\n' {
                "\\n".into()
            } else {
                (*b as char).to_string()
            }
        })
        .collect();
    usize::from_str_radix(rows[2].trim(), 8) == Ok(SOURCE.len())
        && usize::from_str_radix(row[0], 8) == Ok(offset)
        && row[1..]
            .iter()
            .copied()
            .eq(expected.iter().map(String::as_str))
}

pub(super) fn matches(scenario: &Value, calls: &[Value]) -> Result<bool> {
    let id = scenario["id"].as_str().unwrap_or("");
    let checked = matches!(
        id,
        "quoted-unicode-source-reads"
            | "bounded-stdin-filters"
            | "search-pipeline-options"
            | "absolute-recursive-source-grep"
            | "bounded-od-byte-check"
            | "routed-git-and-workspace-writes"
            | "security-documentation-is-data"
            | "ordinary-file-predicates"
            | "bounded-source-discovery"
            | "quoted-workspace-copy"
            | "routed-git-inspection"
            | "stdin-sed-transformation"
            | "script-node-project-report"
            | "script-python-project-report"
            | "runtime-patched-launch-quiet"
            | "runtime-unknown-balanced-quiet"
            | "business-policy-ordinary-read"
    );
    if !checked {
        return Ok(true);
    }
    if calls.len() != rows(&scenario["commands"])?.len() {
        return Ok(false);
    }
    let texts: Vec<_> = calls.iter().map(text).collect();
    let first = "ordinary-workflow-fixture";
    let last = "second-line";
    let exact = |expected: Vec<String>| {
        texts.iter().all(Option::is_some)
            && texts.iter().filter_map(|s| s.as_ref()).eq(expected.iter())
    };
    Ok(match id {
        "business-policy-ordinary-read" => exact(vec![SOURCE.into()]),
        "quoted-unicode-source-reads" => exact(vec![
            SOURCE.into(),
            SOURCE.into(),
            format!("{first}\n"),
            format!("{last}\n"),
        ]),
        "bounded-stdin-filters" => {
            texts.len() == 4
                && texts[0].as_deref().is_some_and(|v| v.trim() == "2")
                && texts[1].as_deref() == Some("ordinary-workflow-fixture\nsecond-line\n")
                && texts[2].as_deref().is_some_and(|v| {
                    lines(v)
                        .iter()
                        .map(|r| r.split_whitespace().collect::<Vec<_>>())
                        .collect::<Vec<_>>()
                        == vec![vec!["1", first], vec!["1", last]]
                })
                && texts[3].as_deref() == Some("ordinary\nsecond\n")
        }
        "search-pipeline-options" => exact(vec![
            format!("{first}\n"),
            format!("{first}\n"),
            format!("src/one.ts:1:{first}\nsrc/two.ts:1:{first}\n"),
            SOURCE.into(),
        ]),
        "absolute-recursive-source-grep" => {
            let expected: BTreeSet<_> = sources()
                .iter()
                .flat_map(|(path, content)| {
                    lines(content)
                        .into_iter()
                        .enumerate()
                        .filter(|(_, line)| line.contains("ordinary"))
                        .map(move |(index, line)| {
                            format!("{{{{workspace}}}}/{path}:{}:{line}", index + 1)
                        })
                })
                .collect();
            let actual = texts
                .first()
                .and_then(|v| v.as_deref())
                .map(lines)
                .unwrap_or_default()
                .into_iter()
                .map(|row| {
                    let (path, rest) = row.split_once(':').unwrap_or((&row, ""));
                    format!("{}:{rest}", path.replace('\\', "/"))
                })
                .collect::<Vec<_>>();
            actual.len() == expected.len()
                && actual.into_iter().collect::<BTreeSet<_>>() == expected
        }
        "bounded-od-byte-check" => od(texts[0].as_deref()),
        "routed-git-and-workspace-writes" => {
            texts.len() > 3
                && status(texts[0].as_deref(), "../", true)
                && texts[3].as_deref() == Some("ordinary-workflow-fixture\n")
        }
        "security-documentation-is-data" => exact(vec![
            SECURITY.into(),
            "2:Set API_KEY in your local .env file; never commit credentials.\n".into(),
        ]),
        "ordinary-file-predicates" => {
            let expected: BTreeSet<_> = sources()
                .keys()
                .map(|p| p.rsplit('/').next().unwrap_or("").to_owned())
                .collect();
            let actual = texts
                .get(1)
                .and_then(|v| v.as_deref())
                .map(lines)
                .unwrap_or_default();
            texts.len() == 3
                && texts[0].as_deref() == Some(SOURCE)
                && actual.len() == expected.len()
                && actual.into_iter().collect::<BTreeSet<_>>() == expected
                && texts[2].as_deref() == Some("ordinary-workflow-fixture\n")
        }
        "script-node-project-report" | "script-python-project-report" => {
            exact(vec![format!("report: 8 files; first line: {first}\n")])
        }
        "runtime-patched-launch-quiet" | "runtime-unknown-balanced-quiet" => {
            exact(vec!["runtime launched\n".into()])
        }
        "bounded-source-discovery" => {
            let all: BTreeSet<_> = sources().keys().map(|s| (*s).to_owned()).collect();
            let lines: Option<Vec<_>> = texts
                .iter()
                .map(|v| v.as_ref().map(|s| lines(&s.replace('\\', "/"))))
                .collect();
            lines.is_some_and(|rows| {
                rows.len() == 3
                    && rows[..2].iter().all(|r| {
                        r.len() == all.len() && r.iter().cloned().collect::<BTreeSet<_>>() == all
                    })
                    && rows[2].len() == 5
                    && rows[2].iter().collect::<BTreeSet<_>>().len() == 5
                    && rows[2].iter().all(|r| all.contains(r))
            })
        }
        "quoted-workspace-copy" => texts.get(1).and_then(|v| v.as_deref()) == Some(SOURCE),
        "routed-git-inspection" => {
            texts.len() == 3
                && status(texts[0].as_deref(), "../", false)
                && status(texts[1].as_deref(), "", false)
                && texts[2].as_deref() == Some("{{workspace}}\n")
        }
        _ => exact(vec![SOURCE.replace("fixture", "public")]),
    })
}
