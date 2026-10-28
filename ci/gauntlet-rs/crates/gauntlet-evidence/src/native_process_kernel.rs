//! Match reported peers against separate, caller-pinned public kernel samples.
//! These observations do not admit an observer or a controller signing key.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{require, text};
use crate::payload::exact_keys;
use crate::{EvidenceError, Result};
use serde_json::{json, Value};

pub(crate) const NAMESPACES: [&str; 7] = ["cgroup", "ipc", "mnt", "net", "pid", "user", "uts"];
pub(crate) fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or(EvidenceError::Invalid("positive kernel integer required"))
}
pub(crate) fn list(value: &Value, maximum: usize) -> Result<&Vec<Value>> {
    value
        .as_array()
        .filter(|v| v.len() <= maximum)
        .ok_or(EvidenceError::Invalid("bounded kernel list required"))
}
pub(crate) fn decimal(value: &str) -> Result<u64> {
    require(!value.is_empty() && value.len() <= 20 && value.bytes().all(|b| b.is_ascii_digit()))?;
    value
        .parse::<u64>()
        .map_err(|_| EvidenceError::Invalid("kernel integer overflow"))
}
pub(crate) fn status(
    value: &Value,
    pid: u64,
    uid: &str,
    namespace_pids: Option<&Value>,
) -> Result<()> {
    for name in ["Uid", "Gid"] {
        require(
            text(value, name)?
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                == [uid; 4],
        )?;
    }
    let groups = text(value, "Groups")?
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    require(groups.is_empty() || groups == [uid])?;
    require(value["NoNewPrivs"] == "1" && value["Seccomp"] == "2")?;
    require(decimal(text(value, "Seccomp_filters")?)? > 0)?;
    for name in ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"] {
        require(value[name] == "0000000000000000")?;
    }
    if let Some(pids) = namespace_pids {
        let actual = text(value, "NSpid")?
            .split_ascii_whitespace()
            .map(decimal)
            .collect::<Result<Vec<_>>>()?;
        require(
            (2..=8).contains(&actual.len()) && actual[0] == pid && actual.iter().all(|n| *n > 0),
        )?;
        require(json!(actual) == *pids)?;
    }
    Ok(())
}
fn profile(identity: &Value, job: &str, mode: &str) -> Result<()> {
    require(hex(job, 16) && matches!(mode, "sdk" | "mcp"))?;
    require(number(&identity["pid"])? <= i32::MAX as u64)?;
    number(&identity["start_ticks"])?;
    require(identity["pidfd_held"] == true)?;
    let label = text(identity, "lsm_label")?;
    let nonce = label
        .strip_prefix(&format!("crun//&hol-gauntlet-{mode}-{job}-"))
        .and_then(|v| v.strip_suffix(" (unconfined)"))
        .ok_or(EvidenceError::Invalid(
            "fixed SDK/MCP kernel profile required",
        ))?;
    require(hex(nonce, 32))?;
    let cgroup = text(identity, "cgroup")?;
    let container = cgroup
        .strip_prefix(&format!("/holgauntletrust{job}.slice/libpod-"))
        .and_then(|v| v.strip_suffix(".scope/container"))
        .ok_or(EvidenceError::Invalid(
            "fixed job container cgroup required",
        ))?;
    require(hex(container, 64))?;
    let ns = identity["namespaces"]
        .as_object()
        .ok_or(EvidenceError::Invalid("kernel namespaces missing"))?;
    require(ns.len() == NAMESPACES.len())?;
    for name in NAMESPACES {
        let raw = text(&identity["namespaces"], name)?;
        require(
            decimal(
                raw.strip_prefix("4:")
                    .ok_or(EvidenceError::Invalid("namespace device differs"))?,
            )? > 0,
        )?;
    }
    Ok(())
}

pub(crate) struct KernelSamples<'a> {
    pub(crate) rows: &'a Vec<Value>,
}
impl<'a> KernelSamples<'a> {
    pub(crate) fn for_launch(
        observed: &'a Value,
        observer_sha256: &str,
        launch: &Value,
    ) -> Result<Self> {
        if observed["schema"] == "hol-gauntlet-outside-native-mcp-kernel.v2" {
            require(
                (launch["schema"] == "hol-gauntlet-cell-supervisor.v3"
                    && launch["process_events"] == "outside-root-ptrace.v1")
                    || (launch["schema"] == "hol-gauntlet-cell-supervisor.v4"
                        && launch["process_events"] == "outside-root-ptrace.v2"),
            )?;
        }
        Self::new(observed, observer_sha256)
    }

    fn new(observed: &'a Value, observer_sha256: &str) -> Result<Self> {
        let maximum = match observed["schema"].as_str() {
            Some("hol-gauntlet-outside-native-mcp-kernel.v1") => 10_000,
            Some("hol-gauntlet-outside-native-mcp-kernel.v2") => {
                require(
                    exact_keys(
                        observed,
                        &[
                            "schema",
                            "observer_sha256",
                            "deduplication",
                            "observations",
                            "errors",
                            "execution_eligible",
                            "guard_causality_verified",
                            "collection_limits",
                        ],
                    ) && observed["collection_limits"]
                        == json!({
                            "observations":2048, "argv_bytes":32768, "executable_bytes":134217728,
                        }),
                )?;
                2048
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "outside kernel sample version differs",
                ))
            }
        };
        require(
            hex(observer_sha256, 64)
                && observed["deduplication"] == "pid-start-executable-inode-and-argv-v1"
                && observed["observer_sha256"] == observer_sha256
                && observed["errors"] == json!([])
                && observed["execution_eligible"] == false
                && observed["guard_causality_verified"] == false,
        )?;
        let rows = list(&observed["observations"], maximum)?;
        require(!rows.is_empty())?;
        for row in rows {
            for name in [
                "pid",
                "start_ticks",
                "parent_pid",
                "executable_device",
                "executable_inode",
            ] {
                number(&row[name])?;
            }
            let argv = text(row, "argv_utf8")?;
            require(
                !argv.is_empty()
                    && argv.len() <= 32_768
                    && argv.ends_with('\0')
                    && row["argv_sha256"] == sha256(argv.as_bytes())
                    && hex(text(row, "executable_sha256")?, 64)
                    && row["pidfd_held"] == true,
            )?;
        }
        Ok(Self { rows })
    }
    pub(crate) fn observed(&self, identity: &Value) -> bool {
        self.rows
            .iter()
            .any(|r| r["pid"] == identity["pid"] && r["start_ticks"] == identity["start_ticks"])
    }
    pub(crate) fn match_identity(
        &self,
        identity: &Value,
        argv: &[String],
        executable: &str,
        job: &str,
        mode: &str,
    ) -> Result<Vec<&Value>> {
        profile(identity, job, mode)?;
        require(
            hex(executable, 64)
                && !argv.is_empty()
                && argv.len() <= 64
                && argv
                    .iter()
                    .all(|s| !s.is_empty() && s.len() <= 16_384 && !s.contains('\0')),
        )?;
        let wire = format!("{}\0", argv.join("\0"));
        let pin = sha256(wire.as_bytes());
        let matches = self
            .rows
            .iter()
            .filter(|r| {
                r["pid"] == identity["pid"]
                    && r["start_ticks"] == identity["start_ticks"]
                    && r["executable_sha256"] == executable
                    && r["argv_sha256"] == pin
            })
            .collect::<Vec<_>>();
        require(!matches.is_empty())?;
        let uid = if mode == "sdk" { "10001" } else { "10005" };
        for row in &matches {
            require(
                row["argv_utf8"] == wire
                    && row["cgroup"] == identity["cgroup"]
                    && row["lsm_label"] == identity["lsm_label"]
                    && row["pidfd_held"] == true,
            )?;
            let ns = row["namespaces"]
                .as_object()
                .ok_or(EvidenceError::Invalid("outside namespaces missing"))?;
            require(ns.len() == NAMESPACES.len())?;
            for name in NAMESPACES {
                let reported = text(&identity["namespaces"], name)?
                    .strip_prefix("4:")
                    .unwrap();
                require(number(&row["namespaces"][name])? == decimal(reported)?)?;
            }
            status(&row["status"], number(&identity["pid"])?, uid, None)?;
            status(
                &identity["status"],
                number(&identity["pid"])?,
                uid,
                Some(&row["namespace_pids"]),
            )?;
            let limits = if mode == "sdk" {
                json!({"memory.max":"2147483648","pids.max":"256","cpu.max":"200000 100000"})
            } else {
                json!({"memory.max":"1073741824","pids.max":"256","cpu.max":"100000 100000"})
            };
            require(row["limits"] == limits)?;
        }
        Ok(matches)
    }
}

#[cfg(test)]
#[path = "native_process_kernel_tests.rs"]
mod tests;
