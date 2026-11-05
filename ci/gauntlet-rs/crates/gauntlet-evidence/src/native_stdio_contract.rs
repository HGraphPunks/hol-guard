//! Closed declarations for the read-only Native stdio snapshot protocol.
use crate::native_diagnostic_artifacts::{require, text};
use crate::native_process_kernel::hex;
use crate::payload::exact_keys;
use crate::Result;
use serde_json::Value;

pub(crate) fn declaration(value: &Value) -> Result<()> {
    require(
        exact_keys(
            value,
            &[
                "mode",
                "native_runtime_sha256",
                "scope",
                "memory_or_register_mutation",
                "atomic_kernel_pipe_bytes_verified",
                "concurrent_tracees_frozen",
                "execution_eligible",
            ],
        ) && value["mode"] == "outside-root-native-stdio.v1"
            && hex(text(value, "native_runtime_sha256")?, 64)
            && matches!(
                value["scope"].as_str(),
                Some("owned-product-native-stream" | "owned-process-fixture")
            )
            && value["memory_or_register_mutation"] == false
            && value["atomic_kernel_pipe_bytes_verified"] == false
            && value["concurrent_tracees_frozen"] == false
            && value["execution_eligible"] == false,
    )
}

pub(crate) fn binding(value: &Value) -> Result<()> {
    require(
        exact_keys(
            value,
            &[
                "schema",
                "available",
                "events",
                "bytes",
                "tail_sha256",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
                "links",
            ],
        ) && value["schema"] == "hol-gauntlet-cell-journal-binding.v1"
            && value["available"] == true
            && value["uid"] == 0
            && value["gid"] == 0
            && value["mode"] == 0o600
            && value["links"] == 1
            && value["events"]
                .as_u64()
                .is_some_and(|v| (2..=65536).contains(&v))
            && value["bytes"]
                .as_u64()
                .is_some_and(|v| (1..=64 * 1024 * 1024).contains(&v))
            && value["device"].as_u64().is_some()
            && value["inode"].as_u64().is_some_and(|v| v > 0)
            && hex(text(value, "tail_sha256")?, 64),
    )
}

pub(crate) fn checkpoint(value: &Value) -> Result<()> {
    require(
        exact_keys(
            value,
            &[
                "schema",
                "complete",
                "declaration",
                "counts",
                "journal",
                "execution_eligible",
            ],
        ) && value["schema"] == "hol-gauntlet-native-stdio.v1"
            && value["complete"] == true
            && value["execution_eligible"] == false,
    )?;
    declaration(&value["declaration"])?;
    binding(&value["journal"])?;
    let counts = &value["counts"];
    require(
        exact_keys(
            counts,
            &[
                "streams",
                "closed_streams",
                "calls",
                "syscall_stops",
                "bytes",
            ],
        ) && counts["streams"].as_u64().is_some_and(|v| v <= 1024)
            && counts["closed_streams"] == counts["streams"]
            && counts["calls"].as_u64().is_some_and(|v| v <= 8192)
            && counts["syscall_stops"]
                .as_u64()
                .is_some_and(|v| v <= 1_000_000)
            && counts["bytes"]
                .as_u64()
                .is_some_and(|v| v <= 32 * 1024 * 1024),
    )?;
    require(counts["calls"].as_u64() <= counts["syscall_stops"].as_u64())
}
