use gauntlet_host_state::{load_operations_bytes, TelemetryError as Error, VmNativeProbePlan};
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::atomic::AtomicBool;

fn sample() -> Value {
    json!({"schema":"hol-gauntlet-vm-telemetry.v1","platform":"Linux","status":"running",
        "checked_at":1_000_000.0,"cpus":2,"load":0.25,"memory_total":16_u64*1024*1024*1024,
        "memory_available":12_u64*1024*1024*1024,"disk_total":48_u64*1024*1024*1024,
        "disk_free":10_u64*1024*1024*1024})
}

#[test]
fn fixed_native_plan_preserves_metric_meanings_without_an_interpreter() {
    let operations = load_operations_bytes(b"{}").unwrap();
    let digest = "a".repeat(64);
    let plan = VmNativeProbePlan::new(&operations, &digest).unwrap();
    assert_eq!(
        plan.argv,
        vec![
            operations["limactl"].as_str().unwrap().to_owned(),
            "shell".into(),
            operations["vm"].as_str().unwrap().to_owned(),
            "--".into(),
            format!("/opt/hol-gauntlet/gauntlet-vm-telemetry-{digest}")
        ]
    );
    let parsed = plan
        .parse_response(sample().to_string().as_bytes())
        .unwrap();
    for key in [
        "status",
        "checked_at",
        "cpus",
        "load",
        "memory_total",
        "memory_available",
        "disk_total",
        "disk_free",
    ] {
        assert_eq!(parsed[key], sample()[key]);
    }
    assert_eq!(parsed["name"], operations["vm"]);
    assert_eq!(plan.to_json()["admission_eligible"], false);
    assert!(VmNativeProbePlan::new(&operations, "bad").is_err());
}

#[test]
fn malformed_extra_duplicate_wrong_platform_and_unavailable_metrics_refuse() {
    let plan =
        VmNativeProbePlan::new(&load_operations_bytes(b"{}").unwrap(), &"b".repeat(64)).unwrap();
    for (key, bad) in [
        ("schema", json!("unrecognized")),
        ("platform", json!("Darwin")),
        ("memory_available", json!(u64::MAX)),
        ("memory_total", Value::Null),
        ("checked_at", json!(0)),
        ("cpus", json!(true)),
        ("load", json!(-1)),
        ("private_config", json!("must not be published")),
    ] {
        let mut value = sample();
        value[key] = bad;
        assert!(
            plan.parse_response(value.to_string().as_bytes()).is_err(),
            "{key}"
        );
    }
    assert_eq!(
        plan.parse_response(b"{\"status\":1,\"status\":2}"),
        Err(Error::InvalidProbe)
    );
    assert_eq!(plan.parse_response(&vec![b'x'; 8193]), Err(Error::TooLarge));
}

#[test]
fn fake_lima_receives_only_the_fixed_native_probe_and_cancellation_refuses() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("limactl");
    let encoded = sample().to_string();
    let script = format!("#!/bin/sh\n[ \"$#\" = 4 ] || exit 7\n[ \"$1\" = shell ] || exit 8\n[ \"$3\" = -- ] || exit 9\nprintf '%s\\n' '{encoded}'\n");
    fs::write(&executable, script).unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let operations =
        load_operations_bytes(json!({"limactl":executable}).to_string().as_bytes()).unwrap();
    let plan = VmNativeProbePlan::new(&operations, &"c".repeat(64)).unwrap();
    let value = plan.execute_read_only(&AtomicBool::new(false)).unwrap();
    assert_eq!(value["cpus"], 2);
    assert_eq!(
        plan.execute_read_only(&AtomicBool::new(true)),
        Err(Error::Unavailable)
    );
}

#[test]
fn actual_telemetry_executable_requires_linux_and_rejects_arguments() {
    let binary = env!("CARGO_BIN_EXE_gauntlet-vm-telemetry");
    let invalid = Command::new(binary).arg("unexpected").output().unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let output = Command::new(binary).output().unwrap();
    if cfg!(target_os = "linux") {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let plan = VmNativeProbePlan::new(&load_operations_bytes(b"{}").unwrap(), &"d".repeat(64))
            .unwrap();
        let sample = plan.parse_response(&output.stdout).unwrap();
        assert!(sample["memory_total"].as_u64().unwrap() > 0);
        assert!(sample["disk_free"].as_u64().unwrap() <= sample["disk_total"].as_u64().unwrap());
    } else {
        assert_eq!(output.status.code(), Some(2));
    }
}
