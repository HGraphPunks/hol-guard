//! Synthetic original-dispatch cleanup; no VM, model or Root volume runs.
use super::*;
use crate::native_operation::{
    preparation::tests::{abort_fixture, abort_reply},
    tests::{intent, journal},
};

#[test]
fn new_native_admission_refuses_legacy_init_and_sdk_roles_before_dispatch() {
    let (_temp, j) = journal();
    let absent = j.path.join("absent-journal");
    let mut initialize = vec!["unused".into(); 9];
    initialize[0] = "initialize".into();
    initialize[1] = absent.to_str().unwrap().into();
    for command in [
        crate::run_native_operation_command,
        crate::run_live_campaign_command,
    ] {
        assert!(command(&initialize)
            .unwrap_err()
            .contains("bounded storage"));
        assert!(!absent.exists());
    }
    for role in [
        "success",
        "input-binding",
        "injection",
        "boundary",
        "timeout",
        "cancel",
    ] {
        let mut record = vec!["unused".into(); 14];
        record[0] = "record".into();
        record[1] = absent.to_str().unwrap().into();
        record[9] = role.into();
        assert!(crate::run_native_operation_command(&record)
            .unwrap_err()
            .contains("ordinary SDK/Bash"));
        assert!(!absent.exists());
    }
    let native = intent(&"1".repeat(16), &j.path);
    let original = native.raw().unwrap();
    j.write(native.job(), "intent", &original).unwrap();
    for action in ["run", "prepare", "read", "prepare-read", "report", "repair"] {
        let mut args = vec![
            action.into(),
            j.path.to_str().unwrap().into(),
            native.job().into(),
            native.digest().unwrap(),
        ];
        if action == "prepare" {
            args.extend([absent.to_str().unwrap().into(), "b".repeat(64)]);
        }
        if action == "repair" {
            args.push("c".repeat(64));
        }
        let error = crate::run_native_operation_command(&args).unwrap_err();
        assert_eq!(
            error.contains("ordinary SDK/Bash"),
            matches!(action, "run" | "prepare"),
            "{action}: {error}"
        );
        assert_eq!(j.read(native.job(), "intent").unwrap(), original);
        for suffix in [
            "dispatch",
            "prepare-bundle",
            "prepare-dispatch",
            "repair-intent",
        ] {
            assert!(j.absent(native.job(), suffix).unwrap());
        }
    }
}

#[test]
fn readonly_new_work_requires_original_bounded_storage_without_upgrading_legacy_receipts() {
    let (_temp, j) = journal();
    let mut native = intent(&"1".repeat(16), &j.path);
    native.0["role"] = json!("readonly-utility");
    assert!(super::super::require_new_work(&j, &native)
        .unwrap_err()
        .contains("bounded initialization"));
    let (initial, result, _) = abort_fixture(&j);
    assert_eq!(initial.job(), native.job());
    super::super::require_new_work(&j, &native).unwrap();
    let before = j.read(native.job(), "initialize-result").unwrap();
    assert_eq!(serde_json::from_slice::<Value>(&before).unwrap(), result);
    native.0["source_sha"] = json!("f".repeat(40));
    assert!(super::super::require_new_work(&j, &native).is_err());
    assert_eq!(j.read(initial.job(), "initialize-result").unwrap(), before);
    assert!(j.absent(initial.job(), "dispatch").unwrap());
}
#[test]
fn unreleased_abort_consumes_original_run_without_a_host_pin_or_ack() {
    let (_temp, j) = journal();
    let (i, v, _) = abort_fixture(&j);
    let native = intent(i.job(), &j.path);
    j.write(i.job(), "intent", &native.raw().unwrap()).unwrap();
    j.write(
        i.job(),
        "dispatch",
        &Journal::dispatch_raw(&native).unwrap(),
    )
    .unwrap();
    let a = abort_context_mode(
        &j,
        &i,
        &v,
        v["receipt_sha256"].as_str().unwrap(),
        v["receipt"]["storage"]["receipt_sha256"].as_str().unwrap(),
        &"b".repeat(64),
        &"c".repeat(64),
        true,
    )
    .unwrap();
    assert_eq!(
        a["unreleased"]["native_intent_sha256"],
        native.digest().unwrap()
    );
    assert!(j.require_idle().is_err());
    assert!(abort_execute(&j, &i, &v, &a, false, false, |_| Err(
        "lost cleanup reply".into()
    ))
    .is_err());
    let raw = bytes(&abort_reply(&i, &v, &a)).unwrap();
    let summary = abort_execute(&j, &i, &v, &a, false, true, |_| Ok(raw)).unwrap();
    assert!(summary["model_requests"].is_null());
    assert!(j.require_idle().is_ok());
    assert_eq!(
        j.read(i.job(), "dispatch").unwrap(),
        Journal::dispatch_raw(&native).unwrap()
    );
    assert!(super::super::initialization_for(&j, &native).is_err());
}
#[test]
fn unreleased_cleanup_refuses_missing_or_substituted_dispatch_unknown_files_and_unsafe_pin() {
    let (_temp, j) = journal();
    let (i, v, _) = abort_fixture(&j);
    let native = intent(i.job(), &j.path);
    j.write(i.job(), "intent", &native.raw().unwrap()).unwrap();
    assert!(unreleased(&j, &i).is_err());
    j.write(i.job(), "dispatch", b"{}").unwrap();
    assert!(unreleased(&j, &i).is_err());
    std::fs::write(
        j.path.join(Journal::name(i.job(), "dispatch").unwrap()),
        Journal::dispatch_raw(&native).unwrap(),
    )
    .unwrap();
    assert!(unreleased(&j, &i).is_ok());
    let mut other = i.clone();
    other.0["source_sha"] = json!("f".repeat(40));
    assert!(unreleased(&j, &other).is_err());
    j.write(i.job(), "prelaunch", b"{}").unwrap();
    assert!(abort_context_mode(
        &j,
        &i,
        &v,
        v["receipt_sha256"].as_str().unwrap(),
        v["receipt"]["storage"]["receipt_sha256"].as_str().unwrap(),
        &"b".repeat(64),
        &"c".repeat(64),
        true
    )
    .is_err());
    std::fs::write(
        j.path.join(format!("{}.controller-key-pin.json", i.job())),
        b"{invalid pin}",
    )
    .unwrap();
    assert!(unreleased(&j, &i).is_err());
}
