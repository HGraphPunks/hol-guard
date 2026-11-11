//! Synthetic original-dispatch cleanup; no VM, model or Root volume runs.
use super::*;
use crate::native_operation::{
    preparation::tests::{abort_fixture, abort_reply},
    tests::{intent, journal},
};
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
