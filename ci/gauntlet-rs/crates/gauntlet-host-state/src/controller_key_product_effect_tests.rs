use super::*;
use serde_json::json;

#[test]
fn kernel_effect_readback_requires_host_pins_known_writers_and_exact_surface() {
    let pin = HostEffectEventsPin {
        run_id: "a".repeat(16),
        host_key_record_sha256: "b".repeat(64),
        terminal_sha256: "c".repeat(64),
        report_sha256: "d".repeat(64),
        journal_sha256: "e".repeat(64),
        journal_bytes: 100,
        events: 12,
        unknown_writers: 1,
        raw_sha256: "f".repeat(64),
    };
    let value = json!({"schema":"hol-gauntlet-staging-kernel-bound-effect.v1","run_id":pin.run_id,
        "role":"success","surface":"provider-home","final_sha256":"59cae128f1e25176c5c65014eca5ecf8a6ad57360b867f2d5b22837ca4712d74",
        "final_bytes":24,"device":8,"inode":10,"close_writes":2,"writers":[{"pid":42,"start_ticks":123}],
        "outside_journal_sha256":pin.journal_sha256,"held_final_file_checked":true,"physical_owner_uid":10001,
        "event_view_owner_uid":10004,"idmap_kernel_verified":true,"guard_causality_verified":false,"execution_eligible":false,
        "kernel_observed_cgroup":format!("/holgauntletrust{}.slice/hol-product-cell-{}.service",pin.run_id,"b".repeat(32)),
        "kernel_product_pid":41,"kernel_product_start_ticks":122,"outside_report_sha256":pin.report_sha256,"continuously_observed":false});
    let read = |v: &Value| validate(v.to_string().as_bytes(), &pin, "success", "provider-home");
    assert_eq!(read(&value).unwrap(), value);
    for (field, change) in [
        ("outside_report_sha256", json!("0".repeat(64))),
        ("outside_journal_sha256", json!("0".repeat(64))),
        ("idmap_kernel_verified", json!(false)),
        ("guard_causality_verified", json!(true)),
        ("execution_eligible", json!(true)),
        ("surface", json!("provider-remote")),
        ("writers", json!([])),
        ("close_writes", json!(13)),
        (
            "kernel_observed_cgroup",
            json!("/system.slice/other.service"),
        ),
        ("final_bytes", json!(25)),
    ] {
        let mut changed = value.clone();
        changed[field] = change;
        assert!(read(&changed).is_err(), "{field}");
    }
    let mut changed = value.clone();
    let duplicate = changed["writers"][0].clone();
    changed["writers"].as_array_mut().unwrap().push(duplicate);
    assert!(read(&changed).is_err());
    changed = value.clone();
    changed["caller_expected_cgroup"] = json!("/system.slice/other.service");
    assert!(read(&changed).is_err());
}
