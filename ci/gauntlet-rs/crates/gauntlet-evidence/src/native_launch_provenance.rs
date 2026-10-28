//! A versioned outside preparation plus signed Root journal bind launch pins.
//! Declaring an observer digest does not authenticate its process or admit it.
use crate::native_diagnostic_artifacts::{ineligible, require};
use crate::native_process_kernel::{hex, number};
use crate::Result;
use serde_json::{json, Value};

pub(crate) fn verify(
    preparation: &Value,
    events: &[Value],
    interpreter: &str,
    observer: &str,
    journal_bound: bool,
) -> Result<Option<Value>> {
    let launch = &preparation["launch"];
    let pins = events
        .iter()
        .enumerate()
        .filter(|(_, r)| r["kind"] == "image-interpreter-pinned")
        .collect::<Vec<_>>();
    if launch["schema"] == "hol-gauntlet-cell-supervisor.v1" {
        require(
            pins.is_empty()
                && launch.get("image_interpreter_sha256").is_none()
                && launch.get("outside_observer_sha256").is_none(),
        )?;
        return Ok(None);
    }
    require(
        matches!(
            launch["schema"].as_str(),
            Some("hol-gauntlet-cell-supervisor.v2" | "hol-gauntlet-cell-supervisor.v3")
        ) && (launch["schema"] != "hol-gauntlet-cell-supervisor.v3"
            || launch["process_events"] == "outside-root-ptrace.v1")
            && journal_bound
            && hex(interpreter, 64)
            && hex(observer, 64)
            && launch["image_interpreter_sha256"] == interpreter
            && launch["outside_observer_sha256"] == observer
            && pins.len() == 1
            && pins[0].0 == 1
            && events[0]["kind"] == "prepared",
    )?;
    let pin = &pins[0].1["data"];
    ineligible(pin)?;
    require(
        pin.as_object().is_some_and(|v| v.len() == 15)
            && pin["schema"] == "hol-gauntlet-image-interpreter-pin.v1"
            && pin["path"] == "/usr/bin/python3.12"
            && pin["sha256"] == interpreter
            && pin["outside_observer_declared_sha256"] == observer
            && pin["uid"].as_u64() == Some(0)
            && pin["gid"].as_u64() == Some(0)
            && pin["mode"].as_u64() == Some(0o755)
            && pin["links"].as_u64() == Some(1)
            && pin["verified_before_product_launch"] == true
            && pin["bytes"]
                .as_u64()
                .is_some_and(|n| (64..=16 * 1024 * 1024).contains(&n)),
    )?;
    number(&pin["device"])?;
    number(&pin["inode"])?;
    Ok(Some(
        json!({"schema":"hol-gauntlet-native-launch-provenance.v1","interpreter_prelaunch_pinned":true,
        "interpreter_sha256":interpreter,"image_interpreter_generation":pin,"outside_observer_prelaunch_declared":true,
        "outside_observer_sha256":observer,"observer_execution_authenticated":false,"outside_signing_key_admitted":false,
        "execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Vec<Value>) {
        let prep = json!({"launch":{"schema":"hol-gauntlet-cell-supervisor.v2","image_interpreter_sha256":"a".repeat(64),"outside_observer_sha256":"b".repeat(64)}});
        let pin = json!({"schema":"hol-gauntlet-image-interpreter-pin.v1","path":"/usr/bin/python3.12","sha256":"a".repeat(64),
            "bytes":1024,"device":2,"inode":3,"uid":0,"gid":0,"mode":493,"links":1,"verified_before_product_launch":true,
            "outside_observer_declared_sha256":"b".repeat(64),"execution_eligible":false,"guard_causality_verified":false,"model_requests":0});
        (
            prep,
            vec![
                json!({"kind":"prepared"}),
                json!({"kind":"image-interpreter-pinned","data":pin}),
                json!({"kind":"before-cell-gate"}),
            ],
        )
    }
    fn read(prep: &Value, events: &[Value], bound: bool) -> Result<Option<Value>> {
        verify(prep, events, &"a".repeat(64), &"b".repeat(64), bound)
    }
    #[test]
    fn legacy_report_cannot_gain_prelaunch_credit_from_an_invented_event() {
        let legacy = json!({"launch":{"schema":"hol-gauntlet-cell-supervisor.v1"}});
        assert_eq!(read(&legacy, &[], false).unwrap(), None);
        let (prep, events) = fixture();
        assert!(read(&legacy, &events, true).is_err());
        assert!(read(&prep, &events, false).is_err());
        let value = read(&prep, &events, true).unwrap().unwrap();
        assert_eq!(value["interpreter_prelaunch_pinned"], true);
        assert_eq!(value["observer_execution_authenticated"], false);
        assert_eq!(value["execution_eligible"], false);
    }
    #[test]
    fn late_duplicate_wrong_pin_and_changed_physical_generation_refuse() {
        let (prep, events) = fixture();
        let mut late = events.clone();
        late.swap(1, 2);
        assert!(read(&prep, &late, true).is_err());
        let mut duplicate = events.clone();
        duplicate.push(events[1].clone());
        assert!(read(&prep, &duplicate, true).is_err());
        for (field, value) in [
            ("sha256", json!("c".repeat(64))),
            ("outside_observer_declared_sha256", json!("c".repeat(64))),
            ("path", json!("/tmp/python")),
            ("uid", json!(10004)),
            ("mode", json!(0o777)),
            ("links", json!(2)),
            ("inode", json!(true)),
            ("verified_before_product_launch", json!(false)),
            ("execution_eligible", json!(true)),
        ] {
            let mut changed = events.clone();
            changed[1]["data"][field] = value;
            assert!(read(&prep, &changed, true).is_err(), "{field}");
        }
        let mut changed = prep;
        changed["launch"]["outside_observer_sha256"] = json!("c".repeat(64));
        assert!(read(&changed, &events, true).is_err());
    }

    #[test]
    fn v3_retains_prelaunch_pins_and_cannot_select_another_recorder() {
        let (mut prep, events) = fixture();
        prep["launch"]["schema"] = json!("hol-gauntlet-cell-supervisor.v3");
        assert!(read(&prep, &events, true).is_err());
        prep["launch"]["process_events"] = json!("outside-root-ptrace.v1");
        assert!(read(&prep, &events, true).unwrap().is_some());
        assert!(read(&prep, &events, false).is_err());
        prep["launch"]["process_events"] = json!("poll");
        assert!(read(&prep, &events, true).is_err());
    }
}
