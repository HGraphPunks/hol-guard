use gauntlet_evidence::verify_private_actor;
use serde_json::{json, Value};

#[path = "support/private_custody_source.rs"]
mod private_custody_source;

#[test]
fn python_private_actor_privilege_floor_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private_actor_v1.json")).unwrap();
    assert_eq!(fixture["schema"], "gauntlet-python-private-actor.v1");
    private_custody_source::assert_private_custody_source(&fixture, &["_actor"]);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    assert_eq!(
        cases.iter().filter(|row| row["accepted"] == true).count(),
        4
    );
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let observed = verify_private_actor(
            &row["identity"],
            row["label"].as_str().unwrap(),
            &row["namespaces"],
            row["filtered"].as_bool().unwrap(),
        );
        if row["accepted"] == true {
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                json!({"actor_consistent": true, "execution_eligible": false}),
                "{name}"
            );
        } else {
            assert_eq!(
                observed.unwrap_err().to_string(),
                row["reason"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
