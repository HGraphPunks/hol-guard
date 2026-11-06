use base64::{engine::general_purpose::STANDARD, Engine};
use gauntlet_evidence::normalize_native_hook_response;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn source_pinned_python_native_hook_wire_decisions_match() {
    let fixture: Value = serde_json::from_str(include_str!(
        "fixtures/python_native_hook_responses_v1.json"
    ))
    .unwrap();
    assert_eq!(
        fixture["schema"],
        "hol-gauntlet-python-native-hook-response.v1"
    );
    assert_eq!(
        fixture["source_sha256"],
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../../gauntlet/benchmark/native_builtin_plane.py"
            ))
        )
    );
    assert_eq!(
        fixture["json_source_sha256"],
        format!(
            "{:x}",
            Sha256::digest(include_bytes!(
                "../../../../gauntlet/benchmark/json_data.py"
            ))
        )
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 64);
    assert_eq!(
        cases
            .iter()
            .filter(|case| case["expected"]["accepted"] == true)
            .count(),
        20
    );
    for case in cases {
        let raw = STANDARD
            .decode(case["raw_base64"].as_str().unwrap())
            .unwrap();
        let result = normalize_native_hook_response(
            &raw,
            case["returncode"].as_i64().unwrap(),
            case["event"].as_str(),
        );
        if case["expected"]["accepted"] == true {
            assert_eq!(
                result.unwrap_or_else(|e| panic!("{}: {e}", case["name"])),
                case["expected"]["value"]
            );
        } else {
            let error = result.unwrap_err().to_string();
            if case["expected"]["kind"] == "json" {
                assert_eq!(error, "invalid bounded NativeHook JSON", "{}", case["name"]);
            } else {
                assert_eq!(
                    error,
                    case["expected"]["reason"].as_str().unwrap(),
                    "{}",
                    case["name"]
                );
            }
        }
    }
}
