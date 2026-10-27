//! Verify actual SDK capture delivery separately from the benign test outcome.
use serde_json::Value;

pub(crate) fn verify(sdk: &Value, output: &Value) -> Result<(), String> {
    let result = &sdk["result"];
    if sdk["exit_code"] != 0
        || result["schema"] != "private-cell-sdk-conformance-result.v1"
        || result["version"] != "18.4.12"
        || result["uid"] != 10001
        || result["syntheticStreamCalls"] != 2
        || result["mcpExercised"] != false
        || result["modelExercised"] != false
        || result["providerRequests"] != 0
        || result["qualificationEligible"] != false
        || result["modelContextProjection"]["originalCommandVisible"] != true
        || result["modelContextProjection"]["executionTransportRetained"] != true
    {
        return Err("actual SDK conformance result/context projection differs".into());
    }
    let rows = result["results"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("one actual SDK Bash result required")?;
    let error = output["is_error"]
        .as_bool()
        .ok_or("Root capture error flag missing")?;
    if output["schema"] != "controller-contained-output.v1"
        || rows[0]["toolCallId"] != "sdk-contained-control"
        || rows[0]["toolName"] != "bash"
        || rows[0]["isError"] != error
        || rows[0]["content"] != output["tool_response"]
    {
        return Err("SDK did not receive the exact Native-reviewed captured output".into());
    }
    if error {
        return Err(
            "SDK preserved exact captured output, but the benign Native fixture failed".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture(error: bool) -> (Value, Value) {
        let output = json!({"schema":"controller-contained-output.v1","is_error":error,
            "tool_response":[{"type":"text","text":"captured binary-safe representation"}]});
        let sdk = json!({"exit_code":0,"result":{"schema":"private-cell-sdk-conformance-result.v1",
            "version":"18.4.12","uid":10001,"syntheticStreamCalls":2,"mcpExercised":false,
            "modelExercised":false,"providerRequests":0,"qualificationEligible":false,
            "modelContextProjection":{"originalCommandVisible":true,"executionTransportRetained":true},
            "results":[{"toolCallId":"sdk-contained-control","toolName":"bash","isError":error,
                "content":output["tool_response"]}]}});
        (sdk, output)
    }
    #[test]
    fn exact_failure_delivery_remains_a_failed_benign_control() {
        let (sdk, output) = fixture(true);
        assert_eq!(
            verify(&sdk, &output).unwrap_err(),
            "SDK preserved exact captured output, but the benign Native fixture failed"
        );
        let (sdk, output) = fixture(false);
        verify(&sdk, &output).unwrap();
    }
    #[test]
    fn changed_output_or_error_cannot_claim_exact_delivery() {
        for error in [false, true] {
            let (sdk, output) = fixture(error);
            let mut changed = sdk.clone();
            changed["result"]["results"][0]["content"][0]["text"] = json!("substituted");
            assert_eq!(
                verify(&changed, &output).unwrap_err(),
                "SDK did not receive the exact Native-reviewed captured output"
            );
            let mut changed = sdk;
            changed["result"]["results"][0]["isError"] = json!(!error);
            assert!(verify(&changed, &output)
                .unwrap_err()
                .contains("did not receive"));
        }
    }
    #[test]
    fn synthetic_result_cannot_claim_model_or_qualification() {
        for field in ["modelExercised", "qualificationEligible", "mcpExercised"] {
            let (mut sdk, output) = fixture(false);
            sdk["result"][field] = json!(true);
            assert!(verify(&sdk, &output).is_err());
        }
    }
}
