//! Verify actual SDK capture delivery separately from the benign test outcome.
use serde_json::Value;

pub(crate) fn verify(sdk: &Value, output: &Value) -> Result<(), String> {
    verify_profile(sdk, output, None, false, false)
}
pub(crate) fn verify_mcp(sdk: &Value, output: &Value, read: &Value) -> Result<(), String> {
    verify_profile(sdk, output, Some(read), false, false)
}
pub(crate) fn verify_mcp_injection(
    sdk: &Value,
    output: &Value,
    read: &Value,
) -> Result<(), String> {
    verify_profile(sdk, output, Some(read), true, false)
}
pub(crate) fn verify_mcp_timeout(sdk: &Value, output: &Value, read: &Value) -> Result<(), String> {
    verify_profile(sdk, output, Some(read), false, true)
}
fn verify_profile(
    sdk: &Value,
    output: &Value,
    read: Option<&Value>,
    allow_withheld: bool,
    expected_bash_error: bool,
) -> Result<(), String> {
    let result = &sdk["result"];
    if sdk["exit_code"] != 0
        || result["schema"] != "private-cell-sdk-conformance-result.v1"
        || result["version"] != "18.4.12"
        || result["uid"] != 10001
        || result["syntheticStreamCalls"] != if read.is_some() { 3 } else { 2 }
        || result["mcpExercised"] != read.is_some()
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
        .filter(|a| a.len() == if read.is_some() { 2 } else { 1 })
        .ok_or("exact actual SDK control result count required")?;
    if let Some(read) = read {
        verify_read(result, &rows[0], read, allow_withheld)?;
    }
    let row = rows.last().ok_or("actual SDK Bash result absent")?;
    let error = output["is_error"]
        .as_bool()
        .ok_or("Root capture error flag missing")?;
    if output["schema"] != "controller-contained-output.v1"
        || row["toolCallId"] != "sdk-contained-control"
        || row["toolName"] != "bash"
        || row["isError"] != error
        || row["content"] != output["tool_response"]
    {
        return Err("SDK did not receive the exact Native-reviewed captured output".into());
    }
    if error != expected_bash_error {
        return Err(
            "SDK preserved exact captured output, but the benign Native fixture failed".into(),
        );
    }
    Ok(())
}
fn verify_read(
    result: &Value,
    row: &Value,
    read: &Value,
    allow_withheld: bool,
) -> Result<(), String> {
    let tools = result["resourceTools"]
        .as_array()
        .ok_or("actual SDK MCP inventory absent")?;
    let matches = tools
        .iter()
        .filter(|t| t["server"] == "docs" && t["rawTool"] == "docs.read")
        .collect::<Vec<_>>();
    let is_error = if allow_withheld {
        read["result"]["isError"]
            .as_bool()
            .ok_or("typed Native MCP read disposition required")?
    } else {
        false
    };
    if matches.len() != 1
        || row["toolName"] != matches[0]["name"]
        || row["toolCallId"] != "sdk-mcp-control"
        || row["isError"] != is_error
        || row["content"] != read["result"]["content"]
        || !read["result"]["content"].is_array()
        || (!allow_withheld && read["result"]["isError"] == true)
        || read.get("error").is_some()
    {
        return Err("SDK did not receive the exact delegated Native MCP read result".into());
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
    #[test]
    fn composed_result_requires_exact_native_read_and_actual_tool_mapping() {
        let (mut sdk, output) = fixture(false);
        let read = json!({"jsonrpc":"2.0","id":"sdk-read","result":{"content":[{"type":"text","text":"physical record"}],"isError":false}});
        let result = &mut sdk["result"];
        result["syntheticStreamCalls"] = json!(3);
        result["mcpExercised"] = json!(true);
        result["resourceTools"] =
            json!([{"name":"actual_docs_read","server":"docs","rawTool":"docs.read"}]);
        result["results"].as_array_mut().unwrap().insert(
            0,
            json!({"toolCallId":"sdk-mcp-control","toolName":"actual_docs_read",
            "isError":false,"content":read["result"]["content"]}),
        );
        verify_mcp(&sdk, &output, &read).unwrap();
        assert!(verify(&sdk, &output).is_err());
        for (pointer, bad) in [
            ("/result/results/0/content/0/text", json!("substitution")),
            ("/result/resourceTools/0/server", json!("mail")),
            ("/result/results/0/isError", json!(true)),
            ("/result/mcpExercised", json!(false)),
        ] {
            let mut changed = sdk.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(verify_mcp(&changed, &output, &read).is_err(), "{pointer}");
        }
    }
    #[test]
    fn withheld_read_cannot_borrow_a_clean_result_or_changed_native_error() {
        let (mut sdk, output) = fixture(false);
        let read = json!({"jsonrpc":"2.0","id":"sdk-read","result":{"content":[{"type":"text","text":"Native withheld this result"}],"isError":true}});
        sdk["result"]["syntheticStreamCalls"] = json!(3);
        sdk["result"]["mcpExercised"] = json!(true);
        sdk["result"]["resourceTools"] =
            json!([{"name":"actual_docs_read","server":"docs","rawTool":"docs.read"}]);
        sdk["result"]["results"].as_array_mut().unwrap().insert(0,json!({"toolCallId":"sdk-mcp-control","toolName":"actual_docs_read","isError":true,"content":read["result"]["content"]}));
        verify_mcp_injection(&sdk, &output, &read).unwrap();
        assert!(verify_mcp(&sdk, &output, &read).is_err());
        for (pointer, bad) in [
            ("/result/results/0/isError", json!(false)),
            ("/result/results/0/content/0/text", json!("substituted")),
        ] {
            let mut changed = sdk.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(verify_mcp_injection(&changed, &output, &read).is_err());
        }
    }
    #[test]
    fn a_controlled_timeout_preserves_the_error_and_cannot_pass_the_benign_profile() {
        let (mut sdk, output) = fixture(true);
        let read = json!({"jsonrpc":"2.0","id":"sdk-read","result":{"content":[{"type":"text","text":"physical record"}],"isError":false}});
        sdk["result"]["syntheticStreamCalls"] = json!(3);
        sdk["result"]["mcpExercised"] = json!(true);
        sdk["result"]["resourceTools"] =
            json!([{"name":"actual_docs_read","server":"docs","rawTool":"docs.read"}]);
        sdk["result"]["results"].as_array_mut().unwrap().insert(0,json!({"toolCallId":"sdk-mcp-control","toolName":"actual_docs_read","isError":false,"content":read["result"]["content"]}));
        verify_mcp_timeout(&sdk, &output, &read).unwrap();
        assert!(verify_mcp(&sdk, &output, &read).is_err());
        sdk["result"]["results"][1]["isError"] = json!(false);
        assert!(verify_mcp_timeout(&sdk, &output, &read).is_err());
    }
}
