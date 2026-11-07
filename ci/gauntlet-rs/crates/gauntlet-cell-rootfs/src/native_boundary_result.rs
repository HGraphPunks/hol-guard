//! Validate unprivileged measurements without treating them as authenticated
//! kernel evidence. Outside canary custody and process checks are separate.
use crate::Result;
use serde_json::Value;

pub(crate) fn verify(value: &Value, paths: &[String]) -> Result<()> {
    let rows = value["rows"]
        .as_array()
        .filter(|r| r.len() == 8)
        .ok_or("eight actual boundary measurements required")?;
    if paths.len() != 3
        || value["schema"] != "hol-gauntlet-native-boundary-negatives.v1"
        || value["kernel_claims_authenticated"] != false
    {
        return Err("versioned unprivileged boundary report required".into());
    }
    for (index, row) in rows.iter().enumerate() {
        let valid = if index < 6 {
            row["surface"] == "path"
                && row["path"] == paths[index / 2]
                && row["operation"] == if index % 2 == 0 { "read" } else { "write" }
                && row["errno"]
                    .as_i64()
                    .is_some_and(|e| matches!(e, 1 | 2 | 13 | 30))
        } else {
            row["surface"] == "network"
                && row["family"] == if index == 6 { 2 } else { 10 }
                && row["errno"]
                    .as_i64()
                    .is_some_and(|e| matches!(e, 1 | 13 | 101 | 97))
        };
        if !valid || row["denied"] != true {
            return Err("boundary probe did not observe the exact refusal".into());
        }
    }
    let kernel = &value["kernel"];
    if kernel["Uid"] != "10004\t10004\t10004\t10004"
        || kernel["Gid"] != "10004\t10004\t10004\t10004"
        || kernel["CapEff"] != "0000000000000000"
        || kernel["NoNewPrivs"] != "1"
        || kernel["Seccomp"] != "2"
    {
        return Err("reported contained boundary privilege differs".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn unavailable_network_and_false_typed_denials_do_not_count_as_isolation() {
        let paths = ["controller", "sdk-agent", "product-guard"].map(String::from);
        let mut rows = Vec::new();
        for path in &paths {
            for operation in ["read", "write"] {
                rows.push(json!({"surface":"path","path":path,"operation":operation,"denied":true,"errno":2}));
            }
        }
        for family in [2, 10] {
            rows.push(json!({"surface":"network","family":family,"denied":true,"errno":101}));
        }
        let valid = json!({"schema":"hol-gauntlet-native-boundary-negatives.v1","rows":rows,"kernel_claims_authenticated":false,
            "kernel":{"Uid":"10004\t10004\t10004\t10004","Gid":"10004\t10004\t10004\t10004","CapEff":"0000000000000000","NoNewPrivs":"1","Seccomp":"2"}});
        verify(&valid, &paths).unwrap();
        for (pointer, bad) in [
            ("/rows/6/errno", json!(110)),
            ("/rows/7/errno", json!(2)),
            ("/rows/0/denied", json!("true")),
            ("/rows/2/path", json!("other")),
            ("/kernel/CapEff", json!("0000000000000001")),
            ("/kernel_claims_authenticated", json!(true)),
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).unwrap() = bad;
            assert!(verify(&changed, &paths).is_err(), "{pointer}");
        }
    }
}
