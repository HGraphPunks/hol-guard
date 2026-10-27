use crate::{
    collections, json,
    operations::{self, Outcome},
    Error, Result,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use rusqlite::Connection;
use serde_json::Value;

pub(crate) fn search(
    connection: &Connection,
    actor: &str,
    key: &Ed25519KeyPair,
    family: &str,
    args: &Value,
) -> Result<Outcome> {
    let collection = json::text(args, "collection")?;
    if !collections(family).contains(&collection) {
        return Err(Error::invalid("invalid service collection"));
    }
    let limit = if args.get("limit").is_none() {
        20
    } else {
        args["limit"]
            .as_u64()
            .filter(|n| (1..=100).contains(n))
            .ok_or_else(|| Error::invalid("limit must be between 1 and 100"))?
    };
    let query = caseless::default_case_fold_str(
        args.get("query")
            .unwrap_or(&json!(""))
            .as_str()
            .ok_or_else(|| Error::invalid("query must be a string"))?,
    );
    let mut selected = vec![];
    for row in operations::records(connection)? {
        let value = row.value;
        let acl = value["acl"]["read"].as_array().expect("validated ACL");
        if value["collection"] == collection
            && (acl.contains(&json!(actor)) || acl.contains(&json!("*")))
            && (!json::truthy(&args["tenant_id"]) || value["tenant_id"] == args["tenant_id"])
            && caseless::default_case_fold_str(&json::python_text(&row.data)).contains(&query)
        {
            selected.push(value);
        }
    }
    let fingerprint = json::digest(
        &json!({"query":query,"collection":collection,"tenant":args["tenant_id"],"records":selected}),
    )?;
    let offset = if args.get("cursor").is_some_and(json::truthy) {
        offset(key, &args["cursor"], &fingerprint, selected.len())?
    } else {
        0
    };
    let filtered = selected.len();
    let mut page = selected
        .into_iter()
        .skip(offset)
        .take(limit as usize)
        .map(|row| operations::projected(row, args))
        .collect::<Result<Vec<_>>>()?;
    let next_offset = offset + page.len();
    let cursor = if next_offset < filtered {
        let cursor = json!({"offset":next_offset,"fingerprint":fingerprint});
        let signature = B64.encode(key.sign(&json::canonical(&cursor)?).as_ref());
        Value::String(B64.encode(json::canonical(
            &json!({"cursor":cursor,"signature":signature}),
        )?))
    } else {
        Value::Null
    };
    let ids: Vec<Value> = page.iter().map(|row| row["id"].clone()).collect();
    Ok(Outcome {
        result: json!({"records":std::mem::take(&mut page),"next_cursor":cursor}),
        before: Value::Null,
        after: json!({"record_ids":ids}),
        effect: "search",
    })
}

fn offset(key: &Ed25519KeyPair, raw: &Value, fingerprint: &str, count: usize) -> Result<usize> {
    let invalid = || Error::invalid("invalid or stale cursor");
    let raw = raw.as_str().ok_or_else(invalid)?;
    if raw.len() > 16384 {
        return Err(invalid());
    }
    let decoded = B64.decode(raw).map_err(|_| invalid())?;
    let text = std::str::from_utf8(&decoded).map_err(|_| invalid())?;
    let envelope = json::parse(text).map_err(|_| invalid())?;
    let cursor = envelope
        .get("cursor")
        .filter(|v| v.is_object())
        .ok_or_else(invalid)?;
    let signature = B64
        .decode(envelope["signature"].as_str().ok_or_else(invalid)?)
        .map_err(|_| invalid())?;
    UnparsedPublicKey::new(&ED25519, key.public_key().as_ref())
        .verify(&json::canonical(cursor)?, &signature)
        .map_err(|_| Error::invalid("invalid cursor signature"))?;
    let offset = cursor["offset"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(invalid)?;
    if cursor["fingerprint"] != fingerprint || offset >= count {
        return Err(invalid());
    }
    Ok(offset)
}
