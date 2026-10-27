use crate::{collections, json, Error, Result};
use guard_runtime_pyjson::PyVal;
use ring::signature::Ed25519KeyPair;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) struct Record {
    pub value: Value,
    pub data: PyVal,
}
pub(crate) struct Outcome {
    pub result: Value,
    pub before: Value,
    pub after: Value,
    pub effect: &'static str,
}

pub(crate) fn tenant_allowed(meta: &Value, tenant: &Value) -> bool {
    meta["provider_scope"]["tenants"]
        .as_array()
        .is_some_and(|v| v.contains(tenant))
}
pub(crate) fn validate_record(record: &Value) -> Result<()> {
    for key in ["id", "collection", "tenant_id", "owner_id"] {
        json::text(record, key)?;
    }
    if record["version"].as_i64().is_none_or(|n| n < 1) {
        return Err(Error::invalid("invalid record version"));
    }
    for mode in ["read", "write"] {
        let values = record["acl"][mode]
            .as_array()
            .ok_or_else(|| Error::invalid("invalid record ACL"))?;
        if values.iter().any(|v| !v.is_string()) {
            return Err(Error::invalid("invalid record ACL"));
        }
    }
    Ok(())
}
pub(crate) fn validate_data(data: &Value) -> Result<()> {
    if !data.is_object() {
        return Err(Error::invalid("data must be an object"));
    }
    for field in ["recipients", "attendees"] {
        let Some(values) = data.get(field) else {
            continue;
        };
        let valid = values.as_array().is_some_and(|values| {
            values.iter().all(|v| {
                v.as_str().is_some_and(|v| {
                    (v.contains('@') && v.ends_with(".test"))
                        || (field == "attendees"
                            && !v.is_empty()
                            && v.len() <= 128
                            && v.as_bytes()[0].is_ascii_alphanumeric()
                            && v.bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c)))
                })
            })
        });
        if !valid {
            return Err(Error::invalid(
                "only synthetic .test destinations are accepted",
            ));
        }
    }
    Ok(())
}
fn decoded(raw: &str) -> Result<Record> {
    let value = json::parse(raw)?;
    validate_record(&value)?;
    let data = json::ordered(raw)?
        .get("data")
        .cloned()
        .ok_or_else(|| Error::invalid("record has no data"))?;
    validate_data(&value["data"])?;
    Ok(Record { value, data })
}
pub(crate) fn records(connection: &Connection) -> Result<Vec<Record>> {
    let mut stmt = connection.prepare("SELECT value FROM records ORDER BY id")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    rows.map(|row| decoded(&row?)).collect()
}
fn record(
    connection: &Connection,
    id: &str,
    family: &str,
    actor: &str,
    mode: &str,
) -> Result<Record> {
    let raw: Option<String> = connection
        .query_row("SELECT value FROM records WHERE id=?1", [id], |r| r.get(0))
        .optional()?;
    let row = decoded(&raw.ok_or_else(|| Error::invalid("record not found"))?)?;
    if !collections(family).contains(&json::text(&row.value, "collection")?) {
        return Err(Error::invalid("record belongs to another service"));
    }
    let acl = row.value["acl"][mode].as_array().expect("validated ACL");
    if !(acl.contains(&json!(actor)) || mode == "read" && acl.contains(&json!("*"))) {
        return Err(Error::permission("provider ACL denied"));
    }
    Ok(row)
}
pub(crate) fn projected(mut row: Value, args: &Value) -> Result<Value> {
    if args.get("fields").is_some_and(json::truthy) {
        let fields = args["fields"]
            .as_array()
            .ok_or_else(|| Error::invalid("invalid fields"))?;
        let mut selected = serde_json::Map::new();
        for key in fields {
            let key = key
                .as_str()
                .ok_or_else(|| Error::invalid("invalid fields"))?;
            if let Some(value) = row["data"].get(key) {
                selected.insert(key.to_owned(), value.clone());
            }
        }
        row["data"] = Value::Object(selected);
    }
    Ok(row)
}
fn set_data(row: &mut Record, key: &str, value: Value) -> Result<()> {
    json::set(&mut row.data, key, json::ordered(&value.to_string())?)?;
    row.value["data"] = json::value(&row.data)?;
    Ok(())
}
fn create(
    connection: &Connection,
    meta: &Value,
    actor: &str,
    family: &str,
    method: &str,
    args: &Value,
    original: &PyVal,
) -> Result<Outcome> {
    let collection = match method {
        "create_draft" => "mail.drafts",
        "post" => "chat.messages",
        _ => args["collection"].as_str().unwrap_or(""),
    };
    if !collections(family).contains(&collection) {
        return Err(Error::invalid("invalid service collection"));
    }
    let default = json!("task-tenant");
    let tenant = args.get("tenant_id").unwrap_or(&default);
    if !tenant_allowed(meta, tenant) {
        return Err(Error::permission("tenant outside provider scope"));
    }
    let mut data = original
        .get("data")
        .cloned()
        .unwrap_or_else(|| PyVal::Dict(vec![]));
    validate_data(&json::value(&data)?)?;
    for (key, value) in match collection {
        "mail.drafts" | "chat.drafts" => vec![("state", "draft"), ("visibility", "internal")],
        "docs.documents" | "tables.sheets" => vec![("visibility", "private")],
        _ => vec![],
    } {
        if data.get(key).is_none() {
            json::set(&mut data, key, PyVal::Str(value.into()))?;
        }
    }
    let id = json::text(args, "record_id")?;
    let value = json!({"id":id,"collection":collection,"tenant_id":tenant,"owner_id":actor,
        "version":1,"acl":{"read":[actor],"write":[actor]},"data":json::value(&data)?});
    connection.execute(
        "INSERT INTO records VALUES (?1,?2)",
        params![id, json::record_text(&value, &data)?],
    )?;
    Ok(Outcome {
        result: value.clone(),
        before: Value::Null,
        after: value,
        effect: "create",
    })
}
fn permissions(before: &Value, after: &mut Record, args: &Value, original: &PyVal) -> Result<()> {
    let permissions = args["permissions"]
        .as_array()
        .filter(|v| v.len() <= 256)
        .ok_or_else(|| Error::invalid("permissions must be a bounded principal list"))?;
    let owner = json::text(before, "owner_id")?;
    let mut readers = BTreeSet::from([owner.to_owned()]);
    let mut writers = readers.clone();
    let mut seen = BTreeSet::new();
    let mut normalized = vec![];
    let originals = original
        .get("permissions")
        .and_then(PyVal::as_list)
        .ok_or_else(|| Error::invalid("permissions must be a bounded principal list"))?;
    for (permission, original_item) in permissions.iter().zip(originals) {
        let item = if permission.is_string() {
            json!({"principal_id":permission,"role":"reader"})
        } else {
            permission.clone()
        };
        if item.as_object().is_none_or(|m| {
            m.len() != 2 || !m.contains_key("principal_id") || !m.contains_key("role")
        }) {
            return Err(Error::invalid("invalid permission fields"));
        }
        let principal = item["principal_id"]
            .as_str()
            .filter(|s| !s.is_empty() && *s != "*")
            .ok_or_else(|| Error::invalid("invalid or duplicate permission principal"))?;
        if !seen.insert(principal.to_owned()) {
            return Err(Error::invalid("invalid or duplicate permission principal"));
        }
        let role = item["role"]
            .as_str()
            .filter(|s| ["owner", "reader", "viewer", "writer", "editor"].contains(s))
            .ok_or_else(|| Error::invalid("unsupported permission role"))?;
        if role == "owner" && principal != owner {
            return Err(Error::invalid("document owner is immutable"));
        }
        readers.insert(principal.to_owned());
        if ["owner", "writer", "editor"].contains(&role) {
            writers.insert(principal.to_owned());
        }
        let mut ordered_item = if permission.is_string() {
            PyVal::Dict(vec![
                ("principal_id".into(), PyVal::Str(principal.into())),
                ("role".into(), PyVal::Str(role.into())),
            ])
        } else {
            original_item.clone()
        };
        if principal == owner {
            json::set(&mut ordered_item, "role", PyVal::Str("owner".into()))?;
        }
        normalized.push(ordered_item);
    }
    if !seen.contains(owner) {
        normalized.push(PyVal::Dict(vec![
            ("principal_id".into(), PyVal::Str(owner.into())),
            ("role".into(), PyVal::Str("owner".into())),
        ]));
    }
    let visibility = match args.get("visibility") {
        None => "private",
        Some(value) => value
            .as_str()
            .ok_or_else(|| Error::invalid("unsupported document visibility"))?,
    };
    if !["private", "internal", "public", "link"].contains(&visibility) {
        return Err(Error::invalid("unsupported document visibility"));
    }
    if ["public", "link"].contains(&visibility) {
        readers.insert("*".into());
    }
    after.value["acl"] = json!({"read":readers,"write":writers});
    json::set(&mut after.data, "permissions", PyVal::List(normalized))?;
    set_data(after, "visibility", json!(visibility))
}

// The direct Python World compares numerically (including bool and 1.0);
// the separate MCP schema rejects those mistyped integer inputs before World.
fn version_matches(value: &Value, version: i64) -> bool {
    match value {
        Value::Bool(v) => i64::from(*v) == version,
        Value::Number(v) => v.as_i64().map(|n| n == version).unwrap_or_else(|| {
            v.is_f64()
                && v.as_f64().is_some_and(|n| {
                    n.is_finite() && n.fract() == 0.0 && n as i128 == i128::from(version)
                })
        }),
        _ => false,
    }
}

pub(crate) fn perform(
    connection: &Connection,
    meta: &Value,
    actor: &str,
    key: &Ed25519KeyPair,
    operation: (&str, &str),
    args: &Value,
    original: &PyVal,
) -> Result<Outcome> {
    let (family, method) = operation;
    if method == "search" {
        return crate::search::search(connection, actor, key, family, args);
    }
    if ["create", "create_draft", "post"].contains(&method) {
        return create(connection, meta, actor, family, method, args, original);
    }
    let mut after = record(
        connection,
        json::text(args, "record_id")?,
        family,
        actor,
        if ["read", "read_attachment"].contains(&method) {
            "read"
        } else {
            "write"
        },
    )?;
    let before = after.value.clone();
    if ["read", "read_attachment"].contains(&method) {
        let (result, observed) = if method == "read_attachment" {
            let id = json::text(args, "attachment_id")?;
            let attachment = before["data"]["attachments"]
                .as_array()
                .and_then(|items| items.iter().find(|a| a["id"] == id))
                .cloned()
                .ok_or_else(|| Error::invalid("attachment not found"))?;
            let observed = json!({"id":before["id"],"collection":before["collection"],"version":before["version"],"parent_record":before,"attachment":attachment});
            (attachment, observed)
        } else {
            let projected = projected(before.clone(), args)?;
            (projected.clone(), projected)
        };
        return Ok(Outcome {
            result,
            before: Value::Null,
            after: observed,
            effect: "read",
        });
    }
    let version = before["version"].as_i64().expect("validated version");
    if !version_matches(&args["expected_version"], version) {
        return Err(Error::invalid("stale or missing expected version"));
    }
    if method == "delete" {
        connection.execute(
            "DELETE FROM records WHERE id=?1",
            [json::text(&before, "id")?],
        )?;
        return Ok(Outcome {
            result: json!({"deleted":before["id"]}),
            before,
            after: Value::Null,
            effect: "delete",
        });
    }
    match (family, method) {
        ("mail", "send") => {
            if before["collection"] != "mail.drafts" {
                return Err(Error::invalid("send requires a persisted draft"));
            }
            if !json::truthy(&before["data"]["recipients"]) {
                return Err(Error::invalid("send requires recipients"));
            }
            after.value["collection"] = json!("mail.outbox");
            set_data(&mut after, "state", json!("sent"))?;
        }
        ("calendar", "invite") => set_data(&mut after, "state", json!("invited"))?,
        ("docs", "set_permissions") => permissions(&before, &mut after, args, original)?,
        (_, "update") => {
            validate_data(&args["data"])?;
            let update = original
                .get("data")
                .and_then(PyVal::as_dict)
                .ok_or_else(|| Error::invalid("data must be an object"))?;
            for (key, value) in update {
                json::set(&mut after.data, key, value.clone())?;
            }
            after.value["data"] = json::value(&after.data)?;
        }
        _ => return Err(Error::invalid("unsupported operation")),
    }
    validate_data(&after.value["data"])?;
    after.value["version"] = json!(version
        .checked_add(1)
        .ok_or_else(|| Error::invalid("record version overflow"))?);
    connection.execute(
        "UPDATE records SET value=?1 WHERE id=?2",
        params![
            json::record_text(&after.value, &after.data)?,
            json::text(&after.value, "id")?
        ],
    )?;
    Ok(Outcome {
        result: after.value.clone(),
        before,
        after: after.value,
        effect: "update",
    })
}
