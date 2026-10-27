//! Root-side synthetic provider state. No network, executable selection, or
//! admission authority. Callers own the connection's filesystem custody; the
//! signing key is supplied in memory and is never stored in the database.
mod json;
mod operations;
mod search;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use guard_runtime_pyjson::PyVal;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fmt, time::Duration};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Permission(String),
    Storage(rusqlite::Error),
}
impl Error {
    pub(crate) fn invalid(text: &str) -> Self {
        Self::Invalid(text.into())
    }
    pub(crate) fn permission(text: &str) -> Self {
        Self::Permission(text.into())
    }
    pub fn category(&self) -> &'static str {
        match self {
            Self::Invalid(_) => "ValueError",
            Self::Permission(_) => "PermissionError",
            Self::Storage(_) => "DatabaseError",
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(v) | Self::Permission(v) => f.write_str(v),
            Self::Storage(v) => v.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}

pub fn collections(family: &str) -> &'static [&'static str] {
    match family {
        "mail" => &["mail.messages", "mail.drafts", "mail.outbox"],
        "crm" => &["crm.contacts", "crm.accounts"],
        "calendar" => &["calendar.events", "calendar.availability"],
        "docs" => &["docs.documents"],
        "tables" => &["tables.sheets"],
        "chat" => &["chat.messages", "chat.drafts"],
        "tickets" => &["tickets.tickets"],
        _ => &[],
    }
}

struct Authority {
    meta: Value,
    actor: String,
    key: Ed25519KeyPair,
}
pub struct World {
    connection: Connection,
    authority: Authority,
}

fn configure(connection: &Connection) -> Result<()> {
    if !connection.is_autocommit() {
        return Err(Error::invalid("world connection already has a transaction"));
    }
    connection.busy_timeout(Duration::from_secs(10))?;
    connection.execute_batch(
        "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF;",
    )?;
    Ok(())
}

impl World {
    /// The caller creates a fresh private database exclusively. Initialization
    /// refuses any existing schema instead of replacing or clearing it.
    pub fn initialize(
        mut connection: Connection,
        snapshot_json: &str,
        key: Ed25519KeyPair,
    ) -> Result<Self> {
        let mut meta = json::parse(snapshot_json)?;
        let ordered = json::ordered(snapshot_json)?;
        if meta["schema"] != "gauntlet-workflow-snapshot.v1" {
            return Err(Error::invalid("unsupported seed snapshot"));
        }
        let records = meta
            .as_object_mut()
            .ok_or_else(|| Error::invalid("invalid seed snapshot"))?
            .remove("records")
            .and_then(|v| v.as_array().cloned())
            .ok_or_else(|| Error::invalid("invalid seed records"))?;
        let ordered_records = ordered
            .get("records")
            .and_then(PyVal::as_list)
            .ok_or_else(|| Error::invalid("invalid seed records"))?;
        let mut ids = BTreeSet::new();
        for record in &records {
            let collection = json::text(record, "collection")?;
            if !collections(collection.split('.').next().unwrap_or("")).contains(&collection) {
                return Err(Error::invalid("unknown seed collection"));
            }
            if !operations::tenant_allowed(&meta, &record["tenant_id"]) {
                return Err(Error::invalid("seed outside provider scope"));
            }
            if !ids.insert(json::text(record, "id")?) {
                return Err(Error::invalid("duplicate seed record"));
            }
            operations::validate_record(record)?;
            operations::validate_data(&record["data"])?;
        }
        meta["producer"] = Value::String(B64.encode(key.public_key().as_ref()));
        configure(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if existing != 0 {
            return Err(Error::invalid("world database already initialized"));
        }
        tx.execute_batch(
            "CREATE TABLE meta(id INTEGER PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE journal(sequence INTEGER PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE cached(id TEXT PRIMARY KEY,digest TEXT NOT NULL,result TEXT NOT NULL);",
        )?;
        tx.execute("INSERT INTO meta VALUES (1,?1)", [meta.to_string()])?;
        for (record, original) in records.iter().zip(ordered_records) {
            let data = original
                .get("data")
                .ok_or_else(|| Error::invalid("invalid seed data"))?;
            tx.execute(
                "INSERT INTO records VALUES (?1,?2)",
                params![json::text(record, "id")?, json::record_text(record, data)?],
            )?;
        }
        tx.commit()?;
        Self::open(connection, key)
    }

    /// Open a caller-custodied Python-compatible database under the same key.
    pub fn open(mut connection: Connection, key: Ed25519KeyPair) -> Result<Self> {
        configure(&connection)?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let raw: String = tx.query_row("SELECT value FROM meta WHERE id=1", [], |r| r.get(0))?;
        let meta = json::parse(&raw)?;
        if meta["producer"] != B64.encode(key.public_key().as_ref()) {
            return Err(Error::invalid("controller signing identity mismatch"));
        }
        let actor = json::text(&meta, "actor_id")?.to_owned();
        tx.commit()?;
        Ok(Self {
            connection,
            authority: Authority { meta, actor, key },
        })
    }

    pub fn public_key(&self) -> String {
        B64.encode(self.authority.key.public_key().as_ref())
    }
    pub fn inspect(&mut self, id: &str) -> Result<Option<Value>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = tx
            .query_row("SELECT value FROM records WHERE id=?1", [id], |r| {
                r.get::<_, String>(0)
            })
            .optional()?
            .map(|s| json::parse(&s))
            .transpose()?;
        tx.commit()?;
        Ok(value)
    }
    pub fn snapshot(&mut self) -> Result<Value> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let records = operations::records(&tx)?;
        tx.commit()?;
        let mut value = self.authority.meta.clone();
        value
            .as_object_mut()
            .expect("validated meta")
            .remove("producer");
        value["records"] = Value::Array(records.into_iter().map(|r| r.value).collect());
        Ok(value)
    }
    pub fn receipts(&mut self) -> Result<Vec<Value>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let values = {
            let mut stmt = tx.prepare("SELECT value FROM journal ORDER BY sequence")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.map(|r| json::parse(&r?)).collect::<Result<Vec<_>>>()?
        };
        tx.commit()?;
        Ok(values)
    }
    /// Preserve original arguments, including omitted defaults and insertion
    /// order, while digesting the strict canonical form. Commit state, receipt
    /// and idempotency result together; every error rolls the transaction back.
    pub fn call(
        &mut self,
        operation: &str,
        arguments_json: &str,
        request_id: Value,
    ) -> Result<Value> {
        let args = json::parse(arguments_json)?;
        let ordered = json::ordered(arguments_json)?;
        if !args.is_object()
            || json::canonical(&args)?.len() > 4_000_000
            || String::from_utf8(json::canonical(&args)?)
                .map_err(|_| Error::invalid("invalid arguments"))?
                .chars()
                .count()
                > 1_000_000
        {
            return Err(Error::invalid("invalid or oversized arguments"));
        }
        if !(request_id.is_string()
            || request_id
                .as_number()
                .is_some_and(|n| !n.to_string().contains(['.', 'e', 'E'])))
        {
            return Err(Error::invalid("invalid request id"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = self
            .authority
            .execute(&tx, operation, args, ordered, request_id)?;
        tx.commit()?;
        Ok(result)
    }
}

/// Verify signed state receipts against separately supplied custody anchors.
/// Valid signatures alone never establish Guard causality or admission.
pub fn verify_receipts(
    receipts: &[Value],
    public_key: &[u8],
    expected_count: usize,
    expected_final_hash: &str,
) -> Result<()> {
    if public_key.len() != 32 {
        return Err(Error::invalid("invalid controller public key"));
    }
    if receipts.len() != expected_count {
        return Err(Error::invalid("receipt count mismatch"));
    }
    let key = UnparsedPublicKey::new(&ED25519, public_key);
    let mut previous = "0".repeat(64);
    for (index, receipt) in receipts.iter().enumerate() {
        let event = &receipt["event"];
        if event["sequence"] != json!(index + 1) || event["previous_hash"] != previous {
            return Err(Error::invalid("receipt chain mismatch"));
        }
        let signature = B64
            .decode(
                receipt["signature"]
                    .as_str()
                    .ok_or_else(|| Error::invalid("invalid receipt signature"))?,
            )
            .map_err(|_| Error::invalid("invalid receipt signature"))?;
        key.verify(&json::canonical(event)?, &signature)
            .map_err(|_| Error::invalid("invalid receipt signature"))?;
        previous = json::digest(receipt)?;
    }
    if previous != expected_final_hash {
        return Err(Error::invalid("receipt anchor mismatch"));
    }
    Ok(())
}

impl Authority {
    fn execute(
        &self,
        connection: &Connection,
        operation: &str,
        mut args: Value,
        ordered: PyVal,
        request_id: Value,
    ) -> Result<Value> {
        let (family, method) = operation.split_once('.').unwrap_or((operation, ""));
        if collections(family).is_empty() {
            return Err(Error::invalid("unknown service"));
        }
        let raw_args_digest = json::digest(&args)?;
        let cache = args
            .as_object_mut()
            .expect("checked args")
            .remove("idempotency_key")
            .unwrap_or(Value::Null);
        let identity =
            json::digest(&json!({"operation":operation,"args":args,"actor":self.actor}))?;
        let cache_id = if json::truthy(&cache) {
            Some(
                cache
                    .as_str()
                    .ok_or_else(|| Error::invalid("invalid idempotency key"))?,
            )
        } else {
            None
        };
        if let Some(id) = cache_id {
            let row: Option<(String, String)> = connection
                .query_row("SELECT digest,result FROM cached WHERE id=?1", [id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()?;
            if let Some((digest, result)) = row {
                if digest != identity {
                    return Err(Error::invalid(
                        "idempotency key reused for a different operation",
                    ));
                }
                return json::parse(&result);
            }
        }
        let outcome = operations::perform(
            connection,
            &self.meta,
            &self.actor,
            &self.key,
            (family, method),
            &args,
            &ordered,
        )?;
        let last: Option<(i64, String)> = connection
            .query_row(
                "SELECT sequence,value FROM journal ORDER BY sequence DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (sequence, previous) = match last {
            Some((n, s)) => (
                n.checked_add(1)
                    .ok_or_else(|| Error::invalid("receipt sequence overflow"))?,
                json::digest(&json::parse(&s)?)?,
            ),
            None => (1, "0".repeat(64)),
        };
        let event = json!({"sequence":sequence,"previous_hash":previous,"request_id":request_id,"operation":operation,
            "actor":self.actor,"args_digest":identity,"raw_args_digest":raw_args_digest,
            "before":outcome.before,"after":outcome.after,"effect":outcome.effect,"status":"ok","result_digest":json::digest(&outcome.result)?});
        let signature = B64.encode(self.key.sign(&json::canonical(&event)?).as_ref());
        connection.execute(
            "INSERT INTO journal VALUES (?1,?2)",
            params![
                sequence,
                json!({"event":event,"signature":signature}).to_string()
            ],
        )?;
        if let Some(id) = cache_id {
            connection.execute(
                "INSERT INTO cached VALUES (?1,?2,?3)",
                params![id, identity, outcome.result.to_string()],
            )?;
        }
        Ok(outcome.result)
    }
}
