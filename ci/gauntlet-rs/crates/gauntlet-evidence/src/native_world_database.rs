//! Reconcile bounded public provider bytes in a read-only memory database.
//! No archive member becomes a path; expectations have separate custody.
use crate::native_diagnostic_artifacts::{parse, require};
use crate::{EvidenceError, Result};
use rusqlite::{Connection, MAIN_DB};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const INVALID: EvidenceError = EvidenceError::Invalid("Native physical provider database differs");
const TABLES: [(&str, &str); 4] = [
    (
        "meta",
        "CREATE TABLE meta(id INTEGER PRIMARY KEY,value TEXT NOT NULL)",
    ),
    (
        "records",
        "CREATE TABLE records(id TEXT PRIMARY KEY,value TEXT NOT NULL)",
    ),
    (
        "journal",
        "CREATE TABLE journal(sequence INTEGER PRIMARY KEY,value TEXT NOT NULL)",
    ),
    (
        "cached",
        "CREATE TABLE cached(id TEXT PRIMARY KEY,digest TEXT NOT NULL,result TEXT NOT NULL)",
    ),
];

fn database(raw: &[u8]) -> Result<Connection> {
    require(
        raw.len() >= 512
            && raw.len() <= 32 * 1024 * 1024
            && raw.starts_with(b"SQLite format 3\0")
            && raw[18..21] == [1, 1, 0],
    )?;
    let encoded = u16::from_be_bytes(raw[16..18].try_into().map_err(|_| INVALID)?);
    let page_size = if encoded == 1 {
        65_536
    } else {
        encoded as usize
    };
    let pages = u32::from_be_bytes(raw[28..32].try_into().map_err(|_| INVALID)?) as usize;
    require(
        (512..=65_536).contains(&page_size)
            && page_size.is_power_of_two()
            && pages > 0
            && pages.checked_mul(page_size) == Some(raw.len()),
    )?;
    let mut connection = Connection::open_in_memory().map_err(|_| INVALID)?;
    connection
        .deserialize_read_exact(MAIN_DB, raw, raw.len(), true)
        .map_err(|_| INVALID)?;
    let mut progress = 0_u32;
    connection
        .progress_handler(
            1000,
            Some(move || {
                progress += 1;
                progress > 10_000
            }),
        )
        .map_err(|_| INVALID)?;
    connection
        .execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;")
        .map_err(|_| INVALID)?;
    let mut statement = connection
        .prepare("SELECT type,name,sql FROM sqlite_schema ORDER BY name")
        .map_err(|_| INVALID)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                (row.get::<_, String>(0)?, row.get::<_, Option<String>>(2)?),
            ))
        })
        .map_err(|_| INVALID)?
        .collect::<std::result::Result<BTreeMap<_, _>, _>>()
        .map_err(|_| INVALID)?;
    let mut expected = TABLES
        .iter()
        .map(|(name, sql)| {
            (
                name.to_string(),
                ("table".to_string(), Some(sql.to_string())),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for name in ["sqlite_autoindex_records_1", "sqlite_autoindex_cached_1"] {
        expected.insert(name.into(), ("index".into(), None));
    }
    require(rows == expected)?;
    drop(statement);
    let integrity: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| INVALID)?;
    require(integrity == "ok")?;
    Ok(connection)
}

/// Check independently custodied archive bytes against supplied expectations.
/// This establishes physical content, never provenance or execution admission.
pub fn verify_native_world_database(
    raw: &[u8],
    expected_metadata: &Value,
    expected_records: &BTreeMap<String, Value>,
    expected_journal: &[Value],
) -> Result<Value> {
    require(
        !expected_records.is_empty()
            && expected_records.len() <= 10_000
            && expected_journal.len() <= 10_000,
    )?;
    let connection = database(raw)?;
    let mut statement = connection
        .prepare("SELECT id,value FROM meta LIMIT 2")
        .map_err(|_| INVALID)?;
    let metadata = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| INVALID)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| INVALID)?;
    require(metadata.len() == 1 && metadata[0].0 == 1)?;
    require(parse(metadata[0].1.as_bytes())? == *expected_metadata)?;
    let mut statement = connection
        .prepare("SELECT id,value FROM records ORDER BY id LIMIT 10001")
        .map_err(|_| INVALID)?;
    let values = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| INVALID)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| INVALID)?;
    require(values.len() == expected_records.len())?;
    for (id, text) in values {
        let record = parse(text.as_bytes())?;
        require(record["id"] == id && expected_records.get(&id) == Some(&record))?;
    }
    let mut statement = connection
        .prepare("SELECT sequence,value FROM journal ORDER BY sequence LIMIT 10001")
        .map_err(|_| INVALID)?;
    let values = statement
        .query_map([], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| INVALID)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| INVALID)?;
    require(values.len() == expected_journal.len())?;
    for ((sequence, text), (index, expected)) in
        values.iter().zip(expected_journal.iter().enumerate())
    {
        require(*sequence == index as i64 + 1 && parse(text.as_bytes())? == *expected)?;
    }
    let cached: i64 = connection
        .query_row("SELECT count(*) FROM cached", [], |row| row.get(0))
        .map_err(|_| INVALID)?;
    require(cached == 0)?;
    Ok(
        json!({"schema":"hol-gauntlet-native-world-database-relations.v1",
        "physical_records_checked":expected_records.len(),"journal_receipts_checked":expected_journal.len(),
        "cached_rows":0,"read_only_memory_database":true,"execution_eligible":false,
        "guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_world_database_tests.rs"]
mod tests;
