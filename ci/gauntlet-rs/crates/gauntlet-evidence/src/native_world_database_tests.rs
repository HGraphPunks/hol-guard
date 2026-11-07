use super::*;
use rusqlite::params;

fn expectations() -> (Value, BTreeMap<String, Value>, Vec<Value>) {
    let meta = json!({"schema":"gauntlet-workflow-snapshot.v1","actor_id":"fixture-actor",
        "provider_scope":{"tenants":["task-tenant"]},"producer":"outside-test-key"});
    let record = json!({"id":"developer-spec","version":1,"data":{"body":"fixed synthetic input"}});
    let receipt =
        json!({"event":{"sequence":1,"after":record},"signature":"separate signature proof"});
    (
        meta,
        BTreeMap::from([("developer-spec".into(), record)]),
        vec![receipt],
    )
}
fn fixture(change: impl FnOnce(&Connection)) -> Vec<u8> {
    let (meta, records, receipts) = expectations();
    let connection = Connection::open_in_memory().unwrap();
    for (_, sql) in TABLES {
        connection.execute_batch(sql).unwrap();
    }
    connection
        .execute("INSERT INTO meta VALUES(1,?1)", [meta.to_string()])
        .unwrap();
    for (id, value) in records {
        connection
            .execute(
                "INSERT INTO records VALUES(?1,?2)",
                params![id, value.to_string()],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO journal VALUES(1,?1)",
            [receipts[0].to_string()],
        )
        .unwrap();
    change(&connection);
    connection.serialize(MAIN_DB).unwrap().to_vec()
}
fn accepts(raw: &[u8]) -> bool {
    let (meta, records, receipts) = expectations();
    verify_native_world_database(raw, &meta, &records, &receipts).is_ok()
}

#[test]
fn bounded_read_only_database_matches_physical_rows_without_changing_input() {
    let bytes = fixture(|_| {});
    let before = bytes.clone();
    assert!(accepts(&bytes));
    assert_eq!(before, bytes);
    let (meta, records, receipts) = expectations();
    let observed = verify_native_world_database(&bytes, &meta, &records, &receipts).unwrap();
    assert_eq!(observed["physical_records_checked"], 1);
    assert_eq!(observed["journal_receipts_checked"], 1);
    assert_eq!(observed["execution_eligible"], false);
}

#[test]
fn changed_record_meta_journal_and_active_cache_refuse() {
    for sql in [
        "UPDATE records SET value='{}'",
        "UPDATE meta SET value='{}'",
        "UPDATE journal SET value='{}'",
        "UPDATE journal SET sequence=2",
        "INSERT INTO cached VALUES('replay','digest','{}')",
        "INSERT INTO meta VALUES(2,'{}')",
        "DELETE FROM records",
    ] {
        assert!(
            !accepts(&fixture(|connection| {
                connection.execute_batch(sql).unwrap();
            })),
            "{sql}"
        );
    }
}

#[test]
fn unknown_schema_views_triggers_and_changed_declarations_refuse() {
    for sql in [
        "CREATE TABLE extra(value TEXT)",
        "CREATE VIEW extra AS SELECT value FROM records",
        "CREATE TRIGGER extra AFTER INSERT ON records BEGIN SELECT 1; END",
        "ALTER TABLE records ADD COLUMN forged TEXT",
    ] {
        assert!(
            !accepts(&fixture(|connection| {
                connection.execute_batch(sql).unwrap();
            })),
            "{sql}"
        );
    }
}

#[test]
fn wrong_header_page_count_wal_and_truncation_refuse() {
    let bytes = fixture(|_| {});
    for (index, changed) in [(0, 0), (16, 3), (18, 2), (19, 2), (20, 1), (28, 127)] {
        let mut hostile = bytes.clone();
        hostile[index] = changed;
        assert!(!accepts(&hostile), "header byte {index}");
    }
    assert!(!accepts(&bytes[..bytes.len() - 1]));
    assert!(!accepts(&bytes[..100]));
}
