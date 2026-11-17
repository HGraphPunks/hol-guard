//! Strict retained records for quiescent recovery, never execution scoring.
use crate::{hash, hex, Result};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeImageHistory {
    Pending,
    Closed,
}

pub(crate) fn image_history(records: &[Value]) -> Result<NativeImageHistory> {
    if records
        .get(3)
        .is_none_or(|row| row["kind"] != "image-cell-launch-pending")
    {
        return Err("retained image launch history is incomplete".into());
    }
    match records.len() {
        4 => Ok(NativeImageHistory::Pending),
        6 => {
            let image = records[0]["data"]["image_id"]
                .as_str()
                .ok_or("retained image identity missing")?;
            closed_image(records, image)?;
            Ok(NativeImageHistory::Closed)
        }
        _ => Err("retained image history is neither pending nor closed".into()),
    }
}

pub(crate) fn events(raw: &[u8]) -> Result<Vec<Value>> {
    if raw.is_empty() || raw.len() > 64 * 1024 * 1024 || raw.last() != Some(&b'\n') {
        return Err("complete bounded recovery journal required".into());
    }
    let mut previous = "0".repeat(64);
    let mut records = Vec::new();
    for line in raw[..raw.len() - 1].split(|b| *b == b'\n') {
        if records.len() >= 10000 || line.len() > 256 * 1024 {
            return Err("recovery event bound".into());
        }
        let canonical = gauntlet_contracts::canonicalize(line).map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
        if canonical != line
            || value.as_object().is_none_or(|o| o.len() != 5)
            || value["schema"] != "hol-gauntlet-cell-event.v1"
            || value["sequence"].as_u64() != Some(records.len() as u64)
            || value["previous_sha256"] != previous
            || value["kind"].as_str().is_none()
            || value.get("data").is_none()
        {
            return Err("recovery event chain malformed or incomplete".into());
        }
        previous = hash(line);
        records.push(value);
    }
    Ok(records)
}

pub(crate) fn active(raw: &[u8], image: &str, stage: &Path) -> Result<()> {
    let canonical = gauntlet_contracts::canonicalize(raw).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_slice(&canonical).map_err(|e| e.to_string())?;
    let mut with_newline = canonical;
    with_newline.push(b'\n');
    if raw != with_newline
        || value.as_object().is_none_or(|o| o.len() != 4)
        || value["schema"] != "hol-gauntlet-cell-image-active.v1"
        || value["image_id"] != image
        || value["stage"] != stage.to_string_lossy().as_ref()
        || value["nonce"].as_str().is_none_or(|s| !hex(s, 32))
    {
        return Err("active image pointer belongs to another or ambiguous lease".into());
    }
    Ok(())
}

pub(crate) fn closed_image(records: &[Value], image: &str) -> Result<()> {
    if records.len() != 6
        || records[4]["kind"] != "image-releasing"
        || records[4]["data"] != serde_json::json!({"image_id":image})
        || records[5]["kind"] != "image-cleanup"
        || records[5]["data"]
            != serde_json::json!({"image_id":image,"owned_mount_absent":true,"borrowed_mount_untouched":false})
    {
        return Err("closed SDK image history is not an owned completed release".into());
    }
    Ok(())
}

pub(crate) fn closed_supervisor(records: &[Value]) -> Result<()> {
    if records.len() < 3
        || records[records.len() - 2]["kind"] != "terminal-cleanup"
        || records[records.len() - 2]["data"]
            != serde_json::json!({"cgroup_absent":true,"rootfs_mount_absent":true,"failures":[]})
        || records.last().unwrap()["kind"] != "rust-image-cleanup"
        || records.last().unwrap()["data"]
            != serde_json::json!({"image_mount_absent":true,"active_lease_removed":true})
    {
        return Err("closed SDK supervisor cleanup history is incomplete".into());
    }
    Ok(())
}

pub(crate) fn failed_supervisor(records: &[Value]) -> Result<()> {
    if records.first().is_none_or(|row| row["kind"] != "prepared") {
        return Err("failed startup lacks original prepared ownership".into());
    }
    let mut startup = 0;
    let mut recorder = 0;
    let mut pipe = 0;
    let mut cleanup = 0;
    let mut image = 0;
    for (index, row) in records.iter().enumerate() {
        match row["kind"].as_str() {
            Some("prepared") if index == 0 => {}
            Some("image-interpreter-pinned" | "private-parent-mount-namespace") if startup == 0 => {
            }
            Some("startup-failure") if startup == 0 => {
                if row["data"]
                    != serde_json::json!({"error":"product management pipe exited before ready marker"})
                {
                    return Err(
                        "failed startup did not prove the first ready marker was missing".into(),
                    );
                }
                startup += 1;
            }
            Some("cell-stderr") if startup == 1 => {}
            Some("process-events-closed") if startup == 1 && recorder == 0 && cleanup == 0 => {
                if row["data"]
                    != serde_json::json!({"available":false,"error":"required process recorder was not established","schema":"hol-gauntlet-native-process-recorder.v1"})
                {
                    return Err("failed startup process recorder was established or unknown".into());
                }
                recorder += 1;
            }
            Some("native-pipe-owner-terminal") if recorder == 1 && pipe == 0 && cleanup == 0 => {
                if row["data"]
                    != serde_json::json!({"available":false,"error":"Native pipe owner was not established","execution_eligible":false})
                {
                    return Err(
                        "failed startup Native pipe owner was established or unknown".into(),
                    );
                }
                pipe += 1;
            }
            Some("terminal-cleanup") if startup == 1 && recorder == 1 && pipe == 1 => {
                let data = &row["data"];
                if data.as_object().is_none_or(|o| o.len() != 3)
                    || data["cgroup_absent"] != true
                    || data["rootfs_mount_absent"] != true
                    || data["failures"]
                        .as_array()
                        .is_none_or(|v| v.iter().any(|s| s.as_str().is_none_or(str::is_empty)))
                {
                    return Err("failed startup cleanup observations differ".into());
                }
                cleanup += 1;
            }
            Some("rust-image-cleanup") if cleanup > 0 => {
                if row["data"]
                    != serde_json::json!({"image_mount_absent":true,"active_lease_removed":true})
                {
                    return Err("failed startup image cleanup differs".into());
                }
                image += 1;
            }
            _ => {
                return Err(
                    "failed startup history reached a gate or has unknown observations".into(),
                )
            }
        }
    }
    if startup != 1 || recorder != 1 || pipe != 1 || cleanup == 0 || image == 0 {
        return Err("failed startup history is incomplete".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_startup_preserves_errors_without_becoming_clean_history() {
        let rows = vec![
            serde_json::json!({"kind":"prepared"}),
            serde_json::json!({"kind":"image-interpreter-pinned"}),
            serde_json::json!({"kind":"private-parent-mount-namespace"}),
            serde_json::json!({"kind":"startup-failure","data":{"error":"product management pipe exited before ready marker"}}),
            serde_json::json!({"kind":"cell-stderr","data":{"data":"original diagnostic"}}),
            serde_json::json!({"kind":"process-events-closed","data":{"available":false,"error":"required process recorder was not established","schema":"hol-gauntlet-native-process-recorder.v1"}}),
            serde_json::json!({"kind":"native-pipe-owner-terminal","data":{"available":false,"error":"Native pipe owner was not established","execution_eligible":false}}),
            serde_json::json!({"kind":"terminal-cleanup","data":{"cgroup_absent":true,"rootfs_mount_absent":true,"failures":["original stop refusal","required process recorder was not established","Native pipe owner was not established"]}}),
            serde_json::json!({"kind":"rust-image-cleanup","data":{"image_mount_absent":true,"active_lease_removed":true}}),
            serde_json::json!({"kind":"terminal-cleanup","data":{"cgroup_absent":true,"rootfs_mount_absent":true,"failures":["original stop refusal","required process recorder was not established","Native pipe owner was not established"]}}),
            serde_json::json!({"kind":"rust-image-cleanup","data":{"image_mount_absent":true,"active_lease_removed":true}}),
        ];
        failed_supervisor(&rows).unwrap();
        assert!(closed_supervisor(&rows).is_err());
        for pointer in ["/data/cgroup_absent", "/data/rootfs_mount_absent"] {
            let mut changed = rows.clone();
            *changed[7].pointer_mut(pointer).unwrap() = serde_json::json!(false);
            assert!(failed_supervisor(&changed).is_err());
        }
        let mut changed = rows.clone();
        changed.insert(1, serde_json::json!({"kind":"before-cell-gate"}));
        assert!(failed_supervisor(&changed).is_err());
        assert!(failed_supervisor(&rows[..8]).is_err());
        assert!(failed_supervisor(&rows[1..]).is_err());
        for error in [
            "no unique outside-measured product process",
            "kernel idmap differs from pinned physical custody",
        ] {
            let mut changed = rows.clone();
            changed[3]["data"]["error"] = serde_json::json!(error);
            assert!(failed_supervisor(&changed).is_err());
        }
        for index in [5, 6] {
            for (field, bad) in [
                ("available", serde_json::json!(true)),
                ("error", serde_json::json!("unknown close result")),
                ("binding", serde_json::json!({})),
            ] {
                let mut changed = rows.clone();
                changed[index]["data"][field] = bad;
                assert!(failed_supervisor(&changed).is_err());
            }
            let mut changed = rows.clone();
            changed.remove(index);
            assert!(failed_supervisor(&changed).is_err());
        }
    }
    use serde_json::json;
    #[test]
    fn pending_ownership_cannot_masquerade_as_a_completed_release() {
        let mut records = vec![json!({}); 4];
        records[0] = json!({"data":{"image_id":"pinned-image"}});
        records[3] = json!({"kind":"image-cell-launch-pending"});
        assert_eq!(
            image_history(&records).unwrap(),
            NativeImageHistory::Pending
        );
        records.push(json!({"kind":"image-releasing","data":{"image_id":"pinned-image"}}));
        assert!(image_history(&records).is_err());
        records.push(
            json!({"kind":"image-cleanup","data":{"image_id":"pinned-image",
            "owned_mount_absent":true,"borrowed_mount_untouched":false}}),
        );
        assert_eq!(image_history(&records).unwrap(), NativeImageHistory::Closed);
        records[5]["data"]["borrowed_mount_untouched"] = json!(true);
        assert!(image_history(&records).is_err());
    }
    fn chain(kinds: &[&str]) -> Vec<u8> {
        let mut raw = Vec::new();
        let mut previous = "0".repeat(64);
        for (sequence, kind) in kinds.iter().enumerate() {
            let value = json!({"schema":"hol-gauntlet-cell-event.v1","sequence":sequence,
                "previous_sha256":previous,"kind":kind,"data":{}});
            let line = gauntlet_contracts::canonicalize(value.to_string().as_bytes()).unwrap();
            previous = hash(&line);
            raw.extend(line);
            raw.push(b'\n');
        }
        raw
    }
    #[test]
    fn truncated_reordered_or_edited_ownership_records_refuse_recovery() {
        let raw = chain(&["reserved", "mounted"]);
        assert_eq!(events(&raw).unwrap().len(), 2);
        assert!(events(&raw[..raw.len() - 1]).is_err());
        let lines = raw.split_inclusive(|b| *b == b'\n').collect::<Vec<_>>();
        assert!(events(&[lines[1], lines[0]].concat()).is_err());
        let edited = String::from_utf8(raw)
            .unwrap()
            .replace("mounted", "released");
        // Editing the last complete record is not detectable without a pin;
        // callers bind its semantic ownership and retain the whole-file hash.
        assert!(events(edited.as_bytes()).is_ok());
        let edited = edited.replace("reserved", "borrowed");
        assert!(events(edited.as_bytes()).is_err());
        assert!(events(b"{}").is_err());
    }
    #[test]
    fn another_job_or_image_cannot_reopen_the_lease() {
        let stage = Path::new("/var/lib/hol-gauntlet-rust/native-jobs/0123456789abcdef/cell");
        let image = format!("sha256:{}", "a".repeat(64));
        let value = json!({"schema":"hol-gauntlet-cell-image-active.v1","image_id":image,"stage":stage,"nonce":"b".repeat(32)});
        let mut raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes()).unwrap();
        raw.push(b'\n');
        active(&raw, &image, stage).unwrap();
        assert!(active(&raw, &format!("sha256:{}", "c".repeat(64)), stage).is_err());
        assert!(active(&raw, &image, Path::new("/var/lib/hol-gauntlet-rust/other")).is_err());
        assert!(active(&raw[..raw.len() - 1], &image, stage).is_err());
    }
    #[test]
    fn closed_history_cannot_borrow_a_mount_or_hide_uncertain_cleanup() {
        let mut image = vec![json!({}); 6];
        image[4] = json!({"kind":"image-releasing","data":{"image_id":"image"}});
        image[5] = json!({"kind":"image-cleanup","data":{"image_id":"image","owned_mount_absent":true,"borrowed_mount_untouched":false}});
        closed_image(&image, "image").unwrap();
        assert!(closed_image(&image[..4], "image").is_err());
        assert!(closed_image(&image, "other").is_err());
        image[5]["data"]["borrowed_mount_untouched"] = json!(true);
        assert!(closed_image(&image, "image").is_err());
        let mut supervisor = vec![
            json!({}),
            json!({"kind":"terminal-cleanup","data":{"cgroup_absent":true,"rootfs_mount_absent":true,"failures":[]}}),
            json!({"kind":"rust-image-cleanup","data":{"image_mount_absent":true,"active_lease_removed":true}}),
        ];
        closed_supervisor(&supervisor).unwrap();
        assert!(closed_supervisor(&supervisor[..2]).is_err());
        supervisor[1]["data"]["failures"] = json!(["uncertain"]);
        assert!(closed_supervisor(&supervisor).is_err());
    }
}
