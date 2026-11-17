//! A ptrace stop is live; a zombie, missing PID or replaced generation is not.
use crate::Result;
use std::collections::{BTreeMap, BTreeSet};

/// A stopped TID retains its own security identity. Its process-wide thread
/// count can change while a different, still-running sibling creates or exits.
/// Keep both counts bounded; the caller retains the first actual observation.
pub(crate) fn status_changes(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
) -> Result<Vec<String>> {
    for fields in [before, after] {
        if fields
            .get("Threads")
            .and_then(|raw| raw.parse::<u32>().ok())
            .is_none_or(|count| !(1..=128).contains(&count))
        {
            return Err("traced task Threads missing or outside the fixed task ceiling".into());
        }
    }
    Ok(before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| key.as_str() != "Threads" && before.get(*key) != after.get(*key))
        .map(|key| format!("status.{key}"))
        .collect())
}

pub(crate) fn start_ticks(raw: &[u8], tid: u32) -> Result<u64> {
    if raw.len() > 4096 {
        return Err("traced stat byte bound".into());
    }
    let text = std::str::from_utf8(raw).map_err(|_| "traced stat UTF-8")?;
    let (head, tail) = text.rsplit_once(')').ok_or("traced stat comm")?;
    let (pid, _) = head.split_once(" (").ok_or("traced stat PID")?;
    let fields = tail.split_ascii_whitespace().collect::<Vec<_>>();
    if pid.parse::<u32>().ok() != Some(tid)
        || tid == 0
        || fields.len() < 22
        || !matches!(fields[0], "R" | "S" | "D" | "T" | "t")
    {
        return Err("live exact traced TID required".into());
    }
    fields[19]
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| "positive traced start tick required".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_count_is_observed_while_every_security_status_field_remains_exact() {
        let before = BTreeMap::from(
            [
                ("Uid", "10004 10004 10004 10004"),
                ("Gid", "10004 10004 10004 10004"),
                ("Groups", ""),
                ("CapAmb", "0000000000000000"),
                ("CapBnd", "0000000000000000"),
                ("CapEff", "0000000000000000"),
                ("CapInh", "0000000000000000"),
                ("CapPrm", "0000000000000000"),
                ("NoNewPrivs", "1"),
                ("Seccomp", "2"),
                ("Seccomp_filters", "2"),
                ("NSpid", "42 7"),
                ("TracerPid", "31"),
                ("Threads", "9"),
                ("Cpus_allowed_list", "0"),
            ]
            .map(|(key, value)| (key.to_owned(), value.to_owned())),
        );
        for count in ["1", "8", "10", "128"] {
            let mut after = before.clone();
            after.insert("Threads".into(), count.into());
            assert!(status_changes(&before, &after).unwrap().is_empty());
            assert_eq!(
                before["Threads"], "9",
                "the retained observation is not rewritten"
            );
        }
        for key in before.keys().filter(|key| key.as_str() != "Threads") {
            let mut after = before.clone();
            after.insert(key.clone(), "changed".into());
            assert_eq!(
                status_changes(&before, &after).unwrap(),
                [format!("status.{key}")]
            );
            after.remove(key);
            assert_eq!(
                status_changes(&before, &after).unwrap(),
                [format!("status.{key}")]
            );
        }
        for count in ["0", "129", "-1", "unknown"] {
            let mut after = before.clone();
            after.insert("Threads".into(), count.into());
            assert!(status_changes(&before, &after).is_err());
            assert!(status_changes(&after, &before).is_err());
        }
        let mut absent = before.clone();
        absent.remove("Threads");
        assert!(status_changes(&before, &absent).is_err());
    }

    #[test]
    fn ptrace_and_group_stops_are_live_but_exit_states_and_pid_reuse_are_not() {
        let mut fields = vec!["0"; 22];
        fields[19] = "123";
        for state in ["R", "S", "D", "T", "t"] {
            fields[0] = state;
            let raw = format!("42 (name) with) parentheses) {}", fields.join(" "));
            assert_eq!(start_ticks(raw.as_bytes(), 42).unwrap(), 123);
            assert!(start_ticks(raw.as_bytes(), 43).is_err());
        }
        for state in ["Z", "X", "x", "I", "?"] {
            fields[0] = state;
            assert!(start_ticks(format!("42 (task) {}", fields.join(" ")).as_bytes(), 42).is_err());
        }
        fields[0] = "t";
        fields[19] = "0";
        assert!(start_ticks(format!("42 (task) {}", fields.join(" ")).as_bytes(), 42).is_err());
    }
}
