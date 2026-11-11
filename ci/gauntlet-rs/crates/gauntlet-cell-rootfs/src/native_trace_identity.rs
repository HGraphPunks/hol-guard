//! A ptrace stop is live; a zombie, missing PID or replaced generation is not.
use crate::Result;

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
