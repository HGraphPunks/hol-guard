//! Replay actual task transitions. Signed/caller custody and image grading are
//! separate; neither a hash chain nor a producer's complete flag admits a run.
use crate::crypto::sha256;
use crate::native_diagnostic_artifacts::{parse, require, text};
use crate::native_process_event_identity::{final_status, image, pid, task, Task};
use crate::native_process_kernel::number;
use crate::payload::exact_keys;
use crate::{canonical_value, EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

struct Entry {
    id: u64,
    task: Task,
    exiting: bool,
}
struct Birth {
    parent: u64,
    parent_tid: u64,
    group: u64,
    kind: String,
}
struct Replay {
    cgroup: String,
    tracer: Option<u64>,
    active: BTreeMap<u64, Entry>,
    births: BTreeMap<u64, Birth>,
    retired: BTreeMap<u64, (u64, bool)>,
    vforks: BTreeSet<(u64, u64)>,
    next: u64,
    finals: u64,
    replacements: u64,
    execs: u64,
    done: bool,
}

impl Replay {
    fn start(data: &Value) -> Result<Self> {
        require(
            exact_keys(
                data,
                &[
                    "id",
                    "actor",
                    "cgroup",
                    "options",
                    "memory_or_register_mutation",
                    "execution_eligible",
                ],
            ) && data["id"].as_u64() == Some(0)
                && data["memory_or_register_mutation"] == false
                && data["execution_eligible"] == false
                && data["options"]
                    == json!([
                        "exit-kill",
                        "fork",
                        "vfork",
                        "clone",
                        "exec",
                        "exit",
                        "vfork-done"
                    ]),
        )?;
        let cgroup = text(data, "cgroup")?.to_owned();
        require(
            cgroup.starts_with('/')
                && cgroup.len() <= 4096
                && !cgroup.chars().any(char::is_control)
                && (cgroup == "/"
                    || cgroup[1..]
                        .split('/')
                        .all(|v| !v.is_empty() && v != "." && v != "..")),
        )?;
        let mut tracer = None;
        let actor = image(&data["actor"], &cgroup, &mut tracer)?;
        require(actor.tid == actor.tgid && data["actor"]["task"]["status"]["Threads"] == "1")?;
        Ok(Self {
            cgroup,
            tracer,
            active: BTreeMap::from([(
                actor.tid,
                Entry {
                    id: 0,
                    task: actor,
                    exiting: false,
                },
            )]),
            births: BTreeMap::new(),
            retired: BTreeMap::new(),
            vforks: BTreeSet::new(),
            next: 1,
            finals: 0,
            replacements: 0,
            execs: 0,
            done: false,
        })
    }

    fn entry(&self, data: &Value) -> Result<&Entry> {
        let tid = pid(&data["tid"])?;
        let entry = self
            .active
            .get(&tid)
            .ok_or(EvidenceError::Invalid("event has no live traced task"))?;
        require(data["id"].as_u64() == Some(entry.id))?;
        Ok(entry)
    }

    fn event(&mut self, kind: &str, data: &Value) -> Result<()> {
        require(!self.done)?;
        match kind {
            "kernel-creation" => {
                require(exact_keys(
                    data,
                    &["parent_id", "parent_tid", "child_tid", "creation"],
                ))?;
                let parent_tid = pid(&data["parent_tid"])?;
                let parent = self
                    .active
                    .get(&parent_tid)
                    .ok_or(EvidenceError::Invalid("creation parent missing"))?;
                require(data["parent_id"].as_u64() == Some(parent.id) && !parent.exiting)?;
                let child = pid(&data["child_tid"])?;
                let kind = text(data, "creation")?;
                require(
                    matches!(kind, "fork" | "vfork" | "clone")
                        && self.active.len() + self.births.len() < 128
                        && !self.active.contains_key(&child)
                        && !self.births.contains_key(&child),
                )?;
                let birth = Birth {
                    parent: parent.id,
                    parent_tid,
                    group: parent.task.tgid,
                    kind: kind.to_owned(),
                };
                if kind == "vfork" {
                    require(self.vforks.insert((parent.id, child)))?;
                }
                self.births.insert(child, birth);
            }
            "task-created" => {
                require(
                    exact_keys(data, &["id", "parent_id", "parent_tid", "creation", "task"])
                        && data["id"].as_u64() == Some(self.next),
                )?;
                let child = task(&data["task"], &self.cgroup, &mut self.tracer)?;
                let birth = self
                    .births
                    .remove(&child.tid)
                    .ok_or(EvidenceError::Invalid(
                        "created task has no kernel creation",
                    ))?;
                require(
                    data["parent_id"].as_u64() == Some(birth.parent)
                        && data["parent_tid"].as_u64() == Some(birth.parent_tid)
                        && data["creation"] == birth.kind
                        && !self.active.contains_key(&child.tid)
                        && (child.tid == child.tgid
                            || (birth.kind == "clone" && child.tgid == birth.group)),
                )?;
                self.retired.remove(&child.tid);
                self.active.insert(
                    child.tid,
                    Entry {
                        id: self.next,
                        task: child,
                        exiting: false,
                    },
                );
                self.next += 1;
            }
            "task-exit-stop" => {
                require(
                    exact_keys(data, &["id", "tid", "status", "death_observed"])
                        && data["death_observed"] == false,
                )?;
                let entry = self.entry(data)?;
                require(!entry.exiting)?;
                let tid = entry.task.tid;
                final_status(&data["status"])?;
                self.active.get_mut(&tid).unwrap().exiting = true;
            }
            "task-final-wait" => {
                require(
                    exact_keys(
                        data,
                        &[
                            "id",
                            "tid",
                            "tgid",
                            "start_ticks",
                            "status",
                            "death_observed",
                        ],
                    ) && data["death_observed"] == true,
                )?;
                let entry = self.entry(data)?;
                require(
                    data["tgid"].as_u64() == Some(entry.task.tgid)
                        && data["start_ticks"].as_u64() == Some(entry.task.start),
                )?;
                let tid = entry.task.tid;
                final_status(&data["status"])?;
                self.active.remove(&tid);
                self.finals += 1;
            }
            "task-exec" => self.exec(data)?,
            "exec-retired-final-wait" => {
                require(exact_keys(data, &["id", "tid", "status"]))?;
                let tid = pid(&data["tid"])?;
                let (id, may_report) = self
                    .retired
                    .remove(&tid)
                    .ok_or(EvidenceError::Invalid("final wait has no exec retirement"))?;
                require(
                    may_report
                        && !self.active.contains_key(&tid)
                        && data["id"].as_u64() == Some(id),
                )?;
                final_status(&data["status"])?;
            }
            "signal-delivery" | "seized-stop" => {
                require(exact_keys(data, &["id", "tid", "signal"]))?;
                self.entry(data)?;
                let signal = number(&data["signal"])?;
                require(if kind == "signal-delivery" {
                    signal <= 64
                } else {
                    signal == 5 || (19..=22).contains(&signal)
                })?;
            }
            "vfork-done" => {
                require(exact_keys(data, &["id", "tid", "child_tid"]))?;
                let id = self.entry(data)?.id;
                require(self.vforks.remove(&(id, pid(&data["child_tid"])?)))?;
            }
            "resume-stop-lost" => {
                require(
                    exact_keys(data, &["tid", "signal", "death_observed"])
                        && data["death_observed"] == false
                        && data["signal"].as_u64().is_some_and(|s| s <= 64)
                        && self.active.contains_key(&pid(&data["tid"])?),
                )?;
            }
            "listen-stop-lost" => {
                require(
                    exact_keys(data, &["id", "tid", "death_observed"])
                        && data["death_observed"] == false,
                )?;
                self.entry(data)?;
            }
            "trace-complete" => {
                require(
                    exact_keys(
                        data,
                        &[
                            "created_tasks",
                            "final_waits",
                            "exec_retirements",
                            "execs",
                            "active_tasks",
                            "pending_births",
                            "pending_stops",
                            "execution_eligible",
                        ],
                    ) && self.active.is_empty()
                        && self.births.is_empty()
                        && self.next == self.finals + self.replacements
                        && data["created_tasks"].as_u64() == Some(self.next)
                        && data["final_waits"].as_u64() == Some(self.finals)
                        && data["exec_retirements"].as_u64() == Some(self.replacements)
                        && data["execs"].as_u64() == Some(self.execs)
                        && ["active_tasks", "pending_births", "pending_stops"]
                            .iter()
                            .all(|k| data[k].as_u64() == Some(0))
                        && data["execution_eligible"] == false,
                )?;
                self.done = true;
            }
            _ => {
                return Err(EvidenceError::Invalid(
                    "unsupported or incomplete process event history",
                ))
            }
        }
        Ok(())
    }

    fn exec(&mut self, data: &Value) -> Result<()> {
        require(exact_keys(
            data,
            &["id", "old_tid", "old_start_ticks", "retired", "image"],
        ))?;
        let old = pid(&data["old_tid"])?;
        let caller = self
            .active
            .get(&old)
            .ok_or(EvidenceError::Invalid("exec caller missing"))?;
        let id = caller.id;
        let group = caller.task.tgid;
        require(
            data["id"].as_u64() == Some(id)
                && data["old_start_ticks"].as_u64() == Some(caller.task.start)
                && !caller.exiting,
        )?;
        let next = image(&data["image"], &self.cgroup, &mut self.tracer)?;
        require(
            next.tid == group
                && next.tgid == group
                && data["image"]["task"]["status"]["Threads"] == "1",
        )?;
        let expected = self
            .active
            .iter()
            .filter(|(_, v)| v.task.tgid == group && v.id != id)
            .map(|(t, _)| *t)
            .collect::<BTreeSet<_>>();
        let retired = data["retired"]
            .as_array()
            .filter(|v| v.len() <= 128)
            .ok_or(EvidenceError::Invalid(
                "bounded exec retirement list required",
            ))?;
        require(retired.len() == expected.len())?;
        let mut seen = BTreeSet::new();
        for row in retired {
            require(
                exact_keys(
                    row,
                    &["id", "tid", "start_ticks", "reason", "final_wait_observed"],
                ) && row["reason"] == "kernel-exec-thread-replacement"
                    && row["final_wait_observed"] == false,
            )?;
            let tid = pid(&row["tid"])?;
            require(expected.contains(&tid) && seen.insert(tid))?;
            let entry = &self.active[&tid];
            require(
                row["id"].as_u64() == Some(entry.id)
                    && row["start_ticks"].as_u64() == Some(entry.task.start),
            )?;
            self.retired.insert(tid, (entry.id, tid != next.tid));
        }
        self.active.retain(|_, v| v.task.tgid != group);
        self.active.insert(
            next.tid,
            Entry {
                id,
                task: next,
                exiting: false,
            },
        );
        self.replacements += retired.len() as u64;
        self.execs += 1;
        Ok(())
    }
}

/// Verify already bounded public bytes and a caller-bound complete checkpoint.
/// Callers must independently authenticate the checkpoint's source/custody.
pub fn verify_native_process_events(raw: &[u8], checkpoint: &Value) -> Result<Value> {
    require(
        !raw.is_empty()
            && raw.len() <= 64 * 1024 * 1024
            && raw.ends_with(b"\n")
            && exact_keys(
                checkpoint,
                &[
                    "schema",
                    "complete",
                    "created_tasks",
                    "final_waits",
                    "exec_retirements",
                    "execs",
                    "journal",
                    "execution_eligible",
                ],
            )
            && checkpoint["schema"] == "hol-gauntlet-native-process-events.v1"
            && checkpoint["complete"] == true
            && checkpoint["execution_eligible"] == false,
    )?;
    let pin = &checkpoint["journal"];
    require(
        exact_keys(
            pin,
            &[
                "schema",
                "available",
                "events",
                "bytes",
                "tail_sha256",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
                "links",
            ],
        ) && pin["schema"] == "hol-gauntlet-cell-journal-binding.v1"
            && pin["available"] == true
            && pin["bytes"].as_u64() == Some(raw.len() as u64)
            && pin["device"].as_u64().is_some()
            && pin["uid"].as_u64() == Some(0)
            && pin["gid"].as_u64() == Some(0)
            && pin["mode"].as_u64() == Some(0o600)
            && pin["links"].as_u64() == Some(1),
    )?;
    number(&pin["inode"])?;
    let mut previous = "0".repeat(64);
    let mut replay = None;
    let mut count = 0;
    for (sequence, line) in raw[..raw.len() - 1].split(|b| *b == b'\n').enumerate() {
        require(sequence < 65536 && !line.is_empty() && line.len() <= 256 * 1024)?;
        let row = parse(line)?;
        require(
            exact_keys(
                &row,
                &["schema", "sequence", "previous_sha256", "kind", "data"],
            ) && row["schema"] == "hol-gauntlet-cell-event.v1"
                && row["sequence"].as_u64() == Some(sequence as u64)
                && row["previous_sha256"] == previous
                && canonical_value(&row)? == line,
        )?;
        previous = sha256(line);
        let kind = text(&row, "kind")?;
        if sequence == 0 {
            require(kind == "trace-start")?;
            replay = Some(Replay::start(&row["data"])?);
        } else {
            replay.as_mut().unwrap().event(kind, &row["data"])?;
        }
        count = sequence + 1;
    }
    let replay = replay.ok_or(EvidenceError::Invalid("process event start missing"))?;
    require(
        replay.done
            && pin["events"].as_u64() == Some(count as u64)
            && pin["tail_sha256"] == previous
            && checkpoint["created_tasks"].as_u64() == Some(replay.next)
            && checkpoint["final_waits"].as_u64() == Some(replay.finals)
            && checkpoint["exec_retirements"].as_u64() == Some(replay.replacements)
            && checkpoint["execs"].as_u64() == Some(replay.execs),
    )?;
    Ok(
        json!({"schema":"hol-gauntlet-native-process-event-readback.v1","complete_task_relation_verified":true,
        "journal_sha256":sha256(raw),"journal_events":count,"created_tasks":replay.next,"final_waits":replay.finals,
        "exec_retirements":replay.replacements,"execs":replay.execs,"process_custody_authenticated":false,
        "all_native_descendants_verified":false,"execution_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    )
}

#[cfg(test)]
#[path = "native_process_events_tests.rs"]
pub(crate) mod tests;
