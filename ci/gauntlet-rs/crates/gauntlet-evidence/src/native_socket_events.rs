//! Replay the measured socket handoff, without claiming socket bytes or writers.
use super::*;

pub(super) const SCHEMA: &str = "hol-gauntlet-native-transports.v2";

pub(super) fn objects<const N: usize>(value: &Value) -> Result<[[u64; 2]; N]> {
    let shape = if N == 4 {
        "four Native pipe objects required"
    } else {
        "two Native socket objects required"
    };
    let pair_error = if N == 4 {
        "Native pipe object pair required"
    } else {
        "Native socket object pair required"
    };
    let device_error = if N == 4 {
        "pipe device required"
    } else {
        "socket device required"
    };
    let rows = value
        .as_array()
        .filter(|v| v.len() == N)
        .ok_or(EvidenceError::Invalid(shape))?;
    let mut out = [[0; 2]; N];
    for (pair, value) in out.iter_mut().zip(rows) {
        let row = value
            .as_array()
            .filter(|v| v.len() == 2)
            .ok_or(EvidenceError::Invalid(pair_error))?;
        pair[0] = row[0]
            .as_u64()
            .ok_or(EvidenceError::Invalid(device_error))?;
        pair[1] = number(&row[1])?;
    }
    require(out.iter().collect::<BTreeSet<_>>().len() == N)?;
    Ok(out)
}

fn helper_argv(image: &Value, program: &[u8]) -> Result<Vec<Vec<u8>>> {
    let argv = command(image)?;
    require(
        argv.len() == 6
            && argv[0] == program
            && argv[1] == b"daemon-edge"
            && argv[2] == b"--upstream-port"
            && argv[4] == b"--parent-pid",
    )?;
    for (index, low, high) in [(3, 1, u64::from(u16::MAX)), (5, 2, i32::MAX as u64)] {
        let raw = std::str::from_utf8(&argv[index])
            .map_err(|_| EvidenceError::Invalid("Native helper decimal required"))?;
        let value = decimal(raw)?;
        require((low..=high).contains(&value) && value.to_string() == raw)?;
    }
    Ok(argv)
}

struct Entry {
    wrapper: Value,
    event: usize,
    sockets: [[u64; 2]; 2],
    parent: (u64, u64),
    exec: Option<usize>,
}

#[derive(Default)]
pub(super) struct Helpers(BTreeMap<usize, Entry>);
impl Helpers {
    pub(super) fn ids(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.keys().copied()
    }
    pub(super) fn pending(&self) -> usize {
        self.0.values().filter(|v| v.exec.is_none()).count()
    }

    pub(super) fn handoff(
        &mut self,
        data: &Value,
        events: &[Value],
        actor: &Value,
        connector: &str,
    ) -> Result<()> {
        require(
            exact_keys(
                data,
                &[
                    "session",
                    "wrapper",
                    "wrapper_exec_event",
                    "parent_tid",
                    "parent_start_ticks",
                    "sockets",
                    "listener",
                    "health_peer_unnamed",
                    "socket_bytes_observed",
                    "execution_eligible",
                    "exclusive_product_authorship_verified",
                ],
            ) && data["health_peer_unnamed"] == true
                && data["socket_bytes_observed"] == false
                && data["execution_eligible"] == false
                && data["exclusive_product_authorship_verified"] == false,
        )?;
        let id = integer(&data["session"])?;
        require(!self.0.contains_key(&id))?;
        let event = integer(&data["wrapper_exec_event"])?;
        let wrapper = &data["wrapper"];
        image(events, event, wrapper, connector, actor)?;
        let argv = helper_argv(wrapper, CONNECTOR)?;
        let address: std::net::SocketAddr = text(data, "listener")?
            .parse()
            .map_err(|_| EvidenceError::Invalid("Native helper listener required"))?;
        require(address.ip().is_loopback() && address.port() != 0)?;
        let parent_tid = number(&data["parent_tid"])?;
        let start = number(&data["parent_start_ticks"])?;
        require(wrapper["task"]["parent_pid"] == parent_tid)?;
        let parent = events[..event]
            .iter()
            .rev()
            .find_map(|row| {
                let task = match row["kind"].as_str()? {
                    "trace-start" => &row["data"]["actor"]["task"],
                    "task-exec" => &row["data"]["image"]["task"],
                    "task-created" => &row["data"]["task"],
                    _ => return None,
                };
                (task["tid"] == parent_tid && task["start_ticks"] == start).then_some(task)
            })
            .ok_or(EvidenceError::Invalid(
                "Native helper parent generation missing",
            ))?;
        let local = text(&parent["status"], "NSpid")?
            .split_ascii_whitespace()
            .last()
            .ok_or(EvidenceError::Invalid(
                "Native helper parent namespace PID missing",
            ))?;
        require(local.as_bytes() == argv[5] && parent["cgroup"] == wrapper["task"]["cgroup"])?;
        crate::native_runtime_trace::floors(parent)?;
        self.0.insert(
            id,
            Entry {
                wrapper: wrapper.clone(),
                event,
                sockets: objects(&data["sockets"])?,
                parent: (parent_tid, start),
                exec: None,
            },
        );
        Ok(())
    }

    pub(super) fn bind(
        &mut self,
        data: &Value,
        events: &[Value],
        actor: &Value,
        config: &Value,
    ) -> Result<usize> {
        require(
            exact_keys(
                data,
                &[
                    "session",
                    "process",
                    "exec_event",
                    "sockets",
                    "socket_bytes_observed",
                    "execution_eligible",
                    "exclusive_product_authorship_verified",
                ],
            ) && data["socket_bytes_observed"] == false
                && data["execution_eligible"] == false
                && data["exclusive_product_authorship_verified"] == false,
        )?;
        let entry = self
            .0
            .get_mut(&integer(&data["session"])?)
            .ok_or(EvidenceError::Invalid("Native helper handoff missing"))?;
        let event = integer(&data["exec_event"])?;
        require(
            entry.exec.is_none()
                && event > entry.event
                && objects::<2>(&data["sockets"])? == entry.sockets,
        )?;
        let native = &data["process"];
        image(events, event, native, text(config, "native_sha256")?, actor)?;
        require(!events[..=event].iter().any(|row| {
            row["kind"] == "task-final-wait"
                && row["data"]["tid"] == entry.parent.0
                && row["data"]["start_ticks"] == entry.parent.1
        }))?;
        let mut expected = helper_argv(&entry.wrapper, CONNECTOR)?;
        expected[0] = text(config, "native_program")?.as_bytes().to_vec();
        require(
            helper_argv(native, &expected[0])? == expected
                && events[event]["data"]["id"] == events[entry.event]["data"]["id"],
        )?;
        for field in ["tid", "tgid", "start_ticks", "parent_pid"] {
            require(native["task"][field] == entry.wrapper["task"][field])?;
        }
        let id = &events[event]["data"]["id"];
        let end = events
            .iter()
            .skip(event + 1)
            .find(|row| {
                matches!(row["kind"].as_str(), Some("task-final-wait" | "task-exec"))
                    && row["data"]["id"] == *id
            })
            .ok_or(EvidenceError::Invalid("Native helper final wait missing"))?;
        require(end["kind"] == "task-final-wait")?;
        entry.exec = Some(event);
        Ok(event)
    }

    pub(super) fn summary(&self) -> Result<Vec<Value>> {
        require(self.pending() == 0)?;
        Ok(self.0.iter().map(|(id, entry)| json!({"session":id,"wrapper_exec_event":entry.event,
            "exec_event":entry.exec.unwrap(),"sockets":entry.sockets,"pid_parent_object_relations_verified":true,
            "socket_bytes_observed":false,"exclusive_product_authorship_verified":false})).collect())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::native_process_events::tests::{image_value, pack, pipes::fixture, task_value};
    type Rows = Vec<(&'static str, Value)>;

    fn argv(image: &mut Value, args: &[&str]) {
        let raw = format!("{}\0", args.join("\0"));
        image["argv_base64"] = json!(STANDARD.encode(raw.as_bytes()));
        image["argv_sha256"] = json!(sha256(raw.as_bytes()));
    }
    pub(crate) fn mixed() -> (Rows, Rows, Value) {
        let (mut process, mut pipe, config) = fixture();
        let mut wrapper = image_value(45, 45, 10);
        wrapper["task"]["parent_pid"] = json!(42);
        argv(
            &mut wrapper,
            &[
                "/public/gauntlet-product-cell",
                "daemon-edge",
                "--upstream-port",
                "1234",
                "--parent-pid",
                "42",
            ],
        );
        let mut native = wrapper.clone();
        let core = config["native_program"].as_str().unwrap();
        argv(
            &mut native,
            &[
                core,
                "daemon-edge",
                "--upstream-port",
                "1234",
                "--parent-pid",
                "42",
            ],
        );
        native["executable"]["sha256"] = config["native_sha256"].clone();
        process.truncate(10);
        let mut task = task_value(45, 45, 10);
        task["parent_pid"] = json!(42);
        process.extend([
            ("kernel-creation", json!({"parent_id":0,"parent_tid":42,"child_tid":45,"creation":"fork"})),
            ("task-created", json!({"id":3,"parent_id":0,"parent_tid":42,"creation":"fork","task":task})),
            ("task-exec", json!({"id":3,"old_tid":45,"old_start_ticks":10,"retired":[],"image":wrapper})),
            ("task-exec", json!({"id":3,"old_tid":45,"old_start_ticks":10,"retired":[],"image":native})),
            ("task-final-wait", json!({"id":3,"tid":45,"tgid":45,"start_ticks":10,"status":{"kind":"exit","code":0},"death_observed":true})),
            ("task-final-wait", json!({"id":0,"tid":42,"tgid":42,"start_ticks":7,"status":{"kind":"exit","code":0},"death_observed":true})),
            ("trace-complete", json!({"created_tasks":4,"final_waits":4,"exec_retirements":0,"execs":5,"active_tasks":0,"pending_births":0,"pending_stops":0,"execution_eligible":false})),
        ]);
        pipe[0].1["schema"] = json!(SCHEMA);
        pipe.pop();
        pipe.extend([
            ("native-socket-helper-handoff", json!({"session":1,"wrapper":wrapper,"wrapper_exec_event":12,
                "parent_tid":42,"parent_start_ticks":7,"sockets":[[9,20],[9,21]],"listener":"127.0.0.1:46000",
                "health_peer_unnamed":true,"socket_bytes_observed":false,"execution_eligible":false,"exclusive_product_authorship_verified":false})),
            ("native-socket-helper-exec-bound", json!({"session":1,"process":native,"exec_event":13,"sockets":[[9,20],[9,21]],
                "socket_bytes_observed":false,"execution_eligible":false,"exclusive_product_authorship_verified":false})),
            ("native-pipe-owner-closed", json!({"sessions":2,"execution_eligible":false})),
        ]);
        (process, pipe, config)
    }
    fn replay(process: &Rows, pipe: &Rows, config: &Value, schema: &str) -> Result<Value> {
        let (raw, checkpoint) = pack(process);
        let (journal, binding) = pack(pipe);
        super::super::verify(
            &journal,
            &raw,
            &checkpoint,
            &binding["journal"],
            config,
            &"a".repeat(64),
            schema,
        )
        .map(|readback| readback.summary)
    }

    #[test]
    fn v2_keeps_helper_relations_separate_from_pipe_bytes_and_v1_refuses_it() {
        let (process, pipe, config) = mixed();
        let result = replay(&process, &pipe, &config, SCHEMA).unwrap();
        assert_eq!(
            result["schema"],
            "hol-gauntlet-native-transport-readback.v2"
        );
        assert_eq!(result["session_count"], 1);
        assert_eq!(result["connection_count"], 2);
        assert_eq!(result["socket_helper_count"], 1);
        assert_eq!(result["native_client_streams"], 1);
        for field in [
            "socket_bytes_observed",
            "exclusive_product_authorship_verified",
            "outside_observer_admitted",
            "execution_eligible",
            "guard_causality_verified",
        ] {
            assert_eq!(result[field], false, "{field}");
        }
        assert!(replay(&process, &pipe, &config, super::super::V1).is_err());
        assert!(replay(&process, &pipe, &config, "unsupported").is_err());
    }

    #[test]
    fn rehashed_wrong_objects_parent_command_flags_and_unknown_fields_refuse() {
        let (process, pipe, config) = mixed();
        for (index, field, value) in [
            (12, "sockets", json!([[9, 20], [9, 20]])),
            (12, "parent_tid", json!(43)),
            (12, "parent_start_ticks", json!(8)),
            (12, "listener", json!("0.0.0.0:46000")),
            (12, "health_peer_unnamed", json!(false)),
            (12, "socket_bytes_observed", json!(true)),
            (13, "exec_event", json!(12)),
            (13, "sockets", json!([[9, 20], [9, 22]])),
            (13, "execution_eligible", json!(true)),
            (13, "exclusive_product_authorship_verified", json!(true)),
            (13, "unknown", json!(null)),
            (14, "sessions", json!(1)),
        ] {
            let mut changed = pipe.clone();
            changed[index].1[field] = value;
            assert!(
                replay(&process, &changed, &config, SCHEMA).is_err(),
                "{index}/{field}"
            );
        }
        for args in [
            vec![
                "/public/gauntlet-product-cell",
                "daemon-edge",
                "--upstream-port",
                "0",
                "--parent-pid",
                "42",
            ],
            vec![
                "/public/gauntlet-product-cell",
                "daemon-edge",
                "--upstream-port",
                "1234",
                "--parent-pid",
                "042",
            ],
            vec![
                "/public/gauntlet-product-cell",
                "daemon-edge",
                "--upstream-port",
                "1234",
                "--parent-pid",
                "43",
            ],
            vec![
                "/public/gauntlet-product-cell",
                "daemon-edge",
                "--upstream-port",
                "1234",
                "--parent-pid",
                "42",
                "extra",
            ],
        ] {
            let mut changed = process.clone();
            argv(&mut changed[12].1["image"], &args);
            let mut matching = pipe.clone();
            matching[12].1["wrapper"] = changed[12].1["image"].clone();
            assert!(replay(&changed, &matching, &config, SCHEMA).is_err());
        }
    }

    #[test]
    fn missing_reordered_duplicate_helper_rows_and_socket_byte_claims_refuse() {
        let (process, pipe, config) = mixed();
        for missing in [12, 13, 14] {
            let mut changed = pipe.clone();
            changed.remove(missing);
            assert!(replay(&process, &changed, &config, SCHEMA).is_err());
        }
        let mut reordered = pipe.clone();
        reordered.swap(12, 13);
        assert!(replay(&process, &reordered, &config, SCHEMA).is_err());
        let mut duplicate = pipe.clone();
        duplicate.insert(13, pipe[12].clone());
        assert!(replay(&process, &duplicate, &config, SCHEMA).is_err());
        let mut bytes = pipe.clone();
        bytes.insert(14, ("native-pipe-bytes", json!({"session":1,"kind":"read","direction":0,"offset":0,"bytes_base64":STANDARD.encode(b"private handshake")})));
        assert!(replay(&process, &bytes, &config, SCHEMA).is_err());
    }

    #[test]
    fn a_complete_process_history_cannot_replace_the_original_helper_before_its_wait() {
        let (mut process, pipe, config) = mixed();
        let mut replacement = process[13].clone();
        argv(
            &mut replacement.1["image"],
            &[config["native_program"].as_str().unwrap(), "capabilities"],
        );
        process.insert(14, replacement);
        process.last_mut().unwrap().1["execs"] = json!(6);
        let (raw, checkpoint) = pack(&process);
        assert!(crate::verify_native_process_events(&raw, &checkpoint).is_ok());
        assert!(replay(&process, &pipe, &config, SCHEMA).is_err());
    }
    #[test]
    fn a_parent_that_already_exited_cannot_authorize_the_helper_exec() {
        let (mut process, mut pipe, config) = mixed();
        let parent_wait = process.remove(15);
        process.insert(13, parent_wait);
        pipe[13].1["exec_event"] = json!(14);
        assert!(replay(&process, &pipe, &config, SCHEMA).is_err());
    }
}
