//! Bounded live original-VM channel; model completion is never replayed.
use super::super::transport::Lima;
use super::*;
use base64::Engine as _;
use gauntlet_contracts::WorkerRequest;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub(super) fn provision(i: &Intent, publish: bool) -> Result<Vec<u8>, String> {
    let mut lima = Lima::open(i)?;
    let worker = format!(
        "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
        i.text("worker_generation")
    );
    let mut command = lima.command(i.text("vm"))?;
    command.args([
        worker.as_str(),
        if publish {
            "--prepare-native-live-omp-v1"
        } else {
            "--read-native-live-omp-preparation-v1"
        },
        i.text("source_sha"),
        i.job(),
        i.text("deployment_digest"),
        i.text("worker_generation"),
        i.text("preparation_sha256"),
        text(context_value(i), "spec_sha256")?,
    ]);
    let seconds = spec()?.0["execution_budget"]["preparation_wall_seconds"]
        .as_u64()
        .ok_or("source preparation budget absent")?;
    let output = crate::stream_process::run_streamed_command(
        command,
        &[],
        Duration::from_secs(seconds + 30),
        8192,
    )
    .map_err(|_| "live provisioning transport uncertain; read original dispatch without retry")?;
    lima.recheck()?;
    Ok(output)
}
fn suffix(turn: u64, kind: &str) -> String {
    format!("live-turn-{turn:05}-{kind}")
}
fn validate_request(i: &Intent, v: &Value, turn: u64) -> Result<(), String> {
    if !exact(
        v,
        &[
            "schema",
            "source_sha",
            "provider_job_id",
            "job_id",
            "budget_digest",
            "turn",
            "request_sha256",
            "body_b64",
        ],
    ) || v["schema"] != "hol-gauntlet-native-live-model-request.v1"
        || v["source_sha"] != i.text("source_sha")
        || v["provider_job_id"] != binding(i)["provider_job_id"]
        || v["job_id"] != i.job()
        || v["budget_digest"] != binding(i)["budget_digest"]
        || v["turn"] != turn
        || !(1..=64).contains(&turn)
    {
        return Err("live model request differs from original source/cell/turn/budget".into());
    }
    let encoded = text(v, "body_b64")?;
    if encoded.len() > 1_398_104 {
        return Err("live model request exceeds bound".into());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "live model request encoding invalid")?;
    if raw.len() > 1024 * 1024
        || sha(&raw) != text(v, "request_sha256")?
        || base64::engine::general_purpose::STANDARD.encode(&raw) != encoded
    {
        return Err("live model request byte binding differs".into());
    }
    Ok(())
}
fn response_pins(i: &Intent, request: &Value, response: &Value) -> Result<Value, String> {
    if !exact(
        response,
        &[
            "schema",
            "source_sha",
            "provider_job_id",
            "job_id",
            "budget_digest",
            "turn",
            "request_sha256",
            "response_sha256",
            "body_b64",
            "usage_receipt",
            "before",
            "after",
        ],
    ) || response["schema"] != "hol-gauntlet-native-live-model-response.v1"
        || [
            "source_sha",
            "provider_job_id",
            "job_id",
            "budget_digest",
            "turn",
            "request_sha256",
        ]
        .iter()
        .any(|k| response[*k] != request[*k])
    {
        return Err("actual provider response differs from retained live request".into());
    }
    let encoded = text(response, "body_b64")?;
    if encoded.len() > 5_592_408 {
        return Err("live response exceeds bound".into());
    }
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| "live response encoding invalid")?;
    if raw.is_empty()
        || raw.len() > 4 * 1024 * 1024
        || sha(&raw) != text(response, "response_sha256")?
        || base64::engine::general_purpose::STANDARD.encode(&raw) != encoded
    {
        return Err("live response exact bytes differ".into());
    }
    let usage = &response["usage_receipt"];
    if !usage["reservation_id"].as_str().is_some_and(|s| hex(s, 32))
        || !usage["prepared_input_sha256"]
            .as_str()
            .is_some_and(|s| hex(s, 64))
    {
        return Err("actual provider reservation pins absent".into());
    }
    let mut pins = json!({"cell_job_id":i.job(),"budget_digest":request["budget_digest"],"turn":request["turn"],"request_sha256":request["request_sha256"],"response_sha256":response["response_sha256"],"response_bytes":raw.len(),"model_id":binding(i)["model_id"],"reservation_id":usage["reservation_id"],"prepared_input_sha256":usage["prepared_input_sha256"]});
    let mut expected = binding(i)["status_pins"].clone();
    for (k, v) in pins.as_object().ok_or("turn pins invalid")? {
        expected[k] = v.clone();
    }
    gauntlet_evidence::verify_rust_provider_usage(
        usage,
        &expected,
        &response["before"],
        &response["after"],
    )
    .map_err(|_| "actual provider usage does not reconcile retained quota")?;
    // Bind the actual retained observation after the unchanged usage verifier.
    // Aggregate-provided snapshots cannot replace this outside byte pin.
    pins["observation_sha256"] = json!(sha(&bytes(&json!({
        "usage":usage,"before":response["before"],"after":response["after"]
    }))?));
    Ok(pins)
}
pub(super) fn turn_pins(j: &Journal, i: &Intent, count: u64) -> Result<Value, String> {
    if count > 64 {
        return Err("live model count exceeds source budget".into());
    }
    let mut pins = Vec::new();
    let mut previous: Option<Value> = None;
    for turn in 1..=64 {
        let request = suffix(turn, "request");
        let response = suffix(turn, "response");
        if turn > count {
            if !j.absent(i.job(), &request)?
                || !j.absent(i.job(), &response)?
                || !j.absent(i.job(), &suffix(turn, "pins"))?
            {
                return Err("orphan live model attempt contradicts terminal count".into());
            }
            continue;
        }
        let request = parse(&j.read(i.job(), &request)?)?;
        validate_request(i, &request, turn)?;
        let response = parse(&j.read(i.job(), &response)?)?;
        let pin = response_pins(i, &request, &response)?;
        if j.read(i.job(), &suffix(turn, "pins"))? != bytes(&pin)?
            || previous.as_ref().is_some_and(|q| q != &response["before"])
        {
            return Err("outside live provider turns are missing or discontinuous".into());
        }
        previous = Some(response["after"].clone());
        pins.push(pin);
    }
    Ok(json!({"status_pins":binding(i)["status_pins"],"turn_pins":pins}))
}

struct Frames<R, W> {
    input: W,
    output: R,
    buffer: Vec<u8>,
    deadline: Instant,
    total: usize,
    search: usize,
}
fn nonblocking(fd: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("live pipe unavailable".into());
    }
    Ok(())
}
impl<R: Read + AsRawFd, W: Write + AsRawFd> Frames<R, W> {
    fn new(input: W, output: R, deadline: Instant) -> Result<Self, String> {
        nonblocking(input.as_raw_fd())?;
        nonblocking(output.as_raw_fd())?;
        Ok(Self {
            input,
            output,
            buffer: Vec::new(),
            deadline,
            total: 0,
            search: 0,
        })
    }
    fn check(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            return Err("source-owned live worker deadline reached".into());
        }
        Ok(())
    }
    fn line(&mut self) -> Result<Option<Vec<u8>>, String> {
        let mut chunk = [0_u8; 8192];
        loop {
            self.check()?;
            if let Some(end) = self.buffer[self.search..]
                .iter()
                .position(|b| *b == b'\n')
                .map(|n| n + self.search)
            {
                if end > gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT {
                    return Err("live frame exceeds bound".into());
                }
                let mut raw = self.buffer.drain(..=end).collect::<Vec<_>>();
                raw.pop();
                self.search = 0;
                return Ok(Some(raw));
            }
            self.search = self.buffer.len();
            match self.output.read(&mut chunk) {
                Ok(0) => {
                    return if self.buffer.is_empty() {
                        Ok(None)
                    } else {
                        Err("partial live frame remains unknown".into())
                    }
                }
                Ok(n) => {
                    self.total += n;
                    if self.total > 192 * 1024 * 1024
                        || self.buffer.len() + n
                            > gauntlet_contracts::NATIVE_HOST_PINNED_COMPLETION_LIMIT + 1
                    {
                        return Err("live channel exceeds bounded traffic".into());
                    }
                    self.buffer.extend_from_slice(&chunk[..n]);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => {
                    return Err("live channel read failed; original job remains unknown".into())
                }
            }
        }
    }
    fn send(&mut self, value: &Value) -> Result<(), String> {
        let mut raw = bytes(value)?;
        if raw.len() > 6 * 1024 * 1024 {
            return Err("live response frame exceeds bound".into());
        }
        raw.push(b'\n');
        let mut offset = 0;
        while offset < raw.len() {
            self.check()?;
            match self.input.write(&raw[offset..]) {
                Ok(0) => return Err("live response pipe closed".into()),
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(_) => {
                    return Err("live response transport failed; never replay model request".into())
                }
            }
        }
        Ok(())
    }
}
#[cfg(test)]
#[path = "live_campaign_tests.rs"]
mod tests;
pub(super) fn execute(
    j: &Journal,
    i: &Intent,
    lima: &mut Lima,
    run: bool,
) -> Result<Vec<u8>, String> {
    if !run {
        return super::super::transport::execute(j, i, lima, false);
    }
    j.require_dispatch(i)?;
    let prepared = provisioned(j, i)?;
    recheck_provider(i)?;
    let keys = HostControllerKeyPinJournal::open(&j.path)
        .map_err(|_| "live Host key journal unavailable")?;
    if !matches!(keys.read(i.job()), Err(crate::HostKeyPinError::Missing)) {
        return Err("live prelaunch already pinned or uncertain; never rerun".into());
    }
    let request=WorkerRequest::parse(&bytes(&json!({"schema":"hol-gauntlet-worker-request.v1","action":"run","source_sha":i.text("source_sha"),"job_id":i.job(),"deployment_digest":i.text("deployment_digest")}))?).map_err(|_|"live worker request invalid")?;
    let worker = format!(
        "/opt/hol-gauntlet/rust-native-host-pinned-worker-{}",
        i.text("worker_generation")
    );
    let child = lima
        .command(i.text("vm"))?
        .args([
            worker.as_str(),
            "--live-native-host-pinned-v1",
            i.text("source_sha"),
            i.text("deployment_digest"),
            i.text("worker_generation"),
            text(&prepared, "receipt_sha256")?,
        ])
        .spawn()
        .map_err(|_| "live VM dispatch consumed; reconcile original job without retry")?;
    let mut accepted = keys
        .send_native_run_request_and_accept_prepared_child(
            child,
            &request,
            &i.expected(),
            Duration::from_secs(210),
        )
        .map_err(|_| "live prelaunch uncertain; original dispatch remains consumed")?;
    let retained = accepted.record().clone();
    let (input, output) = accepted
        .take_live_pipes()
        .map_err(|_| "live acknowledged pipes unavailable")?;
    let active = spec()?.0["execution_budget"]["worker_active_seconds"]
        .as_u64()
        .ok_or("source active budget absent")?;
    let active_deadline = Instant::now() + Duration::from_secs(active);
    let mut frames = Frames::new(input, output, active_deadline + Duration::from_secs(120))?;
    let mut turn = 0_u64;
    let completion = loop {
        let raw = frames
            .line()?
            .ok_or("live channel closed without completion; read original job")?;
        let value = parse(&raw)?;
        if value["schema"] == "hol-gauntlet-native-host-pinned-completion.v3" {
            break raw;
        }
        if raw.len() > 2 * 1024 * 1024 {
            return Err("live model request frame exceeds bound".into());
        }
        turn += 1;
        validate_request(i, &value, turn)?;
        j.require_dispatch(i)?;
        lima.recheck()?;
        recheck_provider(i)?;
        j.write(i.job(), &suffix(turn, "request"), &raw)?;
        let remaining = active_deadline
            .checked_duration_since(Instant::now())
            .ok_or("live worker active budget expired before model dispatch")?;
        let live = context_value(i);
        let response = crate::live_provider_operation::relay_live_model_request_bounded(
            Path::new(text(live, "provider_journal")?),
            text(live, "provider_intent_sha256")?,
            &value,
            remaining.min(Duration::from_secs(900)),
        )?;
        let pins = response_pins(i, &value, &response)?;
        if turn > 1 {
            let previous = parse(&j.read(i.job(), &suffix(turn - 1, "response"))?)?;
            if previous["after"] != response["before"] {
                return Err("actual provider quota changed between cell turns".into());
            }
        }
        j.write(i.job(), &suffix(turn, "response"), &bytes(&response)?)?;
        j.write(i.job(), &suffix(turn, "pins"), &bytes(&pins)?)?;
        j.require_dispatch(i)?;
        lima.recheck()?;
        frames.send(&response)?;
    };
    frames.deadline = frames
        .deadline
        .min(Instant::now() + Duration::from_secs(30));
    if frames.line()?.is_some() {
        return Err("unexpected data after live terminal frame".into());
    }
    drop(frames);
    accepted
        .wait_bounded(Duration::from_secs(10))
        .map_err(|_| "live host transport exit uncertain")?;
    lima.recheck()?;
    if keys
        .read(i.job())
        .map_err(|_| "live Host pin unavailable")?
        != retained
    {
        return Err("live Host pin changed during execution".into());
    }
    j.require_dispatch(i)?;
    Ok(completion)
}
