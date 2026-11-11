//! Fixed worker/Host live channel over the already pinned SSH descriptors.
//! Provider messages are serial; an uncertain frame never receives a retry.
use crate::native_live_model::{sha, REQUEST_FRAME_LIMIT, RESPONSE_FRAME_LIMIT};
use crate::BoottimeDeadline;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::Value;
use std::{
    fs::File,
    net::Shutdown,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) struct NativeLiveDispatch {
    pub channel: UnixStream,
    pub prepared_sha256: String,
    pub requests: Arc<AtomicU64>,
    pub pending: Arc<AtomicBool>,
}
fn duplicate(fd: &impl AsRawFd) -> Result<File, String> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 16) };
    if raw < 0 {
        return Err("live Host descriptor retention failed".into());
    }
    Ok(unsafe { File::from_raw_fd(raw) })
}
struct Nonblocking {
    fd: File,
    flags: i32,
}
impl Nonblocking {
    fn new(fd: &impl AsRawFd) -> Result<Self, String> {
        let fd = duplicate(fd)?;
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err("bounded live Host descriptors required".into());
        }
        Ok(Self { fd, flags })
    }
}
impl Drop for Nonblocking {
    fn drop(&mut self) {
        unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_SETFL, self.flags) };
    }
}
fn ready(fd: i32, event: i16, stop: &AtomicBool, deadline: Instant) -> Result<(), String> {
    loop {
        if stop.load(Ordering::Acquire)
            || crate::native_worker::cancellation_requested()
            || Instant::now() >= deadline
        {
            return Err("live Host channel cancelled or expired".into());
        }
        let mut poll = libc::pollfd {
            fd,
            events: event,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, 100) };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err("live Host channel poll failed".into());
        }
        if result == 0 {
            continue;
        }
        if poll.revents & (libc::POLLNVAL | libc::POLLERR) != 0 {
            return Err("live Host channel failed".into());
        }
        if poll.revents & event != 0 {
            return Ok(());
        }
        if poll.revents & libc::POLLHUP != 0 {
            if event == libc::POLLIN {
                return Ok(());
            }
            return Err("live Host channel ended".into());
        }
    }
}
fn write_line(fd: i32, raw: &[u8], stop: &AtomicBool, deadline: Instant) -> Result<(), String> {
    if raw.is_empty() || raw.len() > REQUEST_FRAME_LIMIT || raw.contains(&b'\n') {
        return Err("bounded canonical live request frame required".into());
    }
    let mut raw = raw.to_vec();
    raw.push(b'\n');
    let mut offset = 0;
    while offset < raw.len() {
        ready(fd, libc::POLLOUT, stop, deadline)?;
        let count = unsafe {
            libc::write(
                fd,
                raw[offset..].as_ptr().cast(),
                (raw.len() - offset).min(65536),
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        return Err("live Host request delivery uncertain".into());
    }
    Ok(())
}
fn read_line(fd: i32, stop: &AtomicBool, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut raw = Vec::new();
    let mut buffer = [0; 65536];
    loop {
        ready(fd, libc::POLLIN, stop, deadline)?;
        let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        if count <= 0 {
            return Err("live Host response ended before complete frame".into());
        }
        raw.extend_from_slice(&buffer[..count as usize]);
        if raw.len() > RESPONSE_FRAME_LIMIT + 1 {
            return Err("live Host response frame exceeds bound".into());
        }
        if let Some(index) = raw.iter().position(|b| *b == b'\n') {
            if index + 1 != raw.len() || index == 0 {
                return Err("live Host response frame boundary differs".into());
            }
            raw.pop();
            return Ok(raw);
        }
    }
}

fn read_exact(
    fd: i32,
    raw: &mut [u8],
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<bool, String> {
    let mut offset = 0;
    while offset < raw.len() {
        ready(fd, libc::POLLIN, stop, deadline)?;
        let count =
            unsafe { libc::read(fd, raw[offset..].as_mut_ptr().cast(), raw.len() - offset) };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count == 0 && offset == 0 {
            return Ok(false);
        }
        if count < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        return Err("live controller frame ended partially".into());
    }
    Ok(true)
}
fn controller_frame(
    fd: i32,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<Option<Value>, String> {
    let mut length = [0; 4];
    if !read_exact(fd, &mut length, stop, deadline)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > REQUEST_FRAME_LIMIT {
        return Err("live controller frame bound exceeded".into());
    }
    let mut raw = vec![0; length];
    if !read_exact(fd, &mut raw, stop, deadline)? {
        return Err("live controller frame body missing".into());
    }
    if gauntlet_contracts::canonicalize(&raw).map_err(|_| "live controller frame JSON invalid")?
        != raw
    {
        return Err("canonical live controller frame required".into());
    }
    serde_json::from_slice(&raw)
        .map(Some)
        .map_err(|_| "live controller frame JSON invalid".into())
}
fn controller_response(
    fd: i32,
    value: &Value,
    stop: &AtomicBool,
    deadline: Instant,
) -> Result<(), String> {
    let raw = gauntlet_contracts::canonicalize(value.to_string().as_bytes())
        .map_err(|_| "live controller response JSON invalid")?;
    if raw.is_empty() || raw.len() > RESPONSE_FRAME_LIMIT {
        return Err("live controller response frame exceeds bound".into());
    }
    let mut framed = (raw.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(&raw);
    let mut offset = 0;
    while offset < framed.len() {
        ready(fd, libc::POLLOUT, stop, deadline)?;
        let count = unsafe {
            libc::write(
                fd,
                framed[offset..].as_ptr().cast(),
                (framed.len() - offset).min(65536),
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count < 0
            && matches!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            )
        {
            continue;
        }
        return Err("live controller response delivery uncertain".into());
    }
    Ok(())
}

pub fn dispatch_native_worker_live_pipe(
    source: &str,
    deployment: &str,
    generation: &str,
    prepared_sha256: &str,
    input: &impl AsRawFd,
    output: &impl AsRawFd,
) -> Result<Vec<u8>, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    crate::verify_running_binary(generation).map_err(|e| e.to_string())?;
    if !crate::hex(prepared_sha256, 64) {
        return Err("outside live preparation receipt SHA required".into());
    }
    let request = crate::read_run_request_pipe(
        input,
        &BoottimeDeadline::start(60).map_err(|e| e.to_string())?,
        &AtomicBool::new(false),
    )
    .map_err(|e| e.to_string())?;
    if request.source_sha() != source || request.deployment_digest() != Some(deployment) {
        return Err("live run differs from outside source/deployment".into());
    }
    let (spec, _) = crate::native_job_io::load(&request, generation)?;
    let live = match &spec.execution {
        crate::NativeJobExecution::HostPinnedLive { live, .. } => live.clone(),
        _ => return Err("live selector requires explicit live OMP profile".into()),
    };
    let (relay, channel) = UnixStream::pair().map_err(|e| e.to_string())?;
    relay.set_nonblocking(true).map_err(|e| e.to_string())?;
    let input = Nonblocking::new(input)?;
    let output = Nonblocking::new(output)?;
    let stop = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicU64::new(0));
    let pending = Arc::new(AtomicBool::new(false));
    let dispatch = NativeLiveDispatch {
        channel,
        prepared_sha256: prepared_sha256.into(),
        requests: requests.clone(),
        pending: pending.clone(),
    };
    let (s, c, p) = (stop.clone(), requests.clone(), pending.clone());
    let reader = duplicate(&input.fd)?;
    let writer = duplicate(&output.fd)?;
    let source = source.to_owned();
    let deployment = deployment.to_owned();
    let generation = generation.to_owned();
    let cell = spec.job_id.clone();
    let relay_source = source.clone();
    let thread = std::thread::Builder::new()
        .name("root-live-host-relay".into())
        .spawn(move || -> Result<(), String> {
            let deadline =
                Instant::now() + Duration::from_secs(crate::native_live_spec::ACTIVE_SECONDS);
            loop {
                if s.load(Ordering::Acquire) {
                    return Ok(());
                }
                let frame = match controller_frame(relay.as_raw_fd(), &s, deadline) {
                    Ok(Some(value)) => value,
                    Ok(None) if !p.load(Ordering::Acquire) => return Ok(()),
                    Err(_) if s.load(Ordering::Acquire) => return Ok(()),
                    Ok(None) => {
                        return Err("live model channel ended with a pending request".into())
                    }
                    Err(e) => return Err(e),
                };
                let turn = c.load(Ordering::Acquire) + 1;
                if frame.as_object().is_none_or(|o| o.len() != 8)
                    || frame["schema"] != "hol-gauntlet-native-live-model-request.v1"
                    || frame["source_sha"] != relay_source
                    || frame["provider_job_id"] != live.model.provider_job_id
                    || frame["job_id"] != cell
                    || frame["budget_digest"] != live.model.budget_digest
                    || frame["turn"] != turn
                    || turn > live.model.max_turns
                    || frame["request_sha256"]
                        .as_str()
                        .is_none_or(|v| !crate::hex(v, 64))
                {
                    return Err(
                        "live controller request differs from outside job/budget/turn".into(),
                    );
                }
                let encoded = frame["body_b64"]
                    .as_str()
                    .ok_or("live controller request bytes missing")?;
                let body = STANDARD
                    .decode(encoded)
                    .map_err(|_| "live controller request encoding differs")?;
                if body.is_empty()
                    || body.len() > crate::native_live_model::REQUEST_LIMIT
                    || STANDARD.encode(&body) != encoded
                    || frame["request_sha256"] != sha(&body)
                {
                    return Err("live controller request byte pin differs".into());
                }
                let raw = gauntlet_contracts::canonicalize(frame.to_string().as_bytes())
                    .map_err(|_| "live request JSON invalid")?;
                p.store(true, Ordering::Release);
                c.store(turn, Ordering::Release);
                write_line(writer.as_raw_fd(), &raw, &s, deadline)?;
                let response = read_line(reader.as_raw_fd(), &s, deadline)?;
                if gauntlet_contracts::canonicalize(&response)
                    .map_err(|_| "live response JSON invalid")?
                    != response
                {
                    return Err("canonical live response required".into());
                }
                let response: Value =
                    serde_json::from_slice(&response).map_err(|_| "live response JSON invalid")?;
                if response["schema"] != "hol-gauntlet-native-live-model-response.v1"
                    || response["source_sha"] != relay_source
                    || response["provider_job_id"] != live.model.provider_job_id
                    || response["job_id"] != cell
                    || response["budget_digest"] != live.model.budget_digest
                    || response["turn"] != turn
                    || response["request_sha256"] != frame["request_sha256"]
                {
                    return Err("Host live response differs from original consumed request".into());
                }
                controller_response(relay.as_raw_fd(), &response, &s, deadline)?;
                p.store(false, Ordering::Release);
            }
        })
        .map_err(|e| e.to_string())?;
    let raw = gauntlet_contracts::canonicalize(request.to_json().to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    let result = crate::native_worker::dispatch_native_worker_inner(
        &source,
        &deployment,
        &generation,
        &raw,
        Some(&mut |prepared, deadline, cancel| {
            crate::exchange_prelaunch_pipe(prepared, &output.fd, &input.fd, deadline, cancel)
                .map_err(|e| e.to_string())
        }),
        Some(&dispatch),
    );
    stop.store(true, Ordering::Release);
    let _ = dispatch.channel.shutdown(Shutdown::Both);
    let relayed = thread.join().map_err(|_| "live Host relay panicked")?;
    result.and_then(|value| relayed.map(|_| value))
}
