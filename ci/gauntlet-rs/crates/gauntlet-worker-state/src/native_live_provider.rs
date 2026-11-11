//! Root-owned live inference relay. Only the original worker's inherited
//! private descriptor can reach Host; no URL or credential enters the guest.
use crate::native_live_http::{normalize_request, read_frame, write_frame};
use crate::native_live_model::{
    sha, NativeLiveModelLedger, REQUEST_FRAME_LIMIT, RESPONSE_FRAME_LIMIT,
};
use crate::native_sdk_peer::NativeSdkModelPeer;
use crate::{NativeJobSpec, NativeLiveJob, NativeSdkBoundary, NativeSdkSockets};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustix::fs::{fstat, openat, Mode, OFlags};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{Read, Write},
    net::Shutdown,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::net::UnixStream,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};

pub(crate) const MODEL_CHANNEL_FD: i32 = 4;

pub(crate) fn inherited_channel(generation: &str) -> Result<UnixStream, String> {
    let mut peer = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt fills only the supplied ucred. This exact FD is handed
    // off by the trusted worker, separate from controller key3 and World key5.
    if unsafe {
        libc::getsockopt(
            MODEL_CHANNEL_FD,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            peer.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
    {
        return Err("inherited live model channel unavailable".into());
    }
    let peer = unsafe { peer.assume_init() };
    if peer.uid != 0 || peer.gid != 0 || peer.pid <= 0 || peer.pid != unsafe { libc::getppid() } {
        return Err("live model channel is not owned by the original Root worker".into());
    }
    let mut program = File::open(format!("/proc/{}/exe", peer.pid))
        .map_err(|_| "original model worker executable unavailable")?;
    let before = fstat(&program).map_err(|_| "original model worker metadata unavailable")?;
    if before.st_uid != 0
        || before.st_gid != 0
        || before.st_nlink != 1
        || before.st_mode & 0o177777 != 0o100500
        || before.st_size <= 0
        || before.st_size > 128 * 1024 * 1024
    {
        return Err("original model worker executable custody differs".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut program)
        .take(128 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "original model worker read failed")?;
    if bytes.len() as i64 != before.st_size
        || sha(&bytes) != generation
        || !crate::dependency_prefix_meta::same(
            &before,
            &fstat(&program).map_err(|_| "original model worker changed")?,
        )
    {
        return Err("original model worker pin differs".into());
    }
    // SAFETY: this inherited descriptor transfers once to the Root controller.
    let channel = unsafe { UnixStream::from_raw_fd(MODEL_CHANNEL_FD) };
    if unsafe { libc::fcntl(channel.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err("live model channel could leak across exec".into());
    }
    channel
        .set_read_timeout(Some(Duration::from_secs(
            crate::native_live_spec::ACTIVE_SECONDS,
        )))
        .and_then(|_| channel.set_write_timeout(Some(Duration::from_secs(30))))
        .map_err(|_| "bounded inherited live model channel required")?;
    Ok(channel)
}

pub(crate) struct NativeLiveProvider {
    channel: UnixStream,
    parent: UnixStream,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<(), String>>>,
    ledger: Arc<Mutex<NativeLiveModelLedger>>,
    turns: Arc<Mutex<Vec<Value>>>,
    peer: Value,
}
impl NativeLiveProvider {
    pub(crate) fn bind(
        job: &NativeJobSpec,
        live: &NativeLiveJob,
        sockets: &NativeSdkSockets,
        boundary: NativeSdkBoundary,
        program: &File,
        mut parent: UnixStream,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut socket = loop {
            if let Some(socket) = sockets.accept_model()? {
                break socket;
            }
            if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err("live model bridge did not bind before deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(
                crate::native_live_spec::ACTIVE_SECONDS,
            )))
            .and_then(|_| socket.set_write_timeout(Some(Duration::from_secs(30))))
            .map_err(|_| "bounded SDK model channel required")?;
        let peer = NativeSdkModelPeer::bind(
            &socket,
            boundary,
            program,
            &job.source_sha,
            &job.job_id,
            &job.worker_generation,
            &live.model.budget_digest,
        )?;
        let hello = read_frame(&mut socket, 4096)?;
        if hello
            != json!({"schema":"hol-gauntlet-native-live-http-hello.v1","source_sha":job.source_sha,"job_id":job.job_id,
            "worker_generation":job.worker_generation,"budget_digest":live.model.budget_digest})
        {
            return Err("live model bridge context differs".into());
        }
        peer.recheck(&socket)?;
        write_frame(
            &mut socket,
            &json!({"schema":"hol-gauntlet-native-live-http-ready.v1","source_sha":job.source_sha,
            "job_id":job.job_id,"budget_digest":live.model.budget_digest}),
            4096,
        )?;
        let observation = peer.observation();
        let root =
            crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
        let fd = openat(
            &root,
            "live-provider-events.v1.jsonl",
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| e.to_string())?;
        let mut journal = File::from(fd);
        let ledger = Arc::new(Mutex::new(NativeLiveModelLedger::new(
            &job.source_sha,
            &job.job_id,
            &live.model,
        )?));
        let turns = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (l, t, s) = (ledger.clone(), turns.clone(), stop.clone());
        let channel = socket.try_clone().map_err(|e| e.to_string())?;
        let retained_parent = parent.try_clone().map_err(|e| e.to_string())?;
        let thread=std::thread::Builder::new().name("root-live-model-channel".into()).spawn(move||{
            let mut sequence=0;let mut total=0;
            let mut retain=|kind:&str,value:&Value|->Result<(),String>{
                sequence+=1;let mut raw=gauntlet_contracts::canonicalize(json!({"sequence":sequence,"kind":kind,"data":value}).to_string().as_bytes()).map_err(|_|"live model journal encoding failed")?;
                raw.push(b'\n');total+=raw.len();if total>64*1024*1024{return Err("live model journal byte budget exhausted".into());}
                journal.write_all(&raw).and_then(|_|journal.sync_all()).map_err(|_|"live model journal commit uncertain".into())
            };
            loop {
                if s.load(Ordering::Acquire)||cancel.load(Ordering::Acquire){return Ok(());}
                let incoming=match read_frame(&mut socket,REQUEST_FRAME_LIMIT) {Ok(v)=>v,Err(_) if s.load(Ordering::Acquire)=>return Ok(()),Err(e)=>return Err(e)};
                peer.recheck(&socket)?;
                if incoming.as_object().is_none_or(|o|o.len()!=4)||incoming["schema"]!="hol-gauntlet-native-live-sdk-model-request.v1" {return Err("closed actual SDK model request required".into());}
                let encoded=incoming["body_b64"].as_str().ok_or("actual SDK model bytes missing")?;
                let raw=STANDARD.decode(encoded).map_err(|_|"actual SDK model encoding invalid")?;
                if raw.len()>crate::native_live_model::REQUEST_LIMIT||STANDARD.encode(&raw)!=encoded||incoming["sdk_request_sha256"]!=sha(&raw){return Err("actual SDK model byte pin differs".into());}
                let (normalized,streamed)=normalize_request(&raw)?;
                let request=l.lock().map_err(|_|"live model ledger poisoned")?.begin(&normalized,&sha(&raw))?;
                if incoming["turn"]!=request["turn"]{return Err("SDK model turn was changed or repeated".into());}
                retain("model-request-consumed",&request)?;
                write_frame(&mut parent,&request,REQUEST_FRAME_LIMIT)?;
                let response=read_frame(&mut parent,RESPONSE_FRAME_LIMIT)?;
                let response_raw=gauntlet_contracts::canonicalize(response.to_string().as_bytes()).map_err(|_|"live model response encoding failed")?;
                let body=l.lock().map_err(|_|"live model ledger poisoned")?.finish(&response_raw)?;
                let expected_delivery=if streamed{crate::native_live_http::sse_response(&body)?}else{body.clone()};
                retain("model-response-settled",&response)?;
                let request_raw=gauntlet_contracts::canonicalize(request.to_string().as_bytes()).map_err(|_|"live model request encoding failed")?;
                t.lock().map_err(|_|"live provider turns poisoned")?.push(json!({"request":format!("{}\n",std::str::from_utf8(&request_raw).map_err(|_|"live request UTF8")?),
                    "response":format!("{}\n",std::str::from_utf8(&response_raw).map_err(|_|"live response UTF8")?),"usage":response["usage_receipt"],"before":response["before"],"after":response["after"]}));
                peer.recheck(&socket)?;
                write_frame(&mut socket,&json!({"schema":"hol-gauntlet-native-live-sdk-model-response.v1","turn":request["turn"],
                    "sdk_request_sha256":sha(&raw),"response_sha256":sha(&body),"body_b64":STANDARD.encode(&body)}),RESPONSE_FRAME_LIMIT)?;
                let delivered=read_frame(&mut socket,4096)?;
                if delivered.as_object().is_none_or(|o|o.len()!=5)||delivered["schema"]!="hol-gauntlet-native-live-sdk-model-delivered.v1"
                    ||delivered["turn"]!=request["turn"]||delivered["sdk_request_sha256"]!=sha(&raw)
                    ||delivered["delivery_sha256"]!=sha(&expected_delivery)||delivered["delivery_bytes"]!=expected_delivery.len() {return Err("actual SDK model delivery acknowledgment differs".into());}
                peer.recheck(&socket)?;retain("model-response-delivered",&delivered)?;
                l.lock().map_err(|_|"live model ledger poisoned")?.delivered()?;
            }
        }).map_err(|e|e.to_string())?;
        Ok(Self {
            channel,
            parent: retained_parent,
            stop,
            thread: Some(thread),
            ledger,
            turns,
            peer: observation,
        })
    }
    pub(crate) fn close(&mut self) -> Value {
        let grace = Instant::now() + Duration::from_secs(3);
        while self.thread.is_some() && Instant::now() < grace {
            let settled = self
                .ledger
                .lock()
                .map(|l| {
                    let o = l.observation();
                    o["pending_turn"].is_null()
                        && o["turns"]
                            .as_array()
                            .is_some_and(|a| a.iter().all(|t| t["delivered_to_sdk"] == true))
                })
                .unwrap_or(false);
            if settled {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        self.stop.store(true, Ordering::Release);
        let _ = self.channel.shutdown(Shutdown::Both);
        let _ = self.parent.shutdown(Shutdown::Both);
        let error = self.thread.take().and_then(|t| match t.join() {
            Ok(r) => r.err(),
            Err(_) => Some("live model relay panicked".into()),
        });
        let ledger = self
            .ledger
            .lock()
            .map(|l| l.observation())
            .unwrap_or(Value::Null);
        let turns = self.turns.lock().map(|t| t.clone()).unwrap_or_default();
        json!({"schema":"hol-gauntlet-native-live-provider.v1","peer":self.peer,"ledger":ledger,"provider_turns":turns,
            "error":error,"execution_eligible":false,"qualification_eligible":false})
    }
}
impl Drop for NativeLiveProvider {
    fn drop(&mut self) {
        if self.thread.is_some() {
            let _ = self.close();
        }
    }
}
