//! The daemon helper inherits sockets and execs in place. Root authenticates
//! their objects without relaying or claiming ownership of socket bytes.
use super::*;
use gauntlet_product_cell::{
    inspect_native_socket_stdio, native_socket_helper, NATIVE_SOCKET_MARKER,
};

fn objects(task: &Task) -> Result<[(u64, u64); 2]> {
    let [input, output] = [0, 1].map(|fd| -> Result<(u64, u64)> {
        let info = rustix::fs::fstat(task.stdio_socket(fd)?).map_err(|e| e.to_string())?;
        Ok((info.st_dev, info.st_ino))
    });
    Ok([input?, output?])
}

fn receive_sockets(
    socket: &UnixStream,
    expected: [(u64, u64); 2],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<gauntlet_product_cell::NativeSocketStdio> {
    let endpoints: [OwnedFd; 2] =
        gauntlet_agent_bridge::receive_fd_frame(socket, NATIVE_SOCKET_MARKER, 2, deadline, cancel)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "two Native socket ends required")?;
    let stdio =
        inspect_native_socket_stdio(&endpoints[0], &endpoints[1]).map_err(|e| e.to_string())?;
    if stdio.objects != expected {
        return Err("Native socket handoff objects differ".into());
    }
    // Return only metadata. Live duplicates drop before the caller can ACK;
    // Root must not postpone the Python parent's real liveness EOF.
    Ok(stdio)
}

pub(super) fn session(
    mut socket: UnixStream,
    context: Context,
    id: u64,
    wrapper: Task,
    image: PipeProcessImage,
    mut argv: Vec<Vec<u8>>,
) -> Result<()> {
    let deadline = (Instant::now() + Duration::from_secs(5)).min(context.deadline);
    argv[0] = context.config.native_program.as_bytes().to_vec();
    let helper = native_socket_helper(&argv)
        .map_err(|e| e.to_string())?
        .ok_or("exact Native socket helper command required")?;
    let parent_pid = image.image["task"]["parent_pid"]
        .as_u64()
        .and_then(|v| u32::try_from(v).ok())
        .ok_or("Native socket helper parent unavailable")?;
    let parent = Task::open(parent_pid, context.cgroup()?)?;
    if parent.local_pid()? != helper.parent_pid || wrapper.parent_pid()? != parent.tid {
        return Err("actual Native socket helper parent differs".into());
    }
    let expected = objects(&wrapper)?;
    if image.pipes.is_some() || image.sockets != Some(expected) {
        return Err("Native socket objects differ from their actual exec stop".into());
    }
    let stdio = receive_sockets(&socket, expected, deadline, &context.cancel)?;
    context.append("native-socket-helper-handoff", json!({"session":id,"wrapper":image.image,
        "wrapper_exec_event":image.event,"parent_tid":parent.tid,"parent_start_ticks":parent.start,
        "sockets":stdio.objects,"listener":stdio.listener.to_string(),"health_peer_unnamed":true,
        "socket_bytes_observed":false,"execution_eligible":false,"exclusive_product_authorship_verified":false}))?;
    wrapper.recheck(context.cgroup()?)?;
    parent.recheck(context.cgroup()?)?;
    send(&mut socket, 1, deadline, &context.cancel)?;
    drop(socket);
    let actual = loop {
        if context.cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("actual Native socket helper exec stop join unavailable".into());
        }
        let row = context
            .images
            .get(wrapper.tid, wrapper.start)?
            .ok_or("Native socket helper exec history lost")?;
        if row.event != image.event {
            break row;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    crate::native_stdio_identity::privilege_floor(&actual.image, &context.actor)?;
    if actual.image["executable"]["sha256"] != context.config.native_sha256
        || actual.image["task"]["status"]["Seccomp"] != "2"
        || actual.image["task"]["status"]["Threads"] != "1"
        || actual.image["task"]["parent_pid"] != parent.tid
        || actual.pipes.is_some()
        || actual.sockets != Some(stdio.objects)
        || crate::native_stdio_identity::command(&actual.image)? != argv
    {
        return Err("actual Native socket helper exec, ancestry or objects differ".into());
    }
    parent.recheck(context.cgroup()?)?;
    context.append(
        "native-socket-helper-exec-bound",
        json!({"session":id,"process":actual.image,
        "exec_event":actual.event,"sockets":stdio.objects,"socket_bytes_observed":false,
        "execution_eligible":false,"exclusive_product_authorship_verified":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    #[test]
    fn socket_handoff_is_exact_and_drops_live_copies_before_acknowledgement() {
        for case in 0..5 {
            let (mut owner, mut actor) = UnixStream::pair().unwrap();
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let (health, mut parent) = UnixStream::pair().unwrap();
            parent
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            health
                .set_read_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            if case == 0 {
                parent.write_all(b"fixture-handshake\n").unwrap();
            }
            let mut expected = inspect_native_socket_stdio(&listener, &health)
                .unwrap()
                .objects;
            if case == 3 {
                expected[1].1 += 1;
            }
            let deadline = Instant::now() + Duration::from_secs(1);
            let passed = std::thread::spawn(move || {
                let result = receive_sockets(&owner, expected, deadline, &AtomicBool::new(false));
                if result.is_ok() {
                    send(&mut owner, 1, deadline, &AtomicBool::new(false)).unwrap();
                }
                result.is_ok()
            });
            let descriptors = if case == 4 {
                vec![health.as_fd(), listener.as_fd()]
            } else if case == 2 {
                vec![listener.as_fd()]
            } else {
                vec![listener.as_fd(), health.as_fd()]
            };
            gauntlet_agent_bridge::send_fd_frame(
                &actor,
                if case == 1 {
                    NATIVE_WIRE_MARKER
                } else {
                    NATIVE_SOCKET_MARKER
                },
                &descriptors,
                deadline,
                &AtomicBool::new(false),
            )
            .unwrap();
            drop(descriptors);
            assert_eq!(passed.join().unwrap(), case == 0);
            if case == 0 {
                assert_eq!(
                    receive::<1>(&mut actor, deadline, &AtomicBool::new(false)).unwrap(),
                    [1]
                );
                let mut endpoint = &health;
                let mut handshake = [0; 18];
                endpoint.read_exact(&mut handshake).unwrap();
                assert_eq!(&handshake, b"fixture-handshake\n");
                endpoint.write_all(b"A").unwrap();
                let mut activity = [0];
                parent.read_exact(&mut activity).unwrap();
                assert_eq!(activity, [b'A']);
            }
            drop(health);
            assert_eq!(
                parent.read(&mut [0]).unwrap(),
                0,
                "live socket retained in case {case}"
            );
        }
    }
}
