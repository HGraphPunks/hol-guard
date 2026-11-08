//! Unprivileged Native interface. Root still authenticates every process and
//! received descriptor; this connector's claims never confer admission.
use crate::{CellError, Result};
use serde_json::Value;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

pub const NATIVE_WIRE_CONFIG: &str = "/etc/hol-native-wire.v1.json";
pub const NATIVE_WIRE_MARKER: u8 = b'W';
const INVALID: CellError = CellError("invalid fixed Native wire configuration");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWireConfig {
    pub endpoint: String,
    pub native_program: String,
    pub native_sha256: String,
}
impl NativeWireConfig {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > 4096 {
            return Err(INVALID);
        }
        let canonical = gauntlet_contracts::canonicalize(raw).map_err(|_| INVALID)?;
        let value: Value = serde_json::from_slice(&canonical).map_err(|_| INVALID)?;
        let field = |name: &str| value[name].as_str().ok_or(INVALID);
        let hex = |s: &str, n| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let endpoint = field("endpoint")?;
        let program = field("native_program")?;
        let pin = field("native_sha256")?;
        if value.as_object().is_none_or(|v| v.len() != 4)
            || field("schema")? != "product-cell-native-wire.v1"
            || !endpoint
                .strip_prefix("hol-native-wire-")
                .is_some_and(|v| hex(v, 32))
            || !program.starts_with("/opt/hol-gauntlet/")
            || !program.ends_with(
                "/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime",
            )
            || program.len() > 2048
            || program.as_bytes().contains(&0)
            || program
                .split('/')
                .skip(1)
                .any(|v| v.is_empty() || matches!(v, "." | ".."))
            || !hex(pin, 64)
        {
            return Err(INVALID);
        }
        Ok(Self {
            endpoint: endpoint.into(),
            native_program: program.into(),
            native_sha256: pin.into(),
        })
    }
    pub fn to_json(&self) -> Value {
        serde_json::json!({"schema":"product-cell-native-wire.v1","endpoint":self.endpoint,
            "native_program":self.native_program,"native_sha256":self.native_sha256})
    }
}

pub(crate) fn validate_native_argv(argv: &[OsString]) -> Result<()> {
    if !(1..=128).contains(&argv.len())
        || !argv[0].as_bytes().starts_with(b"/")
        || argv.iter().any(|v| v.as_bytes().contains(&0))
        || argv
            .iter()
            .try_fold(0usize, |n, v| n.checked_add(v.as_bytes().len()))
            .is_none_or(|n| n > 65536)
    {
        return Err(CellError("bounded absolute Native argv required"));
    }
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub(crate) fn load() -> Result<NativeWireConfig> {
    let input = crate::root_input::read_root_input(std::path::Path::new(NATIVE_WIRE_CONFIG), 4096)?
        .ok_or(INVALID)?;
    NativeWireConfig::parse(&input.bytes)
}

pub fn run_native_wrapper(args: &[OsString]) -> Result<std::convert::Infallible> {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        linux::run(args)
    }
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    {
        let _ = args;
        Err(CellError("Native wire connector requires Linux ARM64"))
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod linux {
    use super::*;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::time::{Duration, Instant};

    static CHILD: AtomicI32 = AtomicI32::new(-1);
    extern "C" fn forward(signal: libc::c_int) {
        let error = unsafe { libc::__errno_location() };
        let saved = unsafe { *error };
        let pidfd = CHILD.load(Ordering::Relaxed);
        if pidfd >= 0 {
            // A held pidfd cannot signal a reused numeric PID after wait.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd,
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        unsafe { *error = saved };
    }
    struct OwnedChild(Child, Option<OwnedFd>);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            CHILD.store(-1, Ordering::Relaxed);
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn signals() -> Result<()> {
        for signal in [libc::SIGHUP, libc::SIGINT, libc::SIGQUIT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = forward as usize;
            action.sa_flags = libc::SA_RESTART;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
                || unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0
            {
                return Err(CellError("Native signal forwarding unavailable"));
            }
        }
        Ok(())
    }
    fn send(socket: &UnixStream, bytes: &[u8], deadline: Instant) -> Result<()> {
        gauntlet_agent_bridge::send_control_bytes(socket, bytes, deadline, &AtomicBool::new(false))
            .map_err(|_| CellError("Native handoff send failed"))
    }
    fn expect(socket: &mut UnixStream, byte: u8, deadline: Instant) -> Result<()> {
        let mut value = [0];
        gauntlet_agent_bridge::receive_control_bytes(
            socket,
            &mut value,
            deadline,
            &AtomicBool::new(false),
        )
        .map_err(|_| CellError("Native handoff acknowledgement missing"))?;
        if value != [byte] {
            return Err(CellError("Native handoff acknowledgement differs"));
        }
        Ok(())
    }
    fn root_peer(socket: &UnixStream) -> Result<()> {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of_val(&peer)
            || peer.uid != 0
            || peer.gid != 0
        {
            return Err(CellError("outside Root Native handoff owner required"));
        }
        // Root may be outside this PID namespace, so its translated PID can be zero.
        Ok(())
    }
    fn connect(endpoint: &[u8]) -> Result<UnixStream> {
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        if endpoint.is_empty() || endpoint.len() >= address.sun_path.len() || endpoint.contains(&0)
        {
            return Err(INVALID);
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, byte) in address.sun_path[1..].iter_mut().zip(endpoint) {
            *target = *byte as libc::c_char;
        }
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(CellError("Native owner socket unavailable"));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + 1 + endpoint.len();
        // AF_UNIX completes locally. A full backlog (EAGAIN), interrupted or
        // otherwise incomplete connection refuses this one-use attempt. It
        // cannot block before the handoff's absolute deadline is established.
        if unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length as libc::socklen_t,
            )
        } != 0
        {
            return Err(CellError("Root Native owner unavailable or busy"));
        }
        Ok(UnixStream::from(fd))
    }
    pub(super) fn run(args: &[OsString]) -> Result<std::convert::Infallible> {
        crate::exec_gate::product_identity()?;
        let config = load()?;
        let mut argv = vec![OsString::from(&config.native_program)];
        argv.extend_from_slice(args);
        validate_native_argv(&argv)?;
        let mut owner = connect(config.endpoint.as_bytes())?;
        root_peer(&owner)?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut control, gate_control) =
            UnixStream::pair().map_err(|_| CellError("Native gate channel unavailable"))?;
        let gate_fd = gate_control.as_raw_fd();
        let parent = unsafe { libc::getpid() };
        let mut command = Command::new("/public/gauntlet-product-cell");
        command
            .arg("native-gate")
            .args(&argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        // Only async-signal-safe descriptor/prctl operations precede exec.
        // The blocking gate runs after exec, beyond Command::spawn's error pipe.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0
                    || libc::getppid() != parent
                    || libc::dup2(gate_fd, 3) < 0
                    || libc::fcntl(3, libc::F_SETFD, 0) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = OwnedChild(
            command
                .spawn()
                .map_err(|_| CellError("unprivileged Native gate spawn failed"))?,
            None,
        );
        let pid = rustix::process::Pid::from_raw(child.0.id() as i32)
            .ok_or(CellError("Native child PID invalid"))?;
        child.1 = Some(
            rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
                .map_err(|_| CellError("Native child pidfd unavailable"))?,
        );
        CHILD.store(child.1.as_ref().unwrap().as_raw_fd(), Ordering::Relaxed);
        signals()?;
        drop(gate_control);
        expect(&mut control, b'G', deadline)?;
        let input = child
            .0
            .stdin
            .take()
            .ok_or(CellError("Native stdin unavailable"))?;
        let output = child
            .0
            .stdout
            .take()
            .ok_or(CellError("Native stdout unavailable"))?;
        let stdin = unsafe { BorrowedFd::borrow_raw(0) };
        let stdout = unsafe { BorrowedFd::borrow_raw(1) };
        gauntlet_agent_bridge::send_fd_frame(
            &owner,
            NATIVE_WIRE_MARKER,
            &[stdin, input.as_fd(), output.as_fd(), stdout],
            deadline,
            &AtomicBool::new(false),
        )
        .map_err(|_| CellError("Native descriptor handoff refused"))?;
        // Do not coalesce metadata with the exact one-byte descriptor frame.
        expect(&mut owner, 1, deadline)?;
        send(&owner, &child.0.id().to_be_bytes(), deadline)?;
        expect(&mut owner, 2, deadline)?;
        drop(input);
        drop(output);
        // Root verifies the sender no longer holds any of the four pipe ends.
        if unsafe { libc::close(0) } != 0 || unsafe { libc::close(1) } != 0 {
            return Err(CellError("Native sender pipe closure uncertain"));
        }
        send(&owner, &[3], deadline)?;
        expect(&mut owner, 4, deadline)?;
        send(&control, &[1], deadline)?;
        drop(control);
        drop(owner);
        let status = child
            .0
            .wait()
            .map_err(|_| CellError("Native final status unavailable"))?;
        CHILD.store(-1, Ordering::Relaxed);
        if let Some(signal) = status.signal() {
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            return Err(CellError("Native signal propagation failed"));
        }
        std::process::exit(status.code().unwrap_or(126));
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixListener};
        #[test]
        fn absent_and_saturated_abstract_owners_cannot_block_connect() {
            let endpoint = format!(
                "gauntlet-wire-connect-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            assert!(connect(endpoint.as_bytes()).is_err());
            let address = SocketAddr::from_abstract_name(endpoint.as_bytes()).unwrap();
            let listener = UnixListener::bind_addr(&address).unwrap();
            assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
            let mut connections = Vec::new();
            let mut refused = false;
            for _ in 0..256 {
                match connect(endpoint.as_bytes()) {
                    Ok(socket) => {
                        assert_ne!(
                            unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) }
                                & libc::O_NONBLOCK,
                            0
                        );
                        connections.push(socket);
                    }
                    Err(_) => {
                        refused = true;
                        break;
                    }
                }
            }
            assert!(
                refused && !connections.is_empty(),
                "connected {} sockets",
                connections.len()
            );
            drop(connections);
            drop(listener);
            assert!(connect(endpoint.as_bytes()).is_err());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn configuration_pins_one_root_endpoint_and_the_actual_native_program() {
        let config = NativeWireConfig { endpoint: format!("hol-native-wire-{}", "a".repeat(32)),
            native_program: "/opt/hol-gauntlet/candidates/source/prefix/lib/python3.12/site-packages/codex_plugin_scanner/_native/hol-guard-runtime".into(),
            native_sha256: "b".repeat(64) };
        let good = config.to_json();
        assert_eq!(
            NativeWireConfig::parse(good.to_string().as_bytes()).unwrap(),
            config
        );
        for (key, value) in [
            ("schema", Value::from("other")),
            ("endpoint", Value::from("/tmp/root.sock")),
            ("native_program", Value::from("/tmp/hol-guard-runtime")),
            ("native_sha256", Value::from("B".repeat(64))),
            ("extra", Value::Null),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(NativeWireConfig::parse(bad.to_string().as_bytes()).is_err());
        }
        let duplicate = good.to_string().replacen('{', "{\"schema\":\"wrong\",", 1);
        assert!(NativeWireConfig::parse(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn argv_preserves_binary_arguments_but_refuses_oversized_or_relative_commands() {
        use std::os::unix::ffi::OsStringExt;
        assert!(validate_native_argv(&["/native".into(), OsString::from_vec(vec![255])]).is_ok());
        for argv in [
            vec![],
            vec!["native".into()],
            vec!["/native".into(); 129],
            vec!["/native".into(), OsString::from_vec(vec![0])],
            vec![format!("/{}", "x".repeat(65536)).into()],
        ] {
            assert!(validate_native_argv(&argv).is_err());
        }
    }
}
