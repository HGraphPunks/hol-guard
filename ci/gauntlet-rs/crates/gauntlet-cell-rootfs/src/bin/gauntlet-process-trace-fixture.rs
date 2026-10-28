//! Trusted fixture only: creates its own UID10004 graph after a pipe gate.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod native_stdio_fixture;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod fixture {
    use std::io::{Read, Write};

    fn gate() {
        println!("trace-fixture-ready");
        std::io::stdout().flush().unwrap();
        let mut byte = [0];
        std::io::stdin().read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'G']);
    }

    fn child() -> bool {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "owned fixture fork");
        pid == 0
    }

    fn reap() -> i32 {
        let mut status = 0;
        assert!(unsafe { libc::waitpid(-1, &mut status, 0) } > 0);
        status
    }

    fn exit(code: i32) -> ! {
        unsafe { libc::_exit(code) }
    }

    pub(super) fn run() {
        assert!(
            unsafe {
                libc::getuid() == 10004
                    && libc::geteuid() == 10004
                    && libc::getgid() == 10004
                    && libc::getegid() == 10004
                    && libc::getgroups(0, std::ptr::null_mut()) == 0
                    && libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
            },
            "unprivileged isolated fixture identity required"
        );
        unsafe {
            libc::alarm(10);
        }
        let args = std::env::args().collect::<Vec<_>>();
        assert_eq!(args.len(), 2);
        if args[1].starts_with("stdio-") && args[1].ends_with("-leaf") {
            super::native_stdio_fixture::run(&args[1]);
        }
        if args[1] == "leaf" {
            exit(0);
        }
        gate();
        match args[1].as_str() {
            "stdio-scalar" | "stdio-vector" | "stdio-partial" | "stdio-rebind" | "stdio-linger"
            | "stdio-oversize" => {
                use std::os::unix::process::CommandExt;
                let error = std::process::Command::new("/proc/self/exe")
                    .arg(format!("{}-leaf", args[1]))
                    .exec();
                panic!("owned stdio fixture exec: {error}");
            }
            "fork-tree" => {
                if child() {
                    assert!(unsafe { libc::setsid() } > 0);
                    if child() {
                        exit(17);
                    }
                    assert_eq!(reap(), 17 << 8);
                    exit(23);
                }
                assert_eq!(reap(), 23 << 8);
                let code = std::process::Command::new("/proc/self/exe")
                    .arg("leaf")
                    .status()
                    .unwrap();
                assert!(code.success());
                if child() {
                    unsafe {
                        libc::signal(libc::SIGTRAP, libc::SIG_DFL);
                        libc::raise(libc::SIGTRAP);
                    }
                    exit(99);
                }
                assert_eq!(reap() & 0x7f, libc::SIGTRAP);
            }
            "thread-exec" => {
                std::thread::spawn(|| {
                    let exe = c"/proc/self/exe";
                    let mode = c"leaf";
                    let argv = [exe.as_ptr(), mode.as_ptr(), std::ptr::null()];
                    unsafe {
                        libc::execv(exe.as_ptr(), argv.as_ptr());
                    }
                    exit(98);
                });
                loop {
                    std::thread::park();
                }
            }
            "group-stop" => {
                let pid = unsafe { libc::fork() };
                assert!(pid >= 0);
                if pid == 0 {
                    unsafe {
                        libc::raise(libc::SIGSTOP);
                    }
                    exit(7);
                }
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) },
                    pid
                );
                assert_eq!(status, libc::SIGSTOP << 8 | 0x7f);
                assert_eq!(unsafe { libc::kill(pid, libc::SIGCONT) }, 0);
                assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
                assert_eq!(status, 7 << 8);
            }
            "rapid-exit" => {
                for _ in 0..64 {
                    if child() {
                        exit(0);
                    }
                    assert_eq!(reap(), 0);
                }
            }
            "linger" => {
                if child() {
                    assert!(unsafe { libc::setsid() } > 0);
                    loop {
                        unsafe {
                            libc::pause();
                        }
                    }
                }
                println!("trace-fixture-descendant-created");
                std::io::stdout().flush().unwrap();
                loop {
                    unsafe {
                        libc::pause();
                    }
                }
            }
            _ => exit(97),
        }
    }
}

fn main() {
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    fixture::run();
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64")))]
    panic!("owned Linux ARM64 process trace fixture required");
}
