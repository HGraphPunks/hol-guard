//! Synthetic pipe I/O only, entered after exec by the owned fixture driver.
use std::io::{Read, Write};

pub const FRAME: &[u8] = b"\0\0\0\x09{\"x\":123}";

pub fn run(mode: &str) -> ! {
    match mode {
        "stdio-scalar-leaf" => {
            let mut input = vec![0; FRAME.len()];
            std::io::stdin().read_exact(&mut input[..1]).unwrap();
            std::io::stdin().read_exact(&mut input[1..]).unwrap();
            assert_eq!(input, FRAME);
            std::io::stdout().write_all(&input[..2]).unwrap();
            std::io::stdout().write_all(&input[2..]).unwrap();
            std::io::stdout().flush().unwrap();
        }
        "stdio-vector-leaf" => {
            let mut first = [0u8; 3];
            let mut rest = [0u8; 10];
            let input = [
                libc::iovec {
                    iov_base: first.as_mut_ptr().cast(),
                    iov_len: first.len(),
                },
                libc::iovec {
                    iov_base: rest.as_mut_ptr().cast(),
                    iov_len: rest.len(),
                },
            ];
            assert_eq!(
                unsafe { libc::readv(0, input.as_ptr(), 2) },
                FRAME.len() as isize
            );
            assert_eq!([first.as_slice(), rest.as_slice()].concat(), FRAME);
            let output = [
                libc::iovec {
                    iov_base: first.as_mut_ptr().cast(),
                    iov_len: first.len(),
                },
                libc::iovec {
                    iov_base: std::ptr::null_mut(),
                    iov_len: 0,
                },
                libc::iovec {
                    iov_base: rest.as_mut_ptr().cast(),
                    iov_len: rest.len(),
                },
            ];
            assert_eq!(
                unsafe { libc::writev(1, output.as_ptr(), 3) },
                FRAME.len() as isize
            );
        }
        "stdio-partial-leaf" => {
            assert_eq!(unsafe { libc::fcntl(1, libc::F_SETPIPE_SZ, 4096) }, 4096);
            let raw = vec![b'P'; 128 * 1024];
            let flags = unsafe { libc::fcntl(1, libc::F_GETFL) };
            assert!(flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(1, libc::F_SETFL, flags | libc::O_NONBLOCK) },
                0
            );
            let count = unsafe { libc::write(1, raw.as_ptr().cast(), raw.len()) };
            assert!(count > 0 && count < raw.len() as isize);
        }
        "stdio-rebind-leaf" => {
            let path = c"/dev/null";
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
            assert!(fd > 2);
            assert_eq!(unsafe { libc::dup2(fd, 1) }, 1);
            unsafe {
                libc::close(fd);
            }
            let _ = unsafe { libc::write(1, FRAME.as_ptr().cast(), FRAME.len()) };
        }
        "stdio-linger-leaf" => {
            std::io::stdout().write_all(FRAME).unwrap();
            std::io::stdout().flush().unwrap();
            let mut byte = 0u8;
            let _ = unsafe { libc::read(0, (&mut byte as *mut u8).cast(), 1) };
        }
        "stdio-oversize-leaf" => {
            let raw = vec![b'X'; 8 * 1024 * 1024 + 1];
            let _ = unsafe { libc::write(1, raw.as_ptr().cast(), raw.len()) };
        }
        _ => unsafe { libc::_exit(97) },
    }
    unsafe { libc::_exit(0) }
}
