use std::sync::atomic::{AtomicBool, Ordering};

pub static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_signal: libc::c_int) {
    STOP.store(true, Ordering::Release);
}

pub struct Signals(Vec<(libc::c_int, libc::sigaction)>);
impl Signals {
    pub fn install() -> Result<Self, String> {
        STOP.store(false, Ordering::Release);
        let mut guard = Self(Vec::new());
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = stop as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
                || unsafe { libc::sigaction(signal, &action, &mut previous) } != 0
            {
                return Err("observer signal setup unavailable".to_owned());
            }
            guard.0.push((signal, previous));
        }
        Ok(guard)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (signal, previous) in self.0.iter().rev() {
            unsafe {
                libc::sigaction(*signal, previous, std::ptr::null_mut());
            }
        }
    }
}
