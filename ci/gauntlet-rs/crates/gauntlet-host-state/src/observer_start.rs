//! A reader's short lock must not terminate observer startup. Only Busy is
//! retried; an uncertain commit, changed identity or invalid state is final.
use crate::observer_collect::now_ms;
use crate::{HostLifecycleError as Error, HostLifecycleStore, HostObserverLease};
use std::path::Path;
use std::time::{Duration, Instant};

fn retry_busy<T>(mut operation: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match operation() {
            Err(Error::Busy) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

/// Open for observer startup under a bounded transient-reader/writer wait.
/// Operator mutations keep their existing immediate contention refusal.
pub fn open_observer_store(parent: &Path) -> Result<HostLifecycleStore, Error> {
    retry_busy(|| HostLifecycleStore::open(parent))
}

/// Every attempt reacquires the exclusive kernel lease and samples a fresh
/// timestamp. Busy is returned before any checkpoint mutation; other errors
/// must never be retried as though a write had not happened.
pub fn start_observer_bounded(store: &HostLifecycleStore) -> Result<HostObserverLease<'_>, Error> {
    retry_busy(|| store.start_observer(now_ms()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertain_commits_and_identity_failures_are_never_retried() {
        for error in [
            Error::CommitUncertain,
            Error::Changed,
            Error::InvalidState,
            Error::Clock,
        ] {
            let mut attempts = 0;
            let result: Result<(), Error> = retry_busy(|| {
                attempts += 1;
                Err(error)
            });
            assert_eq!(result, Err(error));
            assert_eq!(attempts, 1);
        }
    }
}
