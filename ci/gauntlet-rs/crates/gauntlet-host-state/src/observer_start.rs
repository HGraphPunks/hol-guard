//! A reader's short lock must not terminate lifecycle commands. Only Busy is
//! retried; an uncertain commit, changed identity or invalid state is final.
use crate::observer_collect::now_ms;
use crate::{HostLifecycleError as Error, HostLifecycleStore, HostObserverLease};
use std::path::Path;
use std::time::{Duration, Instant};

/// Retry only a read or an operation whose Busy result precedes all mutation.
/// Commit uncertainty and every other error are final.
pub fn wait_for_lifecycle<T>(mut operation: impl FnMut() -> Result<T, Error>) -> Result<T, Error> {
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

/// Open under a bounded transient-reader/writer wait. The underlying store
/// methods retain their immediate contention refusal for API callers.
pub fn open_observer_store(parent: &Path) -> Result<HostLifecycleStore, Error> {
    wait_for_lifecycle(|| HostLifecycleStore::open(parent))
}

/// Every attempt reacquires the exclusive kernel lease and samples a fresh
/// timestamp. Busy is returned before any checkpoint mutation; other errors
/// must never be retried as though a write had not happened.
pub fn start_observer_bounded(store: &HostLifecycleStore) -> Result<HostObserverLease<'_>, Error> {
    wait_for_lifecycle(|| store.start_observer(now_ms()?))
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
            let result: Result<(), Error> = wait_for_lifecycle(|| {
                attempts += 1;
                Err(error)
            });
            assert_eq!(result, Err(error));
            assert_eq!(attempts, 1);
        }
    }
}
