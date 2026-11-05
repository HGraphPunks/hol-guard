use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) fn spawn_workers<T, F>(
    count: usize,
    receiver: Receiver<T>,
    handler: F,
) -> Vec<JoinHandle<()>>
where
    T: Send + 'static,
    F: Fn(T) + Send + Sync + 'static,
{
    let receiver = Arc::new(Mutex::new(receiver));
    let handler = Arc::new(handler);
    (0..count)
        .map(|_| {
            let receiver = Arc::clone(&receiver);
            let handler = Arc::clone(&handler);
            thread::spawn(move || loop {
                let next = match receiver.lock() {
                    Ok(guard) => guard.recv(),
                    Err(_) => return,
                };
                match next {
                    Ok(item) => handler(item),
                    Err(_) => return,
                }
            })
        })
        .collect()
}

// Stop admission first, then let authenticated work finish. A stuck or slow
// client must not retain the managed owner lock indefinitely.
pub(super) fn drain(workers: Vec<JoinHandle<()>>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while workers.iter().any(|worker| !worker.is_finished()) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    for worker in workers {
        if worker.is_finished() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_store::policy_store_approval::bash_cancellation::Launches;
    use std::sync::mpsc::sync_channel;

    struct StopLaunches(Arc<Launches>);
    impl Drop for StopLaunches {
        fn drop(&mut self) {
            self.0.shutdown();
        }
    }

    #[test]
    fn single_cpu_budget_serves_policy_metadata_and_cancels_both_active_launches() {
        use std::sync::atomic::Ordering;
        const IDS: [&str; 2] = ["worker-budget-launch-0001", "worker-budget-launch-0002"];
        enum Work {
            Launch(&'static str),
            Policy,
            Cancel,
        }
        let budget = crate::resident_worker_budget::for_parallelism(Some(1));
        let reserved = super::super::control::WORKERS;
        let owner = Arc::new(Launches::default());
        let _stop = StopLaunches(Arc::clone(&owner));
        let (entered, starts) = sync_channel(2);
        let (reply, replies) = sync_channel(8);
        let (send, receive) = sync_channel(32);
        let mut workers = spawn_workers(budget.evaluation - reserved, receive, {
            let owner = Arc::clone(&owner);
            let reply = reply.clone();
            move |work| match work {
                Work::Launch(id) => {
                    let registration = owner.register(id).unwrap();
                    entered.send(id).unwrap();
                    while !registration.cancelled.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(1));
                    }
                    drop(registration);
                    reply.send("launch-completed").unwrap();
                }
                Work::Policy => {
                    for id in IDS {
                        assert_eq!(owner.activity(id).unwrap(), (true, false));
                    }
                    assert!(owner.register("worker-budget-launch-0003").is_err());
                    reply.send("policy-served").unwrap();
                }
                Work::Cancel => {
                    for id in IDS {
                        assert!(owner.cancel(id).unwrap());
                    }
                    reply.send("cancel-served").unwrap();
                }
            }
        });
        let (metadata, metadata_rx) = sync_channel(8);
        workers.extend(spawn_workers(reserved, metadata_rx, move |(): ()| {
            reply.send("metadata-served").unwrap();
        }));
        for id in IDS {
            send.send(Work::Launch(id)).unwrap();
        }
        let mut started = (0..2)
            .map(|_| starts.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect::<Vec<_>>();
        started.sort_unstable();
        assert_eq!(started, IDS);
        send.send(Work::Policy).unwrap();
        assert_eq!(
            replies.recv_timeout(Duration::from_secs(5)).unwrap(),
            "policy-served"
        );
        metadata.send(()).unwrap();
        assert_eq!(
            replies.recv_timeout(Duration::from_secs(5)).unwrap(),
            "metadata-served"
        );
        send.send(Work::Cancel).unwrap();
        let mut done = (0..3)
            .map(|_| replies.recv_timeout(Duration::from_secs(5)).unwrap())
            .collect::<Vec<_>>();
        done.sort_unstable();
        assert_eq!(
            done,
            ["cancel-served", "launch-completed", "launch-completed"]
        );
        for id in IDS {
            assert_eq!(owner.activity(id).unwrap(), (false, false));
        }
        drop(send);
        drop(metadata);
        drain(workers, Duration::from_secs(2));
    }

    #[test]
    fn drain_finishes_admitted_work_after_senders_close() {
        let (sender, receiver) = sync_channel(1);
        let (completed, result) = sync_channel(1);
        let workers = spawn_workers(1, receiver, move |value: u8| {
            thread::sleep(Duration::from_millis(20));
            completed.send(value).unwrap();
        });
        sender.send(7).unwrap();
        drop(sender);
        drain(workers, Duration::from_secs(1));
        assert_eq!(result.try_recv().unwrap(), 7);
    }
}
