//! Passive Rust observer plus an optional loopback dashboard in the same
//! process. Closing the process closes both ownership and its listening socket.

use crate::lifecycle_files::nonce;
use crate::observer_collect::{now_ms, Samplers};
use crate::observer_public::ObserverPublic;
use crate::{compose_observer_snapshot, HostLifecycleError as Error, HostLifecycleStore};
use gauntlet_dashboard::{http, snapshot::PublicRoot};
use serde_json::{json, Value};
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

fn queue_observed_releases(store: &HostLifecycleStore, observations: &Value) -> Result<(), Error> {
    let Some(rows) = observations["releases"].as_array() else {
        return Ok(());
    };
    let status = store.status(now_ms()?)?;
    let jobs = status["jobs"].as_array().ok_or(Error::InvalidState)?;
    for row in rows {
        let (Some(tag), Some(sha)) = (row["tag"].as_str(), row["sha"].as_str()) else {
            continue;
        };
        if jobs.iter().any(|job| job["tag"] == tag) {
            continue;
        }
        // Existing tuple/source binding remains immutable. Moved tags are
        // reported by the public projection and never replace a retained job.
        match store.enqueue_release(&nonce()?[..16], tag, sha, now_ms()?) {
            Ok(_) | Err(Error::SourceMoved) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn run_passive_observer(
    store: &HostLifecycleStore,
    expected_config: &str,
    volume: &Path,
    port: Option<u16>,
    once: bool,
    shutdown: &AtomicBool,
) -> Result<Value, Error> {
    let config = store.read_observer_configuration(expected_config)?;
    // Bind before taking an observer lease or recovering jobs. A busy port
    // cannot interrupt an existing listener or claim ownership of its state.
    let listener = port
        .map(|port| TcpListener::bind((Ipv4Addr::LOCALHOST, port)))
        .transpose()
        .map_err(|_| Error::DashboardUnavailable)?;
    if let Some(listener) = &listener {
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::DashboardUnavailable)?;
    }
    let lease = crate::start_observer_bounded(store)?;
    let public = ObserverPublic::open(&lease)?;
    let root = PublicRoot::open(&public.path(&lease)?).map_err(|_| Error::DashboardUnavailable)?;
    if let Some(listener) = &listener {
        println!(
            "{}",
            json!({"service":"hol-gauntlet-dashboard","instance_id":store.instance,
            "url":format!("http://127.0.0.1:{}",listener.local_addr().map_err(|_|Error::DashboardUnavailable)?.port()),
            "configuration_sha256":config.sha256,"mode":"passive","execution_eligible":false})
        );
        io::stdout().flush().map_err(|_| Error::Io)?;
    }
    let (sender, receiver) = mpsc::channel();
    let mut samplers = Samplers::new(sender);
    let mut observations = json!({"releases":[]});
    let started = Instant::now();
    let mut next_metrics = Duration::ZERO;
    let mut next_sources = Duration::ZERO;
    let mut next_heartbeat = Duration::ZERO;
    let mut next_publication = Duration::ZERO;
    let metrics_interval = Duration::from_secs(
        config.operations["telemetry_seconds"]
            .as_u64()
            .ok_or(Error::InvalidObserverConfig)?,
    );
    let source_interval = Duration::from_secs(
        config.operations["poll_seconds"]
            .as_u64()
            .ok_or(Error::InvalidObserverConfig)?,
    );
    let result = (|| {
        loop {
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let now = now_ms()?;
            let status = match store.status(now) {
                Ok(value) => value,
                Err(Error::Busy) => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) => return Err(error),
            };
            if status["stop_requested"] == true {
                break;
            }
            match store.read_observer_configuration(expected_config) {
                Ok(_) => {}
                Err(Error::Busy) => {
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                Err(error) => return Err(error),
            }
            let elapsed = started.elapsed();
            let mut updated = false;
            for update in receiver.try_iter() {
                samplers.apply(update, &mut observations)?;
                updated = true;
            }
            if elapsed >= next_heartbeat {
                match lease.heartbeat(now_ms()?) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                };
                next_heartbeat = elapsed + Duration::from_secs(5);
            }
            if elapsed >= next_publication || updated {
                match queue_observed_releases(store, &observations) {
                    Ok(()) => {}
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                };
            }
            if elapsed >= next_publication || updated {
                let current = match store.status(now_ms()?) {
                    Ok(value) => value,
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                };
                match public.publish(
                    &lease,
                    &compose_observer_snapshot(&config, &current, &observations, now_ms()?)?,
                ) {
                    Ok(()) => {}
                    Err(Error::Busy) => continue,
                    Err(error) => return Err(error),
                }
                next_publication = elapsed + Duration::from_secs(5);
            }
            if once
                && next_metrics != Duration::ZERO
                && next_sources != Duration::ZERO
                && samplers.telemetry_idle()
                && samplers.sources_idle()
            {
                break;
            }
            if elapsed >= next_metrics
                && samplers.telemetry_idle()
                && (!once || next_metrics == Duration::ZERO)
            {
                samplers.telemetry(config.clone(), volume.to_owned());
                next_metrics = elapsed + metrics_interval;
            }
            if elapsed >= next_sources
                && samplers.sources_idle()
                && (!once || next_sources == Duration::ZERO)
            {
                samplers.sources(config.clone());
                next_sources = elapsed + source_interval;
            }
            if let Some(listener) = &listener {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if http::handle(stream, &root).is_err() {
                            eprintln!("dashboard request failed");
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => return Err(Error::DashboardUnavailable),
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    })();
    // Cancel and join every owned read-only sampler before releasing the
    // observer lease, on normal shutdown and error paths alike.
    drop(samplers);
    let final_now = now_ms()?;
    let mut status = store.status(final_now)?;
    status["observer"]["status"] = json!("stopped");
    let stopped = compose_observer_snapshot(&config, &status, &observations, final_now)?;
    let publication = public.publish(&lease, &stopped);
    let finish = lease.finish(now_ms()?);
    result?;
    publication?;
    finish?;
    Ok(stopped)
}

impl HostLifecycleStore {
    pub fn published_observer_snapshot(
        &self,
        expected_config: &str,
        now: u64,
    ) -> Result<Value, Error> {
        let config = self.read_observer_configuration(expected_config)?;
        let root =
            PublicRoot::open(&self.files.public_path()).map_err(|_| Error::DashboardUnavailable)?;
        if root.identity().as_deref() != Some(self.instance.as_str()) {
            return Err(Error::Changed);
        }
        let value = root.snapshot(now as f64 / 1000.0);
        if value["instance_id"] != self.instance
            || value["observer"]["configuration_sha256"] != config.sha256
        {
            return Err(Error::Changed);
        }
        self.files.stable()?;
        Ok(value)
    }
}
