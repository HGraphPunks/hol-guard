//! Root owner for the composed SDK MCP routes, provider world and cleanup.
use crate::native_mcp_connection::ConnectionBudget;
use crate::native_mcp_route::{bind, pause, NativeMcpRoute};
use crate::native_operation_budget::NativeOperationBudget;
use crate::native_sdk_mcp_frontend::Frontend;
use crate::{
    NativeJobSpec, NativeMcpAgent, NativeMcpProcess, NativeMcpProxyClient, NativeMcpSockets,
    NativeMcpWorld, NativeSdkPeer,
};
use gauntlet_cell_rootfs::{CellPreparation, NativeGuardPins};
use gauntlet_mcp_service::Family;
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

struct Session {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<Value, String>>>,
}
struct Route {
    family: Family,
    client: NativeMcpProxyClient,
    process: NativeMcpProcess,
    closing: Arc<AtomicBool>,
}
pub(crate) struct NativeSdkMcpPlane {
    pub sockets: NativeMcpSockets,
    world: Arc<Mutex<NativeMcpWorld>>,
    budget: Arc<Mutex<NativeOperationBudget>>,
    agent: Option<NativeMcpAgent>,
    routes: Vec<Route>,
    backends: Vec<Session>,
    frontends: Vec<Session>,
    initial: String,
    boundary: Value,
    measurements: Vec<Value>,
    pub frontend_reports: Vec<Value>,
    backend_reports: Vec<Value>,
    errors: Vec<String>,
    closed: bool,
}
impl NativeSdkMcpPlane {
    pub(crate) fn prepare(
        job: &NativeJobSpec,
        budget: Arc<Mutex<NativeOperationBudget>>,
    ) -> Result<Self, String> {
        Self::prepare_snapshot(job, budget, crate::native_mcp_control::snapshot())
    }
    pub(crate) fn prepare_injection(
        job: &NativeJobSpec,
        budget: Arc<Mutex<NativeOperationBudget>>,
    ) -> Result<Self, String> {
        Self::prepare_snapshot(
            job,
            budget,
            crate::native_mcp_control::injection_snapshot()?,
        )
    }
    fn prepare_snapshot(
        job: &NativeJobSpec,
        budget: Arc<Mutex<NativeOperationBudget>>,
        initial: String,
    ) -> Result<Self, String> {
        let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| "Root MCP key unavailable")?;
        let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(|_| "Root MCP key invalid")?;
        Ok(Self {
            sockets: NativeMcpSockets::prepare(&job.job_id)?,
            world: Arc::new(Mutex::new(NativeMcpWorld::new(&job.job_id, &initial, key)?)),
            budget,
            agent: None,
            routes: Vec::new(),
            backends: Vec::new(),
            frontends: Vec::new(),
            initial,
            boundary: Value::Null,
            measurements: Vec::new(),
            frontend_reports: Vec::new(),
            backend_reports: Vec::new(),
            errors: Vec::new(),
            closed: false,
        })
    }
    pub(crate) fn start(
        &mut self,
        job: &NativeJobSpec,
        preparation: &CellPreparation,
        pins: &NativeGuardPins,
        actor: &Value,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        self.sockets.initialize()?;
        self.agent = Some(NativeMcpAgent::prepare(
            &job.job_id,
            preparation,
            &mut self.sockets,
        )?);
        let owner = self.agent.as_mut().unwrap();
        let boundary = owner.launch(actor, cancel)?;
        self.boundary = boundary.observation();
        self.measurements
            .push(json!({"identity":owner.identity_and_daemon(pins,cancel)?}));
        for family in [Family::Docs, Family::Mail] {
            let route = bind(owner, &mut self.sockets, boundary.clone(), family, cancel)?;
            let NativeMcpRoute {
                client,
                process,
                upstream,
                relay,
                observation,
            } = route;
            self.measurements.push(observation.clone());
            let closing = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let (w, b, c, s) = (
                self.world.clone(),
                self.budget.clone(),
                closing.clone(),
                stop.clone(),
            );
            let thread = std::thread::Builder::new()
                .name(format!("root-sdk-provider-{}", family.name()))
                .spawn(move || {
                    crate::native_mcp_connection::serve(
                        upstream,
                        relay,
                        family,
                        w,
                        ConnectionBudget::Sdk(b),
                        c,
                        s,
                    )
                })
                .map_err(|e| e.to_string())?;
            self.backends.push(Session {
                stop,
                thread: Some(thread),
            });
            self.routes.push(Route {
                family,
                client,
                process,
                closing,
            });
        }
        Ok(())
    }
    pub(crate) fn check_sdk_boundary(&self, sdk: &Value) -> Result<(), String> {
        for name in ["mnt", "pid", "net", "ipc", "uts", "cgroup"] {
            let native = self.boundary["identity"]["namespaces"][name]
                .as_str()
                .ok_or("Native MCP namespace missing")?;
            let actual = sdk["identity"]["namespaces"][name]
                .as_str()
                .ok_or("SDK namespace missing")?;
            if native == actual {
                return Err("SDK and Native MCP share a private namespace".into());
            }
        }
        Ok(())
    }
    pub(crate) fn connect_sdk(
        &mut self,
        peer: &Arc<NativeSdkPeer>,
        cancel: &AtomicBool,
    ) -> Result<(), String> {
        while !self.routes.is_empty() {
            let family = self.routes[0].family;
            let deadline = Instant::now() + Duration::from_secs(35);
            let socket = loop {
                if let Some(stream) = self.sockets.accept_resource(family)? {
                    break stream;
                }
                peer.recheck()?;
                pause(deadline, cancel)?;
            };
            let request_peer = peer.authenticate_mcp(&socket, family)?;
            let Route {
                client,
                process,
                closing,
                ..
            } = self.routes.remove(0);
            let stop = Arc::new(AtomicBool::new(false));
            let frontend = Frontend {
                socket,
                peer: request_peer,
                client,
                proxy: process,
                family,
                budget: self.budget.clone(),
                closing: closing.clone(),
                cancel: stop.clone(),
            };
            let thread = std::thread::Builder::new()
                .name(format!("root-sdk-frontend-{}", family.name()))
                .spawn(move || frontend.serve())
                .map_err(|e| e.to_string())?;
            self.frontends.push(Session {
                stop,
                thread: Some(thread),
            });
        }
        Ok(())
    }
    pub(crate) fn close(&mut self, abort: bool) -> Result<(), String> {
        if self.closed {
            return if self.errors.is_empty() {
                Ok(())
            } else {
                Err(format!("SDK MCP cleanup: {:?}", self.errors))
            };
        }
        for route in &mut self.routes {
            if let Err(e) = route.client.close() {
                self.errors.push(e);
            }
        }
        for session in &self.frontends {
            if abort {
                session.stop.store(true, Ordering::Release);
            }
        }
        collect(
            &mut self.frontends,
            &mut self.frontend_reports,
            &mut self.errors,
        );
        for session in &self.backends {
            session.stop.store(true, Ordering::Release);
        }
        collect(
            &mut self.backends,
            &mut self.backend_reports,
            &mut self.errors,
        );
        if let Some(agent) = self.agent.as_mut() {
            if let Err(e) = agent.close() {
                self.errors.push(e);
            }
        }
        if let Err(e) = self.sockets.close() {
            self.errors.push(e);
        }
        self.closed = true;
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(format!("SDK MCP cleanup: {:?}", self.errors))
        }
    }
    pub(crate) fn observation(&mut self) -> Result<Value, String> {
        let mut world = self.world.lock().map_err(|_| "SDK MCP world poisoned")?;
        Ok(
            json!({"schema":"hol-gauntlet-native-sdk-mcp-plane.v1","boundary":self.boundary,
            "measurements":self.measurements,"frontends":self.frontend_reports,"upstreams":self.backend_reports,
            "world":world.observation()?,"initial":serde_json::from_str::<Value>(&self.initial).map_err(|_|"initial world JSON")?,
            "final":world.snapshot()?,"receipts":world.receipts()?,"sockets":self.sockets.observation(),
            "agent":self.agent.as_ref().map(NativeMcpAgent::observation),
            "public_helpers":self.agent.as_ref().map(NativeMcpAgent::public_observation),
            "cleanup_attempted":self.closed,"cleanup_errors":self.errors,"outside_signing_key_admitted":false,
            "guard_causality_verified":false,"execution_eligible":false,"model_requests":0}),
        )
    }
}
fn collect(sessions: &mut [Session], reports: &mut Vec<Value>, errors: &mut Vec<String>) {
    for session in sessions {
        if let Some(thread) = session.thread.take() {
            match thread.join() {
                Ok(Ok(value)) => {
                    if value["status"] == "failed" {
                        errors.push(format!("SDK MCP session failed: {}", value["error"]));
                    }
                    reports.push(value);
                }
                Ok(Err(error)) => errors.push(error),
                Err(_) => errors.push("SDK MCP thread panicked".into()),
            }
        }
    }
}
