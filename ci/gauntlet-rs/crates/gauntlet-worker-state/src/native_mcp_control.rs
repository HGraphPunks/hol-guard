//! Rust-owned Native CLI -> resident child -> Root SQLite MCP diagnostic.
//! SDK composition and independently scored Guard controls remain separate.
use crate::{
    read_native_sdk_line, write_native_sdk_line, NativeJobSpec, NativeMcpAgent, NativeMcpProcess,
    NativeMcpProxyClient, NativeMcpSockets, NativeMcpWorld,
};
use gauntlet_cell_rootfs::{NativeApparatusReport, NativeGuardPins};
use gauntlet_mcp_service::Family;
use ring::signature::Ed25519KeyPair;
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

fn pause(deadline: Instant, cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
        return Err("MCP control deadline/cancel".into());
    }
    std::thread::sleep(Duration::from_millis(10));
    Ok(())
}
pub(crate) fn snapshot() -> String {
    json!({"schema":"gauntlet-workflow-snapshot.v1","actor_id":"fixture-actor","provider_scope":{"tenants":["task-tenant"]},"records":[
        {"id":"developer-spec","collection":"docs.documents","tenant_id":"task-tenant","owner_id":"fixture-actor","version":1,
            "acl":{"read":["fixture-actor"],"write":["fixture-actor"]},"data":{"title":"Delegated developer input","body":"Read this fixed synthetic document."}},
        {"id":"message","collection":"mail.messages","tenant_id":"task-tenant","owner_id":"fixture-actor","version":1,
            "acl":{"read":["fixture-actor"],"write":["fixture-actor"]},"data":{"subject":"Synthetic input","body":"No external delivery is authorized."}}]}).to_string()
}
pub(crate) fn injection_payload() -> Result<String, String> {
    let catalog: Value = serde_json::from_str(include_str!(
        "../../../../gauntlet/benchmark/workflows.json"
    ))
    .map_err(|e| e.to_string())?;
    let workflow = catalog["workflows"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == "python-cli-with-tests"))
        .ok_or("frozen Python control workflow absent")?;
    let attack = workflow["attacks"]
        .as_array()
        .and_then(|rows| rows.iter().find(|r| r["id"] == "text-injection"))
        .ok_or("frozen text-injection control absent")?;
    if attack["kind"] != "text-injection"
        || attack["surface"] != "tool-result.body"
        || attack["source_id"] != "developer-spec"
    {
        return Err("frozen control injection surface differs".into());
    }
    attack["payload"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 4096)
        .map(String::from)
        .ok_or_else(|| "bounded frozen attack payload required".into())
}
pub(crate) fn injection_snapshot() -> Result<String, String> {
    let mut initial: Value = serde_json::from_str(&snapshot()).map_err(|e| e.to_string())?;
    let payload = injection_payload()?;
    let doc = initial["records"]
        .as_array_mut()
        .and_then(|rows| rows.iter_mut().find(|r| r["id"] == "developer-spec"))
        .ok_or("fixed delegated record absent")?;
    let body = doc["data"]["body"]
        .as_str()
        .ok_or("fixed delegated body absent")?;
    doc["data"]["body"] = json!(format!("{body}\n\n{payload}"));
    Ok(initial.to_string())
}
fn response(
    client: &mut NativeMcpProxyClient,
    request: &Value,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(35);
    let raw = gauntlet_contracts::canonicalize(request.to_string().as_bytes())
        .map_err(|e| e.to_string())?;
    client.write_frame(&raw, deadline, cancel)?;
    let raw = client
        .read_frame(deadline, cancel)?
        .ok_or("Native MCP proxy ended before response")?;
    let raw = gauntlet_contracts::canonicalize(&raw).map_err(|e| e.to_string())?;
    let result: Value = serde_json::from_slice(&raw).map_err(|_| "Native proxy response JSON")?;
    if result["jsonrpc"] != "2.0"
        || result["id"] != request["id"]
        || result.get("error").is_some()
        || result.get("result").is_none()
    {
        return Err(format!("Native proxy response differs: {result}"));
    }
    Ok(result)
}
fn exchange(
    client: &mut NativeMcpProxyClient,
    family: Family,
    cancel: &AtomicBool,
) -> Result<Value, String> {
    let initialized = response(
        client,
        &json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",
        "capabilities":{},"clientInfo":{"name":"rust-native-mcp-control","version":"1"}}}),
        cancel,
    )?;
    client.write_frame(
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        Instant::now() + Duration::from_secs(5),
        cancel,
    )?;
    let tools = response(
        client,
        &json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
        cancel,
    )?;
    let operation = format!("{}.read", family.name());
    if !tools["result"]["tools"]
        .as_array()
        .is_some_and(|rows| rows.iter().any(|r| r["name"] == operation))
    {
        return Err("normal Native proxy omitted the delegated read tool".into());
    }
    let record = if family == Family::Docs {
        "developer-spec"
    } else {
        "message"
    };
    let result = response(
        client,
        &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":operation,
        "arguments":{"record_id":record}}}),
        cancel,
    )?;
    if result["result"]["isError"] == true {
        return Err(format!("actual Native MCP read refused: {result}"));
    }
    let text = result["result"]["content"][0]["text"]
        .as_str()
        .ok_or("Native read content missing")?;
    let value: Value = serde_json::from_str(text).map_err(|_| "Native read result content JSON")?;
    if value["id"] != record
        || value["collection"]
            != format!(
                "{}.{}",
                family.name(),
                if family == Family::Docs {
                    "documents"
                } else {
                    "messages"
                }
            )
    {
        return Err("Native MCP result is not the requested physical provider record".into());
    }
    Ok(
        json!({"family":family.name(),"initialize":initialized,"tools":tools,"read":result,"record":value}),
    )
}

pub(crate) fn run_native_mcp_transport(
    job: &NativeJobSpec,
    pins: &NativeGuardPins,
    cancelled: Arc<AtomicBool>,
) -> Result<NativeApparatusReport, String> {
    gauntlet_cell_rootfs::require_outside_root()?;
    let host_null = crate::native_sdk_host_device::NativeSdkHostNull::open()?;
    let root =
        crate::open_root_owned_public_directory(&job.job_root()).map_err(|e| e.to_string())?;
    let raw = crate::read_bounded_regular(&root, "preparation.v1.json", 49152)
        .map_err(|e| e.to_string())?
        .ok_or("MCP preparation absent")?;
    let preparation = job.preparation(&raw)?;
    let fixture = gauntlet_cell_rootfs::seed_native_sdk_fixture(&preparation)?;
    let initial = snapshot();
    let key = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| "Root MCP key unavailable")?;
    let key = Ed25519KeyPair::from_pkcs8(key.as_ref()).map_err(|_| "Root MCP key invalid")?;
    let world = Arc::new(Mutex::new(NativeMcpWorld::new(&job.job_id, &initial, key)?));
    let mut sockets = NativeMcpSockets::prepare(&job.job_id)?;
    let mut agent = None;
    let mut cell = None;
    let mut client = None;
    let mut sessions = Vec::<(
        Arc<AtomicBool>,
        Arc<AtomicBool>,
        JoinHandle<Result<Value, String>>,
    )>::new();
    let mut measurements = Vec::new();
    let mut actor = Value::Null;
    let budget = Arc::new(AtomicUsize::new(0));
    let attempted = (|| -> Result<(), String> {
        sockets.initialize()?;
        cell = Some(gauntlet_cell_rootfs::prepare_and_start(
            &job.preparation_path(),
            &job.preparation_sha256,
            cancelled.clone(),
        )?);
        actor = cell
            .as_ref()
            .unwrap()
            .actor_observation()
            .cloned()
            .ok_or("MCP product actor absent")?;
        agent = Some(NativeMcpAgent::prepare(
            &job.job_id,
            &preparation,
            &mut sockets,
        )?);
        let owner = agent.as_mut().unwrap();
        let boundary = owner.launch(&actor, &cancelled)?;
        measurements.push(json!({"identity":owner.identity_and_daemon(pins,&cancelled)?}));
        let python = boundary.python()?;
        for family in [Family::Docs, Family::Mail] {
            world
                .lock()
                .map_err(|_| "MCP world mutex poisoned")?
                .verify()?;
            client = Some(owner.launch_proxy(family, &cancelled)?);
            let proxy = client.as_mut().unwrap();
            let deadline = Instant::now() + Duration::from_secs(35);
            let mut gate = loop {
                if let Some(stream) = sockets.accept_gate()? {
                    break stream;
                }
                if proxy.poll()?.is_some() {
                    return Err("Native MCP proxy exited before binding".into());
                }
                pause(deadline, &cancelled)?;
            };
            if read_native_sdk_line(&mut gate, 128, deadline, &cancelled)?
                != format!("native-mcp-proxy-ready.v1 {}", family.name()).as_bytes()
            {
                return Err("Native MCP proxy gate differs".into());
            }
            let mut reply = gate.try_clone().map_err(|e| e.to_string())?;
            let mut process = NativeMcpProcess::bind(
                gate,
                boundary.clone(),
                &python,
                &owner.bootstrap_argv(family),
            )?;
            let bootstrap = process.observation();
            write_native_sdk_line(
                &mut reply,
                b"native-mcp-proxy-bound.v1",
                deadline,
                &cancelled,
            )?;
            while process.observe_exec(&owner.proxy_argv(family)).is_err() {
                pause(deadline, &cancelled)?;
            }
            let native_proxy = process.observation();
            let stream = loop {
                if let Some(stream) = sockets.accept_upstream(family)? {
                    break stream;
                }
                if proxy.poll()?.is_some() {
                    return Err("Native proxy exited before upstream connection".into());
                }
                process.recheck()?;
                pause(deadline, &cancelled)?;
            };
            // The resident owns the real child. Authenticate its actual kernel
            // process, exact interpreter and fixed readonly relay argv. This
            // diagnostic does not infer proxy ancestry or a Guard verdict.
            let relay_args = vec![
                "/usr/bin/python3.12".into(),
                "/product/public/service_relay.py".into(),
                "--socket".into(),
                format!("/upstream/{}.sock", family.name()),
            ];
            let peer = NativeMcpProcess::bind(
                stream.try_clone().map_err(|e| e.to_string())?,
                boundary.clone(),
                &python,
                &relay_args,
            )?;
            let closing = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let (w, b, c, s) = (world.clone(), budget.clone(), closing.clone(), stop.clone());
            let thread = std::thread::Builder::new()
                .name(format!("root-mcp-{}", family.name()))
                .spawn(move || {
                    crate::native_mcp_connection::serve(
                        stream,
                        peer,
                        family,
                        w,
                        crate::native_mcp_connection::ConnectionBudget::Diagnostic(b),
                        c,
                        s,
                    )
                })
                .map_err(|e| e.to_string())?;
            sessions.push((closing.clone(), stop, thread));
            let result = exchange(proxy, family, &cancelled)?;
            process.recheck()?;
            closing.store(true, Ordering::Release);
            let completion = proxy.finish(Instant::now() + Duration::from_secs(10), &cancelled)?;
            if completion["exit_code"] != 0 {
                return Err(format!("Native proxy completion failed: {completion}"));
            }
            measurements.push(json!({"bootstrap":bootstrap,"native_proxy":native_proxy,"exchange":result,"completion":completion,
                "relay_proxy_ancestry_verified":false}));
            client = None;
        }
        Ok(())
    })();
    let client_cleanup = client.as_mut().map_or(Ok(()), NativeMcpProxyClient::close);
    for (_, stop, _) in &sessions {
        stop.store(true, Ordering::Release);
    }
    let mut served = Vec::new();
    let mut errors = Vec::new();
    for (_, _, thread) in sessions {
        match thread.join() {
            Ok(Ok(value)) => served.push(value),
            Ok(Err(error)) => errors.push(error),
            Err(_) => errors.push("Root MCP serving thread panicked".into()),
        }
    }
    let agent_cleanup = agent.as_mut().map_or(Ok(()), NativeMcpAgent::close);
    let socket_cleanup = sockets.close();
    let cell_cleanup = cell
        .as_mut()
        .map_or(Ok(()), gauntlet_cell_rootfs::NativeCell::close);
    let host_null_after = host_null.recheck();
    for result in [
        &client_cleanup,
        &agent_cleanup,
        &socket_cleanup,
        &cell_cleanup,
    ] {
        if let Err(error) = result {
            errors.push(error.clone());
        }
    }
    if let Err(error) = &host_null_after {
        errors.push(error.clone());
    }
    let prefix = gauntlet_evidence::inventory_tree(
        &preparation.runtime_prefix,
        gauntlet_evidence::TreeKind::InstalledPrefix,
    )
    .map_err(|e| e.to_string());
    let prefix_unchanged = prefix
        .as_ref()
        .is_ok_and(|v| v.digest == preparation.runtime_tree_digest);
    let mut world = world.lock().map_err(|_| "MCP final world mutex poisoned")?;
    let world_observation = world.observation()?;
    let receipts = world.receipts()?;
    let final_snapshot = world.snapshot()?;
    let count = budget.load(Ordering::Acquire);
    if served.iter().any(|session| session["status"] == "failed") {
        errors.push("Root MCP session failed; original frames retained".into());
    }
    let error = attempted
        .err()
        .or_else(|| errors.first().cloned())
        .or_else(|| (!prefix_unchanged).then(|| "MCP runtime prefix changed".into()))
        .or_else(|| {
            (count != 2 || receipts.len() != 2 || served.len() != 2)
                .then(|| "MCP operation/session/receipt count differs".into())
        });
    let report = json!({"schema":"hol-gauntlet-native-mcp-transport.v1","status":if error.is_none(){"passed"}else{"failed"},"error":error,
        "job_id":job.job_id,"guard_pins":pins.to_json(),"fixture":fixture,"actor":actor,"measurements":measurements,
        "upstream_sessions":served,"world":world_observation,"initial":serde_json::from_str::<Value>(&initial).map_err(|_|"initial MCP fixture JSON")?,
        "final":final_snapshot,"receipts":receipts,"upstream_operation_count":count,"sockets":sockets.observation(),
        "agent":agent.as_ref().map(NativeMcpAgent::observation),"public_helpers":agent.as_ref().map(NativeMcpAgent::public_observation),
        "client_cleanup_complete":client_cleanup.is_ok(),"agent_cleanup_complete":agent_cleanup.is_ok(),"cell_cleanup_complete":cell_cleanup.is_ok(),
        "cleanup_errors":errors,"host_null_before":host_null.before(),"host_null_after":host_null_after.as_ref().ok(),
        "host_null_identity_unchanged":host_null_after.is_ok(),"prefix_unchanged":prefix_unchanged,
        "sdk_exercised":false,"model_requests":0,"execution_eligible":false,"guard_causality_verified":false,
        "unavailable_reason":"Native MCP diagnostic; actual SDK composition, global builtin/MCP budget, independent Guard decision/effect scoring and outside signing-key admission remain open"});
    Ok(NativeApparatusReport { report, error })
}
