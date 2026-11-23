//! Synthetic Host boundaries only; these tests do not qualify real inference.
use super::*;
use gauntlet_evidence::{read_provider_quota_snapshot, ProviderQuotaWriter};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

pub(in crate::native_operation) fn fixture(
) -> (tempfile::TempDir, Journal, Intent, ProviderQuotaWriter) {
    let (temp, j) = super::super::super::tests::journal();
    let mut i = super::super::super::tests::intent(&"1".repeat(16), &j.path);
    let root = j.path.join("temporary-quota");
    let mut writer = ProviderQuotaWriter::create_new(
        &root,
        "temporary-live-channel-test",
        900_000,
        100,
        &"b".repeat(64),
    )
    .unwrap();
    let q = read_provider_quota_snapshot(&root, writer.config_digest(), None).unwrap();
    writer = writer
        .extend_allowance(
            1_000_000,
            &"c".repeat(64),
            text(&q, "journal_hash").unwrap(),
        )
        .unwrap();
    let (source, spec_sha) = spec().unwrap();
    let budget = "d".repeat(64);
    let provider_job = "e".repeat(16);
    let pins = json!({"profile":"owned-mlx-rust-serial.v2","source_sha":i.text("source_sha"),"provider_job_id":provider_job,"binding_sha256":budget,"adapter_sha256":"a".repeat(64),"server_sha256":"b".repeat(64),"producer_sha256":"c".repeat(64),"model_identity_digest":"b".repeat(64),"quota_config_digest":writer.config_digest(),"quota_allowance_digest":writer.allowance_digest(),"token_cap":1_000_000,"maximum_requests":100});
    let provider = json!({"schema":"hol-gauntlet-rust-provider-binding.v1","source_sha":i.text("source_sha"),"provider_job_id":provider_job,"budget_digest":budget,"provider_spec_sha256":"f".repeat(64),"source_authorization_sha256":"a".repeat(64),"model_id":"mlx-community/Qwen3.6-35B-A3B-8bit","maximum_accounted_tokens":200_000,"known_tokens_before":0,"job_tokens":200_000,"cells":[{"job_id":i.job(),"episode_id":source["cells"][0]["id"],"token_budget":100_000},{"job_id":"3".repeat(16),"episode_id":source["cells"][1]["id"],"token_budget":100_000}],"status_pins":pins,"private_unix_channel":true,"qualification_eligible":false});
    i.0["schema"] = json!("hol-gauntlet-host-native-live-intent.v1");
    i.0["role"] = json!("feature-ai-unprotected");
    i.0["live"] = json!({"cell_id":source["cells"][0]["id"],"spec_sha256":spec_sha,"provider_journal":j.path.join("provider-not-contacted"),"provider_intent_sha256":budget,"provider_binding":provider});
    let i = Intent::parse(&i.raw().unwrap()).unwrap();
    (temp, j, i, writer)
}
fn request(i: &Intent, turn: u64) -> Value {
    let body=bytes(&json!({"model":binding(i)["model_id"],"messages":[{"role":"user","content":"mock model request"}],"stream":false,"max_tokens":8})).unwrap();
    json!({"schema":"hol-gauntlet-native-live-model-request.v1","source_sha":i.text("source_sha"),"provider_job_id":binding(i)["provider_job_id"],"job_id":i.job(),"budget_digest":binding(i)["budget_digest"],"turn":turn,"request_sha256":sha(&body),"body_b64":base64::engine::general_purpose::STANDARD.encode(body)})
}
fn status(i: &Intent, w: &ProviderQuotaWriter) -> Value {
    let q =
        read_provider_quota_snapshot(&w_root(i), w.config_digest(), w.allowance_digest()).unwrap();
    let p = &binding(i)["status_pins"];
    json!({"adapter":{"schema":"gauntlet-mlx-quota-adapter.v2","source_sha":p["source_sha"],"provider_job_id":p["provider_job_id"],"producer_sha256":p["producer_sha256"],"server_sha256":p["server_sha256"],"adapter_sha256":p["adapter_sha256"],"quota_config_digest":p["quota_config_digest"],"quota_allowance_digest":p["quota_allowance_digest"],"producer_mode":"serial-original-tokenization-and-generation","counting":"full prompt including cached input plus every producer-emitted response token","batching":false,"draft":false,"qualification_eligible":false},"binding_sha256":p["binding_sha256"],"qualification":false,"quota":q})
}
fn w_root(i: &Intent) -> std::path::PathBuf {
    Path::new(text(context_value(i), "provider_journal").unwrap())
        .parent()
        .unwrap()
        .join("temporary-quota")
}
fn response(i: &Intent, w: &ProviderQuotaWriter, request: &Value) -> Value {
    let before = status(i, w);
    let input = "f".repeat(64);
    let reservation = w.reserve(4, 8, &input, Some(200_000)).unwrap();
    w.settle(&reservation, 4, 2).unwrap();
    let after = status(i, w);
    let raw=bytes(&json!({"model":binding(i)["model_id"],"choices":[{"message":{"role":"assistant","content":"mock response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}})).unwrap();
    let usage = json!({"schema":"hol-gauntlet-rust-provider-usage.v1","source_sha":i.text("source_sha"),"provider_job_id":binding(i)["provider_job_id"],"cell_job_id":i.job(),"budget_digest":binding(i)["budget_digest"],"turn":request["turn"],"request_sha256":request["request_sha256"],"response_sha256":sha(&raw),"response_bytes":raw.len(),"model_id":binding(i)["model_id"],"reservation_id":reservation,"prepared_input_sha256":input,"prompt_tokens":4,"output_tokens":2,"complete":true,"quota_before_sha256":sha(&bytes(&before["quota"]).unwrap()),"quota_after_sha256":sha(&bytes(&after["quota"]).unwrap()),"quota_journal_before":before["quota"]["journal_hash"],"quota_journal_after":after["quota"]["journal_hash"],"quota_requests_before":before["quota"]["requests"],"quota_requests_after":after["quota"]["requests"],"qualification_eligible":false});
    json!({"schema":"hol-gauntlet-native-live-model-response.v1","source_sha":request["source_sha"],"provider_job_id":request["provider_job_id"],"job_id":request["job_id"],"budget_digest":request["budget_digest"],"turn":request["turn"],"request_sha256":request["request_sha256"],"response_sha256":sha(&raw),"body_b64":base64::engine::general_purpose::STANDARD.encode(raw),"usage_receipt":usage,"before":before,"after":after})
}
#[test]
fn live_context_refuses_source_cell_budget_and_provider_substitution() {
    let (_temp, _j, i, _writer) = fixture();
    validate_intent(&i.0).unwrap();
    for (pointer, value) in [
        ("/live/spec_sha256", json!("0".repeat(64))),
        ("/live/cell_id", json!("episode-other")),
        ("/live/provider_binding/source_sha", json!("0".repeat(40))),
        (
            "/live/provider_binding/maximum_accounted_tokens",
            json!(200_001),
        ),
        (
            "/live/provider_binding/status_pins/profile",
            json!("owned-mlx-serial.v1"),
        ),
        (
            "/live/provider_binding/cells/0/job_id",
            json!("4".repeat(16)),
        ),
    ] {
        let mut bad = i.0.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(validate_intent(&bad).is_err(), "{pointer}");
    }
    assert!(super::super::super::run_native_operation_command(&[
        "run".into(),
        "/missing-private-directory".into(),
        i.job().into(),
        i.digest().unwrap()
    ])
    .is_err());
}
#[test]
fn live_v9_declaration_has_no_top_level_role_and_exact_outside_model_scope() {
    let (_temp, _j, mut i, _writer) = fixture();
    let mut d = json!({"schema":"hol-gauntlet-native-worker-job.v9","profile":"native-host-pinned-live-omp-v1","source_sha":i.text("source_sha"),"job_id":i.job(),"worker_generation":i.text("worker_generation"),"preparation_sha256":i.text("preparation_sha256"),"guard":{},"sdk":{},"live":{"schema":"hol-gauntlet-native-live-omp-job.v1","cell_id":context_value(&i)["cell_id"],"spec_sha256":context_value(&i)["spec_sha256"],"model":{"schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":binding(&i)["provider_job_id"],"budget_digest":binding(&i)["budget_digest"],"model_id":binding(&i)["model_id"],"max_turns":64,"token_limit":100_000}}});
    i.0["deployment_digest"] = json!(sha(&bytes(&d).unwrap()));
    verify_bundle_binding(&i, &d).unwrap();
    d["role"] = json!("feature-ai-unprotected");
    i.0["deployment_digest"] = json!(sha(&bytes(&d).unwrap()));
    assert!(verify_bundle_binding(&i, &d).is_err());
    d.as_object_mut().unwrap().remove("role");
    d["live"]["model"]["budget_digest"] = json!("0".repeat(64));
    i.0["deployment_digest"] = json!(sha(&bytes(&d).unwrap()));
    assert!(verify_bundle_binding(&i, &d).is_err());
}
#[test]
fn live_pair_order_refuses_protected_first_and_baseline_after_protected_dispatch() {
    let (_temp, j, baseline, _writer) = fixture();
    require_pair_order(&j, &baseline).unwrap();
    let mut protected = baseline.clone();
    protected.0["job_id"] = binding(&baseline)["cells"][1]["job_id"].clone();
    protected.0["role"] = json!("feature-ai-protected");
    protected.0["live"]["cell_id"] = binding(&baseline)["cells"][1]["episode_id"].clone();
    let protected = Intent::parse(&protected.raw().unwrap()).unwrap();
    assert!(require_pair_order(&j, &protected).is_err());
    j.write(baseline.job(), "intent", &baseline.raw().unwrap())
        .unwrap();
    j.write(
        baseline.job(),
        "dispatch",
        &Journal::dispatch_raw(&baseline).unwrap(),
    )
    .unwrap();
    assert!(require_pair_order(&j, &protected).is_err());
    j.write(
        protected.job(),
        "dispatch",
        &Journal::dispatch_raw(&protected).unwrap(),
    )
    .unwrap();
    assert!(require_pair_order(&j, &baseline).is_err());
    assert!(j.absent(protected.job(), "completion").unwrap());
}
#[test]
fn actual_host_turn_pins_join_temporary_quota_and_refuse_rehashed_usage_or_orphans() {
    let (_temp, j, i, w) = fixture();
    let req = request(&i, 1);
    validate_request(&i, &req, 1).unwrap();
    let rsp = response(&i, &w, &req);
    let pins = response_pins(&i, &req, &rsp).unwrap();
    assert_eq!(pins.as_object().unwrap().len(), 10);
    assert_eq!(
        pins["observation_sha256"],
        sha(&bytes(&json!({
            "usage":rsp["usage_receipt"],"before":rsp["before"],"after":rsp["after"]
        }))
        .unwrap())
    );
    j.write(i.job(), &suffix(1, "request"), &bytes(&req).unwrap())
        .unwrap();
    j.write(i.job(), &suffix(1, "response"), &bytes(&rsp).unwrap())
        .unwrap();
    j.write(i.job(), &suffix(1, "pins"), &bytes(&pins).unwrap())
        .unwrap();
    assert_eq!(turn_pins(&j, &i, 1).unwrap()["turn_pins"], json!([pins]));
    assert!(turn_pins(&j, &i, 0).is_err());
    let mut bad = rsp.clone();
    bad["usage_receipt"]["output_tokens"] = json!(3);
    assert!(response_pins(&i, &req, &bad).is_err());
    let mut bad = rsp;
    bad["body_b64"] = json!(base64::engine::general_purpose::STANDARD.encode(b"{\"forged\":true}"));
    assert!(response_pins(&i, &req, &bad).is_err());
}
#[test]
fn old_identity_only_turn_pin_stays_incomplete_without_rewriting_private_evidence() {
    let (_temp, j, i, w) = fixture();
    let req = request(&i, 1);
    let rsp = response(&i, &w, &req);
    let mut old = response_pins(&i, &req, &rsp).unwrap();
    old.as_object_mut().unwrap().remove("observation_sha256");
    let original = bytes(&old).unwrap();
    j.write(i.job(), &suffix(1, "request"), &bytes(&req).unwrap())
        .unwrap();
    j.write(i.job(), &suffix(1, "response"), &bytes(&rsp).unwrap())
        .unwrap();
    j.write(i.job(), &suffix(1, "pins"), &original).unwrap();
    assert!(turn_pins(&j, &i, 1).is_err());
    assert_eq!(j.read(i.job(), &suffix(1, "pins")).unwrap(), original);
    assert_eq!(
        j.read(i.job(), &suffix(1, "response")).unwrap(),
        bytes(&rsp).unwrap()
    );
}
#[test]
fn live_pipe_refuses_partial_or_late_frames_and_keeps_newline_boundaries() {
    let (host, mut guest) = UnixStream::pair().unwrap();
    let mut frames = Frames::new(
        host.try_clone().unwrap(),
        host,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    guest.write_all(b"{}\n{\"next\":true}\n").unwrap();
    assert_eq!(frames.line().unwrap().unwrap(), b"{}");
    assert_eq!(frames.line().unwrap().unwrap(), b"{\"next\":true}");
    guest.write_all(b"{\"partial\":").unwrap();
    guest.shutdown(Shutdown::Write).unwrap();
    assert!(frames.line().is_err());
    let (host, _guest) = UnixStream::pair().unwrap();
    let mut frames = Frames::new(
        host.try_clone().unwrap(),
        host,
        Instant::now() - Duration::from_millis(1),
    )
    .unwrap();
    assert!(frames.send(&json!({"late":true})).is_err());
}

pub(in crate::native_operation) fn created_fixture(
) -> (tempfile::TempDir, Journal, Intent, Value, Value) {
    created_fixture_mode(true)
}
pub(in crate::native_operation) fn prepared_fixture(
) -> (tempfile::TempDir, Journal, Intent, Value, Value) {
    created_fixture_mode(false)
}
fn created_fixture_mode(released: bool) -> (tempfile::TempDir, Journal, Intent, Value, Value) {
    let (temp, j, mut i, _writer) = fixture();
    let source = i.text("source_sha").to_owned();
    let job = i.job().to_owned();
    let worker = i.text("worker_generation").to_owned();
    let formatter = "a".repeat(64);
    let storage =
        super::super::super::job_storage_fixture(&source, &job, &worker, &formatter, "native-v1");
    let root = format!("/var/lib/hol-gauntlet-rust/native-jobs/{job}");
    let workspace = json!({"source":format!("{root}/workspace"),"destination":"/runtime/home/project","custody_root":root,"device":storage["receipt"]["root_directory"]["device"],"inode":52,"mode":448});
    let prep = json!({"schema":"hol-gauntlet-cell-preparation.v2","runtime_prefix":format!("/opt/hol-gauntlet/candidates/{source}/prefix"),"runtime_tree_digest":"e".repeat(64),"podman_sha256":"a".repeat(64),"task_mounts":{"workspace":workspace},"launch":{"image_interpreter_sha256":i.0["interpreter_sha256"],"outside_observer_sha256":i.0["observer_sha256"]}});
    i.0["preparation_sha256"] = json!(sha(&bytes(&prep).unwrap()));
    let d = json!({"schema":"hol-gauntlet-native-worker-job.v9","profile":"native-host-pinned-live-omp-v1","source_sha":source,"job_id":job,"worker_generation":worker,"preparation_sha256":i.0["preparation_sha256"],"guard":{"source_sha":source},"sdk":{"publication_sha256":"b".repeat(64)},"live":{"schema":"hol-gauntlet-native-live-omp-job.v1","cell_id":context_value(&i)["cell_id"],"spec_sha256":context_value(&i)["spec_sha256"],"model":{"schema":"hol-gauntlet-native-live-model-pins.v1","provider_job_id":binding(&i)["provider_job_id"],"budget_digest":binding(&i)["budget_digest"],"model_id":binding(&i)["model_id"],"max_turns":64,"token_limit":100000}}});
    i.0["deployment_digest"] = json!(sha(&bytes(&d).unwrap()));
    let i = Intent::parse(&i.raw().unwrap()).unwrap();
    let init = json!({"schema":"hol-gauntlet-host-native-initialization-intent.v2","source_sha":source,"job_id":job,"worker_generation":worker,"vm":i.0["vm"],"limactl":i.0["limactl"],"lima_sha256":i.0["lima_sha256"],"transport_context":i.0["transport_context"],"mke2fs_sha256":formatter});
    let mut w = workspace;
    w["uid"] = json!(10001);
    w["gid"] = json!(10001);
    let initialization = json!({"schema":"hol-gauntlet-native-job-initialization.v2","source_sha":source,"job_id":job,"worker_generation":worker,"job_directory":storage["receipt"]["root_directory"],"workspace":w,"storage":storage,"job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,"model_requests":0});
    let wrap = |schema: &str, r: Value| json!({"schema":schema,"receipt_sha256":sha(&bytes(&r).unwrap()),"receipt":r});
    let initialized = wrap(
        "hol-gauntlet-native-job-initialization-result.v2",
        initialization,
    );
    let bundle = json!({"schema":"hol-gauntlet-native-host-pinned-preparation-input.v1","declaration":d,"preparation":prep});
    let normal = wrap(
        "hol-gauntlet-native-host-pinned-preparation-result.v2",
        json!({"schema":"hol-gauntlet-native-host-pinned-preparation.v2","source_sha":source,"job_id":job,"deployment_digest":i.0["deployment_digest"],"worker_generation":worker,"preparation_sha256":i.0["preparation_sha256"],"bundle_sha256":sha(&bytes(&bundle).unwrap()),"initialization_sha256":initialized["receipt_sha256"],"storage_receipt_sha256":storage["receipt_sha256"],"control_role":i.0["role"],"runtime_tree_sha256":"e".repeat(64),"sdk_publication_sha256":"b".repeat(64),"job_dispatched":false,"candidate_executed":false,"artifact_admitted":false,"execution_eligible":false,"qualification_eligible":false,"guard_causality_verified":false,"model_requests":0}),
    );
    let prepared = wrap(
        "hol-gauntlet-native-live-preparation-result.v1",
        json!({"schema":"hol-gauntlet-native-live-prepared.v2","source_sha":source,"job_id":job,"deployment_digest":i.0["deployment_digest"],"worker_generation":worker,"preparation_sha256":i.0["preparation_sha256"],"normal_preparation_receipt_sha256":normal["receipt_sha256"],"role":i.0["role"],"cell_id":context_value(&i)["cell_id"],"spec_sha256":context_value(&i)["spec_sha256"],"world_public_key_hex":"5".repeat(64),"world_initial_sha256":super::super::initial_hash().unwrap(),"cleanup_public_key_hex":"6".repeat(64)}),
    );
    for (suffix, v) in [
        ("intent", i.0.clone()),
        ("initialize-intent", init.clone()),
        (
            "initialize-dispatch",
            json!({"schema":"hol-gauntlet-host-native-initialization-dispatch.v1","job_id":job,"initialization_intent_sha256":sha(&bytes(&init).unwrap()),"retry_allowed":false}),
        ),
        ("initialize-result", initialized.clone()),
        ("prepare-bundle", bundle.clone()),
        (
            "prepare-dispatch",
            json!({"schema":"hol-gauntlet-host-native-preparation-dispatch.v1","job_id":job,"intent_sha256":i.digest().unwrap(),"bundle_sha256":sha(&bytes(&bundle).unwrap()),"bundle_bytes":bytes(&bundle).unwrap().len(),"initialization_sha256":initialized["receipt_sha256"],"retry_allowed":false}),
        ),
        ("prepare-result", normal),
        (
            "live-provision-dispatch",
            json!({"schema":"hol-gauntlet-host-live-provision-dispatch.v1","job_id":job,"intent_sha256":i.digest().unwrap(),"spec_sha256":context_value(&i)["spec_sha256"],"retry_allowed":false}),
        ),
        ("live-prepared", prepared.clone()),
    ] {
        j.write(&job, suffix, &bytes(&v).unwrap()).unwrap();
    }
    if !released {
        return (temp, j, i, initialized, prepared);
    }
    j.write(&job, "dispatch", &Journal::dispatch_raw(&i).unwrap())
        .unwrap();
    let pre = gauntlet_contracts::PrelaunchPrepared {
        source_sha: source.clone(),
        job_id: job.clone(),
        deployment_digest: i.text("deployment_digest").into(),
        worker_generation: worker.clone(),
        started_marker_sha256: "7".repeat(64),
        controller_key_pin_sha256: "8".repeat(64),
        controller_public_key_hex: "1".repeat(64),
    };
    let keys = HostControllerKeyPinJournal::open(&j.path).unwrap();
    let (record, _) = keys
        .accept_prepared(&pre.to_bytes().unwrap(), &i.expected())
        .unwrap();
    let pins = json!({"source_sha":source,"job_id":job,"deployment_digest":i.0["deployment_digest"],"worker_generation":worker,"preparation_sha256":i.0["preparation_sha256"],"live_prepared_sha256":prepared["receipt_sha256"],"storage_receipt_sha256":storage["receipt_sha256"],"host_pin_sha256":record.raw_sha256,"container_id":"a".repeat(64),"creation_sha256":"b".repeat(64),"inspection_sha256":"c".repeat(64),"policy_sha256":"d".repeat(64),"repair_generation":"e".repeat(64)});
    let f = super::super::recovery::created_context(&j, &i, &pins).unwrap();
    j.write(&job, "live-created-repair-intent", &bytes(&f).unwrap())
        .unwrap();
    let receipt = json!({"schema":"hol-gauntlet-native-live-sdk-created-repair.v1","intent_sha256":"f".repeat(64),"pins_sha256":sha(&bytes(&pins).unwrap()),"container_id_sha256":sha("a".repeat(64).as_bytes()),"sdk_agent_absent":true,"sdk_profile_absent":true,"process_signalled":false,"image_adopted":false,"job_terminal_written":false,"model_requests":null,"exit_code":null,"execution_eligible":false,"qualification_eligible":false});
    (temp, j, i, f, receipt)
}
#[test]
fn live_created_repair_resumes_intent_only_loss_without_workload_or_key_replay() {
    let (_temp, j, i, f, receipt) = created_fixture();
    let mut calls = Vec::new();
    assert!(
        super::super::recovery::created_finish(&j, &i, &f, "failure-created-read", |read| {
            calls.push(read);
            Err("unexpected RPC".into())
        })
        .is_err()
    );
    assert!(calls.is_empty());
    assert!(j.absent(i.job(), "live-created-repair-dispatch").unwrap());
    let result =
        super::super::recovery::created_finish(&j, &i, &f, "failure-created-resume", |read| {
            assert!(!j.absent(i.job(), "live-created-repair-dispatch").unwrap());
            calls.push(read);
            if read {
                Err("Root intent absent".into())
            } else {
                bytes(&receipt)
            }
        })
        .unwrap();
    assert_eq!(calls, vec![true, false]);
    assert!(result["model_requests"].is_null());
    assert!(result["exit_code"].is_null());
    assert!(j.absent(i.job(), "completion").unwrap());
    assert!(j.absent(i.job(), "repair").unwrap());
    assert!(j.require_idle().is_err());
    super::super::recovery::created_finish(&j, &i, &f, "failure-created-read", |_| {
        panic!("retained receipt must not replay metadata mutation")
    })
    .unwrap();
}
#[test]
fn live_created_repair_lost_reply_and_substituted_context_remain_bound() {
    let (_temp, j, i, f, receipt) = created_fixture();
    assert!(
        super::super::recovery::created_finish(&j, &i, &f, "failure-created-repair", |_| Err(
            "lost original reply".into()
        ))
        .is_err()
    );
    let mut calls = Vec::new();
    super::super::recovery::created_finish(&j, &i, &f, "failure-created-resume", |read| {
        calls.push(read);
        assert!(read);
        bytes(&receipt)
    })
    .unwrap();
    assert_eq!(calls, vec![true]);
    for field in [
        "pins_sha256",
        "container_id_sha256",
        "model_requests",
        "exit_code",
        "job_terminal_written",
    ] {
        let mut changed = receipt.clone();
        changed[field] = if field == "model_requests" || field == "exit_code" {
            json!(0)
        } else if field == "job_terminal_written" {
            json!(true)
        } else {
            json!("0".repeat(64))
        };
        assert!(
            super::super::recovery::created_result(&f, &bytes(&changed).unwrap()).is_err(),
            "{field}"
        );
    }
    let mut changed = f.clone();
    changed["pins"]["host_pin_sha256"] = json!("0".repeat(64));
    let mut calls = 0;
    assert!(super::super::recovery::created_finish(
        &j,
        &i,
        &changed,
        "failure-created-resume",
        |_| {
            calls += 1;
            bytes(&receipt)
        }
    )
    .is_err());
    assert_eq!(calls, 0);
}
