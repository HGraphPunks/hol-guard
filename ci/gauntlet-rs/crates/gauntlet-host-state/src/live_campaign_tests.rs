//! Synthetic Host boundaries only; these tests do not qualify real inference.
use super::*;
use gauntlet_evidence::{read_provider_quota_snapshot, ProviderQuotaWriter};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;

fn fixture() -> (tempfile::TempDir, Journal, Intent, ProviderQuotaWriter) {
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
