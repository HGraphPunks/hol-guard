use super::adapter::Numerical;
use super::*;
use base64::Engine as _;
use gauntlet_evidence::{verify_rust_provider_usage, ProviderQuotaWriter};
use std::collections::VecDeque;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

struct Fixture {
    _temporary: tempfile::TempDir,
    journal: Journal,
    writer: ProviderQuotaWriter,
    intent: Intent,
    assets: Assets,
}
fn fixture() -> Fixture {
    let temporary = tempfile::Builder::new()
        .prefix("provider-quota-mock-")
        .tempdir_in("/tmp")
        .unwrap();
    let root = temporary.path().canonicalize().unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let quota = root.join("quota");
    let mut writer = ProviderQuotaWriter::create_new(
        &quota,
        "temporary-unit-test-only",
        900_000,
        100,
        &"a".repeat(64),
    )
    .unwrap();
    let before = read_provider_quota_snapshot(&quota, writer.config_digest(), None).unwrap();
    writer = writer
        .extend_allowance(
            1_000_000,
            &"b".repeat(64),
            before["journal_hash"].as_str().unwrap(),
        )
        .unwrap();
    let before =
        read_provider_quota_snapshot(&quota, writer.config_digest(), writer.allowance_digest())
            .unwrap();
    let state = root.join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sample = root.join("numerical.py");
    std::fs::write(&sample, b"mock numerical asset").unwrap();
    std::fs::set_permissions(&sample, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pins = json!({sample.to_str().unwrap():{"sha256":sha(b"mock numerical asset"),"bytes":20}});
    let assets = Assets::capture(&pins).unwrap();
    let spec = json!({"source_sha":"c".repeat(40),"provider_job_id":"d".repeat(16),"model_id":MODEL,"model_identity_digest":"a".repeat(64),"quota_root":quota,"quota_config_digest":writer.config_digest(),"quota_allowance_digest":writer.allowance_digest(),"token_cap":1_000_000,"maximum_requests":100,"server_sha256":"e".repeat(64),"producer_sha256":"f".repeat(64),"assets":pins,"cells":[{"job_id":"1".repeat(16),"episode_id":"episode-a9344653386e0c30b3bd63437f283047","token_budget":100_000},{"job_id":"2".repeat(16),"episode_id":"episode-406531b0394f2bfaba126c5ec3ddfadb","token_budget":100_000}]});
    let intent =
        Intent(json!({"spec":spec,"quota_at_prepare":before,"maximum_accounted_tokens":200_000}));
    Fixture {
        _temporary: temporary,
        journal: Journal::open(&state).unwrap(),
        writer,
        intent,
        assets,
    }
}
fn request(intent: &Intent, job: &str, turn: u64) -> Value {
    let raw=bytes(&json!({"model":MODEL,"messages":[{"role":"user","content":"mock prompt"}],"stream":false,"max_tokens":8})).unwrap();
    json!({"schema":"hol-gauntlet-native-live-model-request.v1","source_sha":intent.spec()["source_sha"],"provider_job_id":intent.spec()["provider_job_id"],"job_id":job,"budget_digest":intent.digest().unwrap(),"turn":turn,"request_sha256":sha(&raw),"body_b64":base64::engine::general_purpose::STANDARD.encode(raw)})
}
struct Mock {
    queue: VecDeque<Result<Value, String>>,
    intent: Intent,
    prompt: u64,
    fail: bool,
    reserved_observed: bool,
}
impl Mock {
    fn new(intent: &Intent) -> Self {
        Self {
            queue: VecDeque::new(),
            intent: intent.clone(),
            prompt: 4,
            fail: false,
            reserved_observed: false,
        }
    }
}
impl Numerical for Mock {
    fn send(&mut self, v: &Value, _journal: &Journal, _digest: &str) -> Result<(), String> {
        match v["schema"].as_str().unwrap_or("") {
            "hol-gauntlet-mlx-numerical-prepare.v1" => {
                assert_eq!(self.intent.snapshot().unwrap()["pending_requests"], 0);
                self.queue.push_back(Ok(json!({"schema":"hol-gauntlet-mlx-numerical-prepared.v1","request_sha256":v["request_sha256"],"prompt_token_ids":vec![7;self.prompt as usize],"generation_args":{"model":{"model":"default_model","draft":null,"adapter":null},"max_tokens":v["request"]["max_tokens"],"num_draft_tokens":0,"seed":0}})));
            }
            "hol-gauntlet-mlx-numerical-admit.v1" => {
                let snapshot = self.intent.snapshot().unwrap();
                assert_eq!(snapshot["pending_requests"], 1);
                assert_eq!(snapshot["reserved_tokens"], self.prompt + 8);
                self.reserved_observed = true;
                self.queue.push_back(Ok(json!({"schema":"hol-gauntlet-mlx-numerical-context.v1","prepared_input_sha256":v["prepared_input_sha256"],"prompt_tokens":self.prompt})));
                if self.fail {
                    self.queue
                        .push_back(Err("mock crashed after durable reservation".into()));
                    return Ok(());
                }
                self.queue.push_back(Ok(json!({"schema":"hol-gauntlet-mlx-numerical-token.v1","token":9,"text":"mock reply","state":"normal","matched_tokens":0,"finish_reason":"stop"})));
                self.queue.push_back(Ok(json!({"schema":"hol-gauntlet-mlx-numerical-complete.v1","prepared_input_sha256":v["prepared_input_sha256"],"prompt_tokens":self.prompt,"output_tokens":1})));
            }
            _ => return Err("unexpected mock command".into()),
        }
        Ok(())
    }
    fn receive(
        &mut self,
        _journal: &Journal,
        _digest: &str,
        _timeout: Duration,
    ) -> Result<Value, String> {
        self.queue.pop_front().expect("mock protocol output")
    }
}
fn usage_pins(intent: &Intent, usage: &Value) -> Value {
    let mut pins = json!({"profile":"owned-mlx-rust-serial.v2","source_sha":intent.spec()["source_sha"],"provider_job_id":intent.spec()["provider_job_id"],"binding_sha256":intent.digest().unwrap(),"adapter_sha256":sha(numerical::CODE.as_bytes()),"server_sha256":intent.spec()["server_sha256"],"producer_sha256":intent.spec()["producer_sha256"],"model_identity_digest":intent.spec()["model_identity_digest"],"quota_config_digest":intent.spec()["quota_config_digest"],"quota_allowance_digest":intent.spec()["quota_allowance_digest"],"token_cap":1_000_000,"maximum_requests":100});
    for key in [
        "cell_job_id",
        "budget_digest",
        "turn",
        "request_sha256",
        "response_sha256",
        "response_bytes",
        "model_id",
        "reservation_id",
        "prepared_input_sha256",
    ] {
        pins[key] = usage[key].clone();
    }
    pins
}
#[test]
fn complete_mock_pair_reserves_before_generation_and_reconciles_real_temporary_quota() {
    let f = fixture();
    let mut engine = inference::Inference::new();
    let mut mock = Mock::new(&f.intent);
    for job in ["1".repeat(16), "2".repeat(16)] {
        let value = request(&f.intent, &job, 1);
        let response = engine
            .complete(&f.intent, &f.journal, &f.assets, &mut mock, &value)
            .unwrap();
        assert!(mock.reserved_observed);
        let prefix = format!("model-{job}-00001");
        let before = f.journal.json(&format!("{prefix}-before.json")).unwrap();
        let after = f.journal.json(&format!("{prefix}-after.json")).unwrap();
        let usage = &response["usage_receipt"];
        let verified =
            verify_rust_provider_usage(usage, &usage_pins(&f.intent, usage), &before, &after)
                .unwrap();
        assert_eq!(verified["model_tokens"], 5);
        assert_eq!(verified["qualification_eligible"], false);
        let raw = base64::engine::general_purpose::STANDARD
            .decode(response["body_b64"].as_str().unwrap())
            .unwrap();
        assert_eq!(sha(&raw), response["response_sha256"]);
        assert_eq!(parse(&raw).unwrap()["usage"]["total_tokens"], 5);
    }
    let snapshot = f.intent.snapshot().unwrap();
    assert_eq!(snapshot["known_tokens"], 10);
    assert_eq!(snapshot["pending_requests"], 0);
    assert_eq!(snapshot["requests"], 2);
    assert!(engine
        .complete(
            &f.intent,
            &f.journal,
            &f.assets,
            &mut mock,
            &request(&f.intent, &"1".repeat(16), 2)
        )
        .is_err());
}
#[test]
fn generation_crash_durably_halts_instead_of_settling_or_retrying() {
    let f = fixture();
    let mut engine = inference::Inference::new();
    let mut mock = Mock::new(&f.intent);
    mock.fail = true;
    let value = request(&f.intent, &"1".repeat(16), 1);
    assert!(engine
        .complete(&f.intent, &f.journal, &f.assets, &mut mock, &value)
        .is_err());
    let snapshot = f.intent.snapshot().unwrap();
    assert_eq!(snapshot["halted"], true);
    assert!(f.writer.reserve(1, 1, &"a".repeat(64), None).is_err());
    assert!(!f
        .journal
        .exists(&format!("model-{}-00001-response.json", "1".repeat(16)))
        .unwrap());
    assert!(inference::Inference::new()
        .complete(&f.intent, &f.journal, &f.assets, &mut mock, &value)
        .is_err());
}
#[test]
fn exact_context_budget_and_source_substitution_refuse_before_inference() {
    let f = fixture();
    let mut engine = inference::Inference::new();
    let mut mock = Mock::new(&f.intent);
    mock.prompt = 32768;
    let value = request(&f.intent, &"1".repeat(16), 1);
    assert!(engine
        .complete(&f.intent, &f.journal, &f.assets, &mut mock, &value)
        .is_err());
    assert!(!mock.reserved_observed);
    assert_eq!(f.intent.snapshot().unwrap()["requests"], 0);
    let mut excessive = value.clone();
    excessive["turn"] = json!(65);
    assert!(inference::validate(&f.intent, &excessive).is_err());
    for key in [
        "source_sha",
        "provider_job_id",
        "job_id",
        "budget_digest",
        "request_sha256",
    ] {
        let mut changed = value.clone();
        changed[key] = json!("0".repeat(if key == "source_sha" {
            40
        } else if key.ends_with("job_id") {
            16
        } else {
            64
        }));
        assert!(inference::validate(&f.intent, &changed).is_err());
    }
}
#[test]
fn actual_request_turn_and_known_usage_are_not_replayed() {
    let f = fixture();
    let mut engine = inference::Inference::new();
    let mut mock = Mock::new(&f.intent);
    let value = request(&f.intent, &"1".repeat(16), 1);
    engine
        .complete(&f.intent, &f.journal, &f.assets, &mut mock, &value)
        .unwrap();
    assert!(engine
        .complete(&f.intent, &f.journal, &f.assets, &mut mock, &value)
        .is_err());
    assert_eq!(f.intent.snapshot().unwrap()["known_tokens"], 5);
    let lease = f.writer.reserve(1, 1, &"a".repeat(64), None).unwrap();
    f.writer.settle(&lease, 1, 1).unwrap();
    assert!(engine
        .complete(
            &f.intent,
            &f.journal,
            &f.assets,
            &mut mock,
            &request(&f.intent, &"1".repeat(16), 2)
        )
        .is_err());
    assert_eq!(f.intent.snapshot().unwrap()["known_tokens"], 7);
}
#[test]
fn elapsed_caller_deadline_refuses_before_numerical_dispatch_or_quota_reservation() {
    let f = fixture();
    let before = f.intent.snapshot().unwrap();
    let mut engine = inference::Inference::new();
    let mut mock = Mock::new(&f.intent);
    assert!(engine
        .complete_bounded(
            &f.intent,
            &f.journal,
            &f.assets,
            &mut mock,
            &request(&f.intent, &"1".repeat(16), 1),
            Duration::ZERO
        )
        .is_err());
    assert!(!mock.reserved_observed);
    assert!(mock.queue.is_empty());
    assert_eq!(f.intent.snapshot().unwrap(), before);
}
#[test]
fn source_authorization_preserves_cap_and_allows_only_real_history_prefix() {
    let f = fixture();
    let mut spec = f.intent.spec().clone();
    spec["schema"] = json!("hol-gauntlet-rust-provider-spec.v1");
    let auth = json!({"schema":"hol-gauntlet-rust-provider-source-authorization.v1","authority":"operator-approved-source-binding-preserve-retained-quota","source_sha":spec["source_sha"],"provider_job_id":spec["provider_job_id"],"profile":"feature-ai","provider_spec_sha256":sha(&bytes(&spec).unwrap()),"quota_root":spec["quota_root"],"quota_config_digest":spec["quota_config_digest"],"quota_allowance_digest":spec["quota_allowance_digest"],"model_identity_digest":spec["model_identity_digest"],"token_cap":spec["token_cap"],"retained_quota":f.intent.0["quota_at_prepare"],"job_tokens":200_000,"allowance_reset":false,"token_cap_increase":false});
    validate_authorization(&auth, &spec, &sha(&bytes(&spec).unwrap())).unwrap();
    let id = f.writer.reserve(4, 8, &"c".repeat(64), None).unwrap();
    f.writer.settle(&id, 4, 1).unwrap();
    let after = f.intent.snapshot().unwrap();
    verify_provider_quota_observations(
        Path::new(spec["quota_root"].as_str().unwrap()),
        f.writer.config_digest(),
        f.writer.allowance_digest(),
        after["journal_hash"].as_str().unwrap(),
        &[auth["retained_quota"].clone(), after.clone()],
    )
    .unwrap();
    let mut fake = auth["retained_quota"].clone();
    fake["known_tokens"] = json!(1);
    assert!(verify_provider_quota_observations(
        Path::new(spec["quota_root"].as_str().unwrap()),
        f.writer.config_digest(),
        f.writer.allowance_digest(),
        after["journal_hash"].as_str().unwrap(),
        &[fake, after.clone()]
    )
    .is_err());
    for key in [
        "source_sha",
        "token_cap",
        "allowance_reset",
        "token_cap_increase",
    ] {
        let mut changed = auth.clone();
        changed[key] = if key == "source_sha" {
            json!("a".repeat(40))
        } else if key == "token_cap" {
            json!(2_000_000)
        } else {
            json!(true)
        };
        assert!(validate_authorization(&changed, &spec, &sha(&bytes(&spec).unwrap())).is_err());
    }
}
#[test]
fn token_tape_counts_control_tokens_and_decodes_qwen_calls_in_rust() {
    let mut tape = output::Tape::new(8);
    let input = "a".repeat(64);
    tape.accept(json!({"schema":"hol-gauntlet-mlx-numerical-context.v1","prepared_input_sha256":input,"prompt_tokens":4}),&input,4).unwrap();
    let raw = "<function=docs.read><parameter=id>kb-current</parameter></function>";
    tape.accept(json!({"schema":"hol-gauntlet-mlx-numerical-token.v1","token":1,"text":raw,"state":"tool","matched_tokens":0,"finish_reason":null}),&input,4).unwrap();
    tape.accept(json!({"schema":"hol-gauntlet-mlx-numerical-token.v1","token":2,"text":"</tool_call>","state":null,"matched_tokens":1,"finish_reason":"stop"}),&input,4).unwrap();
    assert!(tape.accept(json!({"schema":"hol-gauntlet-mlx-numerical-complete.v1","prepared_input_sha256":input,"prompt_tokens":4,"output_tokens":2}),&input,4).unwrap());
    let response = parse(&tape.response(4, "unit", None).unwrap()).unwrap();
    assert_eq!(
        response["choices"][0]["message"]["tool_calls"][0]["function"]["name"],
        "docs.read"
    );
    assert_eq!(response["usage"]["completion_tokens"], 2);
    assert_eq!(tape.tokens[1]["text"], "</tool_call>");
}
#[test]
fn retained_asset_replacement_and_private_record_mode_fail_closed() {
    let f = fixture();
    let path = PathBuf::from(f.assets.facts.as_object().unwrap().keys().next().unwrap());
    std::fs::rename(&path, path.with_extension("old")).unwrap();
    std::fs::write(&path, b"mock numerical asset").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(f.assets.stable().is_err());
    f.journal
        .put("private.json", &json!({"fixture":true}))
        .unwrap();
    std::fs::set_permissions(
        f.journal.path.join("private.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(f.journal.read("private.json").is_err());
}
#[path = "live_provider_preparation_tests.rs"]
mod preparation;
