use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

fn journal() -> (tempfile::TempDir, Journal) {
    let temp = tempfile::Builder::new()
        .prefix("provider-mock-")
        .tempdir_in("/tmp")
        .unwrap();
    let base = temp.path().canonicalize().unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    let long = base.join("long-private-journal-".repeat(8));
    std::fs::create_dir(&long).unwrap();
    std::fs::set_permissions(&long, std::fs::Permissions::from_mode(0o700)).unwrap();
    let short = base.join("socket");
    std::fs::create_dir(&short).unwrap();
    std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o700)).unwrap();
    let context = custody::socket_context(&short).unwrap();
    let mut journal = Journal::open(&long).unwrap();
    journal.configure_socket(&short, &context).unwrap();
    (temp, journal)
}
fn intent() -> Intent {
    Intent(
        json!({"spec":{"source_sha":"a".repeat(40),"provider_job_id":"b".repeat(16)},"channel_key_sha256":sha("ab".repeat(32).as_bytes())}),
    )
}
#[test]
fn private_unix_long_journal_uses_outside_pinned_short_directory_and_authenticated_response() {
    let (_temp, journal) = journal();
    assert!(journal.path.as_os_str().len() > 104);
    let intent = intent();
    let digest = intent.digest().unwrap();
    journal.put("provider-channel.json",&json!({"schema":"hol-gauntlet-rust-provider-private-channel.v1","binding_sha256":digest,"key":"ab".repeat(32)})).unwrap();
    let listener = http::listener(&journal, &digest).unwrap();
    std::thread::scope(|scope| {
        let client = scope.spawn(|| {
            let mut opened = Journal::open(&journal.path).unwrap();
            let socket = journal.socket_path().unwrap();
            let directory = socket.parent().unwrap();
            opened
                .configure_socket(directory, &custody::socket_context(directory).unwrap())
                .unwrap();
            http::client(&opened, &intent, "GET", "/v1/hol-gauntlet/status", None).unwrap()
        });
        let start = Instant::now();
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(start.elapsed() < Duration::from_secs(3));
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("{e}"),
            }
        };
        let request = http::request(&mut stream).unwrap();
        http::authenticate(&request, &journal, &intent).unwrap();
        let mut altered = http::Request {
            method: request.method.clone(),
            path: request.path.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
        };
        altered
            .headers
            .insert("x-hol-provider-remaining-millis".into(), "1".into());
        assert!(http::authenticate(&altered, &journal, &intent).is_err());
        http::reply(
            &mut stream,
            200,
            &json!({"fixture":"private-socket-only","qualification_eligible":false}),
            Some((&request, &journal, &intent)),
        )
        .unwrap();
        assert_eq!(client.join().unwrap()["fixture"], "private-socket-only");
    });
    drop(listener);
    journal.remove_socket(&digest).unwrap();
    assert!(!journal.socket_path().unwrap().exists());
}
#[test]
fn private_socket_replacement_and_ambiguous_http_are_refused() {
    let (_temp, journal) = journal();
    let intent = intent();
    let digest = intent.digest().unwrap();
    let listener = http::listener(&journal, &digest).unwrap();
    std::fs::rename(
        journal.socket_path().unwrap(),
        journal.socket_path().unwrap().with_file_name("old.sock"),
    )
    .unwrap();
    let _replacement = UnixListener::bind(journal.socket_path().unwrap()).unwrap();
    std::fs::set_permissions(
        journal.socket_path().unwrap(),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(journal.verify_socket(&digest).is_err());
    assert!(journal.remove_socket(&digest).is_err());
    drop(listener);
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client.write_all(b"POST /v1/chat/completions HTTP/1.1\r\nHost: provider.invalid\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n").unwrap();
    assert!(http::request(&mut server).is_err());
}
#[test]
fn original_short_socket_directory_replacement_is_refused() {
    let (_temp, journal) = journal();
    let socket = journal.socket_path().unwrap();
    let path = socket.parent().unwrap();
    let expected = custody::socket_context(path).unwrap();
    std::fs::rename(path, path.with_file_name("old-socket-directory")).unwrap();
    std::fs::create_dir(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(journal.stable().is_err());
    assert!(Journal::open(&journal.path)
        .unwrap()
        .configure_socket(path, &expected)
        .is_err());
}
#[test]
fn owned_numerical_process_uses_mock_modules_and_frozen_prepared_tokens() {
    let (_temp, journal) = journal();
    let site = journal.path.join("mock-site-packages");
    for name in ["mlx", "mlx_lm"] {
        std::fs::create_dir_all(site.join(name)).unwrap();
        std::fs::set_permissions(site.join(name), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(site.join(name).join("__init__.py"), b"").unwrap();
    }
    let core="def set_memory_limit(n): pass\ndef set_wired_limit(n): pass\ndef set_cache_limit(n): pass\n";
    std::fs::write(site.join("mlx/core.py"), core).unwrap();
    let server = r#"
from dataclasses import dataclass
@dataclass
class ModelDescription:
    model:object; draft:object; adapter:object
@dataclass
class SamplingArguments:
    temperature:object; top_p:object; top_k:object; min_p:object; xtc_probability:object; xtc_threshold:object
@dataclass
class LogitsProcessorArguments:
    logit_bias:object; repetition_penalty:object; repetition_context_size:object; presence_penalty:object; presence_context_size:object; frequency_penalty:object; frequency_context_size:object
@dataclass
class GenerationArguments:
    model:object; sampling:object; logits:object; stop_words:object; max_tokens:object; num_draft_tokens:object; logprobs:object; top_logprobs:object; seed:object; chat_template_kwargs:object
@dataclass
class CompletionRequest:
    request_type:object; prompt:object; messages:object; tools:object; role_mapping:object
@dataclass
class GenerationContext:
    prompt:object
@dataclass
class Response:
    token:object; text:object; state:object; match:object; finish_reason:object
class LRUPromptCache:
    def __init__(self,*args): pass
class ModelProvider:
    def __init__(self,cli):
        self.cli_args=cli; self.is_distributed=False; self.draft_model=None
        self.tokenizer=type('MockTokenizer',(),{'has_chat_template':True,'has_tool_calling':True})()
    def load_default(self): pass
class ResponseGenerator:
    def _tokenize(self,tokenizer,request,args): return ([3,4,5],[],[],'normal')
    def _serve_single(self,packet):
        output,request,args=packet
        prompt=self._tokenize(self.model_provider.tokenizer,request,args)[0]
        output.put(GenerationContext(prompt))
        output.put(Response(7,'mock numerical output','normal',None,'stop'))
        output.put(None)
"#;
    std::fs::write(site.join("mlx_lm/server.py"), server).unwrap();
    // Darwin's /usr/bin/python3 is a Root-owned launcher. Resolve only its
    // standard interpreter path before the mock; no model library is imported.
    let discovered = std::process::Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-S",
            "-B",
            "-c",
            "import os,sys;print(os.path.realpath(sys.executable))",
        ])
        .output()
        .unwrap();
    assert!(discovered.status.success());
    assert!(discovered.stdout.len() < 4096);
    let capsule=std::path::Path::new("/Users/construct/Documents/projects/hol-guard-refinement/local-model-capsule-20261013/.venv/bin/python");
    let python = std::fs::canonicalize(if capsule.is_file() {
        capsule
    } else {
        std::path::Path::new(std::str::from_utf8(&discovered.stdout).unwrap().trim())
    })
    .unwrap();
    let mut pins = serde_json::Map::new();
    for path in [
        python.clone(),
        site.join("mlx/core.py"),
        site.join("mlx_lm/server.py"),
    ] {
        let raw = std::fs::read(&path).unwrap();
        pins.insert(
            path.to_str().unwrap().into(),
            json!({"sha256":sha(&raw),"bytes":raw.len()}),
        );
    }
    let assets = Assets::capture(&Value::Object(pins)).unwrap();
    let intent = Intent(
        json!({"spec":{"python":python,"site_packages":site,"model_directory":journal.path,"producer_sha256":"a".repeat(64)}}),
    );
    let mut process = adapter::Adapter::spawn(&intent, &journal, &assets).unwrap();
    let digest = intent.digest().unwrap();
    let request_sha = "c".repeat(64);
    process.send(&json!({"schema":"hol-gauntlet-mlx-numerical-prepare.v1","request_sha256":request_sha,"request":{"messages":[{"role":"user","content":"mock"}],"max_tokens":8}}),&journal,&digest).unwrap();
    let prepared = process
        .receive(&journal, &digest, Duration::from_secs(5))
        .unwrap();
    let (prompt, input) = adapter::prepared(&prepared, &request_sha, 8).unwrap();
    assert_eq!(prompt, 3);
    process.send(&json!({"schema":"hol-gauntlet-mlx-numerical-admit.v1","request_sha256":request_sha,"prepared_input_sha256":input}),&journal,&digest).unwrap();
    let mut tape = output::Tape::new(8);
    loop {
        if tape
            .accept(
                process
                    .receive(&journal, &digest, Duration::from_secs(5))
                    .unwrap(),
                &input,
                prompt,
            )
            .unwrap()
        {
            break;
        }
    }
    let response = parse(&tape.response(prompt, "mock", None).unwrap()).unwrap();
    assert_eq!(
        response["choices"][0]["message"]["content"],
        "mock numerical output"
    );
    assert_eq!(process.stop(&journal).unwrap()["child_reaped"], true);
}
