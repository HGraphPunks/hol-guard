use super::*;
use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;

fn logs() -> (tempfile::TempDir, [File; 3]) {
    let directory = tempfile::tempdir().unwrap();
    let files = ["in", "out", "err"].map(|name| {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(directory.path().join(name))
            .unwrap()
    });
    (directory, files)
}
#[test]
fn private_socket_stdio_captures_exact_frames_and_reaps_the_host_client() {
    let (directory, files) = logs();
    // Inert system byte copier, never candidate/controller Python as Root.
    let mut client = NativeMcpProxyClient::spawn_process("/usr/bin/cat", &[], files).unwrap();
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(5);
    for raw in [b"{\"id\":1}".as_slice(), b"binary\x00\xff"] {
        client.write_frame(raw, deadline, &cancel).unwrap();
        assert_eq!(client.read_frame(deadline, &cancel).unwrap().unwrap(), raw);
    }
    let result = client.finish(deadline, &cancel).unwrap();
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["stderr"], "");
    assert_eq!(result["client"]["stderr_complete"], true);
    assert_eq!(result["client"]["host_client_reaped"], true);
    assert_eq!(result["client"]["product_process_drained"], false);
    let expected = b"{\"id\":1}\nbinary\x00\xff\n";
    for name in ["in", "out"] {
        assert_eq!(
            std::fs::read(directory.path().join(name)).unwrap(),
            expected
        );
    }
    assert!(client.write_frame(b"late", deadline, &cancel).is_err());
}
#[test]
fn cancellation_poison_is_sticky_and_cleanup_reaps_a_waiting_helper() {
    let (_directory, files) = logs();
    let mut client =
        NativeMcpProxyClient::spawn_process("/usr/bin/sleep", &["30".into()], files).unwrap();
    assert!(client
        .read_frame(
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(true)
        )
        .is_err());
    assert!(client
        .write_frame(
            b"later",
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false)
        )
        .is_err());
    client.close().unwrap();
    assert!(client.child.try_wait().unwrap().is_some());
    assert_eq!(client.observation()["poisoned"], true);
}
