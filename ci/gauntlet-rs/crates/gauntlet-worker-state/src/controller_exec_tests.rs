use super::*;

#[test]
fn controller_environment_accepts_only_the_four_fixed_keys() {
    let mut environment = BTreeMap::from([
        (
            "HOL_GAUNTLET_RUST_JOB_SLICE",
            "holgauntletrust1234567890abcdef.slice".to_owned(),
        ),
        ("HOME", "/root".to_owned()),
        ("LANG", "C.UTF-8".to_owned()),
        ("PATH", "/usr/bin:/bin".to_owned()),
    ]);
    assert_eq!(fixed_environment(&environment).unwrap().len(), 4);
    environment.remove("HOME");
    assert!(matches!(
        fixed_environment(&environment),
        Err(ControllerExecError::InvalidPlan)
    ));
    environment.insert("HOME", "/root".to_owned());
    environment.insert("UNTRUSTED", "value".to_owned());
    assert!(matches!(
        fixed_environment(&environment),
        Err(ControllerExecError::InvalidPlan)
    ));
}

#[test]
fn stale_report_directory_or_symlink_blocks_a_fresh_job_output() {
    let temp = tempfile::tempdir().unwrap();
    let output = rustix::fs::open(
        temp.path(),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let job = "a1b2c3d4e5f60718";
    assert!(require_absent_child(&output, job).is_ok());
    std::fs::create_dir(temp.path().join(job)).unwrap();
    assert!(matches!(
        require_absent_child(&output, job),
        Err(ControllerExecError::OutputExists)
    ));
    std::fs::remove_dir(temp.path().join(job)).unwrap();
    std::os::unix::fs::symlink("missing", temp.path().join(job)).unwrap();
    assert!(matches!(
        require_absent_child(&output, job),
        Err(ControllerExecError::OutputExists)
    ));
}
