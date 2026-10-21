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
