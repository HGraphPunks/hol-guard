//! Fixed relocatable console scripts, written as data after exact wheel
//! metadata validation. Only the native Root prefix owner calls this writer.
use crate::dependency_prefix_meta::same;
use rustix::fs::{fchmod, fstat, fsync, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::{getegid, geteuid};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;

pub(crate) const ENTRIES: [(&str, &str); 6] = [
    ("hol-guard", "codex_plugin_scanner.cli:main"),
    (
        "hol-guard-eval",
        "codex_plugin_scanner.guard.evaluation_cli:main",
    ),
    (
        "hol-guard-secrets",
        "codex_plugin_scanner.guard.secrets.cli:main",
    ),
    ("plugin-ecosystem-scanner", "codex_plugin_scanner.cli:main"),
    ("plugin-guard", "codex_plugin_scanner.cli:main"),
    ("plugin-scanner", "codex_plugin_scanner.cli:main"),
];

fn declaration(raw: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(raw).map_err(|_| "console metadata UTF-8 required")?;
    let mut lines = text.lines().map(str::trim).filter(|s| !s.is_empty());
    if lines.next() != Some("[console_scripts]") {
        return Err("closed console script section required".into());
    }
    let mut seen = BTreeMap::new();
    for line in lines {
        let (name, target) = line
            .split_once('=')
            .ok_or("console declaration malformed")?;
        if seen.insert(name.trim(), target.trim()).is_some() {
            return Err("duplicate console declaration".into());
        }
    }
    if seen != ENTRIES.into_iter().collect() {
        return Err("wheel console declarations differ from the fixed supported set".into());
    }
    Ok(())
}

fn script(target: &str) -> Vec<u8> {
    let module = target.strip_suffix(":main").expect("fixed reviewed target");
    format!("#!/bin/sh\n'''exec' \"${{0%/*}}/python3\" -I -B \"$0\" \"$@\"\n' '''\nfrom {module} import main\nraise SystemExit(main())\n").into_bytes()
}

fn directory(parent: &OwnedFd, name: &str) -> Result<OwnedFd, String> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let held = fstat(&fd).map_err(|e| e.to_string())?;
    let visible = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if held.st_uid != geteuid().as_raw()
        || held.st_gid != getegid().as_raw()
        || held.st_mode & 0o022 != 0
        || !same(&held, &visible)
    {
        return Err("console directory custody differs".into());
    }
    Ok(fd)
}

fn read(parent: &OwnedFd, name: &str, mode: rustix::fs::RawMode) -> Result<Vec<u8>, String> {
    let fd = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    let before = fstat(&fd).map_err(|e| e.to_string())?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != geteuid().as_raw()
        || before.st_gid != getegid().as_raw()
        || before.st_nlink != 1
        || before.st_mode & 0o7777 != mode
        || !(1..=8192).contains(&before.st_size)
    {
        return Err("ordinary bounded console file required".into());
    }
    let mut file = File::from(fd);
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(8193)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    let after = fstat(&file).map_err(|e| e.to_string())?;
    let visible = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
    if raw.len() as i64 != before.st_size || !same(&before, &after) || !same(&before, &visible) {
        return Err("console file changed".into());
    }
    Ok(raw)
}

pub(crate) fn validate(stage: &OwnedFd, version: &str) -> Result<(), String> {
    if !gauntlet_evidence::valid_package_version(version) {
        return Err("fixed package version required".into());
    }
    let info = directory(stage, &format!("hol_guard-{version}.dist-info"))?;
    declaration(&read(&info, "entry_points.txt", 0o444)?)
}

pub(crate) fn write(stage: &OwnedFd, prefix: &OwnedFd, version: &str) -> Result<u64, String> {
    validate(stage, version)?;
    let bin = directory(prefix, "bin")?;
    for (name, _) in ENTRIES {
        match statat(&bin, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            _ => return Err("console script destination already consumed".into()),
        }
    }
    let mut bytes = 0;
    for (name, target) in ENTRIES {
        let raw = script(target);
        let fd = openat(
            &bin,
            name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|e| e.to_string())?;
        let mut file = File::from(fd);
        file.write_all(&raw).map_err(|e| e.to_string())?;
        fchmod(&file, Mode::from_bits_truncate(0o755)).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let held = fstat(&file).map_err(|e| e.to_string())?;
        let visible = statat(&bin, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|e| e.to_string())?;
        if !same(&held, &visible) || read(&bin, name, 0o755)? != raw {
            return Err("console script readback differs".into());
        }
        bytes += raw.len() as u64;
    }
    fsync(&bin).map_err(|e| e.to_string())?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    #[test]
    fn python_parses_every_launcher_as_data_without_importing_product() {
        for (_, target) in ENTRIES {
            let mut child = Command::new("/usr/bin/python3").args(["-I", "-B", "-S", "-c", "import ast,sys; t=ast.parse(sys.stdin.buffer.read()); assert len(t.body)==3 and isinstance(t.body[1],ast.ImportFrom) and t.body[1].module==sys.argv[1]", target.strip_suffix(":main").unwrap()]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&script(target))
                .unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{:?}", out.stderr);
        }
    }
    #[test]
    fn writer_preserves_all_alias_bytes_on_replay_and_refuses_foreign_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let test_root = rustix::fs::open(
            tmp.path(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .unwrap();
        // Match the synthetic root's declared caller group before children inherit it.
        rustix::fs::fchown(&test_root, None, Some(getegid())).unwrap();
        let stage = tmp.path().join("stage");
        let prefix = tmp.path().join("prefix");
        let info = stage.join("hol_guard-3.57.0.dist-info");
        std::fs::create_dir_all(&info).unwrap();
        std::fs::create_dir_all(prefix.join("bin")).unwrap();
        let mut text = String::from("[console_scripts]\n");
        for (name, target) in ENTRIES {
            text.push_str(&format!("{name} = {target}\n"));
        }
        let metadata = info.join("entry_points.txt");
        std::fs::write(
            &metadata,
            text.replace(
                "plugin-guard = codex_plugin_scanner.cli:main",
                "plugin-guard = foreign:main",
            ),
        )
        .unwrap();
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o444)).unwrap();
        let open = |path: &std::path::Path| {
            rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .unwrap()
        };
        let source = open(&stage);
        let target = open(&prefix);
        assert!(write(&source, &target, "3.57.0").is_err());
        assert_eq!(std::fs::read_dir(prefix.join("bin")).unwrap().count(), 0);
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&metadata, text).unwrap();
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate(&source, "3.57.0").is_err());
        assert_eq!(std::fs::read_dir(prefix.join("bin")).unwrap().count(), 0);
        std::fs::set_permissions(&metadata, std::fs::Permissions::from_mode(0o444)).unwrap();
        let expected: u64 = ENTRIES
            .iter()
            .map(|(_, target)| script(target).len() as u64)
            .sum();
        assert_eq!(write(&source, &target, "3.57.0").unwrap(), expected);
        for (name, destination) in ENTRIES {
            assert_eq!(
                std::fs::read(prefix.join("bin").join(name)).unwrap(),
                script(destination)
            );
        }
        assert!(write(&source, &target, "3.57.0").is_err());
        for (name, destination) in ENTRIES {
            assert_eq!(
                std::fs::read(prefix.join("bin").join(name)).unwrap(),
                script(destination)
            );
        }
    }
    #[test]
    fn exact_aliases_refuse_foreign_duplicate_and_additional_sections() {
        let mut text = String::from("[console_scripts]\n");
        for (name, target) in ENTRIES {
            text.push_str(&format!("{name} = {target}\n"));
        }
        declaration(text.as_bytes()).unwrap();
        for altered in [
            text.replace(
                "plugin-guard = codex_plugin_scanner.cli:main",
                "plugin-guard = foreign:main",
            ),
            format!("{text}hol-guard = codex_plugin_scanner.cli:main\n"),
            format!("{text}[other]\n"),
            text.replace("plugin-scanner = codex_plugin_scanner.cli:main\n", ""),
        ] {
            assert!(declaration(altered.as_bytes()).is_err());
        }
    }
    #[test]
    fn relocatable_launcher_preserves_arguments_and_isolated_interpreter_flags() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("directory with space and 'quote");
        std::fs::create_dir(&bin).unwrap();
        let python = bin.join("python3");
        std::fs::write(&python, b"#!/bin/sh\nprintf '%s\\0' \"$@\"\n").unwrap();
        std::fs::set_permissions(&python, std::fs::Permissions::from_mode(0o755)).unwrap();
        let launcher = bin.join("hol-guard");
        std::fs::write(&launcher, script(ENTRIES[0].1)).unwrap();
        std::fs::set_permissions(&launcher, std::fs::Permissions::from_mode(0o755)).unwrap();
        let out = Command::new(&launcher)
            .args(["argument with space", "single'quote", "$literal"])
            .current_dir("/")
            .output()
            .unwrap();
        assert!(out.status.success(), "{:?}", out.stderr);
        let fields: Vec<_> = out
            .stdout
            .split(|b| *b == 0)
            .filter(|b| !b.is_empty())
            .map(|b| std::str::from_utf8(b).unwrap())
            .collect();
        assert_eq!(
            fields,
            vec![
                "-I",
                "-B",
                launcher.to_str().unwrap(),
                "argument with space",
                "single'quote",
                "$literal"
            ]
        );
    }
}
