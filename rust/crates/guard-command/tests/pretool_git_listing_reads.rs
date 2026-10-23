#![cfg(unix)]

use crate::pretool_git_session_ops::{git, session};

#[test]
fn listing_inspections_are_proven_reads() {
    let session = session("listing-reads");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            // Git reads `-sn` as `-s -n`, so a bundle is the same read as the
            // letters spelled apart and is proven the same way.
            "git shortlog -sn",
            "git check-ignore -vz src",
            "git shortlog",
            "git shortlog --summary --numbered --email",
            "git shortlog -s -n HEAD",
            "git shortlog -w72,6,9 -s",
            "git shortlog --group=committer -s",
            "git shortlog --group trailer:Signed-off-by -sn",
            "git shortlog --max-count=20 -s",
            "git check-ignore -v src",
            "git check-ignore build/ dist/",
            "git check-ignore -q node_modules",
            "git check-ignore --no-index -v src/index.ts",
            "git status --short && git shortlog -sn",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            // A pretty format expands `%G`, which runs the verification
            // program, so a shortlog that carries one keeps its review.
            "git shortlog --format=%G? -s",
            "git shortlog --pretty=%GK",
            // `--group` takes a `git log` format too, and that format reaches
            // the same verification program.
            "git shortlog --group=format:%G? -s",
            "git shortlog --group format:%GK",
            "git shortlog --group=author:name",
            "git shortlog --max-count=all",
            "git shortlog --unknown-option",
            // A bundle is only a bundle when every letter is a known flag.
            "git shortlog -sx",
            "git check-ignore --unknown-option src",
            // The command needs a path or the pipe it reads them from.
            "git check-ignore",
            "git check-ignore -v",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
    // A configured pager runs a program, so the probe keeps the review.
    git(
        &session.home,
        &session.primary,
        &["config", "pager.shortlog", "./synthetic-never-execute"],
    );
    let result = session.evaluate_at("git shortlog -sn", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
    git(
        &session.home,
        &session.primary,
        &["config", "--unset-all", "pager.shortlog"],
    );
    // Reading the index can start the monitor, and `check-ignore` reads it
    // unless the command says not to.
    git(
        &session.home,
        &session.primary,
        &["config", "core.fsmonitor", "./synthetic-never-execute"],
    );
    for (command, allowed) in [
        ("git check-ignore -v src", false),
        ("git check-ignore --no-index -v src", true),
        ("git shortlog -sn", true),
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{command}: {}",
            result.reason_code
        );
    }
    git(
        &session.home,
        &session.primary,
        &["config", "--unset-all", "core.fsmonitor"],
    );
    // A verbose check prints the rule and the file it came from, so a
    // configured excludes file keeps that form reviewed.
    git(
        &session.home,
        &session.primary,
        &["config", "core.excludesFile", "./synthetic-excludes"],
    );
    for (command, allowed) in [
        ("git check-ignore -v src", false),
        ("git check-ignore -vz src", false),
        ("git check-ignore src", true),
        ("git check-ignore -q src", true),
    ] {
        let result = session.evaluate_at(command, &session.primary);
        assert_eq!(
            result.minimum_action == "allow",
            allowed,
            "{command}: {}",
            result.reason_code
        );
    }
}

/// `git sparse-checkout list` prints the patterns the working tree is already
/// narrowed to and writes nothing, but the verb was classified by the
/// spellings that do write a tree, so the listing asked wherever an agent ran
/// it. The listing is now the read it is, and every spelling that changes the
/// narrowing keeps its review.
#[test]
fn a_sparse_checkout_listing_is_a_proven_read() {
    let session = session("sparse-checkout-reads");
    for cwd in [&session.primary, &session.worktree] {
        for command in [
            "git sparse-checkout list",
            "git status --short && git sparse-checkout list",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_eq!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
        for command in [
            // Without an operation the verb is one of the spellings below.
            "git sparse-checkout",
            // The listing takes no options, so a word beside it is a spelling
            // this grammar has not read.
            "git sparse-checkout list --porcelain",
            // Each of these narrows or widens the working tree, which can
            // leave a committed symlink behind a later redirect's path.
            "git sparse-checkout init --cone",
            "git sparse-checkout set src",
            "git sparse-checkout add docs",
            "git sparse-checkout reapply",
            "git sparse-checkout disable",
            // `check-rules` reads the patterns off its own input rather than
            // the ones the tree is narrowed to.
            "git sparse-checkout check-rules src",
        ] {
            let result = session.evaluate_at(command, cwd);
            assert_ne!(
                result.minimum_action, "allow",
                "{command}: {}",
                result.reason_code
            );
        }
    }
    // A configured pager runs a program, so the probe keeps the review.
    git(
        &session.home,
        &session.primary,
        &[
            "config",
            "pager.sparse-checkout",
            "./synthetic-never-execute",
        ],
    );
    let result = session.evaluate_at("git sparse-checkout list", &session.primary);
    assert_ne!(result.minimum_action, "allow", "{}", result.reason_code);
    git(
        &session.home,
        &session.primary,
        &["config", "--unset-all", "pager.sparse-checkout"],
    );
    let result = session.evaluate_at("git sparse-checkout list", &session.primary);
    assert_eq!(result.minimum_action, "allow", "{}", result.reason_code);
}
