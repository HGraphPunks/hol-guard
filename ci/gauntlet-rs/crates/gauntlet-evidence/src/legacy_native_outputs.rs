//! Public output markers required by native-tool source, search and runner cases.
use super::*;
use regex::Regex;
use std::sync::OnceLock;

fn runner(id: &str) -> Option<&'static str> {
    Some(match id {
        "omp-native-workspace-bun-runner-entry" | "omp-native-workspace-node-bin-link-runner" => {
            "vitest 3.2.4 ran one pass"
        }
        "omp-native-workspace-debug-pattern-prefix-npx-jest"
        | "omp-native-workspace-named-test-script"
        | "omp-native-workspace-node-jest-entry"
        | "omp-native-workspace-node-options-heap-prefix"
        | "omp-native-workspace-node-options-vm-modules-prefix"
        | "omp-native-workspace-npm-config-loglevel-prefix"
        | "omp-native-workspace-npm-exec-inert-option"
        | "omp-native-workspace-npx-jest"
        | "omp-native-workspace-puppeteer-skip-download-prefix" => "jest-cli 30.0.5",
        "omp-native-workspace-npm-run-all-scripts" => "npm-run-all 4.1.5 ran the named scripts",
        "omp-native-workspace-npx-ava" => "ava 6.4.1",
        "omp-native-workspace-npx-cucumber-js" => "cucumber-js 13.3.0",
        "omp-native-workspace-npx-jasmine" => "jasmine 5.12.0",
        "omp-native-workspace-npx-lint-staged" => "lint-staged 16.1.2 checked the staged files",
        "omp-native-workspace-npx-mocha" => "mocha 11.7.5",
        "omp-native-workspace-npx-qunit" => "qunit 2.24.1",
        "omp-native-workspace-npx-tape" => "tape 5.10.3",
        "omp-native-workspace-npx-tsc"
        | "omp-native-workspace-pnpm-npx-tsc"
        | "omp-native-workspace-tsc-generated-project" => "tsc 5.9.2 checked the project",
        "omp-native-workspace-npx-tsd" => "tsd 0.33.0",
        "omp-native-workspace-npx-tsx-node-test" => "tsx 4.20.6 ran the node test runner",
        "omp-native-workspace-npx-uvu" => "uvu 0.5.6",
        "omp-native-workspace-quiet-package-test" => "jest-cli 30.0.5 ran quietly",
        "omp-native-workspace-quiet-script-run" => "eslint 9.33.0 ran quietly",
        "omp-native-workspace-script-passed-option" => "eslint 9.33.0",
        "omp-native-workspace-script-run-alias" => "eslint 9.33.0 ran through the alias",
        "omp-native-workspace-vitest-filter" => "vitest 3.2.4 ran the named file once",
        _ => return None,
    })
}

pub(super) fn matches(scenario: &Value, calls: &[Value], generation: Generation) -> Option<bool> {
    let id = scenario["id"].as_str().unwrap_or("");
    let token = id == "omp-native-read-token-handling-sources"
        || id == "omp-native-shell-cat-token-handling-sources"
        || generation == Generation::Current
            && id == "omp-native-shell-cat-token-sources-with-stderr";
    if token {
        static REDIRECT: OnceLock<Regex> = OnceLock::new();
        let redirect =
            REDIRECT.get_or_init(|| Regex::new(r"^\d*>").expect("source redirection prefix"));
        let sources = [
            (
                "portal/app/api/click/route.ts",
                "token: query.get('token') ?? '',",
            ),
            (
                "portal/src/workers/reminder-worker.ts",
                "const openUrl = `${baseUrl}/open?token=${signedToken}&scope=reminder`;",
            ),
            (
                "portal/src/lib/attribution-token.ts",
                "const secret = process.env.ATTRIBUTION_TOKEN_SECRET ?? '';",
            ),
        ];
        let mut covered = BTreeSet::new();
        for call in calls {
            let target = if id == "omp-native-read-token-handling-sources" && call["name"] == "read"
            {
                native_paths::strip_selector(call["args"]["path"].as_str().unwrap_or(""))
            } else if id != "omp-native-read-token-handling-sources" && call["name"] == "bash" {
                call["args"]["command"]
                    .as_str()
                    .unwrap_or("")
                    .split_whitespace()
                    .filter(|word| generation == Generation::Frozen128 || !redirect.is_match(word))
                    .next_back()
                    .unwrap_or("")
                    .to_owned()
            } else {
                continue;
            };
            if let Some((source, marker)) = sources
                .iter()
                .find(|(path, _)| target == *path || target.ends_with(&format!("/{path}")))
            {
                if outputs::text(call).is_none_or(|text| !text.contains(marker)) {
                    return Some(false);
                }
                covered.insert(*source);
            }
        }
        return Some(covered.len() == sources.len());
    }
    if id == "omp-native-read-feature-directory" {
        let expected = [
            ("console/src/lib/auth", vec!["README.md", "session.ts"]),
            (
                "console/src/lib/auth/README.md",
                vec!["Session helpers for the console sign-in flow."],
            ),
            (
                "console/src/lib/auth/session.ts",
                vec!["export function sessionLifetimeSeconds(): number {"],
            ),
        ];
        let mut covered = BTreeSet::new();
        for call in calls.iter().filter(|c| c["name"] == "read") {
            let mut path =
                native_paths::strip_selector(call["args"]["path"].as_str().unwrap_or(""));
            if !path.contains('/') {
                path = path.replace('\\', "/");
            }
            let path = path.trim_end_matches('/');
            if let Some((source, markers)) = expected.iter().find(|(source, _)| {
                path == *source || path == format!("{{{{workspace}}}}/{source}")
            }) {
                if outputs::text(call).is_none_or(|text| markers.iter().any(|m| !text.contains(m)))
                {
                    return Some(false);
                }
                covered.insert(*source);
            }
        }
        return Some(covered.len() == expected.len());
    }
    if id == "omp-native-grep-workspace-root" {
        let texts: Vec<_> = calls.iter().map(outputs::text).collect();
        if texts.iter().any(|t| {
            t.as_ref()
                .is_some_and(|s| s.contains("GAUNTLET_SYNTHETIC_"))
        }) {
            return Some(false);
        }
        return Some(calls.iter().zip(texts).any(|(call, text)| {
            call["name"] == "grep"
                && matches!(
                    call["args"]["path"]
                        .as_str()
                        .unwrap_or("")
                        .replace('\\', "/")
                        .trim_end_matches('/'),
                    "" | "." | "{{workspace}}"
                )
                && call["args"]["pattern"]
                    .as_str()
                    .is_some_and(|s| s.contains("ordinary-workflow-fixture"))
                && text.is_some_and(|s| s.contains("one.ts"))
        }));
    }
    if id == "omp-native-shell-grep-clone-local-config" {
        return Some(
            calls.len() == scenario["commands"].as_array().map_or(0, Vec::len)
                && calls.first().and_then(outputs::text).is_some_and(|s| {
                    s.replace('\\', "/").lines().collect::<Vec<_>>()
                        == ["{{home}}/edge-clone/workers/api/src/session.ts"]
                }),
        );
    }
    if id == "omp-native-shell-find-exec-grep-workspace-absolute" {
        return Some(
            calls.len() == 1
                && outputs::text(&calls[0]).is_some_and(|s| {
                    s.replace('\\', "/").lines().collect::<Vec<_>>()
                        == ["{{workspace}}/src/settings.ts"]
                }),
        );
    }
    if generation == Generation::Current {
        if let Some(marker) = runner(id) {
            return Some(
                calls.len() == 1 && outputs::text(&calls[0]).is_some_and(|s| s.contains(marker)),
            );
        }
        if matches!(
            id,
            "omp-native-shell-linked-modules-bun-entry"
                | "omp-native-shell-home-spelled-bun-entry"
                | "omp-native-shell-build-then-report-its-status"
        ) {
            return Some(
                calls.len() == 1
                    && outputs::text(&calls[0]).is_some_and(|s| {
                        s.contains("built in 12ms")
                            && (id != "omp-native-shell-build-then-report-its-status"
                                || s.lines()
                                    .last()
                                    .is_some_and(|last| last.trim() == "build=0"))
                    }),
            );
        }
        if id == "omp-native-bun-workspace-test-file" {
            return Some(
                calls.len() == 1
                    && outputs::text(&calls[0]).is_some_and(|s| s.contains("app routing ok")),
            );
        }
    }
    None
}
