//! `source .venv/bin/activate && pytest -q` is the first thing a Python
//! project runs, and the canonical parser models no part of it: the shell's
//! `source` builtin is a nested command executor, so the whole chain carried
//! an evaluation failure and the floor could lift it no higher than review.
//! Every ordinary test, lint and type-check run behind an activation paid for
//! that with an approval row.
//!
//! Activating an environment runs a generated script whose whole effect is
//! the settings it exports, so the command after it carries the verdict, the
//! way an inert environment prefix does. The projection earns that reading
//! three times over: the file has to resolve to a real activation script of a
//! marked environment (PEP 405 puts `pyvenv.cfg` directly above `bin`), its
//! text has to bound the programs it can run, and the word the command runs
//! next is rewritten to the environment's own `bin` when that is what the
//! activated `PATH` would reach. Anything else keeps the command unprojected.

use crate::cloud_scrub_shell::shell_tokens;
use crate::pretool::PathContext;
use std::path::Path;

const MAX_PROJECTED_CHARS: usize = 8_192;

/// Characters a plain, literal path is written with. An expansion, a glob or
/// a quote builds the name at run time, and a name this scan cannot read is
/// not an activation script it has proven anything about.
fn plain_path(value: &str) -> bool {
    !value.is_empty()
        && value.contains('/')
        && !value.contains("..")
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | '+'))
}

/// Whether the activated environment's own `bin` holds a program of this
/// name, which is what the activated `PATH` would reach first.
fn environment_program(binaries: &Path, word: &str) -> bool {
    if word.is_empty()
        || word.contains('/')
        || word.contains('=')
        || word.starts_with('-')
        || !word
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'))
    {
        return false;
    }
    binaries.join(word).is_file()
}

/// The command without its leading activation, or `None` when the activation
/// is not one this scan can read through.
pub(super) fn project(command: &str, context: PathContext<'_>) -> Option<String> {
    if !command.is_ascii() || command.len() > MAX_PROJECTED_CHARS {
        return None;
    }
    let characters: Vec<char> = command.chars().collect();
    let tokens = shell_tokens(&characters)?;
    let [sourcing, target, separator, rest @ ..] = tokens.as_slice() else {
        return None;
    };
    if sourcing.is_control || !matches!(sourcing.value.as_str(), "." | "source") {
        return None;
    }
    if target.is_control || !plain_path(&target.value) {
        return None;
    }
    // `source x && y` hands the whole verdict to `y`. `source x; y` and
    // `source x | y` do not: the first runs `y` whatever the activation did,
    // and the second carries the activation's own bytes into it.
    if !separator.is_control || separator.value != "&&" {
        return None;
    }
    let first = rest.first().filter(|token| !token.is_control)?;
    let (script, text) = crate::pretool::activation_script_text(&target.value, context)?;
    if !crate::native_command_controls::bounds_its_owners(&text, command) {
        return None;
    }
    let binaries = script.parent()?;
    // Only the word the command runs next is rewritten. A later word the
    // environment also holds would run a different program once the
    // activation has set `PATH`, and this projection does not answer for it.
    if rest
        .iter()
        .skip(1)
        .any(|token| !token.is_control && environment_program(binaries, &token.value))
    {
        return None;
    }
    let remainder: String = characters[first.start..].iter().collect();
    if remainder.trim().is_empty() {
        return None;
    }
    let (written, _) = target.value.rsplit_once('/')?;
    if environment_program(binaries, &first.value) {
        return Some(format!("{written}/{remainder}"));
    }
    Some(remainder)
}

#[cfg(test)]
#[path = "venv_activation_projection_tests.rs"]
mod tests;
