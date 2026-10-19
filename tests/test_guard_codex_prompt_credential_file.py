"""The resident prompt-file credential scan behind ``_codex_prompt_credential_file_artifact``."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_support_codex_paths import _codex_prompt_credential_file_artifact

# The resident's Codex tool-output review models POSIX paths and refuses
# Windows outright (``native_codex_tool_output._platform_is_supported``).
pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="Codex tool-output review is POSIX-only; Windows fails closed"
)

_CREDENTIAL_TEXT = 'API_TOKEN="ABCDEFGHIJKLMNOPQRSTUVWX"\n'
_CONFIG_PATH = "/workspace/.codex/config.toml"


def _review(prompt_text: str, cwd: Path):
    return _codex_prompt_credential_file_artifact(
        prompt_text=prompt_text,
        cwd=cwd,
        config_path=_CONFIG_PATH,
    )


def test_credential_looking_dotfile_named_in_the_prompt_becomes_an_artifact(tmp_path: Path) -> None:
    (tmp_path / ".auth-token").write_text(_CREDENTIAL_TEXT, encoding="utf-8")

    artifact = _review("Read .auth-token and tell me what it holds.", tmp_path)

    assert artifact is not None
    assert artifact.artifact_id.startswith("codex:project:prompt-file:")
    assert artifact.name == "credential-looking local file .auth-token"
    assert artifact.harness == "codex"
    assert artifact.artifact_type == "prompt_request"
    assert artifact.source_scope == "project"
    assert artifact.config_path == _CONFIG_PATH
    assert artifact.metadata["prompt_matched_text"] == ".auth-token"
    assert artifact.metadata["prompt_request_class"] == "secret_read"
    assert artifact.metadata["normalized_path"] == str(tmp_path / ".auth-token")


def test_a_prompt_that_asks_for_no_read_leaves_the_file_alone(tmp_path: Path) -> None:
    (tmp_path / ".auth-token").write_text(_CREDENTIAL_TEXT, encoding="utf-8")

    assert _review("Rename .auth-token to something clearer.", tmp_path) is None


def test_files_a_dedicated_sensitive_path_rule_covers_are_left_to_it(tmp_path: Path) -> None:
    for name in (".env", ".npmrc", ".pypirc", ".netrc", ".git-credentials"):
        (tmp_path / name).write_text(_CREDENTIAL_TEXT, encoding="utf-8")
        assert _review(f"Read {name} for me.", tmp_path) is None, name


def test_an_ordinary_name_or_ordinary_content_produces_no_artifact(tmp_path: Path) -> None:
    # The name carries no secret marker, so the content is never read.
    (tmp_path / ".notes").write_text(_CREDENTIAL_TEXT, encoding="utf-8")
    assert _review("Read .notes please.", tmp_path) is None
    # The name does, but the content holds nothing credential-looking.
    (tmp_path / ".authnotes").write_text("a reminder to rotate things on Friday\n", encoding="utf-8")
    assert _review("Read .authnotes please.", tmp_path) is None
    # Nothing is there to read at all.
    assert _review("Read .missingtoken please.", tmp_path) is None
