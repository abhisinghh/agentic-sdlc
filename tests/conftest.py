from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agentic_sdlc.config import ROOT, Settings, load_policy, load_settings

SAMPLE_REPO = ROOT / "examples" / "sample_repo"
POISONED_ISSUE = (ROOT / "examples" / "issues" / "sqli_with_injection.md").read_text()

requires_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = load_settings()
    s.sandbox.mode = "off"          # unit tests never execute generated code
    s.github.repo = ""              # local mode: PRs are written to files
    s.paths.workspaces = str(tmp_path / "ws")
    s.paths.prs = str(tmp_path / "prs")
    s.paths.audit_log = str(tmp_path / "audit.jsonl")
    s.paths.kill_switch = str(tmp_path / "KILL")
    return s


@pytest.fixture
def policy():
    return load_policy()
