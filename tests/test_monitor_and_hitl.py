"""Runtime monitoring, approval binding and the audit chain."""

import json

import pytest

from agentic_sdlc.hitl import ApprovalError, ensure_approved
from agentic_sdlc.monitor import RunKilled, RunMonitor
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.schemas import ApprovalDecision, ApprovalRequest, Decision


def _monitor(settings):
    return RunMonitor("r1", settings.limits, AuditLog(settings.paths.audit_log), settings.paths.kill_switch)


def test_identical_calls_are_a_loop(settings):
    m = _monitor(settings)
    for _ in range(settings.limits.max_identical_calls - 1):
        m.on_tool_call("coder", "read_file", {"path": "a.py"}, Decision.ALLOW, [])
    with pytest.raises(RunKilled, match="identical"):
        m.on_tool_call("coder", "read_file", {"path": "a.py"}, Decision.ALLOW, [])


def test_kill_switch_file_stops_the_run(settings, tmp_path):
    m = _monitor(settings)
    (tmp_path / "KILL").touch()
    with pytest.raises(RunKilled, match="kill switch"):
        m.check()


def test_flags_are_collected_for_the_human(settings):
    m = _monitor(settings)
    m.on_tool_call("coder", "write_file", {"path": "Dockerfile"}, Decision.FLAG, ["Dockerfile is sensitive"])
    assert m.summary()["flags"] == ["write_file by coder: Dockerfile is sensitive"]


def test_approval_is_bound_to_the_exact_payload():
    req = ApprovalRequest.create("r1", "pull_request", "t", "diff v1")
    ok = ApprovalDecision(approved=True, approver="alice", payload_hash=req.payload_hash)
    assert ensure_approved(ok, "diff v1", "diff").approver == "alice"
    with pytest.raises(ApprovalError, match="changed after"):
        ensure_approved(ok, "diff v2 (bait and switch)", "diff")
    with pytest.raises(ApprovalError, match="not approved"):
        ensure_approved(ok.model_copy(update={"approved": False}), "diff v1", "diff")
    with pytest.raises(ApprovalError, match="agents cannot approve"):
        ensure_approved(ok.model_copy(update={"approver": "agent:coder"}), "diff v1", "diff")


def test_audit_chain_detects_tampering(settings):
    log = AuditLog(settings.paths.audit_log)
    log.record("a", "r1", x=1)
    log.record("b", "r1", x=2)
    assert log.verify()[0]
    lines = log.path.read_text().splitlines()
    ev = json.loads(lines[0])
    ev["x"] = 999
    log.path.write_text("\n".join([json.dumps(ev), lines[1]]) + "\n")
    assert not AuditLog(settings.paths.audit_log).verify()[0]


def test_docker_sandbox_unavailable_is_not_reported_as_failing_tests(monkeypatch):
    """Daemon down / image missing => executed=False (flagged), never a phantom test failure."""
    import subprocess

    from agentic_sdlc.config import SandboxSettings
    from agentic_sdlc.sandbox import Sandbox

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 1, "", "failed to connect to the docker API at unix:///var/run/docker.sock")

    monkeypatch.setattr(subprocess, "run", fake_run)
    r = Sandbox(SandboxSettings(mode="docker")).run_tests(__import__("pathlib").Path("."))
    assert r.executed is False and not r.passed and "sandbox unavailable" in r.output
