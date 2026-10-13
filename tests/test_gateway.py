"""Tool-calling validation and least privilege: every rule of the gateway, without any model."""

import pytest

from agentic_sdlc.gateway import ToolGateway, matches
from agentic_sdlc.monitor import RunKilled, RunMonitor
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.sandbox import Sandbox
from agentic_sdlc.schemas import Decision
from agentic_sdlc.workspace import Workspace

from .conftest import SAMPLE_REPO, requires_git

pytestmark = requires_git


@pytest.fixture
def gw(settings, policy, tmp_path):
    from agentic_sdlc.config import ROOT

    ws = Workspace.create(SAMPLE_REPO, ROOT / settings.paths.workspaces, "run-test")
    audit = AuditLog(settings.paths.audit_log)
    monitor = RunMonitor("run-test", settings.limits, audit, settings.paths.kill_switch)
    return ToolGateway("run-test", policy, ws, Sandbox(settings.sandbox), monitor, audit)


def test_glob_semantics():
    assert matches(".github/workflows/ci.yml", [".github/**"])
    assert matches("app/.env", ["**/.env"]) and matches(".env", ["**/.env"])
    assert not matches("app/db.py", ["**/auth/**"])


def test_rbac_reviewer_cannot_write(gw):
    d = gw.decide("reviewer", "write_file", {"path": "app/db.py", "content": "x = 1\n"})
    assert d.decision == Decision.DENY and "least privilege" in d.reasons[0]


def test_unknown_tool_and_bad_args_denied(gw):
    assert gw.decide("coder", "shell", {"cmd": "ls"}).decision == Decision.DENY
    assert gw.decide("coder", "read_file", {"path": "a.py", "extra": 1}).decision == Decision.DENY


@pytest.mark.parametrize("path", ["../../etc/passwd", "/etc/passwd", "app/../../x"])
def test_path_escape_denied(gw, path):
    assert gw.decide("coder", "read_file", {"path": path}).decision == Decision.DENY


def test_secrets_never_read(gw):
    assert gw.decide("coder", "read_file", {"path": ".env"}).decision == Decision.DENY


def test_control_plane_never_written(gw):
    for path in [".github/workflows/ci.yml", "policies/policy.yaml", "CODEOWNERS"]:
        assert gw.decide("coder", "write_file", {"path": path, "content": "x"}).decision == Decision.DENY


def test_dangerous_generated_code_denied(gw):
    d = gw.decide("coder", "write_file", {"path": "app/db.py", "content": "def f(x):\n    return eval(x)\n"})
    assert d.decision == Decision.DENY and "generated code rejected" in d.reasons[0]


def test_sensitive_and_out_of_plan_writes_are_flagged(gw):
    gw.plan_files = ["app/db.py"]
    assert gw.decide("coder", "write_file", {"path": "app/db.py", "content": "x = 1\n"}).decision == Decision.ALLOW
    d = gw.decide("coder", "write_file", {"path": "requirements.txt", "content": "requests==2.32.3\n"})
    assert d.decision == Decision.FLAG and any("sensitive" in r for r in d.reasons)
    assert any("outside the approved plan" in r for r in d.reasons)


async def test_tool_output_is_spotlighted_and_audited(gw):
    out = await gw.call("coder", "read_file", {"path": "app/db.py"})
    assert out.startswith("<<untrusted id=") and "find_products" in out
    events = [e["event"] for e in gw.audit.events("run-test")]
    assert events[-2:] == ["tool.decision", "tool.executed"]


async def test_denial_is_explained_to_the_model(gw):
    out = await gw.call("coder", "read_file", {"path": ".env"})
    assert out.startswith("[platform] DENIED") and "DB_PASSWORD" not in out


async def test_probing_gets_the_run_killed(gw):
    await gw.call("coder", "read_file", {"path": ".env"})
    await gw.call("coder", "write_file", {"path": ".github/workflows/ci.yml", "content": "x"})
    with pytest.raises(RunKilled, match="consecutive policy denials"):
        await gw.call("coder", "read_file", {"path": "id_rsa"})
    assert gw.audit.verify()[0]
