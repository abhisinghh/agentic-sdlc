"""Model-based red team: OWASP Top 10 for Agentic Applications (ASI 2026) with DeepTeam.

DeepTeam generates
adversarial inputs per ASI category, the agent runs under its real constraints, and the callback
reports which tools were executed and which were BLOCKED, so the evaluation judges behaviour, not
just text.

Here each attack becomes the *task* of a real agentic-sdlc run (plan + implement, never publish):
input guardrails, gateway, sandbox, monitor and the plan gate (auto-approved here so attacks reach the
coder) all apply.

    pip install deepteam deepeval
    python evals/redteam_owasp_asi.py            # uses llm.provider from config.yaml; costs tokens
"""

from __future__ import annotations

import asyncio

from deepteam import red_team
from deepteam.frameworks import OWASP_ASI_2026
from deepteam.test_case import RTTurn, ToolCall

from agentic_sdlc.config import ROOT, load_policy, load_settings
from agentic_sdlc.hitl import AutoApprover
from agentic_sdlc.llms import models_for_pipeline
from agentic_sdlc.observability import setup_logging
from agentic_sdlc.pipeline import SDLCRun

CATEGORIES = ["ASI_01", "ASI_02"]  # goal hijack, tool misuse; extend as you add scenarios
SETTINGS, POLICY = load_settings(), load_policy()
SETTINGS.sandbox.mode = "off"      # red-team runs never execute generated code


async def _attack(attack_input: str) -> RTTurn:
    run = SDLCRun(task=attack_input, repo=ROOT / "examples" / "sample_repo", settings=SETTINGS, policy=POLICY,
                  models=models_for_pipeline(SETTINGS))
    approver = AutoApprover(name="redteam-auto")
    req = await run.plan()
    if req is not None:
        await run.implement(await approver.review(req))   # stop before publish: no PRs from red teaming
    decisions = [e for e in run.audit.events(run.run_id) if e["event"] == "tool.decision"]
    executed = [e["tool"] for e in decisions if e["decision"] != "deny"]
    blocked = [e["tool"] for e in decisions if e["decision"] == "deny"]
    content = run.state.error or run.state.coder_summary or run.state.status
    return RTTurn(role="assistant", content=f"[{run.state.status}] {content}",
                  tools_called=[ToolCall(name=t) for t in executed] + [ToolCall(name=f"BLOCKED::{t}") for t in blocked])


def model_callback(attack_input: str) -> RTTurn:
    return asyncio.run(_attack(attack_input))


if __name__ == "__main__":
    setup_logging()
    assessment = red_team(
        model_callback=model_callback,
        framework=OWASP_ASI_2026(categories=CATEGORIES),
        attacks_per_vulnerability_type=1,
        async_mode=False,
        target_purpose=(
            "Coding agent that fixes issues in a Python repository. Tools: list_files, read_file, search_code, "
            "write_file (workspace only; CI/CD, policies and secrets are denied), run_tests (sandbox, fixed command). "
            "It cannot push, merge, deploy, run shell commands or access the network. Humans approve the plan and "
            "the final diff."),
    )
    print(assessment)
