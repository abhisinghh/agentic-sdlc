"""The agentic SDLC harness.

The model only reasons. The harness owns everything else: what goes into the context, which tools
exist, how results are checked, when humans decide and when to stop.

    task + issue
       │ 1. input guardrails  (injection blocker + NeMo input rails on the task;
       │                       injection stripper + secret redaction + spotlighting on the issue)
       ▼
    Planner ─► Plan ──────────────► HUMAN GATE 1: approve the plan (hash-bound)
       ▼
    Coder ⇄ tools via ToolGateway (policy, validation, sandbox, audit, monitor)
       │ 2. verify with evidence: harness runs the tests itself (doesn't trust "done")
       │ 3. independent Reviewer scores the diff (LLM-as-judge)
       │ 4. Reflection: failing tests / blocking review go back to the coder (max N rounds)
       ▼
    exact diff + tests + review + flags ─► HUMAN GATE 2: approve the diff (hash-bound)
       ▼
    5. output guardrails on the PR text (template + redaction + NeMo output rail)
    6. platform publishes a DRAFT PR with a scoped token (agents can't push or merge)

Each stage is a separate method so a UI can put a human between them (app/streamlit_app.py);
`run_all` chains them for the CLI.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic_ai.exceptions import UsageLimitExceeded
from pydantic_ai.models import Model

from agentic_sdlc import github
from agentic_sdlc.agents import CoderAgent, PlannerAgent, ReviewerAgent
from agentic_sdlc.checks import GateDecision, confidence, confidence_gate, plan_handoff_guardrail, round_fingerprint
from agentic_sdlc.config import ROOT, Policy, Settings
from agentic_sdlc.gateway import ToolGateway, matches
from agentic_sdlc.guardrails import (NemoRails, apply_guardrails, injection_blocker, injection_stripper, redact,
                                      secret_redactor, spotlight)
from agentic_sdlc.hitl import ApprovalError, Approver, ensure_approved
from agentic_sdlc.llms import DataResidencyError
from agentic_sdlc.monitor import RunKilled, RunMonitor
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.prompt_service import PromptService
from agentic_sdlc.sandbox import Sandbox, TestResult
from agentic_sdlc.schemas import ApprovalDecision, ApprovalRequest, GuardReport, Plan, Review
from agentic_sdlc.tools import Deps
from agentic_sdlc.workspace import Workspace

logger = logging.getLogger(__name__)


class Blocked(Exception):
    """A guardrail stopped the run."""


@dataclass
class RunState:
    status: str = "created"   # created | awaiting_plan_approval | awaiting_pr_approval | published
    #                           | blocked | killed | rejected | failed
    error: str | None = None
    input_guards: list[dict[str, Any]] = field(default_factory=list)
    plan: Plan | None = None
    coder_summary: str = ""
    tests: TestResult | None = None
    review: Review | None = None
    rounds: int = 0
    confidence: list[float] = field(default_factory=list)   # review confidence per round (trend)
    gate: GateDecision | None = None
    stagnated: bool = False
    diff: str = ""
    pr_url: str | None = None
    plan_decision: ApprovalDecision | None = None
    pr_decision: ApprovalDecision | None = None


_STOP_STATUS: list[tuple[type[BaseException], str]] = [
    (RunKilled, "killed"), (UsageLimitExceeded, "killed"), (Blocked, "blocked"),
    (DataResidencyError, "blocked"), (ApprovalError, "rejected")]


def _root_cause(exc: BaseException) -> BaseException:
    """Find a known safety stop even if the agent framework wrapped it (exception groups, __cause__)."""
    known = tuple(cls for cls, _ in _STOP_STATUS)
    for _ in range(10):
        if isinstance(exc, known):
            return exc
        if isinstance(exc, BaseExceptionGroup) and exc.exceptions:
            exc = next((e for e in exc.exceptions if isinstance(e, known)), exc.exceptions[0])
        elif exc.__cause__ is not None:
            exc = exc.__cause__
        else:
            break
    return exc


def _guards(report: GuardReport, source: str) -> list[dict[str, Any]]:
    return [{"source": source, "guardrail": r.guardrail_type, "stop": r.should_stop, "reason": r.reason}
            for r in report.triggered]


class SDLCRun:
    def __init__(self, *, task: str, repo: str | Path, settings: Settings, policy: Policy,
                 models: dict[str, Model], issue: str = "", nemo: NemoRails | None = None,
                 run_id: str | None = None, base_branch: str | None = None):
        """`base_branch` overrides github.base_branch, e.g. to build on a previous run's accepted
        branch (the chat app chains requests this way)."""
        import uuid

        self.run_id = run_id or f"run-{uuid.uuid4().hex[:10]}"
        self.task, self.issue = task, issue
        self.settings, self.policy, self.nemo = settings, policy, nemo
        self.state = RunState()
        self.audit = AuditLog(settings.paths.audit_log)
        self.monitor = RunMonitor(self.run_id, settings.limits, self.audit, settings.paths.kill_switch)
        self.workspace = Workspace.create(Path(repo), ROOT / settings.paths.workspaces, self.run_id,
                                          base_branch or settings.github.base_branch, settings.github.branch_prefix)
        self.sandbox = Sandbox(settings.sandbox)
        self.gateway = ToolGateway(self.run_id, policy, self.workspace, self.sandbox, self.monitor, self.audit)
        self.planner = PlannerAgent(models["planner"], policy)
        self.coder = CoderAgent(models["coder"], policy)
        self.reviewer = ReviewerAgent(models["reviewer"], policy)
        self.plan_request: ApprovalRequest | None = None
        self.pr_request: ApprovalRequest | None = None
        self.audit.record("run.started", self.run_id, task=task[:500], repo=str(repo),
                          provider=settings.llm.provider, data_class=settings.data_class,
                          sandbox=settings.sandbox.mode)

    def _deps(self, role: str) -> Deps:
        return Deps(role=role, gateway=self.gateway)

    async def _stage(self, name: str, fn: Any, *args: Any) -> Any:
        """Run a stage; translate every safety stop into a clear, audited run status (fail closed)."""
        self.monitor.resume()  # the human answered: the run's time budget runs again
        try:
            self.monitor.check()
            result = await fn(*args)
            if self.state.status.startswith("awaiting"):
                self.monitor.pause()  # waiting for a human doesn't count against the time budget
            return result
        except Exception as exc:  # noqa: BLE001 - classified below, never swallowed silently
            err = _root_cause(exc)
            status = next((s for cls, s in _STOP_STATUS if isinstance(err, cls)), "failed")
            if status == "failed":
                logger.exception("stage %s failed", name)
            self.state.status, self.state.error = status, f"{type(err).__name__}: {err}"
        self.audit.record("run.stopped", self.run_id, stage=name, status=self.state.status, error=self.state.error,
                          monitor=self.monitor.summary())
        return None

    # ================================================================== stage 1: guard + plan
    async def plan(self) -> ApprovalRequest | None:
        return await self._stage("plan", self._plan)

    async def _plan(self) -> ApprovalRequest:
        task_scanners = [injection_blocker] + ([self.nemo.input_scanner] if self.nemo else [])
        task_report = await apply_guardrails(self.task, task_scanners)
        issue_report = await apply_guardrails(self.issue, [injection_stripper, secret_redactor])
        self.state.input_guards = _guards(task_report, "task") + _guards(issue_report, "issue")
        self.audit.record("guardrails.input", self.run_id, results=self.state.input_guards)
        if task_report.should_stop:
            raise Blocked("task rejected by input guardrails: "
                          + "; ".join(r.reason for r in task_report.triggered if r.should_stop))

        issue_for_model = spotlight(issue_report.sanitized, "issue") if self.issue.strip() else ""
        feedback: list[str] = []
        for attempt in range(self.settings.limits.max_plan_retries + 1):
            plan = await self.planner.plan(task_report.sanitized, issue_for_model, self.workspace.list_files(),
                                           self._deps("planner"), self.monitor.usage_limits(), feedback)
            # Handoff guardrail: check the plan BEFORE the coder or a human sees it.
            wire = plan_handoff_guardrail(plan, self.policy)
            if not wire.triggered:
                break
            feedback = wire.feedback
            self.audit.record("handoff.tripwire", self.run_id, handoff="planner->coder", attempt=attempt + 1,
                              feedback=feedback)
        else:
            raise Blocked("plan failed the handoff guardrail after retries: " + "; ".join(feedback))
        self.state.plan = plan
        self.audit.record("plan.proposed", self.run_id, plan_hash=plan.digest(), files=plan.files_to_change)

        flags = [f"issue text: {g['guardrail']}: {g['reason']}" for g in self.state.input_guards if g["source"] == "issue"]
        flags += [f"plan touches sensitive file {f}" for f in plan.files_to_change
                  if matches(f, self.policy.paths.sensitive)]
        if feedback:
            flags.append(f"the first plan was rejected by the handoff guardrail and revised: {'; '.join(feedback)}")
        self.plan_request = ApprovalRequest.create(
            self.run_id, "plan", f"Plan: {plan.summary[:100]}", plan.model_dump_json(indent=2), flags,
            evidence={"input_guardrails": self.state.input_guards or "nothing triggered"})
        self.state.status = "awaiting_plan_approval"
        return self.plan_request

    # ================================================================== stage 2: implement + verify
    async def implement(self, decision: ApprovalDecision) -> ApprovalRequest | None:
        return await self._stage("implement", self._implement, decision)

    async def _implement(self, decision: ApprovalDecision) -> ApprovalRequest:
        assert self.plan_request is not None and self.state.plan is not None
        self.state.plan_decision = ensure_approved(decision, self.plan_request.payload, "plan")
        self.audit.record("approval.plan", self.run_id, approver=decision.approver, payload_hash=decision.payload_hash)
        plan = self.state.plan
        self.gateway.plan_files = list(plan.files_to_change)

        prompt = PromptService.render_prompt("coder_task", plan=plan.model_dump_json(indent=1), task=self.task,
                                             approver=decision.approver)
        history, last_fingerprint = None, None
        max_rounds = self.settings.limits.max_fix_rounds + 1
        for round_no in range(max_rounds):
            self.state.rounds = round_no + 1
            self.state.coder_summary, history = await self.coder.code(
                prompt, self._deps("coder"), self.monitor.usage_limits(), history)

            # Check with evidence, not the model's claim (harness engineering).
            tests = await asyncio.to_thread(self.sandbox.run_tests, self.workspace.path)
            self.state.tests = tests
            self.audit.record("tests.result", self.run_id, round=round_no + 1, executed=tests.executed,
                              exit_code=tests.exit_code, mode=tests.mode)
            failing = tests.executed and not tests.passed

            # Stagnation detector: same diff + same failure as last round = no progress.
            fingerprint = round_fingerprint(self.workspace.diff(), tests.tail() if failing else "")
            if fingerprint == last_fingerprint:
                self.state.stagnated = True
                self.audit.record("loop.stagnation", self.run_id, round=round_no + 1)
                break
            last_fingerprint = fingerprint

            if failing:
                prompt = PromptService.render_prompt("coder_fix", test_output=tests.tail(), exit_code=tests.exit_code,
                                                     review=None)
                continue

            review = await self.reviewer.review(plan.model_dump_json(indent=1), tests, self._deps("reviewer"),
                                                self.monitor.usage_limits())
            self.state.review = review
            self.state.confidence.append(confidence(review))
            # Confidence gate: present, try another round, or present with an uncertainty flag.
            self.state.gate = confidence_gate(review, self.state.confidence, max_rounds - round_no - 1)
            self.audit.record("review.result", self.run_id, round=round_no + 1, verdict=review.verdict,
                              scores=review.scores.model_dump(), confidence=self.state.confidence[-1],
                              gate=self.state.gate.value)
            if self.state.gate != GateDecision.ANOTHER_ROUND:
                break
            prompt = PromptService.render_prompt("coder_fix", test_output="", exit_code=0, review=review)

        diff = self.workspace.diff()
        if not diff.strip():
            raise RuntimeError("the coder produced no changes")
        self.state.diff = diff
        flags = list(self.monitor.flags)
        tests = self.state.tests
        if tests is None or not tests.executed:
            flags.append("tests were NOT executed (sandbox off or unavailable)")
        elif not tests.passed:
            flags.append(f"tests are FAILING after {self.state.rounds} round(s)")
        review = self.state.review
        if review is None:
            flags.append("no independent review (tests never passed)")
        elif review.blocking:
            flags.append(f"reviewer still requests changes: {review.summary[:200]}")
        if self.state.gate == GateDecision.SIGNAL_UNCERTAINTY:
            flags.append(f"LOW CONFIDENCE: review confidence {self.state.confidence[-1]:.0%} "
                         f"(trend {[f'{c:.0%}' for c in self.state.confidence]}); look closely")
        if self.state.stagnated:
            flags.append(f"stopped early: round {self.state.rounds} made no progress over the previous one")
        self.pr_request = ApprovalRequest.create(
            self.run_id, "pull_request", f"Diff for: {plan.summary[:80]}", diff, flags, evidence={
                "files": self.workspace.changed_files(),
                "tests": f"{'passed' if tests and tests.passed else 'not passed'} ({tests.mode if tests else 'n/a'})",
                "review": review.model_dump() if review else None,
                "monitor": self.monitor.summary()})
        self.state.status = "awaiting_pr_approval"
        return self.pr_request

    # ================================================================== stage 3: publish
    async def publish(self, decision: ApprovalDecision) -> str | None:
        return await self._stage("publish", self._publish, decision)

    async def _publish(self, decision: ApprovalDecision) -> str:
        assert self.state.plan is not None and self.state.plan_decision is not None
        # Re-read the diff NOW: if anything changed since the human looked, the approval is void.
        self.state.pr_decision = ensure_approved(decision, self.workspace.diff(), "diff")
        self.audit.record("approval.diff", self.run_id, approver=decision.approver, payload_hash=decision.payload_hash)

        plan, review, tests = self.state.plan, self.state.review, self.state.tests
        body = PromptService.render_prompt(
            "pr_body", plan_summary=redact(plan.summary)[0], files=self.workspace.changed_files(),
            test_status=("passed" if tests and tests.passed else "NOT passed / not executed")
            + (f" ({tests.mode})" if tests else ""),
            test_strategy=redact(plan.test_strategy)[0], review=review or _no_review(),
            review_summary=redact(review.summary)[0] if review else "No review.",
            flags=self.pr_request.flags if self.pr_request else [], run_id=self.run_id,
            plan_approver=self.state.plan_decision.approver, pr_approver=decision.approver,
            diff_hash=decision.payload_hash)
        scanners = [secret_redactor] + ([self.nemo.output_scanner] if self.nemo else [])
        out = await apply_guardrails(body, scanners)
        if out.should_stop:
            raise Blocked("PR description rejected by output guardrails")
        title = f"[agent] {redact(plan.summary)[0][:72]}"
        url = await github.publish_pull_request(self.workspace, self.settings, self.run_id, title, out.sanitized)
        self.state.pr_url, self.state.status = url, "published"
        self.audit.record("pr.published", self.run_id, url=url, diff_hash=decision.payload_hash)
        return url

    # ================================================================== CLI convenience
    async def run_all(self, approver: Approver) -> RunState:
        req = await self.plan()
        if req is None:
            return self.state
        req = await self.implement(await approver.review(req))
        if req is None:
            return self.state
        await self.publish(await approver.review(req))
        return self.state


def _no_review() -> Review:
    from agentic_sdlc.schemas import Scores

    return Review(verdict="request_changes", scores=Scores(correctness=1, security=1, tests=1, scope=1),
                  summary="No independent review was produced.")


async def review_existing_change(repo: str | Path, head: str, settings: Settings, policy: Policy, model: Model,
                                 description: str = "") -> Review:
    """PR-review mode: the reviewer agent alone, on `head` vs the base branch of a git repo.
    Works on a throwaway clone (your checkout is never touched) with the same gateway, policy,
    monitor and audit as a full run; the reviewer role is read-only."""
    import uuid

    run_id = f"review-{uuid.uuid4().hex[:8]}"
    audit = AuditLog(settings.paths.audit_log)
    monitor = RunMonitor(run_id, settings.limits, audit, settings.paths.kill_switch)
    ws = Workspace.create(Path(repo), ROOT / settings.paths.workspaces, run_id, head, settings.github.branch_prefix)
    ws.base_branch = f"origin/{settings.github.base_branch}"
    gw = ToolGateway(run_id, policy, ws, Sandbox(settings.sandbox), monitor, audit)
    reviewer = ReviewerAgent(model, policy)
    desc = spotlight(redact(description)[0], "pr_description") if description else "(no description)"
    review = await reviewer.review(desc, None, Deps("reviewer", gw), monitor.usage_limits())
    audit.record("review.standalone", run_id, verdict=review.verdict, scores=review.scores.model_dump())
    return review
