"""Deterministic checks BETWEEN agents.

  plan_handoff_guardrail   handoff guardrail with retry: an agent's output
                           is checked before the next agent receives it. A tripped wire sends the
                           feedback back to the same agent for a bounded retry, instead of letting a
                           bad (or hijacked) plan reach the coder.
  confidence_gate          PRESENT / ANOTHER_ROUND / SIGNAL_UNCERTAINTY, from the
                           reviewer's rubric scores and their trend across reflection rounds.
  fingerprint/stagnation   if a reflection round produces the same diff and
                           the same test failure as the previous one, more rounds won't help, so stop
                           and tell the human instead of burning budget.

These are cheap, deterministic, and testable without a model. They complement the probabilistic
guardrails, they don't replace them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from agentic_sdlc.config import Policy
from agentic_sdlc.gateway import matches
from agentic_sdlc.guardrails import find_injection
from agentic_sdlc.schemas import Plan, Review, digest


# ------------------------------------------------------------------ handoff guardrail: planner -> coder
@dataclass
class Tripwire:
    triggered: bool
    feedback: list[str] = field(default_factory=list)


def plan_handoff_guardrail(plan: Plan, policy: Policy) -> Tripwire:
    problems: list[str] = []
    if not plan.files_to_change:
        problems.append("the plan lists no files_to_change; the coder is held to that list")
    if len(plan.files_to_change) > policy.limits.max_files_changed:
        problems.append(f"the plan touches {len(plan.files_to_change)} files; the limit is "
                        f"{policy.limits.max_files_changed}. Split the work")
    for f in plan.files_to_change:
        if hit := matches(f, policy.paths.deny_write):
            problems.append(f"{f} is human-owned (matches {hit[0]}); remove it from the plan")
    if len(plan.test_strategy.strip()) < 20:
        problems.append("the test strategy is missing or too vague; name the tests that prove the change")
    texts = [plan.summary, plan.test_strategy, *(s.description for s in plan.steps), *plan.risks]
    if hits := sorted({h for t in texts for h in find_injection(t)}):
        problems.append(f"the plan contains instruction-like text ({', '.join(hits)}); it may carry an "
                        "injection from the issue. Describe only engineering steps")
    return Tripwire(bool(problems), problems)


# ------------------------------------------------------------------ confidence gate: reviewer -> human
class GateDecision(str, Enum):
    PRESENT = "present"                         # good enough to show the human
    ANOTHER_ROUND = "another_round"             # fixable: send the review back to the coder
    SIGNAL_UNCERTAINTY = "signal_uncertainty"   # show the human, flagged as low confidence


def confidence(review: Review) -> float:
    s = review.scores
    return round((s.correctness + s.security + s.tests + s.scope) / 20, 3)


def confidence_gate(review: Review, trend: list[float], rounds_left: int) -> GateDecision:
    c = confidence(review)
    if len(trend) >= 3 and trend[-3] > trend[-2] > trend[-1]:
        return GateDecision.SIGNAL_UNCERTAINTY       # fixes keep making it worse: stop, ask a human
    if review.blocking or c < 0.6:
        return GateDecision.ANOTHER_ROUND if rounds_left > 0 else GateDecision.SIGNAL_UNCERTAINTY
    if c < 0.75 and rounds_left > 0 and any(f.severity == "major" for f in review.findings):
        return GateDecision.ANOTHER_ROUND
    return GateDecision.PRESENT


# ------------------------------------------------------------------ stagnation detector: reflection loop
def round_fingerprint(diff: str, failing_output: str = "") -> str:
    """Same diff + same failure => the round made no progress. Timings and memory addresses are
    stripped from the test output so they don't make identical failures look different."""
    normalized = re.sub(r"\b\d+(\.\d+)?s\b|0x[0-9a-fA-F]+", "", failing_output)
    return digest(diff + "\x00" + normalized)
