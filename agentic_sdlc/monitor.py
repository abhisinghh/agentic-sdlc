"""Runtime monitoring of a multi-step agent run.

Guardrails look at text; the monitor looks at BEHAVIOUR across steps, and stops a run whose
behaviour looks like probing, looping or runaway cost:

  * kill switch file (config paths.kill_switch) -> every run stops at its next step
  * consecutive policy denials                  -> a model that keeps hitting the policy is probing
  * identical tool calls repeated               -> loop
  * total tool calls, agent time                -> runaway (time waiting for a human is excluded)
  * model requests / tokens per agent run       -> pydantic-ai UsageLimits (enforced by the framework)

Every observation is written to the audit log, so the run's behaviour can be replayed later.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from pathlib import Path

from pydantic_ai.usage import UsageLimits

from agentic_sdlc.config import ROOT, Limits
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.schemas import Decision


class RunKilled(Exception):
    """The monitor (or a human via the kill switch) stopped the run."""


class RunMonitor:
    def __init__(self, run_id: str, limits: Limits, audit: AuditLog, kill_switch: str | Path):
        self.run_id = run_id
        self.limits = limits
        self.audit = audit
        self.kill_file = Path(kill_switch) if Path(kill_switch).is_absolute() else ROOT / kill_switch
        self.started = time.monotonic()
        self.tool_calls = 0
        self.consecutive_denials = 0
        self.denials = 0
        self.flags: list[str] = []
        self._seen: Counter[str] = Counter()
        self.killed: str | None = None
        self._paused_at: float | None = None
        self._paused_total = 0.0

    # Time spent waiting for a human doesn't count against the run's time budget.
    def pause(self) -> None:
        if self._paused_at is None:
            self._paused_at = time.monotonic()

    def resume(self) -> None:
        if self._paused_at is not None:
            self._paused_total += time.monotonic() - self._paused_at
            self._paused_at = None

    def elapsed(self) -> float:
        now = time.monotonic()
        paused = self._paused_total + ((now - self._paused_at) if self._paused_at is not None else 0.0)
        return max(0.0, now - self.started - paused)

    # ------------------------------------------------------------------ checks
    def check(self) -> None:
        """Called before every step and every tool call."""
        if self.killed:
            raise RunKilled(self.killed)
        if self.kill_file.exists():
            self.kill("kill switch engaged by an operator")
        if self.elapsed() > self.limits.max_run_seconds:
            self.kill(f"run exceeded {self.limits.max_run_seconds}s")

    def kill(self, reason: str) -> None:
        self.killed = reason
        self.audit.record("run.killed", self.run_id, reason=reason, tool_calls=self.tool_calls,
                          denials=self.denials)
        raise RunKilled(reason)

    def usage_limits(self) -> UsageLimits:
        return UsageLimits(request_limit=self.limits.max_model_requests,
                           total_tokens_limit=self.limits.max_total_tokens)

    # ------------------------------------------------------------------ observations
    def on_tool_call(self, role: str, tool: str, args: dict[str, object], decision: Decision,
                     reasons: list[str]) -> None:
        self.tool_calls += 1
        key = hashlib.sha256(json.dumps([tool, args], sort_keys=True, default=str).encode()).hexdigest()
        self._seen[key] += 1
        if decision == Decision.DENY:
            self.denials += 1
            self.consecutive_denials += 1
        else:
            self.consecutive_denials = 0
        if decision == Decision.FLAG:
            self.flags.extend(f"{tool} by {role}: {r}" for r in reasons)

        if self.consecutive_denials >= self.limits.max_consecutive_denials:
            self.kill(f"{self.consecutive_denials} consecutive policy denials (probing) by {role}")
        if self._seen[key] >= self.limits.max_identical_calls:
            self.kill(f"{tool} called {self._seen[key]} times with identical arguments (loop)")
        if self.tool_calls >= self.limits.max_tool_calls:
            self.kill(f"tool-call budget of {self.limits.max_tool_calls} exhausted")

    def summary(self) -> dict[str, object]:
        return {"tool_calls": self.tool_calls, "denials": self.denials, "flags": list(self.flags),
                "elapsed_s": round(self.elapsed(), 1), "killed": self.killed}
