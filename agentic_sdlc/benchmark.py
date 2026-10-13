"""Evaluation harness for the safety layer.

A `Benchmark` (name, examples) and an `Evaluator` that runs every example and reports a pass rate:
  * deterministic checks first (no LLM judge needed to know a `.env` read must be denied);
  * benign cases next to attacks, so false positives are measured too;
  * violation-first CSV export for human review;
  * a threshold gate in CI before prompts, policies or models are promoted.

The model-based red team (OWASP ASI 2026 via DeepTeam) lives in evals/redteam_owasp_asi.py.
Run: `agentic-sdlc eval` (exit code 4 below --min-pass-rate).
"""

from __future__ import annotations

import csv
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentic_sdlc.config import ROOT, Policy, Settings
from agentic_sdlc.gateway import ToolGateway
from agentic_sdlc.guardrails import apply_guardrails, injection_blocker, injection_stripper, secret_redactor
from agentic_sdlc.monitor import RunMonitor
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.sandbox import Sandbox
from agentic_sdlc.workspace import Workspace

SAMPLE_REPO = ROOT / "examples" / "sample_repo"


@dataclass
class Benchmark:
    name: str
    examples: list[dict[str, Any]]


def load_benchmark(path: str | Path = ROOT / "evals" / "security_benchmark.yaml") -> Benchmark:
    data = yaml.safe_load(Path(path).read_text())
    return Benchmark(name=data["name"], examples=data["examples"])


class Evaluator:
    """Runs every example against the REAL scanners and gateway (no model involved)."""

    def __init__(self, settings: Settings, policy: Policy):
        self.settings, self.policy = settings, policy

    async def _actual(self, ex: dict[str, Any], gw: ToolGateway) -> str:
        if ex["kind"] == "task":
            report = await apply_guardrails(ex["text"], [injection_blocker])
            return "block" if report.should_stop else "pass"
        if ex["kind"] == "issue":
            report = await apply_guardrails(ex["text"], [injection_stripper, secret_redactor])
            return "strip" if report.triggered else "pass"
        decision = gw.decide(ex["role"], ex["tool"], ex.get("args") or {})
        return decision.decision.value

    async def run(self, benchmark: Benchmark) -> dict[str, Any]:
        with tempfile.TemporaryDirectory() as tmp:
            audit = AuditLog(Path(tmp) / "audit.jsonl")
            ws = Workspace.create(SAMPLE_REPO, Path(tmp) / "ws", "eval")
            monitor = RunMonitor("eval", self.settings.limits, audit, Path(tmp) / "KILL")
            gw = ToolGateway("eval", self.policy, ws, Sandbox(self.settings.sandbox), monitor, audit)
            results = []
            for ex in benchmark.examples:
                actual = await self._actual(ex, gw)
                results.append({"id": ex["id"], "asi": ex.get("asi", ""), "kind": ex["kind"],
                                "expected": ex["expect"], "actual": actual, "passed": actual == ex["expect"],
                                "input": ex.get("text") or f"{ex.get('role')}:{ex.get('tool')} {ex.get('args')}"})
        passed = sum(r["passed"] for r in results)
        benign = [r for r in results if r["asi"] in ("none", "")]
        return {"name": benchmark.name, "pass_rate": passed / len(results) if results else 0.0,
                "total": len(results), "failed": len(results) - passed,
                "false_positives": sum(not r["passed"] for r in benign), "results": results}


def write_csv(report: dict[str, Any], path: str | Path) -> Path:
    """Violation-first export for domain-expert review."""
    out = Path(path) if Path(path).is_absolute() else ROOT / path
    out.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(report["results"], key=lambda r: (r["passed"], r["id"]))
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "asi", "kind", "expected", "actual", "passed", "input"])
        w.writeheader()
        w.writerows(rows)
    return out
