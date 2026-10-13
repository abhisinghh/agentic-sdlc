"""Structured outputs and records.

Structured outputs: planner and reviewer must return these Pydantic
models (pydantic-ai `output_type`). Anything that doesn't validate is retried, never parsed loosely,
so free text from a model never turns directly into an action.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


def digest(payload: str) -> str:
    return hashlib.sha256(payload.encode()).hexdigest()


# ------------------------------------------------------------------ agent outputs
class PlanStep(BaseModel):
    description: str = Field(max_length=500)
    files: list[str] = Field(default_factory=list, max_length=10)


class Plan(BaseModel):
    summary: str = Field(max_length=600, description="One paragraph: what will change and why")
    steps: list[PlanStep] = Field(min_length=1, max_length=10)
    files_to_change: list[str] = Field(max_length=10, description="Repository-relative paths")
    test_strategy: str = Field(max_length=600)
    risks: list[str] = Field(default_factory=list, max_length=10)

    def digest(self) -> str:
        return digest(self.model_dump_json())


class Finding(BaseModel):
    severity: Literal["blocker", "major", "minor", "nit"]
    file: str = ""
    message: str = Field(max_length=500)


class Scores(BaseModel):
    """LLM-as-judge rubric: each criterion 1 (bad) .. 5 (excellent)."""

    correctness: int = Field(ge=1, le=5)
    security: int = Field(ge=1, le=5)
    tests: int = Field(ge=1, le=5)
    scope: int = Field(ge=1, le=5, description="Changes stay within the approved plan")


class Review(BaseModel):
    verdict: Literal["approve", "request_changes"]
    scores: Scores
    findings: list[Finding] = Field(default_factory=list, max_length=30)
    summary: str = Field(max_length=800)

    @property
    def blocking(self) -> bool:
        return self.verdict == "request_changes" or any(f.severity == "blocker" for f in self.findings) \
            or self.scores.security <= 2


# ------------------------------------------------------------------ guardrails
@dataclass
class GuardResult:
    """Output of one guardrail scanner (activated / should_stop / sanitized_output)."""

    guardrail_type: str
    activated: bool
    should_stop: bool
    sanitized_output: str
    reason: str = ""


@dataclass
class GuardReport:
    should_stop: bool
    triggered: list[GuardResult]
    sanitized: str


# ------------------------------------------------------------------ tool gateway
class Decision(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"   # allowed in the disposable workspace, but a human must explicitly accept it at the PR gate
    DENY = "deny"


@dataclass
class ToolDecision:
    decision: Decision
    reasons: list[str] = field(default_factory=list)


# ------------------------------------------------------------------ HITL
class ApprovalRequest(BaseModel):
    run_id: str
    kind: Literal["plan", "pull_request"]
    title: str
    payload: str                      # exactly what the human is approving (plan JSON or the full diff)
    payload_hash: str                 # the approval is bound to this hash
    flags: list[str] = Field(default_factory=list)   # things the human must look at explicitly
    evidence: dict[str, object] = Field(default_factory=dict)

    @classmethod
    def create(cls, run_id: str, kind: Literal["plan", "pull_request"], title: str, payload: str,
               flags: list[str] | None = None, evidence: dict[str, object] | None = None) -> ApprovalRequest:
        return cls(run_id=run_id, kind=kind, title=title, payload=payload, payload_hash=digest(payload),
                   flags=flags or [], evidence=evidence or {})


class ApprovalDecision(BaseModel):
    approved: bool
    approver: str
    payload_hash: str
    comment: str = ""


def to_json(obj: object) -> str:
    return json.dumps(obj, indent=1, default=str, sort_keys=True)
