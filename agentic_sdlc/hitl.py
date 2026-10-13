"""Human-in-the-loop validation.

Where humans sit, and why (reads and sandboxed work are automatic; anything shared or irreversible
needs a person):

  gate 1  PLAN          before any code is written: cheapest point to stop a wrong or hijacked direction.
                        The approved plan becomes the contract (files outside it are flagged later).
  gate 2  EXACT DIFF    before anything leaves the sandbox: the human sees the diff, test evidence,
                        the independent review and every FLAG (sensitive files, out-of-plan edits).

Approvals are bound to a SHA-256 of the exact payload. If the diff changes after approval, publishing
is refused (no bait-and-switch). Agents have no way to call an approver.
Every decision is logged to logs/feedback.log so approvals and
rejections become evaluation data for the agents.
"""

from __future__ import annotations

import logging
from typing import Protocol

from agentic_sdlc.schemas import ApprovalDecision, ApprovalRequest, digest

logger = logging.getLogger(__name__)


class ApprovalError(Exception):
    pass


class Approver(Protocol):
    async def review(self, request: ApprovalRequest) -> ApprovalDecision: ...


def record_human_feedback(request: ApprovalRequest, decision: ApprovalDecision) -> None:
    logger.info("HumanFeedback", extra={"run_id": request.run_id, "target": request.kind,
                                        "payload_hash": request.payload_hash, "flags": request.flags,
                                        "approved": decision.approved, "approver": decision.approver,
                                        "comment": decision.comment})


def ensure_approved(decision: ApprovalDecision | None, current_payload: str, kind: str) -> ApprovalDecision:
    """Fail closed unless a human approved exactly this payload."""
    if decision is None or not decision.approved:
        raise ApprovalError(f"{kind} was not approved")
    if decision.payload_hash != digest(current_payload):
        raise ApprovalError(f"{kind} changed after it was approved; approval is void")
    if decision.approver.startswith("agent:"):
        raise ApprovalError("agents cannot approve")
    return decision


class CLIApprover:
    """Terminal approvals: shows the exact payload and flags, asks y/N."""

    def __init__(self, name: str):
        self.name = name

    async def review(self, request: ApprovalRequest) -> ApprovalDecision:
        print(f"\n{'=' * 80}\nAPPROVAL NEEDED · {request.kind} · run {request.run_id}\n{request.title}\n{'-' * 80}")
        print(request.payload[:20000])
        for k, v in request.evidence.items():
            print(f"[{k}] {v}")
        if request.flags:
            print("\nFLAGGED, look at these explicitly:")
            for f in request.flags:
                print(f"  ! {f}")
        answer = input(f"\nApprove this {request.kind}? (sha256 {request.payload_hash[:12]}) [y/N] ").strip().lower()
        comment = input("Comment (recorded): ").strip()
        d = ApprovalDecision(approved=answer == "y", approver=self.name, payload_hash=request.payload_hash,
                             comment=comment)
        record_human_feedback(request, d)
        return d


class AutoApprover:
    """Approves everything. ONLY for offline demos and tests; its name makes that visible in the PR."""

    def __init__(self, name: str = "auto-approver (demo only)", reject_flagged: bool = False):
        self.name = name
        self.reject_flagged = reject_flagged

    async def review(self, request: ApprovalRequest) -> ApprovalDecision:
        ok = not (self.reject_flagged and request.flags)
        d = ApprovalDecision(approved=ok, approver=self.name, payload_hash=request.payload_hash,
                             comment="auto" if ok else "auto-rejected: flagged items")
        record_human_feedback(request, d)
        return d
