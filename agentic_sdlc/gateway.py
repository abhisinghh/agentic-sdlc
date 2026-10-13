"""Tool Gateway: the single enforcement point for every agent action.

"The model proposes, the platform disposes." Each tool call passes these stages, in order:

  1. monitor.check()        kill switch, time budget                                  -> RunKilled
  2. known tool?            unknown names are denied
  3. RBAC + quotas          role may use this tool (policies/policy.yaml: roles.*.tools), and the
                            run still has quota for its risk class (read / execute / write_local)
  4. schema                 strict pydantic args (extra fields forbidden, length limits)
  5. path rules             confinement to the workspace, deny_read / deny_write globs
  6. content rules          file size, number of files changed, Guardrails AI code validators
  7. HITL classification    sensitive paths or files outside the approved plan -> FLAG
                            (allowed in the disposable workspace, but listed for explicit human
                            acceptance at the PR gate: reversible now, gated before it matters)
  8. monitor.on_tool_call   probing (consecutive denials), loops, call budget         -> RunKilled
  9. execute                workspace / sandbox only; errors are returned as text; identical reads since
                            the last write are answered from a cache keyed by an idempotency key
 10. sanitise output        secret redaction, truncation, spotlighting (tool output is untrusted data)
 11. audit                  hash-chained record of request, decision, reasons, result size

Denials are returned to the model as text with the reason, so it can adapt (or get stopped by the
monitor if it keeps trying). Production: stage 3-7 become an OPA/Rego query with the same inputs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from functools import lru_cache

from pydantic import ValidationError

from agentic_sdlc.config import Policy
from agentic_sdlc.guardrails import redact, spotlight, validate_generated_file
from agentic_sdlc.monitor import RunMonitor
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.sandbox import Sandbox, TestResult
from agentic_sdlc.schemas import Decision, ToolDecision
from agentic_sdlc.tools import TOOL_SPECS
from agentic_sdlc.workspace import Workspace, WorkspaceError

logger = logging.getLogger(__name__)


@lru_cache(maxsize=512)
def _glob(pattern: str) -> re.Pattern[str]:
    """Gitignore-style glob: `**/` matches any number of directories (including none), `*` stays in one."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def call_key(tool: str, args: dict[str, object]) -> str:
    """Deterministic idempotency key from canonical JSON of the call."""
    canon = json.dumps({"name": tool, "args": args}, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


def matches(path: str, globs: list[str]) -> list[str]:
    path = path.removeprefix("./")
    return [g for g in globs if _glob(g).match(path)]


class ToolGateway:
    def __init__(self, run_id: str, policy: Policy, workspace: Workspace, sandbox: Sandbox,
                 monitor: RunMonitor, audit: AuditLog):
        self.run_id = run_id
        self.policy = policy
        self.workspace = workspace
        self.sandbox = sandbox
        self.monitor = monitor
        self.audit = audit
        self.plan_files: list[str] | None = None   # set when a human approves the plan
        self.last_tests: TestResult | None = None
        self.risk_counts: Counter[str] = Counter()  # executed calls per risk class (capability quotas)
        self._read_cache: dict[str, str] = {}       # idempotency key -> sanitised read result

    # ------------------------------------------------------------------ policy decision
    def decide(self, role: str, tool: str, args: dict[str, object]) -> ToolDecision:
        spec = TOOL_SPECS.get(tool)
        if spec is None or tool not in self.policy.tools:
            return ToolDecision(Decision.DENY, [f"unknown tool '{tool}'"])
        role_policy = self.policy.roles.get(role)
        if role_policy is None or tool not in role_policy.tools:
            return ToolDecision(Decision.DENY, [f"role '{role}' is not allowed to use '{tool}' (least privilege)"])
        risk = self.policy.tools[tool].risk
        quota = self.policy.limits.max_calls_per_risk.get(risk)
        if quota is not None and self.risk_counts[risk] >= quota:
            return ToolDecision(Decision.DENY, [f"quota for '{risk}' actions ({quota}) used up in this run"])
        try:
            parsed = spec.args.model_validate(args)
        except ValidationError as e:
            return ToolDecision(Decision.DENY, [f"invalid arguments: {e.errors()[0]['msg']}"])

        path = getattr(parsed, "path", None)
        if path is None:
            return ToolDecision(Decision.ALLOW)
        try:
            self.workspace.resolve(path)
        except WorkspaceError as e:
            return ToolDecision(Decision.DENY, [str(e)])
        p = self.policy.paths
        if tool == "read_file" and (hit := matches(path, p.deny_read)):
            return ToolDecision(Decision.DENY, [f"reading {path} is not allowed (matches {hit[0]}): secrets "
                                                "never enter the model's context"])
        if tool != "write_file":
            return ToolDecision(Decision.ALLOW)

        # ---- write_file
        if hit := matches(path, p.deny_write):
            return ToolDecision(Decision.DENY, [f"writing {path} is prohibited (matches {hit[0]}): CI/CD, policies "
                                                "and secrets are human-owned"])
        content = str(getattr(parsed, "content", ""))
        if len(content.encode()) > self.policy.limits.max_file_bytes:
            return ToolDecision(Decision.DENY, [f"file larger than {self.policy.limits.max_file_bytes} bytes"])
        changed = set(self.workspace.changed_files()) | {path}
        if len(changed) > self.policy.limits.max_files_changed:
            return ToolDecision(Decision.DENY, [f"change would touch more than {self.policy.limits.max_files_changed} "
                                                "files; keep the change small"])
        problems = validate_generated_file(path, content)  # Guardrails AI validators
        if problems:
            return ToolDecision(Decision.DENY, [f"generated code rejected: {'; '.join(problems)}. Rewrite it safely."])

        flags = []
        if hit := matches(path, p.sensitive):
            flags.append(f"{path} is sensitive (matches {hit[0]})")
        if self.plan_files is not None and path not in self.plan_files:
            flags.append(f"{path} is outside the approved plan")
        return ToolDecision(Decision.FLAG, flags) if flags else ToolDecision(Decision.ALLOW)

    # ------------------------------------------------------------------ enforcement
    async def call(self, role: str, tool: str, args: dict[str, object]) -> str:
        self.monitor.check()
        d = self.decide(role, tool, args)
        preview = {k: (v if k != "content" else f"<{len(str(v))} chars>") for k, v in args.items()}
        self.audit.record("tool.decision", self.run_id, role=role, tool=tool, args=preview,
                          decision=d.decision.value, reasons=d.reasons)
        logger.info(f"{role} -> {tool} {preview}: {d.decision.value} {d.reasons}")
        self.monitor.on_tool_call(role, tool, args, d.decision, d.reasons)  # may stop the run

        if d.decision == Decision.DENY:
            return f"[platform] DENIED: {'; '.join(d.reasons)}. Do not retry this call; adapt your approach."

        spec = TOOL_SPECS[tool]
        risk = self.policy.tools[tool].risk
        key = call_key(tool, args)
        cached = risk == "read" and key in self._read_cache
        if cached:
            # Idempotency key: an identical read since the last write returns the same
            # result without touching the workspace again.
            output, n_redacted = self._read_cache[key], 0
        else:
            self.risk_counts[risk] += 1
            try:
                output = await spec.run(self, spec.args.model_validate(args))
            except WorkspaceError as e:
                output = f"[platform] ERROR: {e}"
            output, n_redacted = redact(output)
            limit = self.policy.limits.max_tool_output_chars
            if len(output) > limit:
                output = output[:limit] + f"\n...[truncated {len(output) - limit} chars]"
            if risk == "read":
                self._read_cache[key] = output
            elif risk == "write_local":
                self._read_cache.clear()  # the workspace changed: earlier reads are stale
        self.audit.record("tool.executed", self.run_id, role=role, tool=tool, call_key=key[:16], cached=cached,
                          output_chars=len(output), redactions=n_redacted)
        if spec.untrusted_output and not output.startswith("[platform]"):
            output = spotlight(output, source=f"tool:{tool}")
        if d.decision == Decision.FLAG:
            output += f"\n[platform] NOTE: flagged for human review at the PR gate: {'; '.join(d.reasons)}"
        return output
