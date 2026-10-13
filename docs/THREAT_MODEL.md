# Threat model: OWASP Top 10 for Agentic Applications (2026)

Each risk gets the controls that address it, the evidence that tests it, and what is honestly not
covered yet. Benchmark ids refer to `evals/security_benchmark.yaml` (`agentic-sdlc eval`).

| ASI | Risk | Controls in agentic-sdlc | Evidence | Gaps / next step |
|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack (injected instructions in issues, code, tool output) | Task blocker + NeMo input rails; issue stripping + redaction + spotlighting; tool output spotlighted; plan **handoff guardrail** catches instruction-like text carried from the issue into the plan; plan gate (a human sees the plan before any code) | T01–T06, I01–I02; `test_poisoned_issue_is_cleaned_not_blocked`; DeepTeam ASI_01 | Heuristics miss novel phrasings. That's why ASI02 controls don't rely on detection |
| **ASI02** | Tool Misuse and Exploitation | Typed tools only (no shell/http); RBAC per role; strict args; path confinement; deny_read/deny_write; size and file-count limits; quotas per risk class; probing kill | G03–G10, `test_gateway.py`, `test_hijacked_coder_is_denied_three_times_and_killed`; DeepTeam ASI_02 | MCP tools would need the same gateway in front (categories from discovery, not names) |
| **ASI03** | Identity and Privilege Abuse | Agents hold no credentials; GitHub token read only by `github.py` at publish time; one repo, contents + PR write, `agent/*` branch, draft PR | G01–G02, `github.py` branch check | Fine-grained PAT → GitHub App installation tokens minted per run; per-agent workload identity |
| **ASI04** | Agentic Supply Chain | Dependency files (`requirements*.txt`, `pyproject.toml`, `package.json`) are FLAGGED for the human; sandbox has no network, so nothing is installed at test time; prompts and policies are versioned files | G11 | SCA (pip-audit/OSV) on the diff as evidence at gate 2 |
| **ASI05** | Unexpected Code Execution | Generated code runs only in Docker: no network, read-only, cap-drop ALL, non-root, limits, optional gVisor; fixed test command with no model arguments; Guardrails AI rejects eval/exec/shell=True/f-string SQL | C01–C04, `test_dangerous_generated_code_denied` | Regex validators → add Semgrep/Bandit as an additional validator |
| **ASI06** | Memory & Context Poisoning | No long-term memory by design; short-term memory (coder history) holds only spotlighted, redacted tool output; every run starts from a fresh workspace | design | If memory is added: write-gated memory (only human-approved review outcomes), provenance per entry |
| **ASI07** | Insecure Inter-Agent Communication | Agents never message each other directly; the harness passes typed artifacts (Plan, Review) in-process, validated by Pydantic | `schemas.py` | For A2A/remote agents: mTLS + signed messages; same governor in front of every call |
| **ASI08** | Cascading Failures | Validation at every agent boundary (structured outputs, tests as evidence, independent review), bounded reflection rounds, usage limits, fail-closed stages (*product reliability rule / Lusser's law*: unvalidated success probabilities multiply); handoff guardrail between planner and coder; stagnation detector and confidence gate end unproductive loops | `test_rejected_plan_stops_before_any_code`, `test_checks.py`, `_stage` status mapping | Circuit breaker per provider + model fallback (`llm.fallback_to_local`) is in place; add checkpoint/resume |
| **ASI09** | Human-Agent Trust Exploitation | Gate 2 shows the **exact diff**, test evidence, independent scores and explicit FLAGS (sensitive, out-of-plan, tests not run, LOW CONFIDENCE from the confidence gate, stagnation); approvals bound to a hash; PR template stops the agent claiming approvals; NeMo output rail | `test_diff_changed_after_approval_is_not_published`, `prompts/pr_body.j2` | Rubber-stamp metrics (median approval time) from `logs/feedback.log` |
| **ASI10** | Rogue Agents | Behaviour monitor (denials, loops, budgets) + kill switch; complete audit trail; least privilege makes misalignment low-impact | `test_monitor_and_hitl.py` | Anomaly alerts on audit streams (SIEM) |

## Trust boundaries

```
operator task (trusted, still screened) ──┐
issue / PR text (UNTRUSTED) ──────────────┼─► guardrails ─► agents (untrusted OUTPUT) ─► ToolGateway ─► workspace / sandbox
repo files, test output (UNTRUSTED data) ─┘                                        │
                                                                                   └─► humans (gate 1, gate 2) ─► github.py ─► draft PR
```

* Model output is a *request*, never authority.
* Credentials exist only on the right-hand side, in platform code.
* Detection (guardrails) can fail. Enforcement (gateway, sandbox, hash-bound approvals, monitor) does not depend on detection succeeding.
