# Design notes

The patterns used, and where each one lives in the code.

| Pattern | What it does here | Where |
|---|---|---|
| Structured outputs | Planner returns a `Plan`, reviewer returns a `Review`; invalid output is retried, never parsed loosely | `schemas.py`, `agents.py` |
| Chain of thought | The planner reasons step by step before writing the plan | `prompts/planner_system.j2` |
| Multi-agent team | Planner → coder → reviewer, each with its own instructions, tools and model tier | `agents.py` |
| Tool calling behind a gateway | Agents see small typed tools; every call is checked by one enforcement point before it runs | `tools.py`, `gateway.py` |
| Least privilege | Each role only sees and may call its own tools; secrets and CI files are off-limits; credentials never reach the model | `policies/policy.yaml`, `gateway.py`, `github.py` |
| Guardrails | Scanners (block / strip / redact) on the task, the issue, tool output and published text; NeMo Guardrails rails; Guardrails AI checks on generated code | `guardrails.py`, `rails/nemo/` |
| Spotlighting | Untrusted text is fenced with a random boundary and treated as data | `guardrails.spotlight` |
| Sandboxed code execution | Tests run with a fixed command in Docker (no network, read-only, no capabilities) | `sandbox.py`, `sandbox/Dockerfile` |
| Harness that checks evidence | The harness runs the tests itself instead of trusting the model's "done" | `pipeline.py` |
| Reflection | Failing tests or review feedback go back to the coder, for a bounded number of rounds | `pipeline.py`, `prompts/coder_fix.j2` |
| LLM-as-judge | An independent reviewer scores correctness, security, tests and scope | `prompts/reviewer_system.j2`, `schemas.Review` |
| Handoff guardrail with retry | The plan is checked before the coder sees it; if it trips, it goes back to the planner once with the reasons | `checks.py` |
| Confidence gate | Review scores decide: present, another round, or present with a low-confidence flag | `checks.py` |
| Stagnation detector | A round with the same diff and the same failure as the last one stops the loop | `checks.py` |
| Human-in-the-loop gates | A human approves the plan and the exact diff; approvals are bound to a hash and void if the content changes | `hitl.py` |
| Runtime monitoring | Kill switch, probing (repeated denials), loops, quotas per risk class, time budget that pauses during human waits | `monitor.py`, `gateway.py` |
| Idempotency keys | Every tool call gets a hash; identical reads since the last write come from a cache | `gateway.py` |
| Template generation | The PR description is a fixed template; model text only fills bounded fields | `prompts/pr_body.j2` |
| Model gateway and fallback | One place picks the provider per role, enforces data residency, and can fall back from a hosted model to a local one | `llms.py` |
| Observability | Separate logs for prompts, guardrails, tool calls, approvals and evals; hash-chained audit log; optional tracing | `observability.py`, `logging.json` |
| Evaluation | Deterministic security benchmark with benign cases and a CI gate; optional model-based red team | `benchmark.py`, `evals/` |

Deliberately left out to keep it simple: running several agents concurrently, multi-repo runs, long-term memory,
caching of model calls, and an external policy engine (the YAML policy can be replaced by OPA later).
