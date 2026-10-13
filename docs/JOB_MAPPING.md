# Job requirements → evidence in this repo

Goal: integrate safety frameworks, tool-calling validation and developer tools, using NeMo
Guardrails, an agentic SDLC workflow and enterprise access controls.

## 1. Agent safety frameworks (NeMo Guardrails, Guardrails AI) and prompt-injection defense

* **NeMo Guardrails**, `rails/nemo/`:
  * input flows: a Colang flow `check prompt injection` calls a Python action (cheap, deterministic, runs first), then `self check input` with an SDLC-specific policy prompt;
  * output flow: `self check output` on the PR description;
  * the judge model runs on-prem;
  * `NemoRails` **fails closed** if the rails can't be evaluated.
* **Guardrails AI**: two custom validators (`agentic/no-hardcoded-secrets`, `agentic/safe-python`)
  run on every `write_file` at the gateway. Failures are denials the model must fix (`guardrails.py::_code_guard`).
* **Prompt-injection defense in layers:**
  * the task is screened and blocked;
  * untrusted issue text has injected lines and hidden HTML comments stripped, secrets redacted, and is fenced with a random boundary (spotlighting);
  * all tool output is fenced too;
  * the system prompts say fenced text is data.
  * The real control is that even a fully hijacked model can't do damage: see the attack test.
* Evidence: `tests/test_guardrails.py`, `tests/test_pipeline.py::test_hijacked_coder_is_denied_three_times_and_killed`.
* **Measured, not assumed**: `agentic-sdlc eval` runs a benchmark of attacks tagged with OWASP ASI 2026 categories, plus benign cases (false positives), as a CI gate. `evals/redteam_owasp_asi.py` runs DeepTeam's OWASP ASI 2026 red team against real runs (`docs/THREAT_MODEL.md`).

## 2. Agents integrated into SDLC workflows (planning, code generation, PR reviews)

* **Planning**: the planner produces a structured, human-approved `Plan`. It becomes the contract, and edits outside it are flagged. A **handoff guardrail** checks the plan before the coder or a human sees it, and sends it back once with feedback if it trips.
* **Code generation**: the coder writes code and tests. The harness runs the tests itself, and failing tests and review feedback go back for reflection rounds. A **confidence gate** on the review scores decides between another round, presenting the change, or presenting it with a low-confidence flag. A **stagnation detector** stops rounds that change nothing.
* **PR reviews**:
  * an independent LLM-as-judge reviewer runs inside the pipeline;
  * `agentic-sdlc review` reviews any branch;
  * `.github/workflows/agent-pr-review.yml` runs it as an advisory PR check with `contents: read` + `pull-requests: write` and no fork secrets.
* **Delivery**: draft PR with a provenance block (run id, approvers, diff hash), CI on the PR, merge by humans.

## 3. Enterprise security, tool-calling validation, least-privilege API access

* **Tool gateway** (`gateway.py`), applied to every call:
  * RBAC;
  * strict argument schemas;
  * workspace confinement;
  * `deny_read` for secrets, `deny_write` for CI/policies/CODEOWNERS;
  * size and file-count limits;
  * Guardrails AI code validation;
  * FLAG classification;
  * output redaction and spotlighting;
  * audit.
* **Least privilege at three levels:**
  * the model only *sees* its role's tools;
  * the gateway re-checks every call;
  * credentials never reach the model. The GitHub token is read inside `github.py` at publish time, with fine-grained scope (one repo, `contents: write`, `pull_requests: write`), on an `agent/*` branch only, as a draft PR.
* **No dangerous tools exist**: no shell, http, push, merge or deploy tools.
* **Data residency**: confidential/restricted repos can only use the local (on-prem) provider. `llms.check_residency` fails closed.
* **Production path**: policy.yaml → OPA/Rego with the same inputs; the token → GitHub App installation tokens minted per run; the audit log → WORM/SIEM.

## 4. HITL validation and multi-step runtime monitoring

* **Two gates** (`hitl.py`):
  * the plan, before any code;
  * the exact diff with test evidence, the review and all flags, before anything leaves the sandbox.
* **Approval properties**:
  * SHA-256-bound and void if the diff changes after approval (`test_diff_changed_after_approval_is_not_published`);
  * agents can't approve;
  * every decision is logged as human feedback for evals.
* **Runtime monitor** (`monitor.py`):
  * kill switch file;
  * consecutive denials (probing);
  * identical-call loops;
  * tool-call and wall-clock budgets;
  * capability quotas per risk class (read / execute / write_local), so rotating tools can't dodge a limit;
  * time waiting at a human gate is excluded from the time budget;
  * pydantic-ai token/request `UsageLimits`.
  * Every decision goes to a hash-chained audit log (`verify-audit`), with optional Logfire/OpenTelemetry traces.

---

# Interview answers (application questions 3–7), backed by this repo

**Q3. An agentic system you built or secured: risks and controls.**
A guarded coding agent: issue → plan → code → review → human-approved draft PR.

The main risks are:
* indirect prompt injection (issues, code, test output);
* excessive agency;
* secret exfiltration;
* CI/policy tampering;
* unsafe generated code;
* bait-and-switch after approval;
* runaway loops and cost.

The controls are summarised in the README. I design assuming the model is compromised: the
attack scenario hijacks the coder, and three independent layers deny its three moves before the
monitor kills the run.

**Q4. Guardrail frameworks and runtime enforcement.**
* **NeMo Guardrails** handles input and output rails: a Colang flow calls a deterministic action, then an LLM self-check runs with an SDLC policy. It is on-prem and fails closed.
* **Guardrails AI** validates generated code at the tool boundary.
* **Custom scanners** handle injection and secrets.

I separate detection from enforcement. Guardrails are probabilistic and produce signals, block,
sanitise or flag. Enforcement is deterministic and outside the model: the gateway's policy, the
sandbox, hash-bound approvals and the monitor.

**Q5. SDLC integration and where humans approve.**
There are two gates:
* **The plan**: the cheapest place to stop a wrong or hijacked direction. It becomes the contract.
* **The exact diff**: the last point before anything is shared.

Nothing is gated inside the sandbox, because those actions are reversible; that avoids approval
fatigue. Sensitive and out-of-plan edits are flagged at gate 2 instead of interrupting the agent.
Merging and deploying stay with humans and CI.

**Q6. Least privilege for agents touching repos, CI/CD, internal APIs; logging and monitoring.**
* Tools are role-scoped and are both hidden from and re-checked for the model.
* Every tool is purpose-built and typed; there are no generic shell/http tools.
* Path rules protect secrets and the control plane.
* Credentials are minted or read only by platform code, for one repo, with minimal permissions, and never enter a prompt.
* New internal APIs get a typed tool, a risk class and a role entry, and are added to the attack tests.

Logging and monitoring:
* every rendered prompt, guardrail verdict, gateway decision with reasons, approval, test result and review;
* a hash-chained audit trail;
* alerts on denials (probing), loops, kill-switch use and budget breaches.

**Q7. Useful but unable to make unsafe changes or deploy without approval.**
1. The agent reads and writes only in a disposable workspace on its own branch.
2. Tests run in a network-less, read-only container with a fixed command.
3. Generated code is validated.
4. CI, policies and secrets can't be read or written.
5. A human approves the plan and the exact diff, bound by hash.
6. The platform, not the model, opens a *draft* PR with a minimal token.
7. Merging needs normal review and branch protection.
8. The agent has no deploy capability at all; the CD pipeline is gated by its own environment approvals.

It stays useful because everything reversible is automatic. Humans see evidence (tests, review,
flags), not raw model output.
