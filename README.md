# agentic-sdlc

A coding agent you can trust with your repository.

You describe a change (or point it at an issue). The agent plans it, writes the code and tests, and an
independent reviewer agent checks the result. **A human approves twice**: the plan, and the exact
change. Only then does the platform open a *draft* pull request.

Every action the agent takes goes through a safety layer, so even a confused or hijacked model
can't read secrets, touch CI/CD, run shell commands, or publish anything on its own.

## What it shows

| Area | How |
|---|---|
| **Guardrails and prompt-injection defense** | NeMo Guardrails (input/output rails), Guardrails AI (checks generated code), injection scanners, untrusted text fenced off as data |
| **Agents in the SDLC** | planner → coder → reviewer, with failing tests and review feedback sent back to the coder; a PR-review mode and GitHub Action |
| **Tool-call validation and least privilege** | each agent only gets the tools it needs; every call is checked (allowed tool, valid arguments, safe paths, safe code); no credentials ever reach the model |
| **Human approval and runtime monitoring** | two approval gates bound to the exact content; a monitor stops runs that probe the rules, loop, or overspend; a tamper-evident audit log |

## How to run

**You need:** Python 3.11+ and git. Docker is optional (for running tests in a sandbox).
An API key or a local model is optional too: the tests and the offline demo work without one.

**1. Install**
```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**2. Check it works** (no API key needed)
```bash
pytest -q
agentic-sdlc eval                   # security benchmark, should show 100%
```

**3. Try the chat app**
```bash
streamlit run app/chat_app.py        # opens http://localhost:8501
```
Describe a program, approve the plan, accept the code, then ask for changes.
In the sidebar choose the model:
* **Offline demo**: no key needed, always builds the same sample program;
* **Anthropic / OpenAI**: paste your key;
* **Local**: Ollama or vLLM, then click *Check server & list models*.

**4. Or use the command line**
```bash
# offline demo: fix a SQL injection reported in an issue that contains a hidden prompt injection
agentic-sdlc run --repo examples/sample_repo --issue examples/issues/sqli_with_injection.md \
  --task "Fix the SQL injection in product search and add a test." --offline happy --sandbox off

# same, but the coder is "hijacked": its bad actions are blocked and the run is stopped
agentic-sdlc run --repo examples/sample_repo --issue examples/issues/sqli_with_injection.md \
  --task "Fix the SQL injection in product search and add a test." --offline attack --auto-approve --sandbox off

# your own repo with a real model (set the provider in config.yaml and the key in keys.env)
agentic-sdlc run --repo /path/to/repo --task "Add a max_price filter to product search"
agentic-sdlc review --repo /path/to/repo --head my-branch     # review an existing branch
```
Nothing is pushed to GitHub unless you configure `github.repo` in `config.yaml` and set `GITHUB_TOKEN`.
Otherwise the approved change is saved to `var/prs/`.

> This code has been written and reviewed but not yet run. If the first `pytest` fails, it's most likely
> a small API difference in one of the libraries for your installed version.

## Models

| Option | Setup | Where your code goes |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY` in `keys.env` | Anthropic |
| OpenAI | `OPENAI_API_KEY` in `keys.env` | OpenAI |
| Local | run Ollama or vLLM, set `llm.provider: local` | stays on your machine |

Local model examples:
```bash
# laptop
ollama pull qwen2.5-coder:14b && ollama serve

# GPU server
vllm serve Qwen/Qwen2.5-Coder-32B-Instruct --enable-auto-tool-choice --tool-call-parser hermes --port 8000
```
Use a model that supports tool calling (Qwen2.5/3-Coder, Llama 3.1+). Code marked `confidential` in
`config.yaml` is only ever sent to a local model.

## Project layout

```
app/chat_app.py          chat with the agent to build a program
app/streamlit_app.py     step-by-step view of the security pipeline
agentic_sdlc/           the agent and its safety layer
  pipeline.py            the whole flow: guard → plan → approve → code/test/review → approve → publish
  agents.py              planner, coder, reviewer
  gateway.py             checks every tool call before it runs
  guardrails.py          NeMo Guardrails, Guardrails AI, injection and secret scanners
  checks.py              checks between agents (plan check, confidence gate, stop when stuck)
  monitor.py             runtime monitor and kill switch
  hitl.py                human approvals
config.yaml              models, limits, sandbox, GitHub
policies/policy.yaml     which agent may use which tool, and which files are off-limits
rails/nemo/              NeMo Guardrails configuration
prompts/                 all prompts
tests/  evals/           tests and the security benchmark
docs/                    design notes, threat model, job-requirement mapping
```
