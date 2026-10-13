.PHONY: install test demo demo-attack eval redteam chat ui sandbox-image audit

install:          ## virtualenv + all extras
	python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

test:             ## unit + end-to-end tests with scripted models (no API key, sandbox off)
	.venv/bin/pytest -q

demo:             ## offline happy path; you approve both gates in the terminal
	.venv/bin/agentic-sdlc run --repo examples/sample_repo --issue examples/issues/sqli_with_injection.md \
	  --task "Fix the SQL injection in product search and add a test." --offline happy --sandbox off

demo-attack:      ## offline: a hijacked coder is denied three times and the run is killed
	.venv/bin/agentic-sdlc run --repo examples/sample_repo --issue examples/issues/sqli_with_injection.md \
	  --task "Fix the SQL injection in product search and add a test." --offline attack --auto-approve --sandbox off

eval:             ## deterministic security benchmark (OWASP ASI-tagged attacks + benign cases), CSV in logs/
	.venv/bin/agentic-sdlc eval --min-pass-rate 1.0

redteam:          ## model-based OWASP ASI 2026 red team with DeepTeam (real models, costs tokens)
	.venv/bin/pip install -e ".[redteam]" && .venv/bin/python evals/redteam_owasp_asi.py

chat:             ## chat with the agent to build a program (Streamlit)
	.venv/bin/streamlit run app/chat_app.py

ui:               ## Streamlit step-by-step demo of the security pipeline
	.venv/bin/streamlit run app/streamlit_app.py

sandbox-image:    ## test-runner image for sandbox.mode=docker
	docker build -t agentic-sdlc-runner sandbox/

audit:            ## verify the hash chain of logs/audit.jsonl
	.venv/bin/agentic-sdlc verify-audit
