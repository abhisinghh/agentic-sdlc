# agentic-sdlc demo UI:  pip install -e ".[ui]"  then  streamlit run app/streamlit_app.py
#
# One page, three steps, two human gates. The UI is just a human in front of SDLCRun's stages:
#   1 Plan  -> you approve the plan  -> 2 Implement + verify  -> you approve the exact diff  -> 3 Publish
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import streamlit as st

from agentic_sdlc.config import ROOT, load_policy, load_settings
from agentic_sdlc.hitl import record_human_feedback
from agentic_sdlc.observability import setup_logging
from agentic_sdlc.pipeline import SDLCRun
from agentic_sdlc.schemas import ApprovalDecision, ApprovalRequest

st.set_page_config(page_title="agentic-sdlc", page_icon="🛡️", layout="wide")
if "logging" not in st.session_state:
    setup_logging()
    st.session_state["logging"] = True
loop: asyncio.AbstractEventLoop = st.session_state.setdefault("loop", asyncio.new_event_loop())


def run_async(coro):  # type: ignore[no-untyped-def]
    return loop.run_until_complete(coro)


# ------------------------------------------------------------------ sidebar: provider, sandbox, gates
with st.sidebar:
    st.header("🛡️ agentic-sdlc")
    provider = st.radio("Model provider", ["Offline demo (scripted)", "Anthropic", "OpenAI", "Local (vLLM / Ollama)"])
    scenario = "happy"
    if provider.startswith("Offline"):
        scenario = "attack" if st.toggle("Hijacked coder scenario", value=False) else "happy"
    elif provider == "Anthropic":
        key = st.text_input("ANTHROPIC_API_KEY", type="password")
        if key:
            os.environ["ANTHROPIC_API_KEY"] = key
    elif provider == "OpenAI":
        key = st.text_input("OPENAI_API_KEY", type="password")
        if key:
            os.environ["OPENAI_API_KEY"] = key
    else:
        base_url = st.text_input("Base URL", value="http://localhost:8000/v1")
        local_model = st.text_input("Model", value="Qwen/Qwen3-Coder-30B-A3B-Instruct")
    sandbox_mode = st.selectbox("Run tests in", ["docker", "local", "off"], index=2,
                                help="docker = isolated (no network, read-only, no caps). local = NOT isolated.")
    use_nemo = st.toggle("NeMo Guardrails rails", value=False, help="Needs the rails model in rails/nemo/config.yml")
    approver = st.text_input("Your name (approver)", value=os.environ.get("USER", "reviewer"))
    kill_file = ROOT / load_settings().paths.kill_switch
    if st.toggle("🛑 Global kill switch", value=kill_file.exists(), help="Every run stops at its next step"):
        kill_file.parent.mkdir(parents=True, exist_ok=True)
        kill_file.touch()
    elif kill_file.exists():
        kill_file.unlink()

# ------------------------------------------------------------------ inputs
st.title("Guarded coding agent: issue → plan → code → review → draft PR")
c1, c2 = st.columns(2)
repo = c1.text_input("Repository (git repo or folder)", value=str(ROOT / "examples" / "sample_repo"))
task = c1.text_area("Task (operator instruction)", value="Fix the SQL injection in product search and add a test.")
issue = c2.text_area("Issue text (UNTRUSTED: may contain prompt injection)", height=230,
                     value=(ROOT / "examples" / "issues" / "sqli_with_injection.md").read_text())


def new_run() -> SDLCRun:
    settings, policy = load_settings(), load_policy()
    settings.sandbox.mode = sandbox_mode  # type: ignore[assignment]
    if provider.startswith("Offline"):
        from agentic_sdlc.demo_models import offline_models

        models = offline_models(scenario)
    else:
        from agentic_sdlc.llms import models_for_pipeline

        settings.llm.provider = {"Anthropic": "anthropic", "OpenAI": "openai"}.get(provider, "local")  # type: ignore[assignment]
        if settings.llm.provider == "local":
            settings.llm.local.base_url = base_url
            settings.llm.local.best = settings.llm.local.default = local_model
        models = models_for_pipeline(settings)
    nemo = None
    if use_nemo:
        from agentic_sdlc.guardrails import NemoRails

        nemo = NemoRails()
    return SDLCRun(task=task, repo=repo, issue=issue, settings=settings, policy=policy, models=models,  # type: ignore[arg-type]
                   nemo=nemo)


def decide(req: ApprovalRequest, approved: bool, comment: str) -> ApprovalDecision:
    d = ApprovalDecision(approved=approved, approver=approver, payload_hash=req.payload_hash, comment=comment)
    record_human_feedback(req, d)
    return d


def show_request(req: ApprovalRequest, lang: str) -> None:
    for f in req.flags:
        st.warning(f"⚠️ {f}")
    st.code(req.payload, language=lang)
    with st.expander("Evidence"):
        st.json(req.evidence, expanded=False)
    st.caption(f"Your decision is bound to SHA-256 {req.payload_hash[:16]}…; any later change voids it.")


run: SDLCRun | None = st.session_state.get("run")
if st.button("1 · Plan", type="primary"):
    with st.spinner("Screening inputs and planning…"):
        run = new_run()
        st.session_state["run"] = run
        run_async(run.plan())
    st.rerun()

if run is not None:
    s = run.state
    st.subheader(f"Run `{run.run_id}` · status: **{s.status}**")
    if s.error:
        st.error(s.error)
    if s.input_guards:
        st.info("Input guardrails: " + "; ".join(f"{g['source']}: {g['guardrail']} ({g['reason']})"
                                                for g in s.input_guards))

    if s.status == "awaiting_plan_approval" and run.plan_request:
        st.markdown("### ✋ Gate 1: approve the plan")
        show_request(run.plan_request, "json")
        comment = st.text_input("Comment", key="plan_comment")
        a, b = st.columns(2)
        if a.button("✅ Approve plan → implement"):
            with st.spinner("Coding, testing in the sandbox, independent review…"):
                run_async(run.implement(decide(run.plan_request, True, comment)))
            st.rerun()
        if b.button("❌ Reject plan"):
            run_async(run.implement(decide(run.plan_request, False, comment or "rejected")))
            st.rerun()

    if s.tests is not None:
        st.markdown(f"**Sandbox tests** ({s.tests.mode}): {'✅ passed' if s.tests.passed else '❌ not passed'} "
                    f"after {s.rounds} round(s)")
        with st.expander("Test output"):
            st.code(s.tests.tail(), language="text")
    if s.review is not None:
        sc = s.review.scores
        st.markdown(f"**Independent review:** {s.review.verdict} · correctness {sc.correctness}/5 · security "
                    f"{sc.security}/5 · tests {sc.tests}/5 · scope {sc.scope}/5 — {s.review.summary}")

    if s.status == "awaiting_pr_approval" and run.pr_request:
        st.markdown("### ✋ Gate 2: approve the exact diff")
        show_request(run.pr_request, "diff")
        comment = st.text_input("Comment", key="pr_comment")
        a, b = st.columns(2)
        if a.button("✅ Approve diff → open draft PR"):
            run_async(run.publish(decide(run.pr_request, True, comment)))
            st.rerun()
        if b.button("❌ Reject diff"):
            run_async(run.publish(decide(run.pr_request, False, comment or "rejected")))
            st.rerun()

    if s.pr_url:
        st.success(f"Draft PR: {s.pr_url}")
        if Path(s.pr_url).exists():
            st.markdown(Path(s.pr_url).read_text())

    st.markdown("### 🧾 Audit trail (tool gateway decisions, approvals, monitor)")
    ok, msg = run.audit.verify()
    if ok:
        st.success(msg)
    else:
        st.error(msg)
    st.dataframe([{"event": e["event"], "role": e.get("role", ""), "tool": e.get("tool", ""),
                   "decision": e.get("decision", e.get("status", "")),
                   "detail": json.dumps(e.get("reasons") or e.get("reason") or e.get("error") or "", default=str)[:160]}
                  for e in run.audit.events(run.run_id)], hide_index=True)
    st.json(run.monitor.summary(), expanded=False)
