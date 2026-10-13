# agentic-sdlc chat: talk to the agent and let it write a program for you, under the same controls.
#
#     pip install -e ".[ui]"
#     streamlit run app/chat_app.py
#
# 1. Describe a program ("a CLI that counts words in a file").
# 2. The agent plans it. Approve the plan, or type feedback to change it.
# 3. The agent writes the code + tests (every tool call goes through the gateway), the tests run,
#    and an independent reviewer scores it. Accept the change, or type feedback to revise it.
# 4. Accepted code becomes the starting point for your next request ("now add a --json flag").
from __future__ import annotations

import asyncio
import io
import os
import zipfile
from pathlib import Path

import streamlit as st

from agentic_sdlc.config import ROOT, load_policy, load_settings
from agentic_sdlc.hitl import record_human_feedback
from agentic_sdlc.observability import setup_logging
from agentic_sdlc.pipeline import SDLCRun
from agentic_sdlc.schemas import ApprovalDecision, ApprovalRequest

STARTER = ROOT / "examples" / "starter_project"

# Local model servers (all speak the OpenAI API): name -> (default base URL, example model)
LOCAL_SERVERS = {
    "Ollama": ("http://localhost:11434/v1", "qwen2.5-coder:14b"),
    "vLLM (GPU server)": ("http://localhost:8000/v1", "Qwen/Qwen3-Coder-30B-A3B-Instruct"),
    "LM Studio": ("http://localhost:1234/v1", "qwen2.5-coder-14b-instruct"),
    "llama.cpp server": ("http://localhost:8080/v1", "local-model"),
}


def list_local_models(base_url: str, api_key: str = "") -> list[str]:
    """Ask the server which models it serves (GET /v1/models). Returns ids, or one '⚠️ ...' message."""
    import httpx

    try:
        r = httpx.get(base_url.rstrip("/") + "/models", timeout=5,
                      headers={"Authorization": f"Bearer {api_key}"} if api_key else None)
        r.raise_for_status()
        ids = sorted(m["id"] for m in r.json().get("data", []))
        return ids or ["⚠️ The server is up but serves no models (Ollama: `ollama pull <model>`)."]
    except Exception as e:  # noqa: BLE001
        return [f"⚠️ Can't reach {base_url}: {type(e).__name__}. Is the server running?"]
st.set_page_config(page_title="agentic-sdlc · chat", page_icon="🛡️", layout="centered")
ss = st.session_state


def reset() -> None:
    ss.messages = []            # chat history: {"role", "content", "details"}
    ss.run = None               # the SDLCRun waiting for a decision
    ss.pending = None           # None | "plan" | "diff"
    ss.task = ""                # the request being worked on (feedback is appended to it)
    ss.project = str(STARTER)   # code base the next run starts from
    ss.base_branch = None       # branch of the last accepted change (None = starter project)


if "loop" not in ss:
    setup_logging()
    ss.loop = asyncio.new_event_loop()  # one loop per session: model clients stay bound to it
    reset()


def run_async(coro):  # type: ignore[no-untyped-def]
    return ss.loop.run_until_complete(coro)


def say(content: str, details: dict | None = None) -> None:
    ss.messages.append({"role": "assistant", "content": content, "details": details or {}})


# ================================================================== sidebar
with st.sidebar:
    st.header("🛡️ agentic-sdlc")
    provider = st.selectbox("Model", ["Offline demo (no key)", "Anthropic", "OpenAI", "Local (vLLM / Ollama)"])
    hosted_model = ""
    if provider == "Anthropic":
        key = st.text_input("ANTHROPIC_API_KEY", type="password", value=os.environ.get("ANTHROPIC_API_KEY", ""))
        if key:
            os.environ["ANTHROPIC_API_KEY"] = key
        hosted_model = st.text_input("Model (blank = tiers from config.yaml)", placeholder="claude-sonnet-5-5")
    elif provider == "OpenAI":
        key = st.text_input("OPENAI_API_KEY", type="password", value=os.environ.get("OPENAI_API_KEY", ""))
        if key:
            os.environ["OPENAI_API_KEY"] = key
        hosted_model = st.text_input("Model (blank = tiers from config.yaml)", placeholder="gpt-5")
    if provider in ("Anthropic", "OpenAI"):
        st.caption("☁️ Hosted API: allowed for public/internal code only (data_class in config.yaml).")
    elif provider.startswith("Local"):
        server = st.selectbox("Local server", list(LOCAL_SERVERS))
        base_url = st.text_input("Base URL (OpenAI-compatible)", value=LOCAL_SERVERS[server][0])
        local_key = st.text_input("API key (only if your server needs one)", type="password")
        os.environ["VLLM_API_KEY"] = local_key  # read by llms.py for the local provider
        if st.button("🔌 Check server & list models", use_container_width=True):
            ss.local_models = list_local_models(base_url, local_key)
        found = ss.get("local_models") or []
        if found and not found[0].startswith("⚠️"):
            local_model = st.selectbox("Model", found)
        else:
            if found:
                st.warning(found[0])
            local_model = st.text_input("Model name", value=LOCAL_SERVERS[server][1])
        st.caption("Runs on your machine/GPU server: code never leaves it. Use a model with tool calling "
                   "(e.g. Qwen2.5/3-Coder, Llama 3.1+). Setup commands: README → Local models.")
    else:
        st.caption("Offline demo: scripted agents always build the same small program (a word counter CLI), "
                   "so you can try the whole flow without an API key.")
    tests_mode = st.selectbox("Run tests", ["off", "local", "docker"],
                              help="docker = isolated sandbox · local = runs on this machine (not isolated) · "
                                   "off = code is written but tests aren't run")
    approver = st.text_input("Your name (recorded with each decision)", value=os.environ.get("USER", "me"))
    if st.button("🆕 New project", use_container_width=True):
        reset()
        st.rerun()

    st.divider()
    project = Path(ss.project)
    files = sorted(p.relative_to(project).as_posix() for p in project.rglob("*")
                   if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts)
    st.markdown("**Current project**" + (" (starter)" if ss.base_branch is None else ""))
    if files:
        pick = st.selectbox("Files", files, label_visibility="collapsed")
        st.code((project / pick).read_text(errors="replace")[:6000],
                language="python" if pick.endswith(".py") else None)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in files:
                z.write(project / f, arcname=f)
        st.download_button("⬇️ Download project (.zip)", buf.getvalue(), file_name="project.zip",
                           use_container_width=True)


# ================================================================== agent actions
def new_run(task: str) -> SDLCRun:
    settings, policy = load_settings(), load_policy()
    settings.sandbox.mode = tests_mode  # type: ignore[assignment]
    settings.github.repo = ""           # the chat demo never pushes: accepted changes stay local
    if provider.startswith("Offline"):
        from agentic_sdlc.demo_models import offline_models

        models = offline_models("program")
    else:
        from agentic_sdlc.llms import models_for_pipeline

        settings.llm.provider = {"Anthropic": "anthropic", "OpenAI": "openai"}.get(provider, "local")  # type: ignore[assignment]
        if settings.llm.provider == "local":
            settings.llm.local.base_url = base_url
            settings.llm.local.best = settings.llm.local.default = settings.llm.local.small = local_model
        elif hosted_model.strip():
            tiers = getattr(settings.llm, settings.llm.provider)
            tiers.best = tiers.default = tiers.small = hosted_model.strip()
        models = models_for_pipeline(settings)
    return SDLCRun(task=task, repo=ss.project, settings=settings, policy=policy, models=models,  # type: ignore[arg-type]
                   base_branch=ss.base_branch)


def decision(req: ApprovalRequest, approved: bool, comment: str = "") -> ApprovalDecision:
    d = ApprovalDecision(approved=approved, approver=approver, payload_hash=req.payload_hash, comment=comment)
    record_human_feedback(req, d)
    return d


def tool_log(run: SDLCRun) -> list[dict]:
    return [{"agent": e.get("role"), "tool": e.get("tool"), "args": str(e.get("args"))[:80],
             "decision": e.get("decision"), "why": "; ".join(e.get("reasons") or [])[:120]}
            for e in run.audit.events(run.run_id) if e["event"] == "tool.decision"]


def start(task: str) -> None:
    if provider.startswith("Offline") and ss.base_branch is not None:
        say("The offline demo only builds its one sample program. Pick a real model in the sidebar to keep "
            "changing it, or start a 🆕 New project.")
        return
    ss.task = task
    run = new_run(task)
    req = run_async(run.plan())
    if req is None:
        say(f"⛔ I can't work on that: {run.state.error}", {"guards": run.state.input_guards})
        return
    ss.run, ss.pending = run, "plan"
    plan = run.state.plan
    assert plan is not None
    lines = [f"**Here's my plan.** {plan.summary}", ""]
    lines += [f"{i}. {s.description}" for i, s in enumerate(plan.steps, 1)]
    lines += ["", "**Files:** " + ", ".join(f"`{f}`" for f in plan.files_to_change),
              f"**How I'll test it:** {plan.test_strategy}"]
    if plan.risks:
        lines.append("**Risks:** " + "; ".join(plan.risks))
    lines += [f"⚠️ {f}" for f in req.flags]
    lines.append("\nApprove the plan, or type what you'd like changed.")
    say("\n".join(lines), {"guards": run.state.input_guards, "tools": tool_log(run)})


def approve_plan() -> None:
    run, req = ss.run, ss.run.plan_request
    pr = run_async(run.implement(decision(req, True)))
    if pr is None:
        ss.pending = None
        say(f"⛔ The run stopped: **{run.state.status}**: {run.state.error}", {"tools": tool_log(run)})
        return
    ss.pending = "diff"
    s = run.state
    tests = ("✅ tests passed" if s.tests and s.tests.passed else
             "⚪ tests not run (sandbox off)" if s.tests and not s.tests.executed else "❌ tests failing")
    lines = [f"**Done.** {s.coder_summary}", "",
             f"{tests} ({s.rounds} round(s))"]
    if s.review:
        sc = s.review.scores
        lines.append(f"🧐 Independent review: **{s.review.verdict}** · correctness {sc.correctness}/5 · "
                     f"security {sc.security}/5 · tests {sc.tests}/5 · scope {sc.scope}/5. {s.review.summary}")
    lines.append("**Changed:** " + ", ".join(f"`{f}`" for f in run.workspace.changed_files()))
    lines += [f"⚠️ {f}" for f in pr.flags]
    lines.append("\nAccept the change (it becomes the base for your next request), or type what to fix.")
    say("\n".join(lines), {"diff": pr.payload, "tests": s.tests.tail() if s.tests else "",
                           "tools": tool_log(run)})


def accept_change() -> None:
    run = ss.run
    result = run_async(run.publish(decision(run.pr_request, True)))
    ss.pending = None
    if result is None:
        say(f"⛔ Not saved: **{run.state.status}**: {run.state.error}")
        return
    ss.project, ss.base_branch = str(run.workspace.path), run.workspace.work_branch
    say(f"✅ Saved as a commit on `{run.workspace.work_branch}` (PR description and patch in `{result}`). "
        "Browse or download the code in the sidebar. What next?")


def revise(feedback: str) -> None:
    """Typed feedback while a decision is pending = reject this attempt and try again with the feedback."""
    run, kind = ss.run, ss.pending
    req = run.plan_request if kind == "plan" else run.pr_request
    rejected = decision(req, False, feedback)
    run_async(run.implement(rejected) if kind == "plan" else run.publish(rejected))  # audited rejection
    ss.run, ss.pending = None, None
    start(f"{ss.task}\n\nFeedback on the previous attempt: {feedback}")


def discard() -> None:
    run, kind = ss.run, ss.pending
    req = run.plan_request if kind == "plan" else run.pr_request
    rejected = decision(req, False, "discarded")
    run_async(run.implement(rejected) if kind == "plan" else run.publish(rejected))
    ss.run, ss.pending = None, None
    say("Discarded. Nothing was changed. What would you like instead?")


# ================================================================== chat
st.title("💬 Build a program with a guarded agent")
st.caption("The agent plans, codes and tests; you approve the plan and the exact change. It can't touch "
           "secrets or CI, run shell commands, or publish anything without you.")

if not ss.messages:
    with st.chat_message("assistant", avatar="🛡️"):
        st.markdown("Hi! What should I build? For example: *a command-line tool that counts the most common "
                    "words in a text file*, or *a function that validates email addresses, with tests*.")

for m in ss.messages:
    with st.chat_message(m["role"], avatar="🛡️" if m["role"] == "assistant" else "🧑"):
        st.markdown(m["content"])
        d = m.get("details") or {}
        if d.get("diff"):
            with st.expander("Show the exact change (diff)"):
                st.code(d["diff"], language="diff")
        if d.get("tests"):
            with st.expander("Test output"):
                st.code(d["tests"], language="text")
        if d.get("tools") or d.get("guards"):
            with st.expander("Under the hood: guardrails and every tool call the gateway saw"):
                for g in d.get("guards") or []:
                    st.write(f"🛡️ {g['source']}: {g['guardrail']} ({g['reason']})")
                if d.get("tools"):
                    st.dataframe(d["tools"], hide_index=True, use_container_width=True)

if ss.pending == "plan":
    a, b = st.columns(2)
    if a.button("✅ Approve plan", type="primary", use_container_width=True):
        with st.spinner("Writing code and tests, running the tests, independent review…"):
            approve_plan()
        st.rerun()
    if b.button("🗑️ Discard", use_container_width=True):
        discard()
        st.rerun()
elif ss.pending == "diff":
    a, b = st.columns(2)
    if a.button("✅ Accept change", type="primary", use_container_width=True):
        accept_change()
        st.rerun()
    if b.button("🗑️ Discard", use_container_width=True):
        discard()
        st.rerun()

hint = "Type feedback to revise…" if ss.pending else "Describe the program you want…"
if prompt := st.chat_input(hint):
    ss.messages.append({"role": "user", "content": prompt, "details": {}})
    with st.spinner("Checking the request and planning…"):
        if ss.pending:
            revise(prompt)
        else:
            start(prompt)
    st.rerun()
