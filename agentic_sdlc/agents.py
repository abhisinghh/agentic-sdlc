"""The three agents (a simple sequential multi-agent team).

  PlannerAgent   read-only tools  -> Plan    (structured output, chain-of-thought in the prompt)
  CoderAgent     read/write/test  -> str     (tool-calling loop; reflection rounds via message history)
  ReviewerAgent  read + diff      -> Review  (LLM-as-judge with a rubric)

Each agent is a pydantic-ai Agent with Jinja2 prompts; every AI
input/output saved for evaluation. Agents get their model injected (any provider, or a scripted
FunctionModel in tests/offline demo) and only the tools their policy role allows.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessage
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits

from agentic_sdlc.config import Policy
from agentic_sdlc.observability import record_ai_response
from agentic_sdlc.prompt_service import PromptService
from agentic_sdlc.sandbox import TestResult
from agentic_sdlc.schemas import Plan, Review
from agentic_sdlc.tools import Deps, register_tools

logger = logging.getLogger(__name__)


def _agent(model: Model, role: str, output_type: Any, policy: Policy) -> Agent[Deps, Any]:
    agent: Agent[Deps, Any] = Agent(model, deps_type=Deps, output_type=output_type, name=role, retries=2,
                                    instructions=PromptService.render_prompt(f"{role}_system"))
    register_tools(agent, policy.roles[role].tools)
    return agent


class PlannerAgent:
    def __init__(self, model: Model, policy: Policy):
        self.agent = _agent(model, "planner", Plan, policy)

    async def plan(self, task: str, issue: str, files: list[str], deps: Deps, limits: UsageLimits,
                   feedback: list[str] | None = None) -> Plan:
        """`feedback` = reasons a previous plan tripped the handoff guardrail (bounded retry)."""
        prompt_vars = {"task": task, "issue": issue, "files": "\n".join(files[:200]), "feedback": feedback or []}
        result = await self.agent.run(PromptService.render_prompt("planner_task", **prompt_vars),
                                      deps=deps, usage_limits=limits)
        record_ai_response("plan", prompt_vars, result.output.model_dump())
        return result.output


class CoderAgent:
    def __init__(self, model: Model, policy: Policy):
        self.agent = _agent(model, "coder", str, policy)

    async def code(self, prompt: str, deps: Deps, limits: UsageLimits,
                   history: list[ModelMessage] | None = None) -> tuple[str, list[ModelMessage]]:
        """One coding round. Passing the previous round's messages back is the Reflection loop:
        the coder sees its own work plus the test/review feedback and revises it."""
        result = await self.agent.run(prompt, deps=deps, usage_limits=limits, message_history=history)
        record_ai_response("code", {"prompt": prompt}, result.output)
        return result.output, result.all_messages()


class ReviewerAgent:
    def __init__(self, model: Model, policy: Policy):
        self.agent = _agent(model, "reviewer", Review, policy)

    async def review(self, plan_text: str, tests: TestResult | None, deps: Deps, limits: UsageLimits,
                     context: str = "") -> Review:
        """`plan_text` is the approved plan (pipeline) or the PR description (standalone PR review)."""
        prompt_vars = {"plan": plan_text, "tests": tests, "context": context}
        result = await self.agent.run(PromptService.render_prompt("reviewer_task", **prompt_vars),
                                      deps=deps, usage_limits=limits)
        record_ai_response("review", {"plan": prompt_vars["plan"]}, result.output.model_dump())
        return result.output
