"""The agent's tools.

Two layers, on purpose:
  1. What the MODEL sees: small, typed pydantic-ai tool functions. A role is only given the tools
     its policy allows (`register_tools`), so the planner and reviewer never even see `write_file`.
  2. What actually RUNS: every tool function just forwards to `ToolGateway.call(...)`, which
     re-validates the arguments, applies the policy, executes, sanitises the output and audits it.
     The model holds no credentials and has no shell, no network and no publish/merge tools.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic_ai import Agent, RunContext

if TYPE_CHECKING:
    from agentic_sdlc.gateway import ToolGateway


@dataclass
class Deps:
    """pydantic-ai dependencies handed to every tool call (dependency injection, not globals)."""

    role: str
    gateway: ToolGateway


# ------------------------------------------------------------------ argument schemas (strict)
class NoArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PathArgs(NoArgs):
    path: str = Field(min_length=1, max_length=300)


class WriteArgs(PathArgs):
    content: str = Field(max_length=200_000)


class SearchArgs(NoArgs):
    text: str = Field(min_length=2, max_length=200)


# ------------------------------------------------------------------ executors (run by the gateway)
Executor = Callable[["ToolGateway", Any], Awaitable[str]]


async def _list_files(gw: ToolGateway, a: NoArgs) -> str:
    return "\n".join(gw.workspace.list_files())


async def _read_file(gw: ToolGateway, a: PathArgs) -> str:
    return gw.workspace.read(a.path)


async def _search_code(gw: ToolGateway, a: SearchArgs) -> str:
    return "\n".join(gw.workspace.search(a.text)) or "no matches"


async def _write_file(gw: ToolGateway, a: WriteArgs) -> str:
    gw.workspace.write(a.path, a.content)
    return f"wrote {a.path} ({len(a.content)} chars)"


async def _get_diff(gw: ToolGateway, a: NoArgs) -> str:
    return gw.workspace.diff() or "(no changes)"


async def _run_tests(gw: ToolGateway, a: NoArgs) -> str:
    res = await asyncio.to_thread(gw.sandbox.run_tests, gw.workspace.path)
    gw.last_tests = res
    status = "PASSED" if res.passed else ("NOT EXECUTED" if not res.executed else f"FAILED (exit {res.exit_code})")
    return f"tests {status} [{res.mode} sandbox]\n{res.tail()}"


@dataclass(frozen=True)
class ToolSpec:
    args: type[BaseModel]
    run: Executor
    untrusted_output: bool  # output is repo/test content an attacker may control -> spotlight it


TOOL_SPECS: dict[str, ToolSpec] = {
    "list_files": ToolSpec(NoArgs, _list_files, True),
    "read_file": ToolSpec(PathArgs, _read_file, True),
    "search_code": ToolSpec(SearchArgs, _search_code, True),
    "write_file": ToolSpec(WriteArgs, _write_file, False),
    "get_diff": ToolSpec(NoArgs, _get_diff, True),
    "run_tests": ToolSpec(NoArgs, _run_tests, True),
}


# ------------------------------------------------------------------ what the model sees
async def list_files(ctx: RunContext[Deps]) -> str:
    """List all files in the repository workspace."""
    return await ctx.deps.gateway.call(ctx.deps.role, "list_files", {})


async def read_file(ctx: RunContext[Deps], path: str) -> str:
    """Read one file.

    Args:
        path: repository-relative path, e.g. "app/db.py"
    """
    return await ctx.deps.gateway.call(ctx.deps.role, "read_file", {"path": path})


async def search_code(ctx: RunContext[Deps], text: str) -> str:
    """Find lines containing a literal text (not a regex) across the repository.

    Args:
        text: the literal text to look for
    """
    return await ctx.deps.gateway.call(ctx.deps.role, "search_code", {"text": text})


async def write_file(ctx: RunContext[Deps], path: str, content: str) -> str:
    """Create or overwrite a file with its COMPLETE new content.

    Args:
        path: repository-relative path
        content: the full file content
    """
    return await ctx.deps.gateway.call(ctx.deps.role, "write_file", {"path": path, "content": content})


async def get_diff(ctx: RunContext[Deps]) -> str:
    """Show the full diff of the change against the base branch."""
    return await ctx.deps.gateway.call(ctx.deps.role, "get_diff", {})


async def run_tests(ctx: RunContext[Deps]) -> str:
    """Run the project's test suite in the sandbox and return the result."""
    return await ctx.deps.gateway.call(ctx.deps.role, "run_tests", {})


AGENT_TOOLS = {f.__name__: f for f in (list_files, read_file, search_code, write_file, get_diff, run_tests)}


def register_tools(agent: Agent[Deps, Any], tool_names: list[str]) -> None:
    """Least privilege at the prompt level: register only the tools the role's policy allows."""
    for name in tool_names:
        agent.tool(AGENT_TOOLS[name])
