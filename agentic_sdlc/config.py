"""Typed settings loaded from config.yaml and policies/policy.yaml (one place to see what the agent may do)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]

Provider = Literal["anthropic", "openai", "local"]
DataClass = Literal["public", "internal", "confidential", "restricted"]


class ModelTiers(BaseModel):
    best: str
    default: str
    small: str
    base_url: str | None = None
    api_key_env: str | None = None


class LLMSettings(BaseModel):
    provider: Provider = "anthropic"
    anthropic: ModelTiers
    openai: ModelTiers
    local: ModelTiers
    roles: dict[str, Literal["best", "default", "small"]]
    fallback_to_local: bool = False


class SandboxSettings(BaseModel):
    mode: Literal["docker", "local", "off"] = "docker"
    image: str = "agentic-sdlc-runner:latest"
    runtime: str | None = None
    timeout_s: int = 120


class Limits(BaseModel):
    max_model_requests: int = 40
    max_total_tokens: int = 400_000
    max_tool_calls: int = 60
    max_consecutive_denials: int = 3
    max_identical_calls: int = 4
    max_run_seconds: int = 1800
    max_fix_rounds: int = 2
    max_plan_retries: int = 1


class GitHubSettings(BaseModel):
    repo: str = ""
    base_branch: str = "main"
    token_env: str = "GITHUB_TOKEN"
    branch_prefix: str = "agent/"


class PathSettings(BaseModel):
    workspaces: str = "var/workspaces"
    prs: str = "var/prs"
    audit_log: str = "logs/audit.jsonl"
    kill_switch: str = "var/KILL"


class Settings(BaseModel):
    llm: LLMSettings
    data_class: DataClass = "internal"
    allow_hosted_for: list[DataClass] = Field(default_factory=lambda: ["public", "internal"])
    sandbox: SandboxSettings = SandboxSettings()
    limits: Limits = Limits()
    github: GitHubSettings = GitHubSettings()
    paths: PathSettings = PathSettings()


class RolePolicy(BaseModel):
    tools: list[str]


class ToolPolicy(BaseModel):
    risk: Literal["read", "execute", "write_local"]


class PathPolicy(BaseModel):
    deny_read: list[str] = Field(default_factory=list)
    deny_write: list[str] = Field(default_factory=list)
    sensitive: list[str] = Field(default_factory=list)


class PolicyLimits(BaseModel):
    max_file_bytes: int = 100_000
    max_files_changed: int = 10
    max_tool_output_chars: int = 12_000
    max_calls_per_risk: dict[str, int] = Field(default_factory=lambda: {"read": 60, "execute": 8, "write_local": 30})


class Policy(BaseModel):
    roles: dict[str, RolePolicy]
    tools: dict[str, ToolPolicy]
    paths: PathPolicy = PathPolicy()
    limits: PolicyLimits = PolicyLimits()


def load_settings(path: str | Path = ROOT / "config.yaml") -> Settings:
    return Settings.model_validate(yaml.safe_load(Path(path).read_text()))


def load_policy(path: str | Path = ROOT / "policies" / "policy.yaml") -> Policy:
    return Policy.model_validate(yaml.safe_load(Path(path).read_text()))
