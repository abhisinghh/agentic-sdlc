"""Model gateway: the one place that decides which model serves which role.

BEST / DEFAULT / SMALL model tiers per provider, behind one "model gateway": agents never construct clients themselves, so
provider choice, data-residency rules and keys live in one reviewed place.

  anthropic  -> hosted Claude        (ANTHROPIC_API_KEY)
  openai     -> hosted OpenAI        (OPENAI_API_KEY)
  local      -> any OpenAI-compatible server on your GPU box (vLLM, Ollama, LM Studio)

Data residency fails closed: confidential/restricted repos can only use `local`.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic_ai.models import Model

from agentic_sdlc.config import ROOT, Settings

logger = logging.getLogger(__name__)

load_dotenv(Path(ROOT) / "keys.env")


class DataResidencyError(RuntimeError):
    """A classified repository would have been sent to a hosted model."""


def check_residency(settings: Settings) -> None:
    if settings.llm.provider != "local" and settings.data_class not in settings.allow_hosted_for:
        raise DataResidencyError(
            f"data_class={settings.data_class} may not be sent to hosted provider '{settings.llm.provider}'. "
            "Use llm.provider=local (on-prem model) for this repository.")


def model_for(role: str, settings: Settings) -> Model:
    """Return the pydantic-ai Model for an agent role (planner, coder, reviewer, guard)."""
    check_residency(settings)
    provider = settings.llm.provider
    tiers = getattr(settings.llm, provider)
    name = getattr(tiers, settings.llm.roles.get(role, "default"))
    logger.info(f"role={role} provider={provider} model={name}")

    if provider == "local":
        return _local(role, settings)
    if provider == "anthropic":
        from pydantic_ai.models.anthropic import AnthropicModel

        primary: Model = AnthropicModel(name)  # reads ANTHROPIC_API_KEY
    else:
        from pydantic_ai.models.openai import OpenAIChatModel

        primary = OpenAIChatModel(name)  # reads OPENAI_API_KEY
    if not settings.llm.fallback_to_local:
        return primary
    # Model fallback: if the hosted API errors or is down,
    # the same agent continues on the on-prem model. Fallback only ever moves data INTO the boundary.
    from pydantic_ai.models.fallback import FallbackModel

    return FallbackModel(primary, _local(role, settings))


def _local(role: str, settings: Settings) -> Model:
    from pydantic_ai.models.openai import OpenAIChatModel
    from pydantic_ai.providers.openai import OpenAIProvider

    tiers = settings.llm.local
    name = getattr(tiers, settings.llm.roles.get(role, "default"))
    api_key = os.environ.get(tiers.api_key_env or "", "") or "not-needed"
    return OpenAIChatModel(name, provider=OpenAIProvider(base_url=tiers.base_url, api_key=api_key))


def models_for_pipeline(settings: Settings) -> dict[str, Model]:
    return {role: model_for(role, settings) for role in ("planner", "coder", "reviewer")}
