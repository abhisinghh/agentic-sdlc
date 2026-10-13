"""Prompt management with Jinja2.

Prompts are files in prompts/*.j2, reviewed like code. Every rendered prompt is logged
(logs/prompts.log) so it can later be evaluated or used to post-train a smaller model.
"""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from agentic_sdlc.config import ROOT

TEMPLATE_DIR = ROOT / "prompts"
logger = logging.getLogger(__name__)
_env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), undefined=StrictUndefined,
                   keep_trailing_newline=True, autoescape=False)


class PromptService:
    @staticmethod
    def render_prompt(prompt_name: str, **variables: Any) -> str:
        prompt = _env.get_template(f"{prompt_name}.j2").render(**variables)
        logger.info(prompt, extra={"prompt_name": prompt_name})
        return prompt
