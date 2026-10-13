"""Logging, eval capture and a tamper-evident audit log.

Each horizontal concern logs to its own
file so it can be reviewed, monitored, and later used for evaluation or post-training:

  logs/prompts.log    every rendered prompt                  (prompt_service)
  logs/guards.log     every guardrail verdict                (guardrails)
  logs/tools.log      every gateway decision                 (gateway)
  logs/feedback.log   every human approval / rejection       (hitl)
  logs/evals.log      every AI input/output pair             (record_ai_response)
  logs/audit.jsonl    hash-chained security events           (AuditLog, verify with `agentic-sdlc verify-audit`)

Optional OpenTelemetry traces of every agent run, model call and tool call:
  PHOENIX_COLLECTOR_ENDPOINT=http://localhost:6006   self-hosted Arize Phoenix (`docker run -p 6006:6006 arizephoenix/phoenix`)
  LOGFIRE_TOKEN=...                                  Pydantic Logfire (hosted)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import logging.config
import os
import threading
import time
from pathlib import Path
from typing import Any

from agentic_sdlc.config import ROOT

evals_logger = logging.getLogger("agentic_sdlc.evals")


def setup_logging(config_file: Path = ROOT / "logging.json") -> None:
    from dotenv import load_dotenv

    load_dotenv(ROOT / "keys.env")
    (ROOT / "logs").mkdir(exist_ok=True)
    cfg = json.loads(config_file.read_text())
    for h in cfg.get("handlers", {}).values():   # log files are relative to the project root
        if "filename" in h:
            h["filename"] = str(ROOT / h["filename"])
    logging.config.dictConfig(cfg)
    if os.environ.get("PHOENIX_COLLECTOR_ENDPOINT"):
        # Self-hosted Arize Phoenix: traces stay inside your network.
        from phoenix.otel import register  # optional extra: pip install -e ".[phoenix]"
        from pydantic_ai import Agent

        register(project_name="agentic-sdlc")
        Agent.instrument_all()  # OpenTelemetry spans for every agent run, model call and tool call
    elif os.environ.get("LOGFIRE_TOKEN"):
        import logfire  # optional extra: pip install -e ".[observability]"

        logfire.configure()
        logfire.instrument_pydantic_ai()


def record_ai_response(target: str, ai_input: Any, ai_response: Any) -> None:
    """Save input/output pairs for offline evaluation."""
    evals_logger.info("AI Response", extra={"target": target, "ai_input": ai_input, "ai_response": ai_response})


class AuditLog:
    """Append-only JSON lines; each line carries the hash of the previous one (and an HMAC when
    AGENTIC_AUDIT_KEY is set), so deleting or editing an event breaks the chain.
    Production: ship to WORM storage / SIEM as well."""

    def __init__(self, path: str | Path):
        self.path = Path(path) if Path(path).is_absolute() else ROOT / path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._key = os.environ.get("AGENTIC_AUDIT_KEY", "").encode()
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "genesis"
        lines = self.path.read_text().strip().splitlines()
        return json.loads(lines[-1])["hash"] if lines else "genesis"

    def _seal(self, body: dict[str, Any]) -> str:
        raw = json.dumps(body, sort_keys=True, default=str).encode()
        return (hmac.new(self._key, raw, hashlib.sha256) if self._key else hashlib.sha256(raw)).hexdigest()

    def record(self, event: str, run_id: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            body = {"ts": time.time(), "event": event, "run_id": run_id, **fields, "prev": self._prev}
            body["hash"] = self._seal(body)
            with self.path.open("a") as f:
                f.write(json.dumps(body, default=str) + "\n")
            self._prev = body["hash"]
            return body

    def events(self, run_id: str | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        evs = [json.loads(line) for line in self.path.read_text().splitlines() if line.strip()]
        return [e for e in evs if run_id is None or e.get("run_id") == run_id]

    def verify(self) -> tuple[bool, str]:
        prev = "genesis"
        for i, e in enumerate(self.events(), 1):
            h = e.pop("hash")
            if e.get("prev") != prev or self._seal(e) != h:
                return False, f"chain broken at line {i}"
            prev = h
        return True, "audit chain intact"
