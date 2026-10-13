"""Command line.

  agentic-sdlc run --repo examples/sample_repo --issue examples/issues/sqli_with_injection.md \\
                    --task "Fix the SQL injection in product search"           # real models (config.yaml)
  agentic-sdlc run ... --offline happy|attack [--auto-approve]                # scripted models, no key
  agentic-sdlc review --repo /path/to/git/repo --head my-branch                # PR-review mode
  agentic-sdlc eval [--min-pass-rate 1.0]                                      # security benchmark (CI gate)
  agentic-sdlc verify-audit                                                    # check the audit chain
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path

from agentic_sdlc.config import load_policy, load_settings
from agentic_sdlc.hitl import AutoApprover, CLIApprover
from agentic_sdlc.observability import AuditLog, setup_logging


def _run(args: argparse.Namespace) -> int:
    from agentic_sdlc.pipeline import SDLCRun

    settings, policy = load_settings(args.config), load_policy()
    if args.sandbox:
        settings.sandbox.mode = args.sandbox
    if args.offline:
        from agentic_sdlc.demo_models import offline_models

        models = offline_models(args.offline)
    else:
        from agentic_sdlc.llms import models_for_pipeline

        models = models_for_pipeline(settings)
    nemo = None
    if args.nemo:
        from agentic_sdlc.guardrails import NemoRails

        nemo = NemoRails()
    issue = Path(args.issue).read_text() if args.issue else ""
    run = SDLCRun(task=args.task, repo=args.repo, issue=issue, settings=settings, policy=policy,
                  models=models, nemo=nemo)  # type: ignore[arg-type]
    approver = AutoApprover() if args.auto_approve else CLIApprover(os.environ.get("USER", "reviewer"))
    state = asyncio.run(run.run_all(approver))
    print(json.dumps({"run_id": run.run_id, "status": state.status, "error": state.error, "pr": state.pr_url,
                      "rounds": state.rounds, "monitor": run.monitor.summary()}, indent=2, default=str))
    return 0 if state.status == "published" else 1


def _review(args: argparse.Namespace) -> int:
    from agentic_sdlc.llms import model_for
    from agentic_sdlc.pipeline import review_existing_change

    settings, policy = load_settings(args.config), load_policy()
    review = asyncio.run(review_existing_change(args.repo, args.head, settings, policy,
                                                model_for("reviewer", settings), args.description or ""))
    print(review.model_dump_json(indent=2))
    return 0 if not review.blocking else 2


def _eval(args: argparse.Namespace) -> int:
    from agentic_sdlc.benchmark import Evaluator, load_benchmark, write_csv

    report = asyncio.run(Evaluator(load_settings(args.config), load_policy()).run(load_benchmark(args.benchmark)))
    csv_path = write_csv(report, args.csv)
    for r in report["results"]:
        if not r["passed"]:
            print(f"FAIL {r['id']} [{r['asi']}] expected={r['expected']} actual={r['actual']}: {r['input'][:90]}")
    print(f"{report['name']}: pass rate {report['pass_rate']:.0%} ({report['total'] - report['failed']}/"
          f"{report['total']}), false positives on benign cases: {report['false_positives']}. CSV: {csv_path}")
    return 0 if report["pass_rate"] >= args.min_pass_rate else 4


def _verify(args: argparse.Namespace) -> int:
    ok, msg = AuditLog(load_settings(args.config).paths.audit_log).verify()
    print(msg)
    return 0 if ok else 3


def main() -> None:
    setup_logging()
    p = argparse.ArgumentParser(prog="agentic-sdlc")
    p.add_argument("--config", default=str(Path(__file__).resolve().parents[1] / "config.yaml"))
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="issue -> plan -> code -> review -> human-approved draft PR")
    r.add_argument("--repo", required=True, help="git repo or plain folder to work on")
    r.add_argument("--task", required=True, help="what to do (operator instruction)")
    r.add_argument("--issue", help="file with the issue text (treated as UNTRUSTED)")
    r.add_argument("--offline", choices=["happy", "attack"], help="scripted models, no API key")
    r.add_argument("--auto-approve", action="store_true", help="demo only: approve both gates automatically")
    r.add_argument("--nemo", action="store_true", help="enable NeMo Guardrails rails (needs the rails model)")
    r.add_argument("--sandbox", choices=["docker", "local", "off"], help="override sandbox.mode")
    r.set_defaults(fn=_run)

    v = sub.add_parser("review", help="PR-review mode: independent review of a branch")
    v.add_argument("--repo", required=True)
    v.add_argument("--head", required=True, help="branch to review (compared with github.base_branch)")
    v.add_argument("--description", help="PR description (treated as UNTRUSTED)")
    v.set_defaults(fn=_review)

    e = sub.add_parser("eval", help="deterministic security benchmark (guardrails + gateway), CI gate")
    e.add_argument("--benchmark", default=str(Path(__file__).resolve().parents[1] / "evals" / "security_benchmark.yaml"))
    e.add_argument("--csv", default="logs/eval_results.csv")
    e.add_argument("--min-pass-rate", type=float, default=1.0)
    e.set_defaults(fn=_eval)

    a = sub.add_parser("verify-audit", help="verify the hash chain of logs/audit.jsonl")
    a.set_defaults(fn=_verify)

    args = p.parse_args()
    raise SystemExit(args.fn(args))


if __name__ == "__main__":
    main()
