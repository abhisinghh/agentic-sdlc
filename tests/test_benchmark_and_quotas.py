"""The security benchmark must pass 100%, capability quotas hold, human wait time isn't billed."""

import time

from agentic_sdlc.benchmark import Evaluator, load_benchmark
from agentic_sdlc.monitor import RunMonitor
from agentic_sdlc.observability import AuditLog
from agentic_sdlc.schemas import Decision

from .conftest import requires_git
from .test_gateway import gw  # noqa: F401  (fixture reuse)


@requires_git
async def test_security_benchmark_passes_without_false_positives(settings, policy):
    report = await Evaluator(settings, policy).run(load_benchmark())
    failures = [r for r in report["results"] if not r["passed"]]
    assert report["pass_rate"] == 1.0, failures
    assert report["false_positives"] == 0


@requires_git
def test_execute_quota_blocks_alias_evasion(gw):  # noqa: F811
    quota = gw.policy.limits.max_calls_per_risk["execute"]
    gw.risk_counts["execute"] = quota
    d = gw.decide("coder", "run_tests", {})
    assert d.decision == Decision.DENY and "quota" in d.reasons[0]


def test_time_waiting_for_a_human_is_not_billed(settings):
    m = RunMonitor("r", settings.limits, AuditLog(settings.paths.audit_log), settings.paths.kill_switch)
    m.pause()
    time.sleep(0.05)
    paused_elapsed = m.elapsed()
    m.resume()
    assert paused_elapsed < 0.05
