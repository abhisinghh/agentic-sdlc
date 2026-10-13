"""Code execution in a sandbox.

AI-written code is untrusted code. The agent can only ask for `run_tests`, a tool with NO arguments:
the command is fixed here, so it can't be turned into a shell. Three modes:

  docker  isolated: no network, read-only root and workspace, all capabilities dropped, non-root,
          no-new-privileges, CPU/memory/PID limits, timeout; optional gVisor (runtime: runsc)
  local   NOT isolated: runs pytest as a local process on a copy (developer laptops only)
  off     tests are never executed; the reviewer and the human are told so

The sandbox output is evidence for the harness ("check, don't trust the model's claim it works").
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from agentic_sdlc.config import SandboxSettings

TEST_COMMAND = ["python", "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", "--maxfail=5"]


@dataclass
class TestResult:
    executed: bool
    exit_code: int
    output: str
    mode: str

    @property
    def passed(self) -> bool:
        return self.executed and self.exit_code == 0

    def tail(self, n: int = 4000) -> str:
        return self.output[-n:]


class Sandbox:
    def __init__(self, cfg: SandboxSettings):
        self.cfg = cfg

    def run_tests(self, workdir: Path) -> TestResult:
        if self.cfg.mode == "docker":
            return self._docker(workdir)
        if self.cfg.mode == "local":
            return self._local(workdir)
        return TestResult(False, 0, "sandbox mode is 'off': tests were not executed", "off")

    def _docker(self, workdir: Path) -> TestResult:
        cmd = ["docker", "run", "--rm", "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=64m",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "256",
               "--memory", "1g", "--cpus", "1", "--user", "65534:65534",
               "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp",
               "-v", f"{workdir.resolve()}:/work:ro", "-w", "/work"]
        if self.cfg.runtime:
            cmd += ["--runtime", self.cfg.runtime]
        return self._run([*cmd, self.cfg.image, *TEST_COMMAND], cwd=None, mode="docker")

    def _local(self, workdir: Path) -> TestResult:
        with tempfile.TemporaryDirectory() as tmp:  # run on a copy, never on the workspace itself
            copy = Path(tmp) / "work"
            shutil.copytree(workdir, copy, ignore=shutil.ignore_patterns(".git"))
            return self._run([sys.executable, *TEST_COMMAND[1:]], cwd=copy, mode="local")

    def _run(self, cmd: list[str], cwd: Path | None, mode: str) -> TestResult:
        try:
            p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=self.cfg.timeout_s)
        except subprocess.TimeoutExpired:
            return TestResult(True, 124, f"timed out after {self.cfg.timeout_s}s", mode)
        except FileNotFoundError as e:
            return TestResult(False, 127, f"sandbox unavailable: {e}", mode)
        return TestResult(True, p.returncode, (p.stdout + "\n" + p.stderr).strip(), mode)
