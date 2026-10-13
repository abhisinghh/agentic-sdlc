"""A disposable git workspace per run: the only place the agent can write.

The agent works on its own branch (agent/<run_id>) in a throwaway clone. Nothing it does here is
visible to anyone until a human approves the exact diff and the platform publishes a draft PR.
Git runs with hooks disabled and paths are confined to the workspace (no '..', no symlinks).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class WorkspaceError(Exception):
    pass


_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.symlinks=false", "-c", "user.name=agentic-sdlc",
        "-c", "user.email=agentic-sdlc@noreply.invalid", "-c", "commit.gpgsign=false"]


def git(cwd: Path, *args: str, check: bool = True, extra_env: dict[str, str] | None = None) -> str:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_TERMINAL_PROMPT": "0", "HOME": str(cwd),
           **(extra_env or {})}
    proc = subprocess.run([*_GIT, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    if check and proc.returncode != 0:
        raise WorkspaceError(f"git {args[0]} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout


class Workspace:
    def __init__(self, path: Path, base_branch: str, work_branch: str):
        self.path = path.resolve()
        self.base_branch = base_branch
        self.work_branch = work_branch

    @classmethod
    def create(cls, source: Path, root: Path, run_id: str, base_branch: str = "main",
               branch_prefix: str = "agent/") -> Workspace:
        dest = (root / run_id).resolve()
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if (source / ".git").exists():
            git(dest.parent, "clone", "--no-hardlinks", "--branch", base_branch, str(source.resolve()), str(dest))
        else:  # a plain folder (e.g. examples/sample_repo): snapshot it as the base commit
            shutil.copytree(source, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
            git(dest, "init", "-q")  # `init -b` needs git >= 2.28; symbolic-ref works on any version
            git(dest, "symbolic-ref", "HEAD", f"refs/heads/{base_branch}")
            git(dest, "add", "-A")
            git(dest, "commit", "-q", "-m", "baseline")
        work_branch = f"{branch_prefix}{run_id}"
        git(dest, "checkout", "-q", "-b", work_branch)
        return cls(dest, base_branch, work_branch)

    # ------------------------------------------------------------------ confinement
    def resolve(self, rel: str) -> Path:
        if not rel or rel.startswith(("/", "\\")) or ":" in rel or "\x00" in rel:
            raise WorkspaceError(f"invalid path: {rel!r}")
        target = self.path / rel
        probe = self.path
        for part in Path(rel).parts:          # refuse to traverse symlinks planted in the repo
            probe = probe / part
            if probe.is_symlink():
                raise WorkspaceError(f"refusing to follow symlink: {rel}")
        resolved = target.resolve()
        if resolved != self.path and self.path not in resolved.parents:
            raise WorkspaceError(f"path escapes the workspace: {rel}")
        return resolved

    # ------------------------------------------------------------------ operations used by tools
    def list_files(self, limit: int = 400) -> list[str]:
        out = git(self.path, "ls-files", "--cached", "--others", "--exclude-standard")
        return sorted(set(out.splitlines()))[:limit]

    def read(self, rel: str, max_bytes: int = 100_000) -> str:
        p = self.resolve(rel)
        if not p.is_file():
            raise WorkspaceError(f"not a file: {rel}")
        return p.read_bytes()[:max_bytes].decode(errors="replace")

    def write(self, rel: str, content: str) -> None:
        p = self.resolve(rel)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")

    def search(self, needle: str, limit: int = 100) -> list[str]:
        out = git(self.path, "grep", "-n", "-F", "-I", "--untracked", "-e", needle, check=False)
        return out.splitlines()[:limit]

    def diff(self) -> str:
        git(self.path, "add", "-A")
        return git(self.path, "diff", "--cached", "--no-ext-diff", self.base_branch)

    def changed_files(self) -> list[str]:
        git(self.path, "add", "-A")
        return git(self.path, "diff", "--cached", "--name-only", self.base_branch).splitlines()

    def commit(self, message: str) -> str:
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "--no-verify", "-m", message)
        return git(self.path, "rev-parse", "HEAD").strip()
