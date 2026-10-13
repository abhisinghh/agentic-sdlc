"""Publishing: the ONLY code path that leaves the sandbox. Not a tool, so no model can call it.

Least-privilege access to GitHub:
  * credential: a fine-grained personal access token or (better) a GitHub App installation token
    scoped to ONE repository with only `contents: write` + `pull_requests: write`. It is read from
    the environment here, right before use; it never enters a prompt, a log or the audit trail.
  * branch: only `agent/<run_id>` can be pushed (never main, never --force, never tags);
    branch protection on main makes the PR the only way in.
  * PR: always opened as a DRAFT with an `agent-generated` label; merging stays with humans + CI.

Local mode (github.repo empty): the PR description and patch are written to var/prs/ instead.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import httpx

from agentic_sdlc.config import ROOT, Settings
from agentic_sdlc.workspace import Workspace, git


class PublishError(Exception):
    pass


async def publish_pull_request(ws: Workspace, settings: Settings, run_id: str, title: str, body: str) -> str:
    gh = settings.github
    if not ws.work_branch.startswith(gh.branch_prefix):
        raise PublishError(f"refusing to publish branch {ws.work_branch!r}: only {gh.branch_prefix}* is allowed")
    ws.commit(f"{title}\n\nAgent-Run: {run_id}")

    if not gh.repo:  # local mode
        out = ROOT / settings.paths.prs
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{run_id}.md").write_text(f"# {title}\n\n{body}\n")
        (out / f"{run_id}.patch").write_text(git(ws.path, "format-patch", "--stdout", ws.base_branch))
        return str(out / f"{run_id}.md")

    token = os.environ.get(gh.token_env, "")
    if not token:
        raise PublishError(f"{gh.token_env} is not set")
    # The token reaches git through GIT_ASKPASS + an env var: never in argv, never in .git/config.
    # (Works on any git version; the GIT_CONFIG_COUNT env approach needs git >= 2.31.)
    with tempfile.TemporaryDirectory() as tmp:
        askpass = Path(tmp) / "askpass.sh"
        askpass.write_text('#!/bin/sh\nprintf "%s" "$AGENTIC_GIT_TOKEN"\n')
        askpass.chmod(0o700)
        git(ws.path, "push", "--no-verify", f"https://x-access-token@github.com/{gh.repo}.git",
            f"HEAD:refs/heads/{ws.work_branch}",
            extra_env={"GIT_ASKPASS": str(askpass), "AGENTIC_GIT_TOKEN": token})

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    async with httpx.AsyncClient(base_url="https://api.github.com", headers=headers, timeout=30) as client:
        r = await client.post(f"/repos/{gh.repo}/pulls", json={
            "title": title, "head": ws.work_branch, "base": gh.base_branch, "body": body, "draft": True})
        if r.status_code >= 300:
            raise PublishError(f"GitHub refused the PR: {r.status_code} {r.text[:300]}")
        pr = r.json()
        await client.post(f"/repos/{gh.repo}/issues/{pr['number']}/labels", json={"labels": ["agent-generated"]})
        return str(pr["html_url"])


def local_pr_dir(settings: Settings) -> Path:
    return ROOT / settings.paths.prs
