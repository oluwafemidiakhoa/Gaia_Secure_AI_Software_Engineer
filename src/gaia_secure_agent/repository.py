from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

from pydantic import BaseModel, Field

from .models import CodingJob


_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class RepositoryIdentity(BaseModel):
    owner: str
    name: str


class ResolvedRepository(BaseModel):
    owner: str
    name: str
    branch: str
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_url: str
    manifest_sha256: str


def parse_github_repository(repository: str) -> RepositoryIdentity:
    parsed = urllib.parse.urlparse(repository)
    if parsed.scheme != "https" or parsed.hostname not in {"github.com", "www.github.com"}:
        raise ValueError("repository must be an HTTPS github.com URL")

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise ValueError("repository URL must be exactly https://github.com/<owner>/<repo>")

    owner, name = parts
    name = name.removesuffix(".git")

    if not owner or not name or not _NAME.fullmatch(owner) or not _NAME.fullmatch(name):
        raise ValueError("repository owner or name contains unsupported characters")

    return RepositoryIdentity(owner=owner, name=name)


def _manifest_digest(*, owner: str, name: str, branch: str, commit_sha: str) -> str:
    payload = json.dumps(
        {"owner": owner, "name": name, "branch": branch, "commit_sha": commit_sha},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def resolve_github_commit(job: CodingJob, *, timeout: int = 15) -> ResolvedRepository:
    identity = parse_github_repository(str(job.repository))
    ref = urllib.parse.quote(job.base_branch, safe="")
    url = f"https://api.github.com/repos/{identity.owner}/{identity.name}/commits/{ref}"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "Gaia-Secure-AI-Software-Engineer/0.1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(262_145)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"GitHub commit resolution failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"GitHub commit resolution failed: {exc}") from exc

    if len(raw) > 262_144:
        raise RuntimeError("GitHub commit response exceeded the allowed size")

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("GitHub commit response was not valid JSON") from exc

    commit_sha = data.get("sha") if isinstance(data, dict) else None
    if not isinstance(commit_sha, str) or not _SHA.fullmatch(commit_sha):
        raise RuntimeError("GitHub commit response did not contain a valid immutable SHA")

    digest = _manifest_digest(
        owner=identity.owner,
        name=identity.name,
        branch=job.base_branch,
        commit_sha=commit_sha,
    )
    return ResolvedRepository(
        owner=identity.owner,
        name=identity.name,
        branch=job.base_branch,
        commit_sha=commit_sha,
        source_url=str(job.repository),
        manifest_sha256=digest,
    )


def write_resolution_manifest(resolved: ResolvedRepository, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(resolved.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path
