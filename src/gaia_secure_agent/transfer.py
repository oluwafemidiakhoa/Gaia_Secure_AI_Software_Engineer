from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath

from pydantic import BaseModel, Field, field_validator

from .repository import ResolvedRepository


_SHA = re.compile(r"^[0-9a-f]{40}$")


class RepositoryTransfer(BaseModel):
    owner: str
    name: str
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_url: str
    target_path: str = "/workspace/repository"
    github_write_allowed: bool = False
    credentials_embedded: bool = False
    transfer_sha256: str

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if not path.is_absolute():
            raise ValueError("sandbox repository target must be absolute")
        if ".." in path.parts:
            raise ValueError("sandbox repository target cannot traverse parent directories")
        if str(path) in {"/", "/workspace"}:
            raise ValueError("sandbox repository target must be a dedicated subdirectory")
        return str(path)


def _transfer_digest(*, owner: str, name: str, commit_sha: str, target_path: str) -> str:
    payload = json.dumps(
        {
            "owner": owner,
            "name": name,
            "commit_sha": commit_sha,
            "target_path": target_path,
            "github_write_allowed": False,
            "credentials_embedded": False,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_repository_transfer(
    resolved: ResolvedRepository,
    *,
    target_path: str = "/workspace/repository",
) -> RepositoryTransfer:
    if not _SHA.fullmatch(resolved.commit_sha):
        raise ValueError("resolved repository does not contain a valid immutable commit")

    digest = _transfer_digest(
        owner=resolved.owner,
        name=resolved.name,
        commit_sha=resolved.commit_sha,
        target_path=target_path,
    )
    return RepositoryTransfer(
        owner=resolved.owner,
        name=resolved.name,
        commit_sha=resolved.commit_sha,
        source_url=resolved.source_url,
        target_path=target_path,
        transfer_sha256=digest,
    )
