from __future__ import annotations

import hashlib
import shutil
import urllib.error
import urllib.request
from pathlib import Path

from pydantic import BaseModel, Field

from .repository import ResolvedRepository


class SourceBundle(BaseModel):
    commit_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    archive_path: Path
    archive_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    size_bytes: int = Field(ge=1)


def acquire_public_source_bundle(
    resolved: ResolvedRepository,
    destination: Path,
    *,
    max_bytes: int = 100 * 1024 * 1024,
    timeout: int = 60,
) -> SourceBundle:
    destination.parent.mkdir(parents=True, exist_ok=True)
    url = (
        f"https://codeload.github.com/{resolved.owner}/{resolved.name}/tar.gz/"
        f"{resolved.commit_sha}"
    )
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "Gaia-Secure-AI-Software-Engineer/0.1"},
        method="GET",
    )

    digest = hashlib.sha256()
    total = 0
    temporary = destination.with_suffix(destination.suffix + ".part")

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response, temporary.open("wb") as output:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RuntimeError("repository source archive exceeded the configured size limit")
                digest.update(chunk)
                output.write(chunk)
    except (OSError, urllib.error.URLError, TimeoutError):
        temporary.unlink(missing_ok=True)
        raise
    except RuntimeError:
        temporary.unlink(missing_ok=True)
        raise

    if total == 0:
        temporary.unlink(missing_ok=True)
        raise RuntimeError("repository source archive was empty")

    shutil.move(str(temporary), str(destination))
    return SourceBundle(
        commit_sha=resolved.commit_sha,
        archive_path=destination,
        archive_sha256=digest.hexdigest(),
        size_bytes=total,
    )
