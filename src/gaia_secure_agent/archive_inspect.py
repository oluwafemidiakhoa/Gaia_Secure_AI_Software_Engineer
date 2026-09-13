from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile

from pydantic import BaseModel, Field


class ArchiveInspection(BaseModel):
    accepted: bool = True
    top_level_root: str
    member_count: int = Field(ge=1)
    regular_file_count: int = Field(ge=1)
    total_uncompressed_bytes: int = Field(ge=1)
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def inspect_source_archive(
    archive_path: Path,
    *,
    max_members: int = 50_000,
    max_file_bytes: int = 100 * 1024 * 1024,
    max_uncompressed_bytes: int = 1024 * 1024 * 1024,
) -> ArchiveInspection:
    if not archive_path.is_file():
        raise ValueError(f"source archive does not exist: {archive_path}")

    roots: set[str] = set()
    regular_files = 0
    total_size = 0
    normalized: list[dict[str, object]] = []

    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as exc:
        raise RuntimeError("source archive is not a valid gzip-compressed tar archive") from exc

    if not members:
        raise RuntimeError("source archive is empty")
    if len(members) > max_members:
        raise RuntimeError("source archive contains too many members")

    for member in members:
        path = PurePosixPath(member.name)
        if not member.name or path.is_absolute() or "\\" in member.name:
            raise RuntimeError("source archive contains an unsafe path")
        if any(part in {"", ".", ".."} for part in path.parts):
            raise RuntimeError("source archive contains path traversal")
        if not path.parts:
            raise RuntimeError("source archive contains an empty path")

        roots.add(path.parts[0])
        if ".git" in path.parts:
            raise RuntimeError("source archive contains Git metadata")
        if member.issym() or member.islnk():
            raise RuntimeError("source archive contains a link")
        if not (member.isdir() or member.isfile()):
            raise RuntimeError("source archive contains an unsupported member type")

        kind = "directory" if member.isdir() else "file"
        size = 0
        if member.isfile():
            if member.size < 0 or member.size > max_file_bytes:
                raise RuntimeError("source archive contains an oversized file")
            regular_files += 1
            size = member.size
            total_size += size
            if total_size > max_uncompressed_bytes:
                raise RuntimeError("source archive exceeds the uncompressed size limit")

        normalized.append({"path": member.name, "kind": kind, "size": size})

    if len(roots) != 1:
        raise RuntimeError("source archive must contain exactly one top-level directory")
    if regular_files == 0:
        raise RuntimeError("source archive contains no regular files")

    manifest = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return ArchiveInspection(
        top_level_root=next(iter(roots)),
        member_count=len(members),
        regular_file_count=regular_files,
        total_uncompressed_bytes=total_size,
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
    )
