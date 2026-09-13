from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from .archive_inspect import ArchiveInspection, inspect_source_archive
from .models import CodingJob
from .repository import ResolvedRepository, resolve_github_commit, write_resolution_manifest
from .source_bundle import SourceBundle, acquire_public_source_bundle
from .transfer import RepositoryTransfer, build_repository_transfer


class AcquisitionResult(BaseModel):
    resolved: ResolvedRepository
    transfer: RepositoryTransfer
    bundle: SourceBundle
    inspection: ArchiveInspection
    repository_manifest: Path
    transfer_manifest: Path
    bundle_manifest: Path
    inspection_manifest: Path


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return path


def acquire_job_source(job: CodingJob, output_dir: Path) -> AcquisitionResult:
    output_dir.mkdir(parents=True, exist_ok=True)

    resolved = resolve_github_commit(job)
    repository_manifest = write_resolution_manifest(resolved, output_dir / "repository.json")

    transfer = build_repository_transfer(resolved, target_path="/sandbox/repository")
    transfer_manifest = _write_json(
        output_dir / "transfer.json",
        transfer.model_dump(mode="json"),
    )

    bundle = acquire_public_source_bundle(resolved, output_dir / "source.tar.gz")
    inspection = inspect_source_archive(bundle.archive_path)

    bundle_manifest = _write_json(
        output_dir / "bundle.json",
        bundle.model_dump(mode="json"),
    )
    inspection_manifest = _write_json(
        output_dir / "archive-inspection.json",
        inspection.model_dump(mode="json"),
    )

    return AcquisitionResult(
        resolved=resolved,
        transfer=transfer,
        bundle=bundle,
        inspection=inspection,
        repository_manifest=repository_manifest,
        transfer_manifest=transfer_manifest,
        bundle_manifest=bundle_manifest,
        inspection_manifest=inspection_manifest,
    )
