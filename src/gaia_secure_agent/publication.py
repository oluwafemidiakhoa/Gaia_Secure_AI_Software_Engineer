from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field

from .approval import ApprovalRecord, assert_publish_approved
from .evidence import EvidenceReceipt, verify_evidence_receipt
from .patch import PatchArtifact
from .repository import ResolvedRepository
from .source_bundle import SourceBundle


class PublicationPlan(BaseModel):
    job_id: UUID
    repository: str
    base_branch: str
    base_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_path: Path
    approved_by: str
    approved_at: datetime
    human_approval_verified: bool = True
    evidence_verified: bool = True
    agent_github_write_allowed: bool = False


def _load_model(path: Path, model_type):
    if not path.is_file():
        raise ValueError(f"required manifest does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"manifest is not valid JSON: {path}") from exc
    return model_type.model_validate(payload)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _assert_evidence_matches_artifacts(
    *,
    evidence: EvidenceReceipt,
    repository: ResolvedRepository,
    bundle: SourceBundle,
    patch: PatchArtifact,
) -> None:
    if evidence.job_id != patch.job_id:
        raise PermissionError("evidence receipt belongs to a different coding job")
    if evidence.source_commit != repository.commit_sha:
        raise PermissionError("evidence source commit does not match repository resolution")
    if evidence.source_sha256 != bundle.archive_sha256:
        raise PermissionError("evidence source digest does not match acquired source bundle")
    if evidence.patch_sha256 != patch.sha256:
        raise PermissionError("evidence patch digest does not match verified patch")


def verify_publication(
    *,
    repository_manifest: Path,
    bundle_manifest: Path,
    patch_manifest: Path,
    approval_manifest: Path,
    evidence_manifest: Path,
    run_manifest: Path,
) -> PublicationPlan:
    repository = _load_model(repository_manifest, ResolvedRepository)
    bundle = _load_model(bundle_manifest, SourceBundle)
    patch = _load_model(patch_manifest, PatchArtifact)
    approval = _load_model(approval_manifest, ApprovalRecord)
    evidence = verify_evidence_receipt(
        evidence_manifest,
        run_manifest_path=run_manifest,
    )

    if bundle.commit_sha != repository.commit_sha:
        raise PermissionError("source bundle commit does not match repository resolution")
    if not bundle.archive_path.is_file():
        raise PermissionError("acquired source archive is missing")
    if bundle.archive_path.stat().st_size != bundle.size_bytes:
        raise PermissionError("acquired source archive size changed after acquisition")
    if _sha256(bundle.archive_path) != bundle.archive_sha256:
        raise PermissionError("acquired source archive digest changed after acquisition")
    if patch.source_sha256 != bundle.archive_sha256:
        raise PermissionError("patch source digest does not match acquired source bundle")
    if not patch.has_changes or patch.size_bytes <= 0:
        raise PermissionError("publication requires a non-empty patch")

    if not patch.local_path.is_file():
        raise PermissionError("verified patch file is missing")
    if patch.local_path.stat().st_size != patch.size_bytes:
        raise PermissionError("patch file size changed after collection")
    if _sha256(patch.local_path) != patch.sha256:
        raise PermissionError("patch file digest changed after collection")

    _assert_evidence_matches_artifacts(
        evidence=evidence,
        repository=repository,
        bundle=bundle,
        patch=patch,
    )

    assert_publish_approved(
        job_id=patch.job_id,
        patch_sha256=patch.sha256,
        approval=approval,
    )

    return PublicationPlan(
        job_id=patch.job_id,
        repository=repository.source_url,
        base_branch=repository.branch,
        base_commit=repository.commit_sha,
        source_sha256=bundle.archive_sha256,
        patch_sha256=patch.sha256,
        evidence_sha256=evidence.evidence_sha256,
        patch_path=patch.local_path,
        approved_by=approval.actor,
        approved_at=approval.decided_at,
    )
