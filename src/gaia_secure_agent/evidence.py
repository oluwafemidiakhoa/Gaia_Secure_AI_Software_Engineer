from __future__ import annotations

import hashlib
import json
from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, Field


class EvidenceReceipt(BaseModel):
    job_id: UUID
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_evidence_receipt(
    *,
    job_id: UUID,
    source_commit: str,
    source_sha256: str,
    agent_output_sha256: str,
    patch_sha256: str,
    run_manifest_path: Path,
) -> EvidenceReceipt:
    run_manifest_sha256 = sha256_file(run_manifest_path)
    payload = {
        "job_id": str(job_id),
        "source_commit": source_commit,
        "source_sha256": source_sha256,
        "agent_output_sha256": agent_output_sha256,
        "patch_sha256": patch_sha256,
        "run_manifest_sha256": run_manifest_sha256,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    evidence_sha256 = hashlib.sha256(encoded).hexdigest()
    return EvidenceReceipt(**payload, evidence_sha256=evidence_sha256)


def write_evidence_receipt(receipt: EvidenceReceipt, path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"evidence receipt already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path
