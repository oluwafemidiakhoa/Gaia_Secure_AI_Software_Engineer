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


def _evidence_digest(receipt: EvidenceReceipt) -> str:
    payload = {
        "job_id": str(receipt.job_id),
        "source_commit": receipt.source_commit,
        "source_sha256": receipt.source_sha256,
        "agent_output_sha256": receipt.agent_output_sha256,
        "patch_sha256": receipt.patch_sha256,
        "run_manifest_sha256": receipt.run_manifest_sha256,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
    receipt = EvidenceReceipt(
        job_id=job_id,
        source_commit=source_commit,
        source_sha256=source_sha256,
        agent_output_sha256=agent_output_sha256,
        patch_sha256=patch_sha256,
        run_manifest_sha256=run_manifest_sha256,
        evidence_sha256="0" * 64,
    )
    return receipt.model_copy(update={"evidence_sha256": _evidence_digest(receipt)})


def write_evidence_receipt(receipt: EvidenceReceipt, path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"evidence receipt already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(receipt.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def load_evidence_receipt(path: Path) -> EvidenceReceipt:
    if not path.is_file():
        raise ValueError(f"evidence receipt does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("evidence receipt is not valid JSON") from exc
    return EvidenceReceipt.model_validate(payload)


def verify_evidence_receipt(
    receipt_path: Path,
    *,
    run_manifest_path: Path,
) -> EvidenceReceipt:
    receipt = load_evidence_receipt(receipt_path)
    actual_run_manifest_sha256 = sha256_file(run_manifest_path)
    if actual_run_manifest_sha256 != receipt.run_manifest_sha256:
        raise PermissionError("run manifest digest does not match evidence receipt")
    if _evidence_digest(receipt) != receipt.evidence_sha256:
        raise PermissionError("evidence fingerprint does not match receipt contents")
    return receipt
