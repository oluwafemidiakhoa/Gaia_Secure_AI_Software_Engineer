from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from .approval import ApprovalDecision, ApprovalRecord


def create_approval_record(
    *,
    job_id: UUID,
    patch_sha256: str,
    actor: str,
    decision: ApprovalDecision,
    note: str | None = None,
) -> ApprovalRecord:
    return ApprovalRecord(
        job_id=job_id,
        patch_sha256=patch_sha256.strip().lower(),
        actor=actor.strip(),
        decision=decision,
        note=note,
    )


def write_approval_record(record: ApprovalRecord, path: Path) -> Path:
    if path.exists():
        raise RuntimeError(f"approval record already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(record.model_dump(mode="json"), indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    return path
