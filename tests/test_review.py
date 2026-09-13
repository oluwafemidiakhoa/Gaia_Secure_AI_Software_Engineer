import json
from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.approval import ApprovalDecision
from gaia_secure_agent.review import create_approval_record, write_approval_record


def test_review_record_binds_job_and_exact_patch(tmp_path: Path) -> None:
    job_id = UUID("12345678-1234-5678-1234-567812345678")
    record = create_approval_record(
        job_id=job_id,
        patch_sha256="a" * 64,
        actor="Oluwafemi",
        decision=ApprovalDecision.APPROVE,
        note="Reviewed tests and patch.",
    )

    path = write_approval_record(record, tmp_path / "approval.json")
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["job_id"] == str(job_id)
    assert payload["patch_sha256"] == "a" * 64
    assert payload["decision"] == "approve"
    assert payload["actor"] == "Oluwafemi"


def test_review_record_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "approval.json"
    path.write_text("existing", encoding="utf-8")
    record = create_approval_record(
        job_id=UUID("12345678-1234-5678-1234-567812345678"),
        patch_sha256="b" * 64,
        actor="reviewer",
        decision=ApprovalDecision.REJECT,
    )

    with pytest.raises(RuntimeError, match="already exists"):
        write_approval_record(record, path)
