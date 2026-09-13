import hashlib
import json
from pathlib import Path
from uuid import UUID

from gaia_secure_agent.evidence import build_evidence_receipt, sha256_file, write_evidence_receipt


JOB_ID = UUID("12345678-1234-5678-1234-567812345678")


def test_sha256_file_matches_exact_bytes(tmp_path: Path) -> None:
    path = tmp_path / "artifact.bin"
    payload = b"evidence-bytes"
    path.write_bytes(payload)

    assert sha256_file(path) == hashlib.sha256(payload).hexdigest()


def test_evidence_receipt_binds_all_run_digests(tmp_path: Path) -> None:
    run_manifest = tmp_path / "run.json"
    run_manifest.write_text('{"status":"complete"}\n', encoding="utf-8")

    receipt = build_evidence_receipt(
        job_id=JOB_ID,
        source_commit="a" * 40,
        source_sha256="b" * 64,
        agent_output_sha256="c" * 64,
        patch_sha256="d" * 64,
        run_manifest_path=run_manifest,
    )

    expected_payload = {
        "job_id": str(JOB_ID),
        "source_commit": "a" * 40,
        "source_sha256": "b" * 64,
        "agent_output_sha256": "c" * 64,
        "patch_sha256": "d" * 64,
        "run_manifest_sha256": hashlib.sha256(run_manifest.read_bytes()).hexdigest(),
    }
    expected = hashlib.sha256(
        json.dumps(expected_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    assert receipt.evidence_sha256 == expected
    assert receipt.run_manifest_sha256 == expected_payload["run_manifest_sha256"]


def test_evidence_digest_changes_when_run_manifest_changes(tmp_path: Path) -> None:
    run_manifest = tmp_path / "run.json"
    run_manifest.write_text("first\n", encoding="utf-8")
    first = build_evidence_receipt(
        job_id=JOB_ID,
        source_commit="a" * 40,
        source_sha256="b" * 64,
        agent_output_sha256="c" * 64,
        patch_sha256="d" * 64,
        run_manifest_path=run_manifest,
    )

    run_manifest.write_text("second\n", encoding="utf-8")
    second = build_evidence_receipt(
        job_id=JOB_ID,
        source_commit="a" * 40,
        source_sha256="b" * 64,
        agent_output_sha256="c" * 64,
        patch_sha256="d" * 64,
        run_manifest_path=run_manifest,
    )

    assert first.evidence_sha256 != second.evidence_sha256


def test_evidence_receipt_is_write_once(tmp_path: Path) -> None:
    run_manifest = tmp_path / "run.json"
    run_manifest.write_text("run\n", encoding="utf-8")
    receipt = build_evidence_receipt(
        job_id=JOB_ID,
        source_commit="a" * 40,
        source_sha256="b" * 64,
        agent_output_sha256="c" * 64,
        patch_sha256="d" * 64,
        run_manifest_path=run_manifest,
    )
    destination = tmp_path / "evidence.json"

    write_evidence_receipt(receipt, destination)

    try:
        write_evidence_receipt(receipt, destination)
    except RuntimeError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("evidence receipt overwrite should be rejected")
