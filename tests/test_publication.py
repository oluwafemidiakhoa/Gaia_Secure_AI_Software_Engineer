import hashlib
import json
from pathlib import Path
from uuid import UUID

import pytest

from gaia_secure_agent.approval import ApprovalDecision, ApprovalRecord
from gaia_secure_agent.evidence import build_evidence_receipt, write_evidence_receipt
from gaia_secure_agent.patch import PatchArtifact
from gaia_secure_agent.publication import verify_publication
from gaia_secure_agent.repository import ResolvedRepository
from gaia_secure_agent.source_bundle import SourceBundle


JOB_ID = UUID("12345678-1234-5678-1234-567812345678")


def _write(path: Path, model) -> Path:
    path.write_text(
        json.dumps(model.model_dump(mode="json"), indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    return path


def _fixtures(tmp_path: Path):
    source_path = tmp_path / "source.tar.gz"
    source_bytes = b"trusted-source-archive"
    source_path.write_bytes(source_bytes)
    source_sha = hashlib.sha256(source_bytes).hexdigest()

    patch_path = tmp_path / "changes.patch"
    patch_bytes = b"diff --git a/a.txt b/a.txt\n"
    patch_path.write_bytes(patch_bytes)
    patch_sha = hashlib.sha256(patch_bytes).hexdigest()

    repository = ResolvedRepository(
        owner="example",
        name="project",
        branch="main",
        commit_sha="a" * 40,
        source_url="https://github.com/example/project",
        manifest_sha256="b" * 64,
    )
    bundle = SourceBundle(
        commit_sha="a" * 40,
        archive_path=source_path,
        archive_sha256=source_sha,
        size_bytes=len(source_bytes),
    )
    patch = PatchArtifact(
        job_id=JOB_ID,
        sandbox_name="gaia-test",
        local_path=patch_path,
        source_sha256=source_sha,
        baseline_commit="d" * 40,
        sha256=patch_sha,
        size_bytes=len(patch_bytes),
        has_changes=True,
    )
    approval = ApprovalRecord(
        job_id=JOB_ID,
        patch_sha256=patch_sha,
        decision=ApprovalDecision.APPROVE,
        actor="reviewer",
    )

    run_manifest = tmp_path / "run.json"
    run_manifest.write_text('{"job":"complete"}\n', encoding="utf-8")
    evidence = build_evidence_receipt(
        job_id=JOB_ID,
        source_commit=repository.commit_sha,
        source_sha256=source_sha,
        agent_output_sha256="f" * 64,
        patch_sha256=patch_sha,
        run_manifest_path=run_manifest,
    )
    evidence_manifest = tmp_path / "evidence.json"
    write_evidence_receipt(evidence, evidence_manifest)

    return (
        _write(tmp_path / "repository.json", repository),
        _write(tmp_path / "bundle.json", bundle),
        _write(tmp_path / "patch.json", patch),
        _write(tmp_path / "approval.json", approval),
        evidence_manifest,
        run_manifest,
        patch_path,
        source_path,
    )


def _verify(repository, bundle, patch, approval, evidence, run_manifest):
    return verify_publication(
        repository_manifest=repository,
        bundle_manifest=bundle,
        patch_manifest=patch,
        approval_manifest=approval,
        evidence_manifest=evidence,
        run_manifest=run_manifest,
    )


def test_publication_requires_all_matching_evidence(tmp_path: Path) -> None:
    repository, bundle, patch, approval, evidence, run_manifest, _, _ = _fixtures(tmp_path)

    plan = _verify(repository, bundle, patch, approval, evidence, run_manifest)

    assert plan.job_id == JOB_ID
    assert plan.base_commit == "a" * 40
    assert plan.human_approval_verified is True
    assert plan.evidence_verified is True
    assert plan.agent_github_write_allowed is False
    assert plan.approved_by == "reviewer"
    assert len(plan.evidence_sha256) == 64


def test_publication_refuses_patch_changed_after_approval(tmp_path: Path) -> None:
    repository, bundle, patch, approval, evidence, run_manifest, patch_path, _ = _fixtures(tmp_path)
    patch_path.write_bytes(b"tampered")

    with pytest.raises(PermissionError, match="size changed|digest changed"):
        _verify(repository, bundle, patch, approval, evidence, run_manifest)


def test_publication_refuses_source_changed_after_acquisition(tmp_path: Path) -> None:
    repository, bundle, patch, approval, evidence, run_manifest, _, source_path = _fixtures(tmp_path)
    source_path.write_bytes(b"tampered-source")

    with pytest.raises(PermissionError, match="size changed|digest changed"):
        _verify(repository, bundle, patch, approval, evidence, run_manifest)


def test_publication_refuses_wrong_source_bundle(tmp_path: Path) -> None:
    repository, bundle_path, patch, approval, evidence, run_manifest, _, _ = _fixtures(tmp_path)
    payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    payload["commit_sha"] = "e" * 40
    bundle_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PermissionError, match="commit"):
        _verify(repository, bundle_path, patch, approval, evidence, run_manifest)


def test_publication_refuses_rejected_patch(tmp_path: Path) -> None:
    repository, bundle, patch, approval_path, evidence, run_manifest, _, _ = _fixtures(tmp_path)
    payload = json.loads(approval_path.read_text(encoding="utf-8"))
    payload["decision"] = "reject"
    approval_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PermissionError, match="not been approved"):
        _verify(repository, bundle, patch, approval_path, evidence, run_manifest)


def test_publication_refuses_tampered_run_manifest(tmp_path: Path) -> None:
    repository, bundle, patch, approval, evidence, run_manifest, _, _ = _fixtures(tmp_path)
    run_manifest.write_text('{"job":"tampered"}\n', encoding="utf-8")

    with pytest.raises(PermissionError, match="run manifest digest"):
        _verify(repository, bundle, patch, approval, evidence, run_manifest)


def test_publication_refuses_mismatched_evidence_patch(tmp_path: Path) -> None:
    repository, bundle, patch, approval, evidence, run_manifest, _, _ = _fixtures(tmp_path)
    payload = json.loads(evidence.read_text(encoding="utf-8"))
    payload["patch_sha256"] = "e" * 64
    evidence.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PermissionError, match="evidence fingerprint|patch digest"):
        _verify(repository, bundle, patch, approval, evidence, run_manifest)
