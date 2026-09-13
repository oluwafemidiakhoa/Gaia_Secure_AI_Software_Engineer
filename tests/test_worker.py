from pathlib import Path

from gaia_secure_agent.worker import CheckStatus, inspect_worker


def test_worker_report_fails_when_policy_missing(tmp_path: Path) -> None:
    report = inspect_worker(tmp_path / "missing-policy.yaml", agent="unsupported")

    assert report.ready is False
    assert any(
        check.name == "openshell_policy" and check.status is CheckStatus.FAIL
        for check in report.checks
    )
    assert any(
        check.name == "coding_agent" and check.status is CheckStatus.FAIL
        for check in report.checks
    )


def test_worker_report_includes_python_check(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("version: 1\n", encoding="utf-8")

    report = inspect_worker(policy, agent="unsupported")

    assert any(check.name == "python" for check in report.checks)
