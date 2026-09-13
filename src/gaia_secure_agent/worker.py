from __future__ import annotations

import shutil
import subprocess
import sys
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"


class WorkerCheck(BaseModel):
    name: str
    status: CheckStatus
    detail: str


class WorkerReport(BaseModel):
    ready: bool
    checks: list[WorkerCheck] = Field(default_factory=list)


def _binary_check(name: str, *, required: bool = True) -> WorkerCheck:
    path = shutil.which(name)
    if path:
        return WorkerCheck(name=name, status=CheckStatus.PASS, detail=path)
    status = CheckStatus.FAIL if required else CheckStatus.WARN
    return WorkerCheck(name=name, status=status, detail=f"{name} is not installed or not on PATH")


def _fixed_command_check(name: str, argv: list[str], *, timeout: int = 20) -> WorkerCheck:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return WorkerCheck(name=name, status=CheckStatus.FAIL, detail=f"{type(exc).__name__}: {exc}")

    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode == 0:
        return WorkerCheck(
            name=name,
            status=CheckStatus.PASS,
            detail=output[-1000:] or "command completed successfully",
        )
    return WorkerCheck(
        name=name,
        status=CheckStatus.FAIL,
        detail=output[-1000:] or f"command exited with {completed.returncode}",
    )


def inspect_worker(
    policy_path: Path = Path("policies/openshell-mvp.yaml"),
    *,
    agent: str = "claude",
) -> WorkerReport:
    checks: list[WorkerCheck] = []

    python_ok = sys.version_info >= (3, 12)
    checks.append(
        WorkerCheck(
            name="python",
            status=CheckStatus.PASS if python_ok else CheckStatus.FAIL,
            detail=f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )
    )

    checks.append(_binary_check("git"))
    openshell_binary = _binary_check("openshell")
    checks.append(openshell_binary)

    if policy_path.is_file():
        checks.append(
            WorkerCheck(
                name="openshell_policy",
                status=CheckStatus.PASS,
                detail=str(policy_path),
            )
        )
    else:
        checks.append(
            WorkerCheck(
                name="openshell_policy",
                status=CheckStatus.FAIL,
                detail=f"policy file not found: {policy_path}",
            )
        )

    if openshell_binary.status is CheckStatus.PASS:
        checks.append(_fixed_command_check("openshell_gateway", ["openshell", "status"]))

    if agent == "claude":
        checks.append(_binary_check("claude"))
    elif agent == "codex":
        checks.append(_binary_check("codex"))
    else:
        checks.append(
            WorkerCheck(
                name="coding_agent",
                status=CheckStatus.FAIL,
                detail=f"unsupported worker agent: {agent}",
            )
        )

    driver_candidates = [name for name in ("docker", "podman", "kubectl") if shutil.which(name)]
    checks.append(
        WorkerCheck(
            name="compute_driver_hint",
            status=CheckStatus.PASS if driver_candidates else CheckStatus.WARN,
            detail=(
                f"detected: {', '.join(driver_candidates)}"
                if driver_candidates
                else "no Docker, Podman, or kubectl client detected; OpenShell may still use another configured driver"
            ),
        )
    )

    ready = not any(check.status is CheckStatus.FAIL for check in checks)
    return WorkerReport(ready=ready, checks=checks)
