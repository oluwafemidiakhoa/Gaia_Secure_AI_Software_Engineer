from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from uuid import UUID


_SANDBOX_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class SandboxHandle:
    name: str


class OpenShellSandboxManager:
    def __init__(
        self,
        *,
        policy_path: Path,
        cpu: str = "2",
        memory: str = "4Gi",
        command_timeout: int = 30,
    ) -> None:
        self.policy_path = policy_path
        self.cpu = cpu
        self.memory = memory
        self.command_timeout = command_timeout

    @staticmethod
    def name_for_job(job_id: UUID) -> str:
        return f"gaia-{job_id.hex[:20]}"

    @staticmethod
    def _validate_name(name: str) -> str:
        if not _SANDBOX_NAME.fullmatch(name):
            raise ValueError("sandbox name contains unsupported characters")
        return name

    @staticmethod
    def _validate_sandbox_path(path: str) -> str:
        if not path.startswith("/sandbox/"):
            raise ValueError("sandbox path must stay inside /sandbox")
        if "/../" in f"{path}/" or path.endswith("/.."):
            raise ValueError("sandbox path cannot traverse parent directories")
        return path

    def create(self, name: str) -> SandboxHandle:
        self._validate_name(name)
        if not self.policy_path.is_file():
            raise RuntimeError(f"OpenShell policy missing: {self.policy_path}")
        completed = subprocess.run(
            ["openshell", "sandbox", "create", "--name", name, "--detach", "--output", "json", "--policy", str(self.policy_path), "--cpu", self.cpu, "--memory", self.memory],
            capture_output=True,
            text=True,
            timeout=self.command_timeout,
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox creation failed: {detail}")
        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise RuntimeError("OpenShell returned invalid JSON for sandbox creation") from exc
        reported_name = payload.get("name")
        if reported_name and reported_name != name:
            raise RuntimeError("OpenShell returned an unexpected sandbox name")
        return SandboxHandle(name=name)

    def upload(self, handle: SandboxHandle, source: Path, destination: str) -> None:
        name = self._validate_name(handle.name)
        destination = self._validate_sandbox_path(destination)
        if not source.is_file():
            raise ValueError(f"upload source must be a regular file: {source}")
        completed = subprocess.run(["openshell", "sandbox", "upload", name, str(source), destination], capture_output=True, text=True, timeout=max(self.command_timeout, 120), check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox upload failed: {detail}")

    def sha256(self, handle: SandboxHandle, path: str) -> str:
        name = self._validate_name(handle.name)
        path = self._validate_sandbox_path(path)
        completed = subprocess.run(["openshell", "sandbox", "exec", "-n", name, "--no-login-shell", "--", "sha256sum", path], capture_output=True, text=True, timeout=self.command_timeout, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox checksum failed: {detail}")
        digest = (completed.stdout.strip().split() or [""])[0].lower()
        if not _SHA256.fullmatch(digest):
            raise RuntimeError("OpenShell sandbox checksum returned an invalid digest")
        return digest

    def prepare_repository(self, handle: SandboxHandle) -> None:
        name = self._validate_name(handle.name)
        create_directory = subprocess.run(["openshell", "sandbox", "exec", "-n", name, "--no-login-shell", "--", "mkdir", "/sandbox/repository"], capture_output=True, text=True, timeout=self.command_timeout, check=False)
        if create_directory.returncode != 0:
            detail = (create_directory.stderr or create_directory.stdout).strip()
            raise RuntimeError(f"OpenShell repository directory creation failed: {detail}")
        extraction = subprocess.run(["openshell", "sandbox", "exec", "-n", name, "--no-login-shell", "--", "tar", "--extract", "--gzip", "--file", "/sandbox/input/source.tar.gz", "--directory", "/sandbox/repository", "--strip-components=1", "--no-same-owner", "--no-same-permissions"], capture_output=True, text=True, timeout=max(self.command_timeout, 120), check=False)
        if extraction.returncode != 0:
            detail = (extraction.stderr or extraction.stdout).strip()
            raise RuntimeError(f"OpenShell repository extraction failed: {detail}")

    def initialize_git_baseline(self, handle: SandboxHandle) -> str:
        name = self._validate_name(handle.name)
        prefix = [
            "openshell", "sandbox", "exec", "-n", name,
            "--workdir", "/sandbox/repository",
            "--env", "GIT_CONFIG_GLOBAL=/dev/null",
            "--env", "GIT_CONFIG_SYSTEM=/dev/null",
            "--no-login-shell", "--",
        ]
        commands = [
            ["git", "init", "--initial-branch=baseline", "."],
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.autocrlf=false", "add", "-A", "--", "."],
            [
                "git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.name=Gaia Secure Agent",
                "-c", "user.email=gaia-secure-agent@localhost",
                "commit", "--no-gpg-sign", "--no-verify", "-m", "secure baseline",
            ],
        ]
        for command in commands:
            completed = subprocess.run(
                prefix + command,
                capture_output=True,
                text=True,
                timeout=max(self.command_timeout, 120),
                check=False,
            )
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout).strip()
                raise RuntimeError(f"Local Git baseline initialization failed: {detail}")

        rev = subprocess.run(
            prefix + ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=self.command_timeout,
            check=False,
        )
        if rev.returncode != 0:
            detail = (rev.stderr or rev.stdout).strip()
            raise RuntimeError(f"Local Git baseline commit lookup failed: {detail}")
        commit_sha = rev.stdout.strip().lower()
        if not _COMMIT_SHA.fullmatch(commit_sha):
            raise RuntimeError("Local Git baseline returned an invalid commit SHA")
        return commit_sha

    def claude_version(self, handle: SandboxHandle) -> str:
        name = self._validate_name(handle.name)
        completed = subprocess.run(["openshell", "sandbox", "exec", "-n", name, "--workdir", "/sandbox/repository", "--no-login-shell", "--", "claude", "--version"], capture_output=True, text=True, timeout=self.command_timeout, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"Claude Code version probe failed: {detail}")
        output = (completed.stdout or completed.stderr).strip()
        if not output:
            raise RuntimeError("Claude Code version probe returned no output")
        return output

    def claude_headless_canary(self, handle: SandboxHandle) -> bool:
        name = self._validate_name(handle.name)
        completed = subprocess.run(
            [
                "openshell", "sandbox", "exec", "-n", name,
                "--workdir", "/sandbox/repository",
                "--timeout", "60",
                "--no-tty",
                "--no-login-shell",
                "--",
                "claude", "--bare", "-p", "--max-turns", "1",
                "--permission-mode", "dontAsk",
                "Reply with exactly PROBE_OK. Do not use tools.",
            ],
            capture_output=True,
            text=True,
            timeout=max(self.command_timeout, 75),
            check=False,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"Claude Code headless canary failed: {detail}")
        return completed.stdout.strip() == "PROBE_OK"

    def delete(self, handle: SandboxHandle) -> None:
        name = self._validate_name(handle.name)
        completed = subprocess.run(["openshell", "sandbox", "delete", name], capture_output=True, text=True, timeout=self.command_timeout, check=False)
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise RuntimeError(f"OpenShell sandbox cleanup failed: {detail}")
