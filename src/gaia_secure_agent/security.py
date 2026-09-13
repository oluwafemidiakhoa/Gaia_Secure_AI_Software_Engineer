from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(frozen=True)
class SecurityPolicy:
    """Control-plane policy used before work is delegated to a sandbox runtime."""

    allowed_repository_hosts: frozenset[str] = field(
        default_factory=lambda: frozenset({"github.com", "www.github.com"})
    )
    protected_branches: frozenset[str] = field(
        default_factory=lambda: frozenset({"main", "master", "production", "prod"})
    )
    allow_agent_push: bool = False
    allow_agent_pr_creation: bool = False

    def validate_repository(self, repository: str) -> None:
        host = urlparse(repository).hostname
        if host not in self.allowed_repository_hosts:
            raise PermissionError(f"repository host is not allowed: {host}")

    def assert_agent_git_write_denied(self) -> None:
        if self.allow_agent_push or self.allow_agent_pr_creation:
            raise PermissionError("MVP invariant violated: agent GitHub writes must stay disabled")
