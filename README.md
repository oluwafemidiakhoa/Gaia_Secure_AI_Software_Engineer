# Gaia Secure AI Software Engineer

A security-first autonomous coding agent that works inside isolated sandboxes, modifies a private working copy of a repository, runs verification, and returns a patch plus an execution receipt for human approval.

## Core principle

> Give an AI engineer your repository without giving it your computer.

## MVP contract

The first release will:

1. accept a Git repository and coding task;
2. create an isolated execution job;
3. allow the coding agent to inspect and modify only the sandbox copy;
4. run project-defined tests and checks;
5. collect filesystem, process, and network audit events;
6. produce a patch, verification summary, and execution receipt;
7. require human approval before any GitHub write action.

## Safety invariants

- Deny-by-default network access.
- No host filesystem access.
- No raw GitHub credentials inside the agent workspace.
- No direct push to `main` from an agent.
- No PR creation from the sandbox in the initial MVP.
- Explicit resource and wall-clock limits.
- Every run leaves an auditable receipt.

## Initial stack

- Python 3.12+
- Typer CLI
- Pydantic models
- NVIDIA OpenShell as the target sandbox runtime
- GitHub integration through the trusted control plane
- Pytest

## Planned CLI

```bash
sca run \
  --repo https://github.com/example/project \
  --task "Fix issue #42"
```

The current scaffold starts with a local dry-run control plane. OpenShell execution will be introduced behind a runtime adapter so security boundaries remain explicit and testable.

## Status

Early MVP scaffold.
