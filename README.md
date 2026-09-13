# Gaia Secure AI Software Engineer

A security-first autonomous coding agent that works inside isolated sandboxes, modifies a private working copy of a repository, runs verification, and returns a patch plus an execution receipt for human approval.

## Core principle

> Give an AI engineer your repository without giving it your computer.

## MVP contract

The first release will:

1. accept a GitHub repository and coding task;
2. validate repository, branch, timeout, and agent limits before execution;
3. render a deterministic security-constrained execution plan;
4. create an isolated execution job;
5. allow the coding agent to inspect and modify only the sandbox copy;
6. run approved verification checks;
7. collect filesystem, process, and network audit evidence;
8. produce a patch, verification summary, and execution receipt;
9. require human approval before any GitHub write action.

## Safety invariants

- Deny-by-default network access.
- No host filesystem access for repository code.
- No raw GitHub credentials inside the agent workspace.
- No direct push to `main` from an agent.
- No PR creation from the sandbox in the initial MVP.
- HTTPS-only GitHub repository input with credential-bearing URLs rejected.
- Unsafe Git ref patterns rejected before a worker starts.
- Explicit resource, turn, and wall-clock limits.
- Every run leaves an auditable receipt.
- Sandbox cleanup is part of every execution plan.

## Initial stack

- Python 3.12+
- Typer CLI
- Pydantic models
- NVIDIA OpenShell as the target sandbox runtime
- GitHub integration through the trusted control plane
- Pytest + Ruff in CI

## Current CLI

Install locally:

```bash
python -m pip install -e ".[dev]"
```

Render the execution plan without starting a worker:

```bash
sca plan \
  --repo https://github.com/example/project \
  --task "Fix issue #42"
```

Run the current safe dry-run control plane:

```bash
sca run \
  --repo https://github.com/example/project \
  --task "Fix issue #42" \
  --runtime dry-run
```

## Execution lifecycle

```text
validate
  ↓
resolve immutable base commit
  ↓
create isolated sandbox
  ↓
prepare sandbox-local repository
  ↓
run coding agent
  ↓
run approved verification
  ↓
collect patch + evidence
  ↓
human review
  ↓
trusted control-plane publication
  ↓
cleanup sandbox
```

The coding agent does not receive GitHub write authority. Publication remains a separate control-plane action and requires explicit human approval.

## OpenShell status

The OpenShell adapter currently probes the worker and fails closed if the runtime or policy is unavailable. Full autonomous repository execution remains intentionally disabled until a compatible Linux worker image, provider configuration, and fixed verification profiles are provisioned and independently tested.

## Repository structure

```text
.github/workflows/ci.yml
policies/openshell-mvp.yaml
src/gaia_secure_agent/
  cli.py
  models.py
  orchestrator.py
  planner.py
  runtime.py
  security.py
tests/
  test_models.py
  test_orchestrator.py
  test_security.py
```

## Current milestone

**Milestone 1: trusted control plane**

- [x] package + CLI scaffold
- [x] repository and branch validation
- [x] deterministic execution planning
- [x] fail-closed OpenShell adapter
- [x] execution receipt model
- [x] GitHub Actions CI
- [ ] provision OpenShell Linux worker image
- [ ] fixed verification profiles
- [ ] sandboxed repository execution
- [ ] patch retrieval + integrity hash
- [ ] human-approved PR publication
