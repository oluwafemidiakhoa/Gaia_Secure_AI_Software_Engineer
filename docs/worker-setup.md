# Secure Worker Setup

This guide provisions a Linux host to run the Gaia Secure AI Software Engineer worker boundary.

## Target host

Use Ubuntu 24.04 LTS or another currently supported Linux distribution for OpenShell. Keep the control plane and worker role separate in production.

## Required software

The worker expects:

- Python 3.12+
- Git
- NVIDIA OpenShell CLI and a reachable OpenShell gateway
- a configured OpenShell compute driver
- one supported coding agent (`claude` for the first MVP, or `codex` when enabled)

Follow NVIDIA's current OpenShell installation documentation rather than pinning an installer copied into this repository. OpenShell evolves quickly, so this project intentionally does not curl-pipe an unverified remote installer.

## Install this project

Clone the repository on the worker and install the package in an isolated virtual environment:

```bash
git clone https://github.com/oluwafemidiakhoa/Gaia_Secure_AI_Software_Engineer.git
cd Gaia_Secure_AI_Software_Engineer
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

For development and host-side tests:

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

## Readiness check

Run the fail-closed readiness probe:

```bash
sca doctor --agent claude
```

A worker is considered ready only when all required checks pass. The command validates the Python version, Git, OpenShell CLI, OpenShell gateway reachability, policy file, and selected coding-agent binary.

## Security model

The worker must not receive a general-purpose GitHub write token. The MVP keeps GitHub publication in the trusted control plane and requires human approval bound to the exact patch SHA-256.

The agent runs inside a fresh OpenShell sandbox using `policies/openshell-mvp.yaml`. Network and filesystem access should remain deny-by-default, with only job-specific endpoints enabled.

## Current boundary

`sca doctor` and the control-plane workflow are implemented. The `OpenShellRuntime` remains fail-closed until the repository-transfer, model-provider, sandbox lifecycle, and evidence-export paths are fully implemented and tested.
