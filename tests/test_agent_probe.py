import pytest

from gaia_secure_agent.agent_probe import authorize_claude_execution, parse_claude_version


def test_claude_probe_parses_semantic_version() -> None:
    probe = parse_claude_version("2.1.220 (Claude Code)\n")

    assert probe.agent == "claude"
    assert probe.version == "2.1.220"
    assert probe.bare_mode_required is True
    assert probe.print_mode_required is True
    assert probe.max_turns_required is True
    assert probe.permission_mode_verified is False
    assert probe.executable_autonomy_allowed is False


def test_claude_probe_rejects_unknown_version_output() -> None:
    with pytest.raises(RuntimeError, match="unrecognized"):
        parse_claude_version("Claude Code unknown")


def test_claude_execution_stays_disabled_until_permission_mode_verified() -> None:
    probe = parse_claude_version("2.1.220")

    with pytest.raises(RuntimeError, match="permission mode"):
        authorize_claude_execution(probe, permission_mode_verified=False)

    assert probe.executable_autonomy_allowed is False


def test_claude_execution_can_be_explicitly_authorized_after_probe() -> None:
    probe = parse_claude_version("2.1.220")
    authorized = authorize_claude_execution(probe, permission_mode_verified=True)

    assert authorized.permission_mode_verified is True
    assert authorized.executable_autonomy_allowed is True
