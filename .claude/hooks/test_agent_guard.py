"""Tests for agent_guard.py. pytest skips dot-folders, so run this file by name,
with a Python that has pytest (on the owner's PC, tools\\venv\\Scripts\\python.exe):

    python -m pytest -q .claude/hooks/test_agent_guard.py
"""

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

GUARD = Path(__file__).with_name("agent_guard.py")


@pytest.fixture
def run(tmp_path):
    """Send one hook event to the guard, with its locks under tmp_path."""
    env = dict(os.environ, TMPDIR=str(tmp_path), TEMP=str(tmp_path), TMP=str(tmp_path))

    def send(event, **fields):
        payload = {"session_id": "s1", "hook_event_name": event, **fields}
        done = subprocess.run(
            [sys.executable, str(GUARD)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=env,
        )
        assert done.returncode == 0, done.stderr
        return done.stdout

    send.locks = tmp_path / "otsec-agent-locks" / "s1"
    return send


def launch(run, agent, **fields):
    """True when the guard lets an Agent call through."""
    tool_input = {"prompt": "p", "description": "d"}
    if agent is not None:
        tool_input["subagent_type"] = agent
    out = run("PreToolUse", tool_name="Agent", tool_input=tool_input, **fields)
    if not out:
        return True
    assert json.loads(out)["hookSpecificOutput"]["permissionDecision"] == "deny"
    return False


@pytest.mark.parametrize("agent", ["general-purpose", "Explore", "fork", "d9-new-role", None])
def test_an_agent_with_no_file_is_refused(run, agent):
    assert not launch(run, agent)


LOCKED_ROLES = [
    "d1-principal-architect",
    "d2-ied-integration",
    "d3-security-access",
    "d4-telemetry-ids",
    "d5-platform",
    "d7-release-supply-chain",
    "d8-ui-ux",
]


@pytest.mark.parametrize("role", LOCKED_ROLES)
def test_one_instance_of_each_role_and_any_number_of_roles(run, role):
    assert launch(run, role)
    assert not launch(run, role)  # launched, not yet started
    run("SubagentStart", agent_type=role, agent_id="a1")
    assert not launch(run, role)  # running
    age(run.locks / role, 61)
    assert not launch(run, role)  # still running, however old the lock
    assert launch(run, "d6-verification-safety")
    assert launch(run, next(other for other in LOCKED_ROLES if other != role))
    run("SubagentStop", agent_type=role, agent_id="a1")
    assert launch(run, role)


def test_a_d6_lock_from_before_the_exception_refuses_nothing(run):
    run.locks.mkdir(parents=True)
    (run.locks / "d6-verification-safety").write_text("old-agent")
    assert launch(run, "d6-verification-safety")
    assert launch(run, "d6-verification-safety")


@pytest.mark.parametrize("helper", ["ci-triage", "records-auditor", "d6-verification-safety"])
def test_a_helper_or_d6_runs_any_number_of_instances(run, helper):
    for agent_id in ("a1", "a2", "a3"):
        assert launch(run, helper)
        run("SubagentStart", agent_type=helper, agent_id=agent_id)
    assert not run.locks.exists() or not list(run.locks.iterdir())
    run("SubagentStop", agent_type=helper, agent_id="a2")
    assert launch(run, helper)


def test_the_agent_runs_again_after_it_stops(run):
    assert launch(run, "d2-ied-integration")
    run("SubagentStart", agent_type="d2-ied-integration", agent_id="a1")
    run("SubagentStop", agent_type="d2-ied-integration", agent_id="a1")
    assert launch(run, "d2-ied-integration")


def test_another_agents_stop_does_not_release_the_lock(run):
    assert launch(run, "d4-telemetry-ids")
    run("SubagentStart", agent_type="d4-telemetry-ids", agent_id="a1")
    run("SubagentStop", agent_type="d4-telemetry-ids", agent_id="other")
    run("SubagentStop", agent_type="", agent_id="a1")
    assert not launch(run, "d4-telemetry-ids")


def test_stopping_the_agent_with_taskstop_releases_its_lock(run):
    assert launch(run, "d3-security-access")
    run("SubagentStart", agent_type="d3-security-access", agent_id="a1")
    assert launch(run, "d5-platform")
    run("SubagentStart", agent_type="d5-platform", agent_id="a2")
    run("PostToolUse", tool_name="TaskStop", tool_input={"task_id": "a1"})
    assert launch(run, "d3-security-access")
    assert not launch(run, "d5-platform")
    run("PostToolUse", tool_name="TaskStop", tool_input={"shell_id": "a2"})
    assert launch(run, "d5-platform")


def age(lock, seconds):
    old = time.time() - seconds
    os.utime(lock, (old, old))


def test_a_running_role_stays_refused_however_old_its_lock(run):
    assert launch(run, "d2-ied-integration")
    run("SubagentStart", agent_type="d2-ied-integration", agent_id="a1")
    age(run.locks / "d2-ied-integration", 3600)
    assert not launch(run, "d2-ied-integration")


def test_a_second_start_does_not_take_a_held_lock(run):
    assert launch(run, "d4-telemetry-ids")
    run("SubagentStart", agent_type="d4-telemetry-ids", agent_id="a1")
    run("SubagentStart", agent_type="d4-telemetry-ids", agent_id="a2")
    run("SubagentStop", agent_type="d4-telemetry-ids", agent_id="a2")
    assert not launch(run, "d4-telemetry-ids")
    run("SubagentStop", agent_type="d4-telemetry-ids", agent_id="a1")
    assert launch(run, "d4-telemetry-ids")


def test_only_the_frontmatter_names_an_agent(tmp_path):
    hooks = tmp_path / "project" / ".claude" / "hooks"
    agents = tmp_path / "project" / ".claude" / "agents"
    hooks.mkdir(parents=True)
    agents.mkdir()
    shutil.copy(GUARD, hooks)
    (agents / "one.md").write_text("---\nname: real-role\n---\n\nname: general-purpose\n")
    (agents / "two.md").write_text("no frontmatter\nname: Explore\n")
    (agents / "three.md").write_bytes(b"\xef\xbb\xbf---\r\nname: role-with-a-bom\r\n---\r\n")
    env = dict(os.environ, TMPDIR=str(tmp_path), TEMP=str(tmp_path), TMP=str(tmp_path))

    def allowed(agent):
        event = {"session_id": "s1", "hook_event_name": "PreToolUse", "tool_input": {"subagent_type": agent}}
        done = subprocess.run(
            [sys.executable, str(hooks / GUARD.name)],
            input=json.dumps(event),
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        return not done.stdout

    assert allowed("real-role")
    assert allowed("role-with-a-bom")
    assert not allowed("general-purpose")
    assert not allowed("Explore")


def test_a_resumed_agent_holds_the_lock_again(run):
    run("SubagentStart", agent_type="d5-platform", agent_id="a1")
    assert not launch(run, "d5-platform")


def test_a_launch_that_never_started_frees_the_lock_after_a_minute(run):
    assert launch(run, "d7-release-supply-chain")
    lock = run.locks / "d7-release-supply-chain"
    age(lock, 30)
    assert not launch(run, "d7-release-supply-chain")
    age(lock, 61)
    assert launch(run, "d7-release-supply-chain")
    assert not launch(run, "d7-release-supply-chain")


def test_another_session_has_its_own_locks(run):
    assert launch(run, "d8-ui-ux")
    assert launch(run, "d8-ui-ux", session_id="s2")


def test_resuming_the_session_clears_its_locks(run):
    assert launch(run, "d1-principal-architect")
    run("SubagentStart", agent_type="d1-principal-architect", agent_id="a1")
    run("SessionStart", source="resume")
    assert launch(run, "d1-principal-architect")
