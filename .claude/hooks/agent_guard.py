"""Claude Code hook: only the agents in .claude/agents run, one instance of each role.

The owner's rule (CLAUDE.md, "Subagents"; D4-89). The two helper agents are the
exception: any number of instances of each may run, and they take no lock.
.claude/settings.json wires this script to five events, and each sends its JSON
on stdin:

  PreToolUse on Agent      refuse an agent type that has no file in
                           .claude/agents, and a role that is already running;
                           otherwise take the role's lock
  SubagentStart            write the agent's id into its lock
  SubagentStop             release the lock that agent holds
  PostToolUse on TaskStop  release the lock of the agent that was stopped:
                           SubagentStop does not fire for it
  SessionStart             on resume, clear the session's locks: no agent
                           outlives the process that ran it

A lock is the file <temp>/otsec-agent-locks/<session id>/<agent name>. It is
empty from the launch until the agent starts, and holds the agent's id after.

Not covered: an agent the user stops from the interface fires neither
SubagentStop nor TaskStop, so its lock stays until the session is resumed or
the file is deleted. The refusal names the file. D4-89 lists the other limits.
"""

import json
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

AGENTS = Path(__file__).resolve().parent.parent / "agents"

# The helper agents. Any number of instances of each may run.
MANY_INSTANCES = {"ci-triage", "records-auditor"}

# A lock with no agent id this old is a launch that never started, for example
# one the user declined at the permission prompt.
PENDING_SECONDS = 60


def agent_names():
    names = set()
    for path in AGENTS.glob("*.md"):
        front = re.match(r"---\n(.*?)\n---", path.read_text(encoding="utf-8-sig"), re.S)
        match = front and re.search(r"^name:\s*(\S+)\s*$", front.group(1), re.M)
        if match:
            names.add(match.group(1))
    return names


def session_dir(event):
    session = re.sub(r"[^A-Za-z0-9_-]", "_", event["session_id"])
    return Path(tempfile.gettempdir()) / "otsec-agent-locks" / session


def deny(reason):
    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )


def before_launch(event):
    name = event["tool_input"].get("subagent_type") or ""
    names = agent_names()
    if name not in names:
        deny(
            f"'{name or 'no subagent_type'}' is not an agent defined in .claude/agents. "
            f"Only these run in this project (the owner's rule, D4-89): {', '.join(sorted(names))}."
        )
        return
    if name in MANY_INSTANCES:
        return
    lock = session_dir(event) / name
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        return
    except FileExistsError:
        pass
    if lock.read_text() or time.time() - lock.stat().st_mtime < PENDING_SECONDS:
        deny(
            f"An instance of {name} is already running in this session, and only one "
            "instance of each role runs at a time (the owner's rule, D4-89). Wait for it "
            "to finish, or send it the work with SendMessage. If the user stopped it from "
            f"the interface, its lock is stale: check with ListAgents that no {name} is "
            f"running, then delete {lock}."
        )
        return
    lock.touch()


def agent_started(event):
    name = event.get("agent_type") or ""
    if name not in agent_names() - MANY_INSTANCES:
        return
    lock = session_dir(event) / name
    lock.parent.mkdir(parents=True, exist_ok=True)
    if not (lock.exists() and lock.read_text()):
        lock.write_text(event["agent_id"])


def agent_stopped(event):
    name = event.get("agent_type") or ""
    if name not in agent_names() - MANY_INSTANCES:
        return
    lock = session_dir(event) / name
    if lock.exists() and lock.read_text() == event["agent_id"]:
        lock.unlink()


def task_stopped(event):
    stopped = event["tool_input"].get("task_id") or event["tool_input"].get("shell_id")
    for lock in session_dir(event).glob("*"):
        if stopped and lock.read_text() == stopped:
            lock.unlink()


def session_resumed(event):
    shutil.rmtree(session_dir(event), ignore_errors=True)


HANDLERS = {
    "PreToolUse": before_launch,
    "SubagentStart": agent_started,
    "SubagentStop": agent_stopped,
    "PostToolUse": task_stopped,
    "SessionStart": session_resumed,
}

if __name__ == "__main__":
    event = json.load(sys.stdin)
    HANDLERS[event["hook_event_name"]](event)
