"""The failed-auth floor holds while Level 1 may be open, end to end on the
real binaries (A6, P2-A6; D2-16, D2-20, A3 #131).

The simulator models a relay that keeps Level 1 for a new connection
until TIDLE when a session ends without QUI (--profile-inherit level; the
manual does not say, p. 7.16, H-15 (b)). Replies come 0.7 s late, so the
session can be caught after "=>" and before QUI.

The collector is SIGKILLed once the simulator has received SHO P 1 (the
first line after "=>"), then started again. Before D2-20 nothing was left
in its state, and the next run opened a session onto the open level 61 s
later. Checked:
  - the state the killed collector left holds the open level and a floor;
  - the next runs are refused rate_limited, and health shows it;
  - no second session reaches the device;
  - every line the simulator received is a read-only register line; the
    recording check's only finding is the session the kill left at Level 1.

Evidence class: simulated.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

import harness
from conftest import need
from slicerun import CHECK, REGISTER, Slice

FIRST_RUN = 100.0


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "the Windows leg of the end-to-end run is the PC run (D1-26)")
    s = Slice(str(tmp_path_factory.mktemp("slice-floor")))
    s.build()
    try:
        s.start(sim_extra=("--profile-inherit", "level", "--response-delay", "0.7"))
        lines = lambda: [r.get("text") for r in s.sim_records() if r["event"] == "line"]
        assert harness.wait_for(lambda: "SHO P 1" in lines(), FIRST_RUN, step=0.05), lines()
        s.kill("collector")
        s.lines_at_kill = lines()
        s.state_after_kill = s.collector_asset()
        s.respawn("collector")
        # Two scheduled runs after the kill, each refused before any
        # connection.
        refused = lambda: s.health().count("collector refused the run: rate_limited") >= 2
        assert harness.wait_for(refused, 150.0, step=1.0), s.health()
        s.final_health = s.health()
        s.final_state = s.collector_asset()
        yield s
    finally:
        s.stop()


def test_the_kill_landed_between_login_and_qui(run):
    assert "ACC" in run.lines_at_kill and run.lines_at_kill[-1] == "SHO P 1", run.lines_at_kill


def test_the_killed_collector_left_the_floor(run):
    assert run.state_after_kill.get("level_open") is True, run.state_after_kill
    assert run.state_after_kill.get("unconfirmed_auth_utc"), run.state_after_kill
    assert run.final_state.get("level_open") is True, run.final_state


def test_no_session_landed_on_the_open_level(run):
    opened = [r for r in run.sim_records() if r["event"] == "session_open"]
    assert len(opened) == 1, opened


def test_only_read_only_lines_reached_the_device(run):
    out = subprocess.run([sys.executable, CHECK, "--log", run.sim_log, "--register", REGISTER],
                         capture_output=True, text=True)
    report = json.loads(out.stdout)
    # The one finding is the fault this test injects: the killed collector
    # left session 1 at Level 1 without QUI. Any other violation fails.
    v = report["violations"]
    assert len(v) == 1 and v[0]["verdict"] == "device-effect" and v[0]["session"] == 1, v
    assert v[0]["text"].startswith("session closed at Access Level 1"), v
