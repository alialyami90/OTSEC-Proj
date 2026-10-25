"""The evidence store filled end to end on the real binaries (A6, P2-A6;
V-S9, A5 #135).

The adapter-evidence quota leaves room for a quarantine plus FILL bytes,
the receiver is down, and the simulator's SER buffer grows by GROW rows at
every read (ser="grow", SYNTHESIZED), so the class fills in a few runs
with events nothing has confirmed. Then:

  1. collection-quarantine-room-low comes before
     collection-no-quarantine-room (the warning before runs stop);
  2. runs stop: no session opens while the class has no room;
  3. the node is SIGKILLed while full and started again, still full and
     with the receiver still down;
  4. the receiver comes back. With no operator action, every event is
     confirmed, confirmed events are pruned, and runs resume;
  5. every row the buffer ever held reaches the receiver under exactly one
     event ID (reconcile_grown): nothing unforwarded was evicted.

Evidence class: simulated. Disk exhaustion of the file system itself (E-03,
F-013, F-014) is not this test: the quota is the limit here.
"""

import json
import os
import re
import shutil
import subprocess
import time

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CHECK, REGISTER, Slice

import sys
sys.path.insert(0, os.path.join(harness.REPO, "tests", "safety", "recording_simulator"))
import profile_sel751  # noqa: E402

QUARANTINE_ROOM = (8 << 20) + (16 << 10) + (16 << 10)
FILL = 400 << 10
GROW = 100
ALARM_AT = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+.+?\s{2,}(\S+)\s{2,}", re.M)
LAST_RUN = re.compile(r"^(?:FAILING )?asset \S+: last run (\S+)", re.M)
STREAM = re.compile(r"^\s+(\S+): confirmed (\d+) of (\d+), cursor (\d+)$", re.M)


def _alarms(health):
    """{code: first time seen in the table}."""
    out = {}
    for m in ALARM_AT.finditer(health):
        out.setdefault(m[2], m[1])
    return out


def _all_confirmed(health):
    streams = [(int(m[2]), int(m[3])) for m in STREAM.finditer(health)]
    return streams and all(c == n for c, n in streams)


def _added(s):
    with open(s.grow_state, encoding="utf-8") as f:
        return int(f.read())


def _rows(added):
    return [l for l in profile_sel751.grown_ser(added).split(b"\r\n") if profile_sel751.SER_ROW.match(l)]


def _check(logs):
    """check.py over each recording that exists: only read-only register
    lines, nothing before a prompt, nothing non-printable (V-S7 (b))."""
    checked = 0
    for log in logs:
        if not os.path.exists(log):
            continue
        out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                             capture_output=True, text=True)
        report = json.loads(out.stdout)
        assert out.returncode == 0 and report["pass"], (log, report)
        assert report["violations"] == [], (log, report)
        checked += 1
    return checked


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "the Windows leg of the end-to-end run is the PC run (D1-26)")
    d = str(tmp_path_factory.mktemp("slice-store-full"))
    s = Slice(d)
    s.build()
    s.grow_state = os.path.join(d, "grow")
    diag = lambda: f"health:\n{s.health()}\nnode:\n{s.text('node')[-3000:]}"
    try:
        s.start(sim_extra=("--profile-ser", "grow", "--profile-ser-state", s.grow_state, "--profile-ser-grow", str(GROW)),
                setup_extra=("-quota", f"adapter-evidence={QUARANTINE_ROOM + FILL}"))
        s.kill("receiver")
        # 1, 2: fill until runs stop.
        stopped = lambda: "collection-no-quarantine-room" in _alarms(s.health())
        assert harness.wait_for(stopped, 400.0, step=1.0), diag()
        s.full_health = s.health()
        s.sessions_when_full = s.sessions_closed()
        s.added_when_full = _added(s)
        time.sleep(70)  # one more scheduled run, which must not be sent
        s.sessions_after_full = s.sessions_closed()
        # 3: kill the node while full, and start it again.
        s.kill("node")
        s.respawn("node")
        assert harness.wait_for(lambda: "collecting: true" in s.health() or "database evidence" in s.health(), 30.0), diag()
        time.sleep(70)
        s.restart_health = s.health()
        s.sessions_after_restart = s.sessions_closed()
        # 4: the receiver comes back; nothing else is done.
        s.start_receiver()
        t = time.time()
        resumed = lambda: s.sessions_closed() > s.sessions_after_restart
        assert harness.wait_for(resumed, 240.0, step=1.0), "runs did not resume\n" + diag()
        s.resumed_after = time.time() - t

        def settled():
            added = _added(s)
            _, stats = reconcile.reconcile_grown(s.received(), _rows(added))
            health = s.health()
            if stats["matched"] >= 8 + added and _all_confirmed(health) and _added(s) == added:
                s.added, s.final_health = added, health
                return True
            return False
        assert harness.wait_for(settled, 180.0, step=1.0), diag()
        yield s
    finally:
        s.stop()


def test_the_warning_comes_before_runs_stop(run):
    a = _alarms(run.full_health)
    assert "collection-quarantine-room-low" in a, run.full_health
    assert a["collection-quarantine-room-low"] <= a["collection-no-quarantine-room"], a


def test_no_run_is_sent_while_full(run):
    assert run.sessions_after_full == run.sessions_when_full, (run.sessions_when_full, run.sessions_after_full)
    assert run.sessions_after_restart == run.sessions_when_full, (run.sessions_when_full, run.sessions_after_restart)


def test_runs_resume_without_operator_action(run):
    print(f"runs resumed {run.resumed_after:.0f}s after the receiver came back")
    m = LAST_RUN.search(run.final_health)
    assert m and m[1] == "ok", run.final_health


def test_nothing_unforwarded_was_evicted(run):
    problems, stats = reconcile.reconcile_grown(run.received(), _rows(run.added))
    print(stats)
    assert problems == [], problems
    assert stats["matched"] == 8 + run.added, stats
    # The rows read before the store filled are among them.
    assert run.added >= run.added_when_full


def test_only_read_only_lines_reached_the_device(run):
    # Across the fill, the kill and restart while full, and the resumed runs.
    assert _check(run.sim_logs) >= 1, run.sim_logs
