"""The asset's identity check, its suspension and the clear, end to end on
the real binaries (A6, P2-A6; AP-27, D2-15; A2 #122, A3 #117, A5 #120).

Three runs against the same device address, the simulator replaced
between them:

  1. The ID reply comes without its STX and ETX frame. sel751 cannot read
     it, so it compares nothing: failed.identity_unreadable, ACC not sent,
     nothing suspended on either side (#122).
  2. The ID reply carries another FID: refused.identity_mismatch, ACC not
     sent, the asset suspended on both sides, the node's (from the outcome)
     and the collector's (its own state), under the same ref, the run's
     invocation.
  3. The device is put right and the administrator leaves
     clear-suspension.json naming the asset and that ref. The next run
     clears the node's suspension, sends the collector its
     asset.clear_suspension (#120), and collects all 8 rows, once.

What is checked, against ground truth that is not the product's own:
  - no password reaches a device whose identity was not read and matched
    (the simulator's own recording: no ACC line, no auth event);
  - nothing is collected, and no further session opened, while the asset
    is suspended and no clear is in place;
  - the node's ref and the collector's suspending invocation are the same
    value, so one administrator's file clears both;
  - after the clear, both sides hold nothing, every row arrives once
    (reconcile.py), and health shows neither SUSPENDED nor COLLECTOR STILL
    SUSPENDED;
  - every line any simulator received is a read-only register line
    (check.py; V-S7).

Evidence class: simulated.
"""

import json
import os
import re
import shutil
import subprocess
import sys

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CHECK, REGISTER, SERVICE, Slice

# A FID the asset's record does not allow: the build date differs.
OTHER_FID = harness.ALLOWED_FID[:-1] + ("1" if harness.ALLOWED_FID[-1] != "1" else "2")
# The first run is 60 s after the node starts and the next ones 60 s apart.
RUN_TIMEOUT = 100.0
CLEARED_TIMEOUT = 150.0
SUSPENDED = re.compile(r"^SUSPENDED (\S+): (\S+) since \S+; cleared only by an administrator naming ref (\S+)$", re.M)


def _sessions(log):
    return sum(1 for r in harness.read_log(log) if r["event"] == "session_close") if os.path.exists(log) else 0


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" or SERVICE, "the Windows leg of the end-to-end run is the PC run (D1-26)")
    s = Slice(str(tmp_path_factory.mktemp("slice-identity")))
    s.build()
    diag = lambda: f"health:\n{s.health()}\nnode:\n{s.text('node')}\ncollector:\n{s.text('collector')}"
    try:
        # 1. Unframed: a failure, nothing suspended.
        s.start(framed=False)
        asset = s.layout["asset_id"]
        assert harness.wait_for(lambda: _sessions(s.sim_log) >= 1, RUN_TIMEOUT, step=1.0), diag()
        # The node reports the run upstream just after the session closes.
        harness.wait_for(lambda: len(s.runs_reported()) >= 1, 15.0, step=0.5)
        s.unreadable_runs = s.runs_reported()
        s.unreadable_health = s.health()
        s.unreadable_collector = s.collector_asset()
        s.unreadable_log = s.sim_log

        # 2. Another FID: suspended on both sides.
        s.replace_simulator(OTHER_FID)
        got = harness.wait_for(lambda: SUSPENDED.search(s.health()) and s.collector_asset().get("suspended"),
                               RUN_TIMEOUT, step=1.0)
        assert got, "no suspension on both sides\n" + diag()
        s.suspended_health = s.health()
        s.suspended_collector = s.collector_asset()
        s.mismatch_log = s.sim_log

        # 3. Put right; a run while suspended with no file opens no session.
        s.replace_simulator(harness.ALLOWED_FID)
        harness.wait_for(lambda: _sessions(s.sim_log) > 0, 65.0, step=1.0)
        s.sessions_before_clear = _sessions(s.sim_log)
        s.ser_before_clear = len(s.ser_received())
        s.write_clear(asset, SUSPENDED.search(s.suspended_health).group(3))
        rows = len(reconcile.native_rows())
        done = harness.wait_for(lambda: len(s.ser_received()) >= rows, CLEARED_TIMEOUT, step=1.0)
        assert done, f"{len(s.ser_received())} SER messages {CLEARED_TIMEOUT:.0f}s after the clear\n" + diag()
        s.cleared_health = s.health()
        s.cleared_collector = s.collector_asset()
        yield s
    finally:
        s.stop()



def _lines(log):
    return [r["text"] for r in harness.read_log(log) if r["event"] == "line"]


def test_an_unreadable_id_reply_suspends_nothing(run):
    # The run is reported upstream as failed. Its C2 code is not in the
    # report (status only); A6 raised that with A5 (V-S12).
    assert [r.get("status") for r in run.unreadable_runs] == ["failed"], run.unreadable_runs
    assert not SUSPENDED.search(run.unreadable_health), run.unreadable_health
    assert not run.unreadable_collector.get("suspended"), run.unreadable_collector


def test_no_password_before_a_matching_id(run):
    for log in (run.unreadable_log, run.mismatch_log):
        assert _sessions(log) == 1, log
        assert "ACC" not in _lines(log), (log, _lines(log))
        assert not any(r["event"] == "auth" for r in harness.read_log(log)), log
        assert _lines(log)[-1] in ("ID", "QUI"), _lines(log)


def test_suspended_on_both_sides_under_one_ref(run):
    m = SUSPENDED.search(run.suspended_health)
    assert m and m.group(1) == run.layout["asset_id"], run.suspended_health
    assert m.group(2) == "identity-mismatch", run.suspended_health
    assert run.suspended_collector.get("suspended_by") == m.group(3), (run.suspended_collector, m.group(3))


def test_nothing_collected_while_suspended(run):
    assert run.sessions_before_clear == 0, run.sessions_before_clear
    assert run.ser_before_clear == 0, run.ser_before_clear


def test_the_clear_reaches_both_sides(run):
    assert not SUSPENDED.search(run.cleared_health), run.cleared_health
    assert "COLLECTOR STILL SUSPENDED" not in run.cleared_health, run.cleared_health
    assert not run.cleared_collector.get("suspended"), run.cleared_collector
    assert not run.cleared_collector.get("suspended_by"), run.cleared_collector


def test_every_row_arrives_once_after_the_clear(run):
    problems, stats = reconcile.reconcile(run.received(), reconcile.native_rows())
    assert problems == [], problems
    assert stats["matched"] == stats["rows"] == 8, stats
    assert stats["duplicates"] == 0, stats


def test_only_read_only_lines_reached_any_device(run):
    for log in run.sim_logs:
        out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                             capture_output=True, text=True)
        report = json.loads(out.stdout)
        assert out.returncode == 0 and report["pass"], (log, report)
        assert report["violations"] == [], (log, report)
