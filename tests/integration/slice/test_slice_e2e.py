"""The Phase 2 slice end to end, on the real binaries (A6, P2-A6).

The recording simulator plays the SEL-751 (documented profile, Telnet on
loopback, D2-10). otsec-collector, otsec node and A6's RELP receiver run as
separate processes (D2-3). slicehelper writes the node configuration
through A5's nodeconfigtest (D2-6) and the collector's configuration with
the register on main, signed by a key made for the run, and stands in for
the administrator who installs the credential (sealed to the collector's
published install key, sent over the collector socket). The collector's
stores are created an hour in the past so that its fresh-state floor
(A3 #106) has passed, as on a collector commissioned earlier.

The node runs its schedule twice (the first run 60 s after start, the
next after the minimum interval), so the second SER read returns the
same rows and must forward none of them again (V-S4).

What is checked, against ground truth that is not the product's own:
  - every row of Figure 10.16 reaches the upstream collector exactly once,
    byte for byte, with its own time text and evidence class simulated
    (reconcile.py; V-S2, V-S3, V-S4 overlap);
  - every line the simulator received is a read-only register line, one
    session at a time, one password per session, QUI last (check.py;
    V-S7, V-S13);
  - the test password appears in no file, log, receiver record or process
    argument of the platform (V-S11).

Evidence class: simulated. The simulator answers from manual examples
(documented-example), not from a device; nothing here is hardware
evidence.
"""

import json
import os
import shutil
import subprocess
import sys
import time

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CANARY, CHECK, REGISTER, SERVICE, Slice

RUNS = 2
# The first run starts 60 s after the node, the second at least 60 s after
# the first ends (node.MinIntervalSeconds).
RUN_TIMEOUT = 75.0 * RUNS + 30.0


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" or SERVICE, "the Windows leg of the end-to-end run is the PC run (D1-26)")
    s = Slice(str(tmp_path_factory.mktemp("slice-e2e")))
    s.build()
    try:
        s.start()
        rows = len(reconcile.native_rows())
        done = harness.wait_for(lambda: s.sessions_closed() >= RUNS and len(s.ser_received()) >= rows,
                                RUN_TIMEOUT, step=1.0)
        # The second read's events would arrive within a few seconds of its
        # session; give them the time to show up if they were sent.
        time.sleep(10)
        assert done, (f"{s.sessions_closed()} sessions, {len(s.ser_received())} SER messages after "
                      f"{RUN_TIMEOUT:.0f}s\nnode:\n{s.text('node')}\ncollector:\n{s.text('collector')}")
        for name in ("node", "collector"):
            assert s.procs[name].poll() is None, f"{name} exited:\n{s.text(name)}"
        # As the OS has them while both run: /proc on Linux, Win32_Process
        # on Windows (processes or installed services).
        s.cmdlines = {name: s.cmdline(name) for name in ("node", "collector")}
        yield s
    finally:
        s.stop()


def test_every_row_arrives_once(run):
    problems, stats = reconcile.reconcile(run.received(), reconcile.native_rows())
    assert problems == [], problems
    assert stats["matched"] == stats["rows"] == 8, stats
    assert stats["duplicates"] == 0, stats


def test_the_second_read_forwards_nothing_new(run):
    # Two sessions read the same buffer; the second must add no SER message
    # (the rows are the same rows, R-A4-1).
    assert run.sessions_closed() >= RUNS
    assert len(run.ser_received()) == 8, len(run.ser_received())


def test_only_read_only_lines_reached_the_device(run):
    out = subprocess.run([sys.executable, CHECK, "--log", run.sim_log, "--register", REGISTER],
                         capture_output=True, text=True)
    report = json.loads(out.stdout)
    assert out.returncode == 0 and report["pass"], report
    assert report["violations"] == [], report
    assert report["peak_concurrent_sessions"] == 1, report
    assert report["failed_auth_per_session"] == {}, report
    sessions = {}
    for r in harness.read_log(run.sim_log):
        if r["event"] == "line":
            sessions.setdefault(r["session"], []).append(r["text"])
        if r["event"] == "auth":
            assert r["accepted"], r
    assert len(sessions) >= RUNS, sessions
    for sid, lines in sessions.items():
        assert lines[-1] == "QUI", (sid, lines)
        assert lines.count("ACC") == 1, (sid, lines)


def test_the_password_is_nowhere(run):
    canary = CANARY.encode()
    hits = []
    for name, path in run.logs.items():
        with open(path, "rb") as f:
            if canary in f.read():
                hits.append(f"{name} output")
    with open(run.relp_log, "rb") as f:
        if canary in f.read():
            hits.append("receiver log")
    for m in run.received():
        if canary in m:
            hits.append("a forwarded message")
    for dirpath, _, files in os.walk(run.root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            if not os.path.isfile(p) or os.path.islink(p):
                continue  # the collector's socket, not a file
            try:
                with open(p, "rb") as f:
                    if canary in f.read():
                        hits.append(os.path.relpath(p, run.root))
            except PermissionError:
                # A file the run locked read-only for its owner is still
                # readable; anything else unreadable is a gap in the check.
                hits.append("unreadable: " + os.path.relpath(p, run.root))
    for name, exe in (("node", "otsec"), ("collector", "otsec-collector")):
        cmd = run.cmdlines.get(name) or ""
        # A command line that was not read would pass vacuously: it must
        # name its own binary.
        assert os.path.basename(run.exe(exe)).lower() in cmd.lower(), f"{name} command line not read: {cmd!r}"
        if CANARY in cmd:
            hits.append(f"{name} arguments")
    # The simulator's log records the in-band password as an auth event,
    # never its bytes (sim.py); it is the device's side, checked here too.
    with open(run.sim_log, "rb") as f:
        if canary in f.read():
            hits.append("simulator log")
    assert hits == [], hits
