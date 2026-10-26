"""Randomized interruptions of the slice, end to end on the real binaries
(A6, P2-A6; V-S6, with V-S4's buffer that changes between reads).

The simulator serves a SER buffer that grows by four rows at every read
and renumbers every row so row 1 is the newest (ser="grow", SYNTHESIZED,
see profile_sel751). While the node collects every 60 s, a seeded
scheduler interrupts, every 5 to 40 s, one of:

  - the upstream link: the RELP receiver is SIGKILLed and started again on
    the same port 0.5 to 15 s later;
  - the node: SIGKILLed and started again 0.5 to 10 s later, a run in
    flight included (the collector finishes the session, and the outcome
    is lost: the rows are read again later).

Half the receiver and node kills are timed: the moment the receiver has
acknowledged the first message of the burst a run produces, so the rest
of the burst is in flight, unconfirmed. The other half land wherever the
delay puts them. Also:
  - the device link: the simulator is SIGKILLed while no session is open
    and started again on the same address 1 to 90 s later, so runs in
    between fail to connect;
  - the collector: SIGKILLed while no session is open and at least 20 s
    before its minimum interval allows the next, and started again 0.5 to
    5 s later.

The simulator and the collector are not killed mid-session, nor the
collector while its state still holds the floor. A session cut between
the password and QUI sets the TIDLE + 1 min floor by design (D2-16,
D2-20), which is too long to wait for here; test_slice_floor_e2e checks
that floor after a kill inside the level.

Then the interruptions stop, two clean runs pass, and the node's health
must show every stream confirmed. What is checked, against ground truth
that is not the product's own (GT-REC: the simulator's buffer and
recordings; GT-RX: what the receiver fsynced before acknowledging):

  - every row the buffer ever held arrives, under exactly one event ID,
    with its own bytes (reconcile_grown): zero events lost between the
    device and the upstream collector, and no row stored twice (V-S4);
  - an event ID that arrives more than once carries the same bytes;
  - for every stream, the event IDs received include 1 to the node's
    confirmed cursor, with no gap: every acknowledged event is in GT-RX;
  - the unconfirmed window: the events received again after each break
    (receiver or node killed) are at most the RELP window (relp_window,
    128, C6), and nothing is received twice without a break;
  - every line any simulator received is a read-only register line, one
    session at a time, QUI last (check.py, V-S7);
  - the password is in no log or message.

OTSEC_SLICE_INTERRUPTIONS sets the count (default 6, about 7 minutes; the
V-S6 soak is 100 or more). OTSEC_SLICE_SEED repeats a schedule's choices
and delays; when the interruptions land relative to runs still varies.

Evidence class: simulated.
"""

import base64
import calendar
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CANARY, CHECK, REGISTER, Slice

sys.path.insert(0, os.path.join(harness.REPO, "tests", "safety", "recording_simulator"))
import profile_sel751  # noqa: E402

COUNT = int(os.environ.get("OTSEC_SLICE_INTERRUPTIONS") or 6)
SEED = int(os.environ.get("OTSEC_SLICE_SEED") or time.time_ns() % 1_000_000)
RELP_WINDOW = 128  # nodeconfigtest's relp_window
GROW = 4
STREAM = re.compile(r"^\s+(\S+): confirmed (\d+) of (\d+), cursor (\d+)$", re.M)
SER_SEQ = re.compile(rb' eid="[^":]+:([^"]+):(\d+)"')


def _confirmed(health):
    """{stream: (confirmed, of, cursor)} from otsec health."""
    return {m[1]: (int(m[2]), int(m[3]), int(m[4])) for m in STREAM.finditer(health)}


def _all_confirmed(health):
    streams = _confirmed(health)
    return streams and all(c == n == k for c, n, k in streams.values())


def _added(s):
    with open(s.grow_state, encoding="utf-8") as f:
        return int(f.read())


def _rows(added):
    return [l for l in profile_sel751.grown_ser(added).split(b"\r\n") if profile_sel751.SER_ROW.match(l)]


def _relp_lines(s):
    if not os.path.exists(s.relp_log):
        return 0
    with open(s.relp_log, "rb") as f:
        return sum(1 for _ in f)


def _syslog_by_line(s):
    """[(line number, message bytes)] for every syslog frame the receiver
    acknowledged, in order."""
    out = []
    with open(s.relp_log, encoding="utf-8") as f:
        for i, line in enumerate(f):
            if not line.strip():
                continue
            r = json.loads(line)
            if r.get("event") == "syslog":
                out.append((i, base64.b64decode(r["b64"])))
    return out


def _eid(msg):
    m = SER_SEQ.search(msg)
    return (m[1].decode(), int(m[2])) if m else None


class Interrupter:
    """The seeded scheduler. Each interruption is logged with its time."""

    def __init__(self, s, rng):
        self.s, self.rng = s, rng
        self.log = []
        self.breaks = []  # receiver log line count when a receiver or node was killed

    def _session_open(self):
        recs = harness.read_log(self.s.sim_log) if os.path.exists(self.s.sim_log) else []
        return sum(r["event"] == "session_open" for r in recs) > sum(r["event"] == "session_close" for r in recs)

    def _last_run_at(self):
        """When the collector accepted its last run, to the second, as Unix
        time; None before the first."""
        last = self.s.collector_asset().get("last_run_utc")
        if not last:
            return None
        return calendar.timegm(time.strptime(last[:19], "%Y-%m-%dT%H:%M:%S"))

    def _idle(self, collector=False):
        """No session open now. For the collector also: the last run it
        accepted started under 40 s ago, so the collector's 60 s minimum
        interval keeps the next one at least 20 s away; and that run's
        session has opened and closed, so a run accepted but not yet
        connected is not taken for idle (A5 on #147, seed 564077: a kill
        then left the failed-auth floor running past the wind-down); and
        then the collector's own state holds no floor. The collector clears
        level_open once the run has returned, about 10 ms after the
        simulator records QUI and the close; a kill in that window leaves
        the TIDLE + 1 min floor, the safe side (D2-16; seed 48628 on #183).
        test_slice_floor_e2e pins the floor after a kill inside the level."""
        if self._session_open():
            return False
        if not collector:
            return True
        at = self._last_run_at()
        if at is None or time.time() - at >= 40:
            return False
        recs = harness.read_log(self.s.sim_log) if os.path.exists(self.s.sim_log) else []
        if not any(r["event"] == "session_close" and r["t"] >= at for r in recs):
            return False
        st = self.s.collector_asset()
        return not st.get("level_open") and not st.get("unconfirmed_auth_utc")

    def one(self):
        kind = self.rng.choice(["receiver", "node", "simulator", "collector"])
        down = {"receiver": (0.5, 15), "node": (0.5, 10), "simulator": (1, 90), "collector": (0.5, 5)}
        wait = self.rng.uniform(*down[kind])
        # Half the receiver and node kills land mid-burst: after a session
        # closes, as soon as the receiver has acknowledged the first new
        # message, while the rest of the burst may be sent and unconfirmed.
        burst = kind in ("receiver", "node") and self.rng.random() < 0.5
        if burst:
            closed = self.s.sessions_closed()
            if not harness.wait_for(lambda: self.s.sessions_closed() > closed, 70.0, step=0.2):
                burst = False
            else:
                n = len(_syslog_by_line(self.s))
                if not harness.wait_for(lambda: len(_syslog_by_line(self.s)) > n, 10.0, step=0.01):
                    burst = False
        if kind in ("simulator", "collector"):
            if not harness.wait_for(lambda: self._idle(kind == "collector"), 70.0, step=0.2):
                self.log.append((time.time(), kind, "skipped: no idle window in 70 s"))
                return
        s = self.s
        if kind in ("receiver", "node"):
            self.breaks.append(_relp_lines(s))
        t = time.time()
        if kind == "receiver":
            s.kill("receiver")
            time.sleep(wait)
            s.start_receiver()
        elif kind == "simulator":
            s.kill("simulator")
            time.sleep(wait)
            s.start_simulator(s.sim_fid, s.sim_port)
        else:
            s.kill(kind)
            time.sleep(wait)
            s.respawn(kind)
        self.log.append((t, kind, f"{'mid-burst, ' if burst else ''}down {wait:.1f}s"))


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "the Windows leg of the end-to-end run is the PC run (D1-26)")
    d = str(tmp_path_factory.mktemp("slice-interruptions"))
    s = Slice(d)
    s.build()
    s.seed = SEED
    print(f"V-S6 seed {SEED}, {COUNT} interruptions (OTSEC_SLICE_SEED to repeat)", flush=True)
    s.grow_state = os.path.join(d, "grow")
    diag = lambda: f"seed {SEED}\nhealth:\n{s.health()}\nnode:\n{s.text('node')[-4000:]}\ncollector:\n{s.text('collector')[-4000:]}"
    try:
        s.start(sim_extra=("--profile-ser", "grow", "--profile-ser-state", s.grow_state,
                           "--profile-ser-grow", str(GROW)))
        rng = random.Random(SEED)
        it = Interrupter(s, rng)
        # The first run, so there is something in flight to interrupt.
        assert harness.wait_for(lambda: s.sessions_closed() >= 1, 100.0, step=1.0), diag()
        for _ in range(COUNT):
            time.sleep(rng.uniform(5, 40))
            it.one()
        s.interruptions = it.log
        s.breaks = it.breaks
        # Wind-down: two clean runs, then every stream confirmed.
        closed = s.sessions_closed()
        assert harness.wait_for(lambda: s.sessions_closed() >= closed + 2, 200.0, step=1.0), diag()
        # Settled: the last read's rows (the grown buffer as printed then)
        # have all arrived, every stream is confirmed, and no read started
        # meanwhile. The outcome of the last session reaches the node a
        # moment after the session closes, so confirmed alone is not enough.
        def settled():
            added = _added(s)
            _, stats = reconcile.reconcile_grown(s.received(), _rows(added))
            health = s.health()
            if stats["matched"] >= 8 + added and _all_confirmed(health) and _added(s) == added:
                s.added, s.final_health = added, health
                return True
            return False
        assert harness.wait_for(settled, 90.0, step=1.0), diag()
        yield s
    finally:
        s.stop()


def test_interruptions_happened(run):
    kinds = [k for _, k, what in run.interruptions if not what.startswith("skipped")]
    print(f"seed {run.seed}: " + ", ".join(f"{k} {w}" for _, k, w in run.interruptions))
    assert len(kinds) >= max(1, COUNT // 2), run.interruptions


def test_every_row_arrives_under_one_event_id(run):
    problems, stats = reconcile.reconcile_grown(run.received(), _rows(run.added))
    print(f"seed {run.seed}: {stats}")
    assert problems == [], problems
    assert stats["matched"] == stats["rows"] == 8 + run.added, stats


def test_every_confirmed_event_is_in_gt_rx(run):
    streams = _confirmed(run.final_health)
    got = {}
    for _, msg in _syslog_by_line(run):
        e = _eid(msg)
        assert e is not None, msg[:200]
        got.setdefault(e[0], set()).add(e[1])
    for name, (_, _, cursor) in streams.items():
        have = got.get(name, set())
        # Health events may still arrive after the snapshot: at least the
        # confirmed ones, and no gap.
        assert set(range(1, cursor + 1)) <= have, (name, cursor, sorted(set(range(1, cursor + 1)) - have)[:5])
        assert have == set(range(1, max(have) + 1)), (name, sorted(set(range(1, max(have) + 1)) - have)[:5])


def test_the_unconfirmed_window(run):
    """After each break, count the events received again: the window the
    forwarder had sent and not yet seen confirmed. Nothing is received twice
    except right after a break."""
    msgs = _syslog_by_line(run)
    marks = sorted(set(run.breaks))
    seen = set()
    resent = {m: 0 for m in marks}
    unexplained = []
    for line, msg in msgs:
        e = _eid(msg)
        if e in seen:
            before = [m for m in marks if m <= line]
            if before:
                resent[before[-1]] += 1
            else:
                unexplained.append(e)
        seen.add(e)
    print(f"seed {run.seed}: resent after each break {list(resent.values())}, RELP window {RELP_WINDOW}")
    assert unexplained == [], unexplained
    assert all(n <= RELP_WINDOW for n in resent.values()), resent


def test_only_read_only_lines_reached_any_device(run):
    for log in run.sim_logs:
        out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                             capture_output=True, text=True)
        report = json.loads(out.stdout)
        assert out.returncode == 0 and report["pass"], (log, report)


def test_the_password_is_nowhere(run):
    """Every process output, receiver record, simulator recording (which
    holds the password as an auth event, never its bytes) and store file."""
    canary = CANARY.encode()
    hits = []
    for dirpath, dirs, files in os.walk(run.d):
        dirs[:] = [x for x in dirs if os.path.join(dirpath, x) != run.bin]
        for fn in files:
            p = os.path.join(dirpath, fn)
            if not os.path.isfile(p) or os.path.islink(p):
                continue  # the collector's socket
            try:
                with open(p, "rb") as f:
                    if canary in f.read():
                        hits.append(os.path.relpath(p, run.d))
            except PermissionError:
                hits.append("unreadable: " + os.path.relpath(p, run.d))
    assert hits == [], hits
    assert not any(canary in m for m in run.received())
