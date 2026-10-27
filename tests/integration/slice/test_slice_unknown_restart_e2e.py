"""A node restart does not refill the unknown senders' budget, on the real
binaries (A6, independent check of #198; D3-3, receive.Config.UnknownSpent).

One slice with a syslog-udp listener. The SEL-751's address (127.0.0.2)
first sends 10050 short messages, so the stream holds more than one store
read (store.MaxRead, 10000) before any unknown sender's record. Then a
host no asset claims (127.0.0.3) sends to it:
  1. until about two fifths of the listener's hourly budget is stored;
  2. the node is killed (SIGKILL, no shutdown path) and started again;
  3. it floods while the node is killed a second time and started again,
     and after that until the budget refuses it.

The oracle is the node's own store, read here with sqlite: the bytes of
the listener stream's events flagged asset-unresolved, by their received
time. receive's rule is that unknown senders store at most UnknownBytes in
any trailing UnknownWindow (1 h) plus its refill, across any number of
restarts. Every record this test stores falls inside one hour, so their
sum must stay within UnknownBytes plus the refill over the run. Without
the restart count, each start hands out a fresh UnknownBytes, so the sum
reaches about twice it. The count the node says it started with
(unknown.spent_at_start_bytes) must equal the stream's own count.

Evidence class: simulated (Linux, loopback senders).
"""

import datetime
import glob
import json
import os
import shutil
import socket
import sqlite3
import threading
import time

import pytest

import harness
from conftest import need
from slicerun import Slice

# A platform exemption, so OTSEC_SLICE_REQUIRED=1 does not fail it on
# Windows (as for the admin relay leg, svcdry6 on #179). It has not been run
# on Windows: it binds 127.0.0.2 and 127.0.0.3 and kills the node
# mid-flood, and neither has been tried there. The restart count itself
# (#198's unknownSpent tests) runs in CI's Windows Go job.
pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="Linux-only leg, not yet run on Windows; it runs in CI's Linux integration-long job")

DEVICE, STRANGER = "127.0.0.2", "127.0.0.3"
AHEAD = 10050   # known records ahead of the unknown ones: past one store read
STREAM = "syslog/a6-udp"
WINDOW = 3600.0
MSG = 900       # bytes of message text per datagram
RATE = 60       # datagrams a second, under the per-sender rate (100)


def _status(s):
    with open(os.path.join(s.layout["store_dir"], "status.json"), encoding="utf-8") as f:
        return json.load(f)


def _listener(s):
    return (_status(s).get("listeners") or {}).get("a6-udp") or {}


def _unknown_records(s):
    """(received time, stored length) of every asset-unresolved event on the
    listener stream, from whichever database holds it."""
    out = []
    for path in glob.glob(os.path.join(s.layout["store_dir"], "*.db")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            try:
                rows = db.execute("SELECT event FROM events WHERE stream = ?", (STREAM,)).fetchall()
            except sqlite3.OperationalError:
                continue
        finally:
            db.close()
        for (ev,) in rows:
            raw = ev if isinstance(ev, bytes) else ev.encode("utf-8")
            e = json.loads(raw)
            if "asset-unresolved" not in e.get("flags", []):
                continue
            at = datetime.datetime.fromisoformat(e["received"]["utc"].replace("Z", "+00:00"))
            out.append((at, len(raw)))
    return out


def _rows(s):
    n = 0
    for path in glob.glob(os.path.join(s.layout["store_dir"], "*.db")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            n += db.execute("SELECT COUNT(*) FROM events WHERE stream = ?", (STREAM,)).fetchone()[0]
        except sqlite3.OperationalError:
            pass
        finally:
            db.close()
    return n


def _device(s, n):
    """n short datagrams from the asset's address, under its rate."""
    host, port = s.layout["syslog_udp"].rsplit(":", 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DEVICE, 0))
    try:
        for i in range(n):
            sock.sendto(f"<13>a6 known {i:05d}".encode(), (host, int(port)))
            time.sleep(1 / 95)
    finally:
        sock.close()


def _stored(s):
    return sum(n for _, n in _unknown_records(s))


class Flood:
    """Datagrams from the stranger at RATE a second until stopped."""

    def __init__(self, s, tag):
        self.host, port = s.layout["syslog_udp"].rsplit(":", 1)
        self.port = int(port)
        self.tag = tag
        self.sent = 0
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((STRANGER, 0))
        try:
            while not self.stop.is_set():
                m = f"<13>a6 {self.tag} {self.sent:06d} ".encode() + b"u" * MSG
                try:
                    sock.sendto(m, (self.host, self.port))
                except OSError:
                    pass  # the node is down: nothing listens
                self.sent += 1
                time.sleep(1 / RATE)
        finally:
            sock.close()

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.t.join(5)


def _written(s):
    try:
        return datetime.datetime.fromisoformat(_status(s)["written"].replace("Z", "+00:00"))
    except (OSError, ValueError, KeyError):
        return None


def _restart(s):
    """SIGKILL the node, start it again, and wait for a status the new
    process wrote with the listener in it. Returns what the stream held
    while the node was down: what the new start must count."""
    s.kill("node")
    killed = datetime.datetime.now(datetime.timezone.utc)
    held = _stored(s)
    s.respawn("node")
    ok = harness.wait_for(lambda: (_written(s) or killed) > killed and _listener(s).get("open")
                          and "spent_at_start_bytes" in (_listener(s).get("unknown") or {}), 60, step=0.5)
    assert ok, _listener(s)
    return held


@pytest.fixture(scope="module")
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    s = Slice(str(tmp_path_factory.mktemp("slice-unknown-restart")))
    s.build()
    udp = harness.free_port()
    out = {}
    try:
        s.start(setup_extra=("-syslog-udp", str(udp)))
        assert harness.wait_for(lambda: (_listener(s).get("unknown") or {}).get("hourly_bytes"), 60, step=0.5), _status(s)
        hourly = _listener(s)["unknown"]["hourly_bytes"]
        out["hourly"] = hourly

        # 0. More known records than one store read, all stored.
        _device(s, AHEAD)
        out["ahead"] = harness.wait_for(lambda: _rows(s) >= AHEAD, 60, step=1.0) and _rows(s)
        assert out["ahead"], (_rows(s), _listener(s))
        t0 = time.time()

        # 1. About two fifths of the budget.
        with Flood(s, "one"):
            harness.wait_for(lambda: _stored(s) >= hourly * 2 // 5, 120, step=0.5)
        time.sleep(2)  # the last datagrams commit
        out["first"] = _stored(s)

        # 2. Killed and started again: the start counts what is stored.
        out["stored_at_start"] = _restart(s)
        out["spent_at_start"] = _listener(s)["unknown"]["spent_at_start_bytes"]

        # 3. Killed again in the middle of a flood, then flooded until
        # the budget refuses it.
        with Flood(s, "two") as f:
            time.sleep(1.5)
            out["stored_at_second_start"] = _restart(s)
            out["spent_at_second_start"] = _listener(s)["unknown"]["spent_at_start_bytes"]
            harness.wait_for(lambda: (_listener(s).get("dropped") or {}).get("unknown-budget", 0) > 50, 120, step=0.5)
            time.sleep(3)
            out["sent"] = f.sent
        time.sleep(3)
        out["elapsed"] = time.time() - t0
        out["listener"] = _listener(s)
        out["records"] = _unknown_records(s)
    finally:
        s.stop()
    print(json.dumps({k: v for k, v in out.items() if k != "records"}, indent=1, default=str))
    return out


def test_a_start_counts_what_unknown_senders_stored(got):
    assert got["ahead"] >= AHEAD, got
    assert got["first"] >= got["hourly"] * 2 // 5, got
    assert got["spent_at_start"] == got["stored_at_start"], got
    # Killed during a flood: what was stored before the kill is counted;
    # what was read but not stored is not, and was not stored either.
    assert got["spent_at_second_start"] == got["stored_at_second_start"], got


def test_restarts_do_not_refill_the_budget(got):
    recs = got["records"]
    span = (max(t for t, _ in recs) - min(t for t, _ in recs)).total_seconds()
    assert span < WINDOW, span
    total = sum(n for _, n in recs)
    bound = got["hourly"] * (1 + got["elapsed"] / WINDOW)
    assert total <= bound, f"unknown senders stored {total} bytes in {span:.0f} s across two restarts; the bound is {bound:.0f}"
    # Not vacuous: the budget was used up, not refused from the start.
    assert total >= 0.9 * got["hourly"], (total, got["hourly"])
    assert got["listener"]["dropped"].get("unknown-budget", 0) > 0, got["listener"]
