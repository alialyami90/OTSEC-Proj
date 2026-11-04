"""V-M4's feed, on the real binaries with the stepped test clock (C6;
D4-40 item 4).

The node is built with otsec_testclock and run with -test-clock. The
harness steps the clock to each Syslog event of the GT-INJ series
(tests/integration/gt_inj/events.json, asset gt-inj-syslog) and sends
that event from the GT-INJ asset's address to the node's syslog-udp
listener. This is the half of V-M4 that can run on main now: the node has
no detector yet (D4-40 item 2, C4), so no alarm is checked here. The alarm
half is added when the detector lands.

The oracle is the node's store, read by C6's own SQLite connection. Every
event of the series must be stored once, in schedule order, bound to the
GT-INJ asset, with its sent bytes, and with received.utc equal to its
received_utc, so the series reaches the event baseline on the schedule's
own clock. A step the node had not read when its datagram came would show
as an earlier received time.

Evidence class: simulated. The series is synthetic (GT-INJ), and the
sender is a test socket on loopback.
"""

import datetime
import glob
import hashlib
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
from slicerun import SERVICE, Slice

EVENTS = os.path.join(harness.REPO, "tests", "integration", "gt_inj", "events.json")
STREAM = "syslog/a6-udp"
T0 = datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc)


def _utc(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def _stamp(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _parse(s):
    # Go's RFC 3339 with up to nine fractional digits; Python keeps six.
    s = s.strip().replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        i = rest.index("+")
        s = f"{head}.{rest[:i][:6]}{rest[i:]}"
    return datetime.datetime.fromisoformat(s)


class Clock:
    """The node's test clock file, stepped by write then rename. On Windows
    the rename is refused while the node is reading the file, so it is
    retried (UseTestClock). The node writes the time it has moved to in
    path.seen, which reached() reads."""

    def __init__(self, path, at):
        self.path, self.at = path, at
        self.set(at)

    def set(self, at):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            f.write(_stamp(at) + "\n")
        end = time.monotonic() + 1.0
        while True:
            try:
                os.replace(tmp, self.path)
                break
            except PermissionError:
                if time.monotonic() > end:
                    raise
                time.sleep(0.001)
        self.at = at

    def reached(self):
        """Whether the node's clock is at the last step."""
        try:
            with open(self.path + ".seen") as f:
                return _parse(f.read()) == self.at
        except (OSError, ValueError):
            return False  # not written yet, or read mid-write


def _datagram(e):
    # RFC 5424, its time the scheduled one (the oracle is the received time).
    pri = e["facility"] * 8 + e["severity"]
    return f"<{pri}>1 {e['received_utc']} gtinj app - {e['msgid']} - {e['msg']}".encode()


def _query(store_dir, sql):
    """sql's rows for STREAM, from whichever database holds it."""
    for path in glob.glob(os.path.join(store_dir, "*.db")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = db.execute(sql, (STREAM,)).fetchall()
        except sqlite3.OperationalError:
            rows = []
        finally:
            db.close()
        if rows and rows[0][0]:
            return rows
    return []


def _stored(store_dir):
    """The events of STREAM, in seq order."""
    return [json.loads(ev) for (ev,) in _query(store_dir, "SELECT event FROM events WHERE stream = ? ORDER BY seq")]


def _count(store_dir):
    rows = _query(store_dir, "SELECT COUNT(*) FROM events WHERE stream = ?")
    return rows[0][0] if rows else 0


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "loopback senders other than 127.0.0.1 are a Linux runner's")
    with open(EVENTS) as f:
        series = json.load(f)
    events = [e for e in series["events"] if e["asset"] == "gt-inj-syslog"]
    assert events and _utc(events[0]["received_utc"]) > T0
    d = str(tmp_path_factory.mktemp("slice-gtinj"))
    clock = Clock(os.path.join(d, "clock"), T0)
    s = Slice(d)
    s.node_tags = ("otsec_testclock",)
    s.node_args = ("-test-clock", clock.path)
    s.build()
    udp = harness.free_port()
    # The node's tickers (the admin relay, health) wait on the test clock,
    # so it moves a second each 20 ms until the listener is up, all well
    # before the series' first event.
    starting = threading.Event()
    starting.set()

    def tick():
        while starting.is_set():
            clock.set(clock.at + datetime.timedelta(seconds=1))
            time.sleep(0.02)

    stepper = threading.Thread(target=tick, daemon=True)
    stepper.start()
    out = {"events": events}
    try:
        s.start(setup_extra=("-syslog-udp", str(udp), "-gtinj-events", EVENTS))
        assert harness.wait_for(lambda: "listener a6-udp" in s.health(), 60, step=0.5), s.health() + s.text("node")
        starting.clear()
        stepper.join()
        layout = s.layout
        out["layout"] = layout
        assert _utc(events[0]["received_utc"]) > clock.at, "the start ran past the first event"
        host, port = layout["syslog_udp"].rsplit(":", 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((layout["gtinj_sender"], 0))
        try:
            # The node's clock is at each step before its datagram is sent
            # (C5 on #405), and each datagram is stored before the next
            # step, so none can be stamped with another event's time.
            for i, e in enumerate(events, 1):
                clock.set(_utc(e["received_utc"]))
                if not harness.wait_for(clock.reached, 10, step=0.002):
                    raise AssertionError(f"the node's clock did not reach {e['received_utc']} ({e['id']})")
                sock.sendto(_datagram(e), (host, int(port)))
                if not harness.wait_for(lambda: _count(layout["store_dir"]) >= i, 10, step=0.002):
                    break
        finally:
            sock.close()
        out["arrived"] = _count(layout["store_dir"]) >= len(events)
        time.sleep(1)
    finally:
        starting.clear()
        s.stop()
    out["stored"] = _stored(s.layout["store_dir"])
    return out


def _gtinj(run):
    return [ev for ev in run["stored"] if (ev.get("source", {}).get("asset") or {}).get("id") == run["layout"]["gtinj_asset"]]


def test_every_event_is_stored_once(run):
    assert run["arrived"], f"{len(run['stored'])} of {len(run['events'])} stored"
    got = _gtinj(run)
    assert len(got) == len(run["events"]) == len(run["stored"])


def test_received_time_is_the_schedule(run):
    got = _gtinj(run)
    bad = [(e["id"], e["received_utc"], ev["received"]["utc"]) for e, ev in zip(run["events"], got)
           if _utc(ev["received"]["utc"]) != _utc(e["received_utc"])]
    assert not bad, f"{len(bad)} events with another received time, the first: {bad[:3]}"


def test_bytes_are_the_sent_ones_in_order(run):
    got = _gtinj(run)
    for e, ev in zip(run["events"], got):
        sent = _datagram(e)
        assert ev["native"]["record_sha256"] == hashlib.sha256(sent).hexdigest(), (e["id"], ev["native"])
        assert ev["native"]["record_length"] == len(sent)


def test_type_key_fields_are_the_series(run):
    # The detector's type key is built from pri and msg (C4 on #402), so a
    # parse change shows here, not as wrong alarms in the alarm half.
    got = _gtinj(run)
    for e, ev in zip(run["events"], got):
        fields = {f["name"]: f["value"] for f in ev["native"].get("fields", [])}
        assert fields.get("pri") == str(e["facility"] * 8 + e["severity"]), (e["id"], fields)
        assert fields.get("msg") == e["msg"], (e["id"], fields)
