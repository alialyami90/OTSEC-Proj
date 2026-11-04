"""V-M4 on the real binaries with the stepped test clock, Syslog half (C6;
D4-40 item 4).

The node is built with otsec_testclock and run with -test-clock. The
harness steps the clock to each Syslog event of the GT-INJ series
(tests/integration/gt_inj/events.json, asset gt-inj-syslog) and sends
that event from the GT-INJ asset's address to the node's syslog-udp
listener.

The feed's oracle is the node's store, read by C6's own SQLite
connection. Every event of the series must be stored once, in schedule
order, bound to the GT-INJ asset, with its sent bytes, and with
received.utc equal to its received_utc, so the series reaches the event
baseline on the schedule's own clock. A step the node had not read when its
datagram came would show as an earlier received time.

The alarms: at period.baseline_ack the harness steps the clock until the
node shows the asset's learnt baseline as recorded, and acknowledges it
with a signed node.baseline_ack of kind event, as an administrator would.
After the last event the clock goes to period.test_end. The departure
alarms the node stored (platform/health, baseline.departure) are checked
by tests/integration/gt_inj/alarms.py's check() against events.json, for
the gt-inj-syslog asset only: gt-inj-ser needs the SER half.

Two more nodes run (V-M4's other two measures): one fed the same series,
whose alarms must equal the first's, and one fed events-heldout.json in
place of the test period (its "replay"), which must raise no departure
alarm.

Evidence class: simulated. The series is synthetic (GT-INJ), and the
sender is a test socket on loopback.
"""

import datetime
import glob
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import threading
import time

import pytest

import harness
from conftest import need
from slicerun import SERVICE, Slice

GTINJ = os.path.join(harness.REPO, "tests", "integration", "gt_inj")
EVENTS = os.path.join(GTINJ, "events.json")
STREAM = "syslog/a6-udp"
HEALTH = "platform/health"
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


def _query(store_dir, sql, stream=STREAM):
    """sql's rows for stream, from whichever database holds it."""
    for path in glob.glob(os.path.join(store_dir, "*.db")):
        db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            rows = db.execute(sql, (stream,)).fetchall()
        except sqlite3.OperationalError:
            rows = []
        finally:
            db.close()
        if rows and rows[0][0]:
            return rows
    return []


def _stored(store_dir, stream=STREAM):
    """The events of stream, in seq order."""
    return [json.loads(ev) for (ev,) in _query(store_dir, "SELECT event FROM events WHERE stream = ? ORDER BY seq", stream)]


def _count(store_dir):
    rows = _query(store_dir, "SELECT COUNT(*) FROM events WHERE stream = ?")
    return rows[0][0] if rows else 0


def _status(s):
    try:
        with open(os.path.join(s.layout["store_dir"], "status.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _baseline(s):
    """The GT-INJ asset's event baseline as node status shows it."""
    return (_status(s).get("event_baselines") or {}).get(s.layout["gtinj_asset"]) or {}


def _nudge(clock, until, done, what):
    """Moves the node's clock a second at a time, no further than until,
    until done() holds."""
    while not done():
        if clock.at + datetime.timedelta(seconds=1) >= until:
            raise AssertionError(f"{what} by {_stamp(clock.at)}, before the next event at {_stamp(until)}")
        clock.set(clock.at + datetime.timedelta(seconds=1))
        if not harness.wait_for(clock.reached, 10, step=0.002):
            raise AssertionError(f"the node's clock did not reach {_stamp(clock.at)}")
        time.sleep(0.05)


def _acknowledge(s, clock, at, until):
    """At at, acknowledges the baseline the node recorded for the GT-INJ
    asset with a signed node.baseline_ack, and waits until it is active.
    Returns the baseline status at activation."""
    clock.set(at)
    if not harness.wait_for(clock.reached, 10, step=0.002):
        raise AssertionError(f"the node's clock did not reach {_stamp(at)}")
    _nudge(clock, until, lambda: _baseline(s).get("phase") == "awaiting", f"no baseline recorded ({_baseline(s)})")
    digest = _baseline(s)["recorded"]["hash"]
    out = subprocess.run([s.exe("slicehelper"), "admin-file", "-root", s.root, "-kind", "baseline-ack",
                          "-name", "gtinj-baseline-ack", "-digest", digest], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    try:
        _nudge(clock, until, lambda: (_baseline(s).get("active") or {}).get("hash") == digest, f"baseline {digest} not active")
    except AssertionError as e:
        raise AssertionError(f"{e}: {_baseline(s)}; admin requests {_status(s).get('admin_requests')}") from None
    return _baseline(s)


def _series(name):
    with open(os.path.join(GTINJ, name)) as f:
        return json.load(f)


def _syslog(series):
    return [e for e in series["events"] if e["asset"] == "gt-inj-syslog"]


def _run(tmp_path_factory, events, end):
    """One node fed events on the stepped clock, acknowledged at
    events.json's baseline_ack, and stepped on to end."""
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "loopback senders other than 127.0.0.1 are a Linux runner's")
    series = _series("events.json")
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
    out = {"series": series, "events": events}
    ack = _utc(series["period"]["baseline_ack"])
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
                if "baseline" not in out and _utc(e["received_utc"]) > ack:
                    out["baseline"] = _acknowledge(s, clock, ack, _utc(e["received_utc"]))
                clock.set(_utc(e["received_utc"]))
                if not harness.wait_for(clock.reached, 10, step=0.002):
                    raise AssertionError(f"the node's clock did not reach {e['received_utc']} ({e['id']})")
                sock.sendto(_datagram(e), (host, int(port)))
                if not harness.wait_for(lambda: _count(layout["store_dir"]) >= i, 10, step=0.002):
                    break
        finally:
            sock.close()
        out["arrived"] = _count(layout["store_dir"]) >= len(events)
        # To the end, and past the feeder's lateness, so every event and
        # absence deadline before it reaches the detector.
        clock.set(end)
        harness.wait_for(clock.reached, 10, step=0.002)
        _nudge(clock, end + datetime.timedelta(minutes=10), lambda: clock.at >= end + datetime.timedelta(minutes=3), "")
        time.sleep(1)
        out["status"] = _baseline(s)
    finally:
        starting.clear()
        s.stop()
    out["stored"] = _stored(s.layout["store_dir"])
    out["health"] = _stored(s.layout["store_dir"], HEALTH)
    # The asset's baseline records, as stored: its configuration stream also
    # holds the event-baseline checkpoints.
    out["config"] = [ev for (ev,) in _query(s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq", "config/" + s.layout["gtinj_asset"])
                     if json.loads(ev).get("schema", "").startswith("otsec.baseline/")]
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    series = _series("events.json")
    return _run(tmp_path_factory, _syslog(series), _utc(series["period"]["test_end"]))


@pytest.fixture(scope="module")
def repeat(tmp_path_factory):
    """A second node fed the same series (V-M4: the same input gives the
    same alarms)."""
    series = _series("events.json")
    return _run(tmp_path_factory, _syslog(series), _utc(series["period"]["test_end"]))


@pytest.fixture(scope="module")
def heldout(tmp_path_factory):
    """events.json up to the acknowledgement, then events-heldout.json in
    place of the test period (its "replay"), to its last event."""
    series, ho = _series("events.json"), _series("events-heldout.json")
    ack = _utc(series["period"]["baseline_ack"])
    later = _syslog(ho)
    assert ack < _utc(later[0]["received_utc"])
    events = [e for e in _syslog(series) if _utc(e["received_utc"]) <= ack] + later
    return _run(tmp_path_factory, events, _utc(later[-1]["received_utc"]))


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


def _alarms():
    spec = importlib.util.spec_from_file_location("gtinj_alarms", os.path.join(GTINJ, "alarms.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_the_baseline_is_acknowledged_at_baseline_ack(run):
    b = run.get("baseline")
    assert b and b.get("phase") == "active", b
    ack = _utc(run["series"]["period"]["baseline_ack"])
    assert ack <= _parse(b["active_from"]) < ack + datetime.timedelta(minutes=2), b


def _ids(run):
    """Each stored event's EventID, as alarms cite it, to its series id."""
    got = _gtinj(run)
    assert len(got) == len(run["events"]), "the feed is incomplete, so the alarms are not checked"
    return {f"{ev['id']['node_id']}:{ev['id']['stream']}:{ev['id']['seq']}": e["id"] for e, ev in zip(run["events"], got)}


def _departures(run):
    return [ev["health"] for ev in run["health"] if (ev.get("health") or {}).get("type") == "baseline.departure"]


def test_departure_alarms_are_the_expected_ones(run):
    m = _alarms()
    assert m.DEPARTURE == "baseline.departure"
    ids = _ids(run)
    alarms = _departures(run)
    failures, report = m.check(run["series"], alarms, ids, {run["layout"]["gtinj_asset"]: "gt-inj-syslog"})
    print(json.dumps(report, indent=1, default=str))
    assert not failures, "\n".join(failures)


def test_the_three_runs_learn_the_same_baseline(run, repeat, heldout):
    # The same events before the acknowledgement give the same baseline
    # bytes, however the feeder's steps fell in each run: the period ends
    # where both minima first hold (D4-45; F-020).
    for r in (run, repeat, heldout):
        assert len(r["config"]) == 1, f"{len(r['config'])} baseline records, want one"
        assert r["baseline"]["active"]["hash"] == run["baseline"]["active"]["hash"], (r["baseline"], run["baseline"])
    p = json.loads(run["config"][0])
    print("baseline", run["baseline"]["active"]["hash"], "period", p["period"], "events", p["counts"]["events"])
    # T computed from the series: no gaps, so the later of the event that
    # meets min_events and the first event plus min_duration_s; every event
    # at or before T counts (C4 on #417). Learner 0.1 ended at a watermark,
    # after T, whatever the cadence.
    par, times = run["series"]["params"], [_utc(e["received_utc"]) for e in run["events"]]
    end = max(times[par["min_events"] - 1], times[0] + datetime.timedelta(seconds=par["min_duration_s"]))
    got = (_parse(p["period"]["start_utc"]), _parse(p["period"]["end_utc"]), p["period"]["collected_s"])
    assert got == (times[0], end, int((end - times[0]).total_seconds())) and not p["period"].get("gaps"), (p["period"], end)
    assert p["counts"]["events"] == sum(t <= end for t in times), (p["counts"], end)
    assert repeat["config"][0] == run["config"][0]
    assert heldout["config"][0] == run["config"][0]


def test_the_repeat_run_raises_the_expected_alarms(repeat):
    # The repeat run is checked against the oracle on its own, not only
    # against the first run.
    m = _alarms()
    failures, report = m.check(repeat["series"], _departures(repeat), _ids(repeat), {repeat["layout"]["gtinj_asset"]: "gt-inj-syslog"})
    print(json.dumps(report, indent=1, default=str))
    assert not failures, "\n".join(failures)


def test_a_second_run_raises_the_same_alarms(run, repeat):
    # Every field of every alarm, the baseline it cites among them, and the
    # events it cites.
    def norm(r):
        ids, active = _ids(r), r["baseline"]["active"]["hash"]
        out = []
        for h in _departures(r):
            assert h["details"].get("baseline") == active, (h["details"], active)
            out.append((h["details"], sorted(ids.get(f"{e['node_id']}:{e['stream']}:{e['seq']}", "?") for e in h.get("related") or [])))
        return out
    first = norm(run)
    assert first, "no alarms to compare"
    assert norm(repeat) == first


def test_the_heldout_series_raises_no_departure(heldout):
    # events-heldout.json "pass": at most 0 departure alarms per asset-day.
    assert heldout["arrived"] and len(_gtinj(heldout)) == len(heldout["events"])
    assert (heldout.get("baseline") or {}).get("phase") == "active", heldout.get("baseline")
    alarms = _departures(heldout)
    assert not alarms, json.dumps(alarms, indent=1)
    # No event was refused or late, so the input the learner and the
    # detector took is the series (C4 on #411).
    st = heldout["status"]
    assert st.get("phase") == "active" and st.get("refused", 0) == 0 and st.get("late", 0) == 0, st
