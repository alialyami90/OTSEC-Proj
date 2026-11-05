"""V-M4's SER half on the real binaries (D4-47): the slice's SEL-751 asset,
read over Telnet by the collector, fed tests/integration/gt_inj's
events-ser60.json on the stepped test clock.

events-ser60.json is gt-inj-ser on reads at least 60 s apart, the floor the
node and the collector both keep between SER sessions. The node and the
collector are built with otsec_testclock and run with -test-clock on one
clock file. The simulator serves its SER buffer from a file
(--profile-ser file), which the harness writes before each read, so every
read is a jump of the clock to one of the series' read times, and its rows
are received at that time.

The series is in November 2026, and the clock may only move forward from
near the wall clock, where the credential install is signed (CI on #420).
So the whole series is shifted by a whole number of days, which keeps every
UTC hour and every rate bucket, and the alarms' times are shifted back
before the oracle reads them. The acknowledgement is signed with its
issued_at at the shifted baseline_ack.

The buffer holds the newest 1,024 rows, as the SEL-751 does (S22 Table
7.63). Each row is printed with its events.json time, before the read that
returns it, a millisecond apart where several share a second. The
gap-before read's buffer holds only its own rows, so it shares nothing with
the read before it (event.Align: gap). The first read holds the first-read
backlog.

The checks, against C6's own read of the store: every row is stored once,
in order, on the slice's SER stream, with received.utc equal to its read
time and the series' alignment; the event baseline is recorded and active
only on the acknowledgement; and the baseline.departure health events pass
tests/integration/gt_inj/alarms.py's check() for the gt-inj-ser60 asset:
the 6 expected alarms (new 3, time 2, rate 1), none before the
acknowledgement, none citing a control. Linux. Evidence class: simulated.
"""

import datetime
import json
import os
import shutil
import subprocess
import threading
import time

import pytest

import harness
from conftest import need
from slicerun import SERVICE, Slice
from test_slice_gtinj_feed_e2e import HEALTH, Clock, _alarms, _departures, _parse, _query, _stamp, _status, _stored, _utc

GTINJ = os.path.join(harness.REPO, "tests", "integration", "gt_inj")
SERIES = os.path.join(GTINJ, "events-ser60.json")
SEC = datetime.timedelta(seconds=1)
DAY = datetime.timedelta(days=1)
BUFFER = 1024  # SEL-751 SER rows (S22 Table 7.63)
# Each read keeps its transcript, the whole buffer, about 45 MB over the
# series: above the slice's 64 MiB quota with the rest, which would prune
# the first rows before the oracle reads them.
EVIDENCE_QUOTA = 512 << 20


def _load(name):
    with open(os.path.join(GTINJ, name), encoding="utf-8") as f:
        return json.load(f)


def _reads(series):
    """The series' reads in order: (read time, its rows)."""
    out = []
    for e in series["events"]:
        t = _utc(e["received_utc"])
        if not out or out[-1][0] != t:
            out.append((t, []))
        out[-1][1].append(e)
    return out


def _printed(series):
    """Each row's printed device time: its events.json time, a millisecond
    earlier for each later row of the same second, so no two rows print
    alike and none is after its read."""
    orig = {e["id"]: _utc(e["received_utc"]) for e in _load("events.json")["events"]}
    out, group = {}, []
    for e in series["events"] + [None]:
        if group and (e is None or orig[e["id"]] != orig[group[0]["id"]]):
            for k, g in enumerate(group):
                out[g["id"]] = orig[g["id"]] - (len(group) - 1 - k) * datetime.timedelta(milliseconds=1)
            group = []
        if e is not None:
            group.append(e)
    return out


class _Run:
    def __init__(self, d):
        self.d = d
        self.series = _load("events-ser60.json")
        self.clock_path = os.path.join(d, "clock")
        self.buffer = os.path.join(d, "ser.json")
        self.write_buffer(datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc), [])
        s = self.s = Slice(d)
        s.node_tags = s.collector_tags = ("otsec_testclock",)
        s.node_args = s.collector_args = ("-test-clock", self.clock_path)

    def write_buffer(self, now, rows):
        tmp = self.buffer + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"now": [now.strftime("%m/%d/%Y"), now.strftime("%H:%M:%S")], "rows": rows}, f)
        os.replace(tmp, self.buffer)

    def jump(self, at):
        if at > self.clock.at:
            self.clock.set(at)
        if not harness.wait_for(self.clock.reached, 10, step=0.002):
            raise AssertionError(f"the node's clock did not reach {_stamp(at)}")

    def stored(self):
        return _stored(self.s.layout["store_dir"], "ser/" + self.s.layout["asset_id"])

    def count(self):
        rows = _query(self.s.layout["store_dir"], "SELECT COUNT(*) FROM events WHERE stream = ?", "ser/" + self.s.layout["asset_id"])
        return rows[0][0] if rows else 0

    def result_at(self):
        r = (_status(self.s).get("assets") or {}).get(self.s.layout["asset_id"]) or {}
        return (_parse(r["at"]) if r.get("at") else None), r.get("code")

    def baseline(self):
        return (_status(self.s).get("event_baselines") or {}).get(self.s.layout["asset_id"]) or {}

    def read(self, at, want):
        """Jumps to at, where a read is due, and waits until its rows are
        stored and the run has ended."""
        self.jump(at)
        ok = harness.wait_for(lambda: self.count() >= want and (self.result_at()[0] or at - SEC) >= at, 60, step=0.005)
        if not ok:
            raise AssertionError(f"the read at {_stamp(at)}: {self.count()} of {want} rows stored, result {self.result_at()}")
        # The scheduler reads the clock for the run's end after it writes
        # status, and arms its next timer from the clock too. A jump before
        # then puts the next read a minute of test clock after the jump,
        # which never comes: the read at 06:35:02 on #446's c391a44 (861 of
        # 862 rows), and every time with 50 ms between the two in C6's
        # reproduction. Nothing the node writes says it is past that point,
        # so this wait narrows the race but does not close it; it goes when
        # the node takes the end before status (C5).
        time.sleep(0.25)

    def acknowledge(self, ack, until):
        """At ack, the recorded baseline acknowledged; active before until."""
        b = self.baseline()
        assert b.get("phase") == "awaiting" and b.get("recorded", {}).get("hash"), b
        digest = b["recorded"]["hash"]
        out = subprocess.run([self.s.exe("slicehelper"), "admin-file", "-root", self.s.root, "-kind", "baseline-ack",
                              "-name", "ser60-baseline-ack", "-digest", digest, "-issued", _stamp(ack)[:19] + "Z"],
                             capture_output=True, text=True)
        assert out.returncode == 0, out.stderr
        self.jump(ack)

        def active():
            return (self.baseline().get("active") or {}).get("hash") == digest

        # Up to a second of wall time a step: the node's work takes wall
        # time, so a clock stepped faster than it works passes until first.
        while not harness.wait_for(active, 1, step=0.01):
            if self.clock.at + SEC >= until:
                raise AssertionError(f"baseline {digest} not active by {_stamp(self.clock.at)}: {self.baseline()}; "
                                     f"admin requests {_status(self.s).get('admin_requests')}")
            self.jump(self.clock.at + SEC)
        return self.baseline()

    def run(self):
        series, s = self.series, self.s
        reads = _reads(series)
        printed = _printed(series)
        s.build()
        # As in V-M2: the clock starts after the build, a minute ahead of the
        # wall clock, and moves at its rate until the credential is in.
        t0 = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)).replace(second=0, microsecond=0)
        self.clock = Clock(self.clock_path, t0)
        starting = threading.Event()
        starting.set()

        def tick():
            while starting.is_set():
                self.clock.set(self.clock.at + SEC)
                time.sleep(1.0)

        stepper = threading.Thread(target=tick, daemon=True)
        stepper.start()
        out = {"series": series}
        try:
            s.start(sim_extra=("--profile-ser", "file", "--profile-ser-file", self.buffer),
                    setup_extra=("-every", "60", "-gtinj-ser", SERIES, "-quota", f"adapter-evidence={EVIDENCE_QUOTA}"))
            starting.clear()
            stepper.join()
            out["layout"] = s.layout
            started = self.clock.at
            # No read yet: the schedule's first is due a minute after start.
            assert self.result_at()[0] is None and self.count() == 0, self.result_at()
            shift = out["shift"] = DAY * -(-(started + 5 * 60 * SEC - reads[0][0]) // DAY)
            ack = _utc(series["period"]["baseline_ack"])
            buf, n = [], 0
            for i, (at, rows) in enumerate(reads):
                if "baseline" not in out and at > ack:
                    # The jump to ack is a read of its own, with no new row,
                    # so the acknowledgement must be in before the next is
                    # due, a minute later, and the series' next read is no
                    # sooner than that.
                    assert reads[i - 1][0] + 60 * SEC <= ack and ack + 60 * SEC <= at, (reads[i - 1][0], at)
                    out["baseline"] = self.acknowledge(ack + shift, ack + shift + 60 * SEC)
                if rows[0].get("alignment") == "gap-before":
                    buf = []
                buf = (buf + [[f"{(printed[e['id']] + shift).strftime('%m/%d/%Y')}",
                               f"{(printed[e['id']] + shift).strftime('%H:%M:%S.%f')[:-3]}", e["element"], e["state"]]
                               for e in rows])[-BUFFER:]
                self.write_buffer(at + shift, buf)
                n += len(rows)
                self.read(at + shift, n)
            end = _utc(series["period"]["test_end"]) + shift
            self.jump(end)
            # Past the feeder's lateness, a second at a time.
            while self.clock.at < end + 3 * 60 * SEC:
                time.sleep(0.02)
                self.jump(self.clock.at + SEC)
            time.sleep(1)
            out["status"] = _status(s)
        finally:
            starting.clear()
            s.stop()
        out["stored"] = self.stored()
        out["health"] = _stored(s.layout["store_dir"], HEALTH)
        # The baseline records, in the asset's configuration stream.
        out["config"] = [json.loads(ev) for (ev,) in _query(s.layout["store_dir"], "SELECT event FROM events WHERE stream = ? ORDER BY seq",
                                                             "config/" + s.layout["asset_id"])
                         if json.loads(ev).get("schema", "").startswith("otsec.baseline/")]
        return out


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" and not SERVICE, "the stepped clock on both binaries is a Linux runner's here")
    return _Run(str(tmp_path_factory.mktemp("slice-ser60"))).run()


def test_every_row_is_stored_once_at_its_read_time(run):
    got, want = run["stored"], run["series"]["events"]
    assert len(got) == len(want), f"{len(got)} of {len(want)} rows stored"
    shift = run["shift"]
    bad = [(e["id"], e["received_utc"], ev["received"]["utc"]) for e, ev in zip(want, got)
           if _parse(ev["received"]["utc"]) - shift != _utc(e["received_utc"])]
    assert not bad, f"{len(bad)} rows with another received time, the first: {bad[:3]}"
    assert all((ev.get("source", {}).get("asset") or {}).get("id") == run["layout"]["asset_id"] for ev in got)


def test_alignment_is_the_series(run):
    bad = [(e["id"], e.get("alignment", "ok"), (ev.get("collection") or {}).get("alignment"))
           for e, ev in zip(run["series"]["events"], run["stored"])
           if e.get("alignment", "ok") != (ev.get("collection") or {}).get("alignment")]
    assert not bad, f"{len(bad)} rows aligned otherwise, the first: {bad[:3]}"


def test_the_period_ends_where_both_minima_first_hold(run):
    # D4-45: T is the later of the row that meets min_events and the first
    # row plus min_duration_s, and every row at or before T counts. For
    # events-ser60.json that is 2026-11-16T06:34:08Z and 769 rows (C4 on
    # #426), computed here from the series.
    par, times = run["series"]["params"], [_utc(e["received_utc"]) for e in run["series"]["events"]]
    end = max(times[par["min_events"] - 1], times[0] + datetime.timedelta(seconds=par["min_duration_s"]))
    assert (_stamp(end), sum(t <= end for t in times)) == ("2026-11-16T06:34:08.000Z", 769)
    assert len(run["config"]) == 1, f"{len(run['config'])} baseline records, want one"
    p = run["config"][0]
    got = (_parse(p["period"]["start_utc"]) - run["shift"], _parse(p["period"]["end_utc"]) - run["shift"], p["counts"]["events"])
    assert got == (times[0], end, 769) and not p["period"].get("gaps"), p["period"]


def test_the_baseline_is_active_only_on_the_acknowledgement(run):
    b = run["baseline"]
    ack = _utc(run["series"]["period"]["baseline_ack"]) + run["shift"]
    assert b.get("phase") == "active" and ack <= _parse(b["active_from"]) < ack + 2 * 60 * SEC, b


def test_departure_alarms_are_the_expected_ones(run):
    m = _alarms()
    ids = {f"{ev['id']['node_id']}:{ev['id']['stream']}:{ev['id']['seq']}": e["id"]
           for e, ev in zip(run["series"]["events"], run["stored"])}
    assert len(ids) == len(run["series"]["events"]), "the feed is incomplete, so the alarms are not checked"
    alarms = []
    for h in _departures(run):
        d = dict(h["details"])
        d["at_utc"] = _stamp(_parse(d["at_utc"]) - run["shift"])
        alarms.append(dict(h, details=d))
    failures, report = m.check(run["series"], alarms, ids, {run["layout"]["asset_id"]: "gt-inj-ser60"})
    print(json.dumps(report, indent=1, default=str))
    assert not failures, "\n".join(failures)
