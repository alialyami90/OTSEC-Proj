"""Device time is kept as printed, never given an offset or a sync it does
not have, end to end on the real binaries (A6, P2-A6; V-S3's negative
cases).

Two slices side by side:
  figure  Figure 10.16 as documented: "Time Source: Internal", rows with no
          offset (SEL ASCII SER prints none).
  dst     SYNTHESIZED (profile_sel751, ser="dst"): six rows inside a US
          fall-back hour, the same wall time twice and time going backwards
          in print order, under "Time Source: External".

Checked for every SER message the receiver got, against the rows the
simulator printed (GT-REC):
  - no offset: doff="unknown", dbasis="none", and no dutc; the RFC 5424
    HEADER timestamp is the receive time (rcv), never the device's time;
  - the native time text byte for byte (dt), and the wall clock as printed
    (dwall), with no invalid-time flag and no reordering by time: the event
    order is the print order, through the fall-back;
  - time quality: SEL-751 documents no unsynchronized flag. "Time Source"
    says only whether a time-code input is attached (Table 7.16), so tsrc
    carries it verbatim and tsync stays "unknown" for both values; no
    accuracy against true time (dacc) is claimed.

Evidence class: simulated. How a real relay prints the fall-back hour is
H-10.
"""

import json
import os
import shutil
import subprocess
import threading

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CHECK, REGISTER, SERVICE, Slice

import sys
sys.path.insert(0, os.path.join(harness.REPO, "tests", "safety", "recording_simulator"))
import profile_sel751  # noqa: E402

CASES = {"figure": (), "dst": ("--profile-ser", "dst")}
SOURCES = {"figure": "Internal", "dst": "External"}


def _printed(name):
    body = profile_sel751.dst_ser() if name == "dst" else profile_sel751._load("ser-fig-10-16.txt")
    return [l for l in body.split(b"\r\n") if profile_sel751.SER_ROW.match(l)]


def _run(name, s, out):
    try:
        s.start(sim_extra=CASES[name])
        rows = len(_printed(name))
        ok = harness.wait_for(lambda: len(s.ser_received()) >= rows, 120.0, step=1.0)
        out[name] = s.ser_received() if ok else f"{len(s.ser_received())} of {rows} rows\n{s.health()}"
    except Exception as exc:
        out[name] = repr(exc)
    finally:
        s.stop()


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
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "the Windows leg of the end-to-end run is the PC run (D1-26)")
    base = str(tmp_path_factory.mktemp("slice-time"))
    first = Slice(os.path.join(base, "build"))
    first.build()
    out, threads, slices = {}, [], []
    for name in CASES:
        slices.append(Slice(os.path.join(base, name), bin_dir=first.bin))
        t = threading.Thread(target=_run, args=(name, slices[-1], out))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    out["_sim_logs"] = [log for sl in slices for log in sl.sim_logs]
    return out


def _params(msg):
    m = reconcile.parse_rfc5424(msg)
    return m, m["sd"][reconcile.SDID]


def _all(ps, name):
    return [v for n, v in ps if n == name]


@pytest.mark.parametrize("name", list(CASES))
def test_every_row_arrives_as_printed(got, name):
    assert isinstance(got[name], list), got[name]
    problems, stats = reconcile.reconcile(got[name], _printed(name))
    assert problems == [] and stats["matched"] == len(_printed(name)), (problems, stats)


@pytest.mark.parametrize("name", list(CASES))
def test_no_offset_is_invented(got, name):
    for msg in got[name]:
        m, ps = _params(msg)
        assert _all(ps, "doff") == ["unknown"], ps
        assert _all(ps, "dbasis") == ["none"], ps
        assert _all(ps, "dutc") == [], ps
        # The HEADER carries the receive time, not the device's.
        assert m["timestamp"] == reconcile.first(ps, "rcv"), (m["timestamp"], ps)


@pytest.mark.parametrize("name", list(CASES))
def test_wall_clock_as_printed(got, name):
    for msg in got[name]:
        _, ps = _params(msg)
        date, clock = reconcile.first(ps, "dt").split(" ")
        mm, dd, yyyy = date.split("/")
        assert reconcile.first(ps, "dwall") == f"{yyyy}-{mm}-{dd}T{clock}", ps
        assert "invalid-time" not in _all(ps, "dflag"), ps
        assert reconcile.first(ps, "parse") == "ok", ps


def test_the_fall_back_hour_keeps_print_order(got):
    order = sorted(((reconcile.seq_of(reconcile.first(_params(m)[1], "eid")), reconcile.first(_params(m)[1], "dt"))
                    for m in got["dst"]))
    times = [dt.split(" ")[1] for _, dt in order]
    assert times == [r.split()[2].decode() for r in _printed("dst")], times
    assert times.count("01:45:00.000") == 2 and times[1] > times[2], times


@pytest.mark.parametrize("name", list(CASES))
def test_no_sync_is_claimed_from_the_time_source(got, name):
    for msg in got[name]:
        _, ps = _params(msg)
        assert _all(ps, "tsrc") == [SOURCES[name]], ps
        assert _all(ps, "tsync") == ["unknown"], ps
        assert _all(ps, "tscope") == ["report"], ps
        assert _all(ps, "dacc") == [], ps


def test_only_read_only_lines_reached_the_device(got):
    assert _check(got["_sim_logs"]) == len(CASES), got["_sim_logs"]
