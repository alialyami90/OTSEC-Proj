"""SER reads whose buffer changes between them, end to end on the real
binaries (A6, P2-A6; V-S4, C-06, C-13, D1-7).

The simulator serves a SYNTHESIZED script of seven reads (profile_sel751,
ser="script"), one per scheduled run, every row renumbered so row 1 is the
newest (Table 7.63):

  1  Figure 10.16 (8 rows)                       8 new events, first read
  2  its oldest 3 gone, 2 identical new rows     both identical rows kept
  3  cleared, 2 new rows                         2 new, exactly one ser.gap
  4  1 more row                                  1 new, no gap
  5  a middle row removed, 1 more               1 new, ser.gap naming 1 removed
  6  4 rows of repeating chatter                 4 new, no gap
  7  the chatter again, overlapping at 2 offsets ser.alignment-ambiguous; the
                                                 smallest overlap kept, the rows
                                                 it may repeat flagged

Checked against the script (GT-REC), not against the product: the number of
new events per read, that nothing is stored twice where the overlap is
unambiguous, the gap and ambiguity health events with their counts, the
row number of each event as printed in the read that first saw it, and the
recording check. SEL-751 rows carry no sequence number, so the gap
reports say records may be missing, never how many (C-06).

Evidence class: simulated. How a real buffer behaves under overrun and
after an operator clears it is H-07.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CHECK, REGISTER, Slice

sys.path.insert(0, os.path.join(harness.REPO, "tests", "safety", "recording_simulator"))
import profile_sel751  # noqa: E402

READS = len(profile_sel751.SCRIPT)
# New events per read, for the reads whose overlap is unambiguous.
NEW = [8, 2, 2, 1, 1, 4]


def _ser(msgs):
    out = []
    for m in msgs:
        p = reconcile.parse_rfc5424(m)["sd"][reconcile.SDID]
        if reconcile.first(p, "kind") == "ser":
            out.append(p)
    return out


def _health(msgs, htype):
    out = []
    for m in msgs:
        p = reconcile.parse_rfc5424(m)["sd"][reconcile.SDID]
        if reconcile.first(p, "htype") == htype:
            out.append(dict(v.split("=", 1) for n, v in p if n == "hd"))
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "the Windows leg of the end-to-end run is the PC run (D1-26)")
    d = str(tmp_path_factory.mktemp("slice-buffer"))
    s = Slice(d)
    s.build()
    state = os.path.join(d, "reads")
    try:
        s.start(sim_extra=("--profile-ser", "script", "--profile-ser-state", state))
        s.by_read = []  # the receiver's messages after each read
        for k in range(READS):
            assert harness.wait_for(lambda: s.sessions_closed() >= k + 1, 100.0, step=1.0), s.health()
            # The read's events and health reach the receiver a moment later.
            harness.wait_for(lambda: len(s.runs_reported()) >= k + 1, 20.0, step=0.5)
            harness.wait_for(lambda: False, 3.0, step=0.5)
            s.by_read.append(list(s.received()))
        yield s
    finally:
        s.stop()


def _new_in(run, k):
    before = len(_ser(run.by_read[k - 1])) if k else 0
    return _ser(run.by_read[k])[before:]


def test_new_events_per_read(run):
    got = [len(_new_in(run, k)) for k in range(len(NEW))]
    assert got == NEW, got


def test_each_event_is_the_row_as_first_printed(run):
    for k in range(len(NEW)):
        printed = profile_sel751.script_ser(k).split(b"\r\n")
        rows = [l for l in printed if profile_sel751.SER_ROW.match(l)]
        for p in _new_in(run, k):
            assert reconcile.first(p, "dtext").encode() in rows, (k, reconcile.first(p, "dtext"))


def test_both_identical_rows_are_kept(run):
    new = [reconcile.first(p, "dtext").split()[1:] for p in _new_in(run, 1)]
    assert len(new) == 2 and new[0] == new[1], new
    assert len({reconcile.first(p, "eid") for p in _new_in(run, 1)}) == 2


def test_the_clear_raises_exactly_one_gap(run):
    gaps = [_health(run.by_read[k], "ser.gap") for k in range(len(NEW))]
    counts = [len(g) - (len(gaps[k - 1]) if k else 0) for k, g in enumerate(gaps)]
    assert counts == [0, 0, 1, 0, 1, 0], counts
    clear, removal = gaps[-1]
    assert clear["removed_records"] == "0", clear
    assert removal["removed_records"] == "1", removal
    for p in _new_in(run, 2):
        assert reconcile.first(p, "align") == "gap-before", p


def _overlaps(k):
    """The overlaps d that fit between script reads k-1 and k, worked out
    from the script: the new read (printed oldest first) starts with the last d rows
    of the previous one (row numbers aside)."""
    def keys(n):
        rows = [l for l in profile_sel751.script_ser(n).split(b"\r\n") if profile_sel751.SER_ROW.match(l)]
        return [reconcile.row_key(r.decode()) for r in rows]
    prev, cur = keys(k - 1), keys(k)
    return [d for d in range(1, min(len(prev), len(cur)) + 1) if prev[-d:] == cur[:d]]


def test_ambiguous_overlap_is_reported_and_rows_are_kept(run):
    # C1 align.go: with more than one overlap the smallest is used, so every
    # row that may be new is kept, and the first rows added, as many as the
    # largest overlap less the smallest, are flagged possible-duplicate.
    fits = _overlaps(READS - 1)
    assert len(fits) > 1, fits  # the script is ambiguous here
    rows = len([l for l in profile_sel751.script_ser(READS - 1).split(b"\r\n") if profile_sel751.SER_ROW.match(l)])
    added, maybe = rows - fits[0], fits[-1] - fits[0]
    amb = _health(run.by_read[-1], "ser.alignment-ambiguous")
    assert len(amb) == 1, amb
    assert amb[0]["added_records"] == str(added) and amb[0]["possible_duplicates"] == str(maybe), amb
    got = [reconcile.first(p, "align") for p in _new_in(run, READS - 1)]
    assert got == ["possible-duplicate"] * maybe + ["ok"] * (added - maybe), got


def test_only_read_only_lines_reached_the_device(run):
    out = subprocess.run([sys.executable, CHECK, "--log", run.sim_log, "--register", REGISTER],
                         capture_output=True, text=True)
    report = json.loads(out.stdout)
    assert out.returncode == 0 and report["pass"], report
