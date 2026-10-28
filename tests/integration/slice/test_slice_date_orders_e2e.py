"""The slice end to end in the YMD and DMY date orders, on the real
binaries (B6, P4-B6's carried check; D3-11, #211).

test_sel751_date_orders.py runs the adapter and the normalizer in process
for each DATE_F order. This runs the whole slice instead: the recording
simulator prints every date in the order (--profile-date-f), otsec-collector
runs the SEL-751 adapter (SHO P 1, SHO G, SER), the otsec node normalizes
the result with the order read from DATE_F, and the RELP receiver gets what
the node forwards. One slice per order, one scheduled read each.

Checked against ground truth that is not the product's: Figure 10.16's
rows (reconcile.native_rows, dated 02/28/2007 in MDY), with the date
printed in the order. For each order:
  - every row reaches the upstream collector once, byte for byte, with its
    own time text, number and evidence class (reconcile.reconcile);
  - each SER message's wall clock (dwall) is 2007-02-28 at the row's time,
    and it carries no date-format-assumed flag (dflag);
  - the simulator received only read-only register lines, SHO G before
    SER (check.py).
The day, 28, is above 12, so no other order reads the printed date as a
date at all: an order taken from anywhere but DATE_F fails the wall clock.

MDY is test_slice_e2e.py's run. Evidence class: simulated (the simulator
answers from manual examples and an ASSUMED SHO G layout).
"""

import datetime
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
from slicerun import CHECK, REGISTER, SERVICE, Slice

LAYOUTS = {"YMD": "%Y/%m/%d", "DMY": "%d/%m/%Y"}
FIGURE_DATE = datetime.date(2007, 2, 28)
# The first read starts 60 s after the node.
RUN_TIMEOUT = 75.0 + 30.0


def rows_in(order):
    printed = FIGURE_DATE.strftime(LAYOUTS[order]).encode()
    return [row.replace(b"02/28/2007", printed) for row in reconcile.native_rows()]


@pytest.fixture(scope="module", params=sorted(LAYOUTS))
def run(request, tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" or SERVICE, "the Windows leg of the end-to-end run is the PC run (D1-26)")
    order = request.param
    s = Slice(str(tmp_path_factory.mktemp("slice-date-" + order)))
    s.build()
    try:
        s.start(sim_extra=("--profile-date-f", order))
        rows = len(reconcile.native_rows())
        done = harness.wait_for(lambda: s.sessions_closed() >= 1 and len(s.ser_received()) >= rows,
                                RUN_TIMEOUT, step=1.0)
        time.sleep(5)  # anything else the read sent arrives within seconds
        assert done, (f"{order}: {s.sessions_closed()} sessions, {len(s.ser_received())} SER messages after "
                      f"{RUN_TIMEOUT:.0f}s\nnode:\n{s.text('node')}\ncollector:\n{s.text('collector')}")
        s.order = order
        yield s
    finally:
        s.stop()


def test_every_row_arrives_once_in_the_order(run):
    problems, stats = reconcile.reconcile(run.received(), rows_in(run.order))
    assert problems == [], (run.order, problems)
    assert stats["matched"] == stats["rows"] == 8 and stats["duplicates"] == 0, (run.order, stats)


def test_the_wall_clock_comes_from_date_f(run):
    by_dt = {reconcile.row_time_text(row): row for row in rows_in(run.order)}
    msgs = run.ser_received()
    assert len(msgs) == 8, (run.order, len(msgs))
    for raw in msgs:
        ps = reconcile.parse_rfc5424(raw)["sd"][reconcile.SDID]
        dt = reconcile.first(ps, "dt")
        assert dt in by_dt, (run.order, dt)
        tm = dt.split(" ")[1]
        assert reconcile.first(ps, "dwall") == f"{FIGURE_DATE.isoformat()}T{tm}", (run.order, ps)
        flags = [v for n, v in ps if n == "dflag"]
        assert not [f for f in flags if f.startswith("date-format-assumed")], (run.order, flags)


def test_only_read_only_lines_reached_the_device(run):
    out = subprocess.run([sys.executable, CHECK, "--log", run.sim_log, "--register", REGISTER],
                         capture_output=True, text=True)
    report = json.loads(out.stdout)
    assert out.returncode == 0 and report["pass"], report
    assert report["violations"] == [] and report["peak_concurrent_sessions"] == 1, report
    sent = [r["text"] for r in harness.read_log(run.sim_log) if r.get("event") == "line"]
    assert "SHO G" in sent and sent.index("SHO G") < sent.index("SER"), sent
