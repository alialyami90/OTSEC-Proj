"""The SEL-751 adapter against the recording simulator in each DATE_F order
(A2, P3-A2; for A6's review, D2-13).

For MDY, YMD and DMY the simulator (A6's #166, --profile-date-f) prints every
date in that order, and the adapter (sel751.Run, through its TestSimulator
entry point) reads SHO G before SER and reports DATE_F. The result is then
reconciled here against ground truth that is not the adapter's: A6's
transcription of S22 Figure 10.16 (reconcile.native_rows), whose rows are
dated 02/28/2007 in MDY.

Checked, for each order:
  - the run is ok, DATE_F is reported as the order, and its span selects
    exactly those bytes;
  - the operate lines were SHO P 1, SHO G, SER, in that order;
  - every figure row arrives once as a parsed sel.ser.row, its bytes the
    figure's row with the date printed in the order, its DATE field reading
    as 2007-02-28 in that order and as no other date, and its #, TIME,
    ELEMENT and STATE the figure's;
  - every line the simulator received is a read-only register line
    (check.py).

Not checked here: the normalizer and the forwarder. A4's normalizer takes
the order from DATE_F in its follow-up to C2 0.5; until then a YMD or DMY
row would not reach the upstream collector as a dated event, so the full
slice reconcile in YMD and DMY waits on it.

Evidence class: simulated. The simulator answers from manual examples and
an ASSUMED SHO G layout; nothing here is hardware evidence.
"""

import base64
import datetime
import json
import os
import shutil
import subprocess
import sys

import pytest

import harness
import reconcile
from conftest import need
from slicerun import CHECK, REGISTER

PASSWORD = "Lab!pw-0451"  # a test value (D2-5), the sel751 package's test secret
SERIAL = "2007XXXXXXXXXXX"  # Figure 10.16
LAYOUTS = {"MDY": "%m/%d/%Y", "YMD": "%Y/%m/%d", "DMY": "%d/%m/%Y"}
FIGURE_DATE = datetime.date(2007, 2, 28)


def run_adapter(tmp, order):
    log = os.path.join(tmp, f"sim-{order}.jsonl")
    out = os.path.join(tmp, f"result-{order}.json")
    sim = harness.start_simulator(log, PASSWORD, extra=["--profile-date-f", order])
    try:
        env = dict(os.environ, OTSEC_SEL751_SIM=f"127.0.0.1:{sim.port}", OTSEC_SEL751_SIM_PASSWORD=PASSWORD,
                   OTSEC_SEL751_SIM_FID=harness.ALLOWED_FID, OTSEC_SEL751_SIM_SERIAL=SERIAL,
                   OTSEC_SEL751_SIM_RESULT=out)
        p = subprocess.run(["go", "test", "-count=1", "-run", "^TestSimulator$", "./modules/ied/sel751/"],
                           cwd=harness.REPO, env=env, capture_output=True, text=True, timeout=300)
        assert p.returncode == 0, p.stdout + p.stderr
    finally:
        sim.stop()
    with open(out, encoding="utf-8") as f:
        return json.load(f), log


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to run the adapter)")
    tmp = str(tmp_path_factory.mktemp("date-orders"))
    return {order: run_adapter(tmp, order) for order in LAYOUTS}


def operate_lines(res):
    data = base64.b64decode(res["transcript"]["data"])
    return [data[s["offset"]:s["offset"] + s["length"]].rstrip(b"\r\n").decode()
            for s in res["transcript"]["segments"] if s["dir"] == "tx" and s["phase"] == "operate"]


@pytest.mark.parametrize("order", list(LAYOUTS))
def test_rows_reconcile_in_each_order(runs, order):
    res, _ = runs[order]
    data = base64.b64decode(res["transcript"]["data"])
    assert res["status"] == "ok", res.get("error")
    assert operate_lines(res) == ["SHO P 1", "SHO G", "SER"]

    settings = {s["name"]: s for s in res.get("settings", [])}
    assert list(settings) == ["DATE_F"]
    sp = settings["DATE_F"]["span"]
    assert settings["DATE_F"]["value"] == order
    assert data[sp["offset"]:sp["offset"] + sp["length"]] == order.encode()

    printed = FIGURE_DATE.strftime(LAYOUTS[order]).encode()
    want = [row.replace(b"02/28/2007", printed) for row in reconcile.native_rows()]
    recs = res["records"]
    got = [data[r["span"]["offset"]:r["span"]["offset"] + r["span"]["length"]] for r in recs]
    assert got == want

    for rec, row in zip(recs, reconcile.native_rows()):
        assert rec["kind"] == "sel.ser.row" and rec["parse_ok"], rec
        f = {x["name"]: x["value"] for x in rec["fields"]}
        fig = row.decode().split()
        assert [f["#"], f["TIME"], f["ELEMENT"], f["STATE"]] == [fig[0], fig[2], fig[3], fig[4]]
        assert datetime.datetime.strptime(f["DATE"], LAYOUTS[order]).date() == FIGURE_DATE
        # The day, 28, is above 12, so no other order reads this text as a
        # date: a consumer cannot read it in the wrong order and get one.
        for other, layout in LAYOUTS.items():
            if other != order:
                with pytest.raises(ValueError):
                    datetime.datetime.strptime(f["DATE"], layout)


@pytest.mark.parametrize("order", list(LAYOUTS))
def test_simulator_received_only_read_only_lines(runs, order):
    _, log = runs[order]
    out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                         capture_output=True, text=True)
    report = json.loads(out.stdout)
    assert out.returncode == 0 and report["pass"], report
    assert report["violations"] == [] and report["peak_concurrent_sessions"] == 1, report
    sent = [r["text"] for r in harness.read_log(log) if r.get("event") == "line"]
    assert "SHO G" in sent and sent.index("SHO G") < sent.index("SER"), sent
