"""Telemetry failures are observable, end to end on the real binaries (A6,
P2-A6; V-S12).

Seven slices run side by side, one fault each:

  unreachable   the simulator is stopped before the first run: nothing
                listens at the device address;
  auth          the device's password is not the installed credential's;
  timeout       the device answers every line 20 s late (step timeout 15 s);
  hang          SER stops after four rows, inside its STX ... ETX message,
                and nothing more comes for it (SYNTHESIZED, profile_sel751);
  malformed     one SER row's TIME is damaged (SYNTHESIZED);
  upstream      the RELP receiver is killed after the first run and stays
                down;
  store         the adapter-evidence quota leaves room for one run's
                outcome and no more (the quarantine room, schedule.go).

Pass, for each: within 60 s of the failing run (for upstream, 125 s of the
kill: see test_within_60s_of_the_failing_run), otsec health shows a failure that names it, and no failing run
is shown or reported upstream as ok. The seven failures are told apart by
what health shows: the last run's code, or the alarm it raised (EXPECT).

A late device leaves the QUI language probe unanswered (C2 0.4, D2-19):
failed.timeout, and nothing suspended. Until C2 0.4 it was a rejected probe
that suspended the asset as language-not-english.

Not yet told apart: the late device and the SER that hangs both show only
"last run failed.timeout" in health. The result's detail differs, but health
does not show it (open with A5, V-S12). KNOWN_SAME lists that pair so the
test still catches any other pair that merges.

Evidence class: simulated. The device-side faults are the simulator's, not
a relay's failure signatures (H-04, H-05).
"""

import calendar
import os
import re
import shutil
import threading
import time

import pytest

import harness
from conftest import need
from slicerun import CANARY, Slice

FIRST_RUN = 100.0
# One schedule interval, the 15 s step timeout, and the time to report.
DEADLINE = 60.0 + 15.0 + 25.0
LAST_RUN = re.compile(r"^(?:FAILING )?asset \S+: last run (\S+) at (\S+?)(?: \(([^)]*)\))?(?:;.*)?$", re.M)
ALARM = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s+(.+?)\s{2,}(\S+)\s{2,}(.*)$", re.M)
# The quarantine room (platform/node/schedule.go): collectorwire's largest
# outcome, the largest reason, and 16 KiB.
QUARANTINE_ROOM = (8 << 20) + (16 << 10) + (16 << 10)


def _utc(text):
    return calendar.timegm(time.strptime(text[:19], "%Y-%m-%dT%H:%M:%S"))


def _signs(health, since):
    """What health shows after since (epoch s): the last run's code when
    that run started after since, and the alarm codes raised after since."""
    out = set()
    m = LAST_RUN.search(health)
    if m and _utc(m[2]) >= since - 1:
        out.add("run:" + m[1] + (f" ({m[3]})" if m[3] else ""))
    for a in ALARM.finditer(health):
        if _utc(a[1]) >= since - 1:
            out.add("alarm:" + a[3])
    return out


EXPECT = {
    "unreachable": "run:failed.connect",
    "auth": "run:failed.auth_rejected",
    "timeout": "run:failed.timeout",
    "hang": "run:failed.timeout",
    "malformed": "run:partial.parse_errors",
    "upstream": "alarm:forward-unreachable",
    "store": "alarm:collection-no-quarantine-room",
}


KNOWN_SAME = {("hang", "timeout")}


def _failure(signs):
    return {x for x in signs if x != "run:ok"}


CASES = {
    "unreachable": dict(),
    "auth": dict(sim_password=CANARY[::-1]),
    "timeout": dict(sim_extra=("--response-delay", "20")),
    "hang": dict(sim_extra=("--profile-ser", "hang")),
    "malformed": dict(sim_extra=("--profile-ser", "malformed")),
    "upstream": dict(),
    "store": dict(setup_extra=("-quota", f"adapter-evidence={QUARANTINE_ROOM + 1024}")),
}


def _run_case(name, s, out):
    r = out[name] = {"name": name}
    try:
        s.start(**CASES[name])
        t0 = time.time()
        if name == "unreachable":
            s.kill("simulator")
        if name in ("upstream", "store"):
            # A good first run, then the fault.
            assert harness.wait_for(lambda: LAST_RUN.search(s.health()), FIRST_RUN, step=1.0), "no first run"
            r["before"] = LAST_RUN.search(s.health())[1]
            if name == "upstream":
                s.kill("receiver")
        r["inject"] = t0 = time.time() if name in ("upstream", "store") else t0
        got = harness.wait_for(lambda: _failure(_signs(s.health(), t0)), FIRST_RUN + DEADLINE, step=1.0)
        r["seen"] = time.time()
        r["signs"] = sorted(got or ())
        if name not in ("upstream", "store"):
            # The node reports the run upstream a moment after health.
            harness.wait_for(lambda: s.runs_reported(), 20.0, step=0.5)
        r["health"] = s.health()
        last = s.collector_asset().get("last_run_utc")
        r["run_start"] = _utc(last) if last and _utc(last) >= t0 - 1 else None
        r["runs_reported"] = s.runs_reported()
        r["sim_lines"] = [x.get("text") for x in s.sim_records() if x["event"] == "line"]
    except Exception as exc:  # reported by the tests below
        r["error"] = repr(exc)
    finally:
        s.stop()


@pytest.fixture(scope="module")
def cases(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "the Windows leg of the end-to-end run is the PC run (D1-26)")
    base = str(tmp_path_factory.mktemp("slice-failures"))
    first = Slice(os.path.join(base, "build"))
    first.build()
    out = {}
    threads = []
    for name in CASES:
        s = Slice(os.path.join(base, name), bin_dir=first.bin)
        t = threading.Thread(target=_run_case, args=(name, s, out))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    for name, r in out.items():
        print(f"{name}: {r.get('signs')} after {r.get('seen', 0) - r.get('inject', 0):.0f}s; "
              f"reported {[x.get('status') for x in r.get('runs_reported', [])]}; {r.get('error', '')}")
    return out


@pytest.mark.parametrize("name", list(CASES))
def test_the_failure_shows_in_health(cases, name):
    r = cases[name]
    assert "error" not in r, r
    assert r["signs"], f"{name}: no failure in health\n{r['health']}"
    assert EXPECT[name] in r["signs"], (name, r["signs"])


@pytest.mark.parametrize("name", list(CASES))
def test_within_60s_of_the_failing_run(cases, name):
    r = cases[name]
    start = r["run_start"] or r["inject"]
    limit = 60.0 + 2.0
    if name == "upstream":
        # The node raises forward-unreachable when events wait and nothing
        # has been confirmed for 60 s. On a node with one run a minute the
        # first event to wait can come up to 60 s after the kill, so the
        # alarm can take up to two minutes (77 s seen in CI). D2-21 sets
        # V-S12's bound for this case at 2 minutes from the first event
        # the node cannot deliver.
        limit = 120.0 + 5.0
    assert r["seen"] - start <= limit, (name, r["seen"] - start, r["signs"])


@pytest.mark.parametrize("name", [n for n in CASES if n != "upstream"])
def test_no_failing_run_reports_ok(cases, name):
    r = cases[name]
    assert not any("run:ok" == x for x in r["signs"]), r["signs"]
    reported = [x.get("status") for x in r["runs_reported"]]
    if name == "store":
        # The first run was good; the next is not sent, so not reported.
        assert reported[:1] == ["ok"] and "ok" not in reported[1:], reported
    else:
        assert reported and "ok" not in reported, (name, reported)


def test_the_failures_are_told_apart(cases):
    signs = {name: frozenset(r.get("signs", ())) for name, r in cases.items()}
    for a in signs:
        for b in signs:
            if a < b and (a, b) not in KNOWN_SAME:
                assert signs[a] != signs[b], (a, b, signs[a])


def test_a_late_device_suspends_nothing(cases):
    # D2-19: an unanswered probe is not a language fault.
    assert "alarm:asset-suspended" not in cases["timeout"]["signs"], cases["timeout"]["signs"]
    assert "SUSPENDED" not in cases["timeout"]["health"], cases["timeout"]["health"]
