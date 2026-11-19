"""D6's finding on #744 (D4-118 item 2.5): `table.py public` lists every
capture of MANIFEST.tsv and extra-captures.tsv, a capture that was not
fetched reads `not run (not fetched)` under every configuration, and a
counted run exits non-zero when one is missing. Made-up output folders over
the committed lists; no engine runs. Run: python -m pytest -q
modules/telemetry/experiments/engine-linux/test_public_unfetched.py"""
import os
import subprocess
import sys

import pytest

import table

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
LISTS = [os.path.join(ROOT, "tests", "fixtures", "network", "public-ot-captures", "MANIFEST.tsv"),
         os.path.join(HERE, "extra-captures.tsv")]
WANT = table.listed(LISTS)
ROW = "not run (not fetched)"


def run_dir(tmp_path, skip):
    """A public run whose captures are every listed one but those in SKIP:
    each fetched capture is a file in pcaps, and each ran under every base
    configuration with exit code 0 and one flow."""
    pcaps, out = tmp_path / "public", tmp_path / "out-public"
    pcaps.mkdir()
    out.mkdir()
    for n, d in WANT:
        if d in skip:
            continue
        (pcaps / n).write_bytes(b"")
        for cfg in table.CONFIGS[:6]:
            c = out / d / cfg
            c.mkdir(parents=True)
            (c / "exit-code").write_text("0\n")
            (c / "conn.log").write_text('{"service": "dnp3"}\n')
            (c / "eve.json").write_text('{"event_type": "flow", "app_proto": "dnp3"}\n')
    return str(out), str(pcaps)


def rows(text, name):
    return [l for l in text.splitlines() if l.startswith(f"| {name} | ")]


def main(out, pcaps, *extra):
    return subprocess.run([sys.executable, "-I", os.path.join(HERE, "table.py"), "public", out, pcaps, *LISTS, *extra],
                          capture_output=True, text=True)


def test_lists_hold_every_capture():
    names = [d for _, d in WANT]
    assert len(names) == 23 and len(set(names)) == 23
    assert ("mms.pcap", "mms") in WANT and ("goose-disturbance-underfrequency.pcapng",
                                           "goose-disturbance-underfrequency") in WANT
    # zeek_run and in-container.sh run only these; a listed capture with any
    # other extension would be fetched, never run, and pass --counted (D6's
    # N2 on #751).
    assert all(n.endswith((".pcap", ".pcapng", ".cap")) for n, _ in WANT), WANT


@pytest.mark.parametrize("skip", [set(), {"goose-disturbance-underfrequency"}, {d for _, d in WANT}],
                         ids=["zero-missing", "one-missing", "all-missing"])
def test_missing_captures_are_rows_and_fail_a_counted_run(tmp_path, capsys, skip):
    out, pcaps = run_dir(tmp_path, skip)
    assert table.public(out, pcaps, LISTS) == len(skip)
    text = capsys.readouterr().out
    for _, d in WANT:
        r = rows(text, d)
        assert len(r) == len(table.CONFIGS), d
        assert sum(ROW in l for l in r) == (len(r) if d in skip else 0), d
    assert (f"{len(skip)} of the {len(WANT)} listed captures were not fetched" in text) == bool(skip)
    counted, smoke = main(out, pcaps, "--counted"), main(out, pcaps)
    assert counted.returncode == (3 if skip else 0), counted.stderr
    assert smoke.returncode == 0, smoke.stderr
    cell = f"| {ROW} |\n"
    assert counted.stdout.count(cell) == smoke.stdout.count(cell) == len(skip) * len(table.CONFIGS)


def test_fetched_capture_with_no_output_is_not_run_not_unfetched(tmp_path, capsys):
    """A capture that was fetched but left no output folder still gets its
    rows, and they read `not run`, not `not fetched`; it fails nothing."""
    out, pcaps = run_dir(tmp_path, set())
    for cfg in os.listdir(os.path.join(out, "modbus")):
        for f in os.listdir(os.path.join(out, "modbus", cfg)):
            os.remove(os.path.join(out, "modbus", cfg, f))
        os.rmdir(os.path.join(out, "modbus", cfg))
    os.rmdir(os.path.join(out, "modbus"))
    assert table.public(out, pcaps, LISTS) == 0
    r = rows(capsys.readouterr().out, "modbus")
    assert len(r) == len(table.CONFIGS) and all(l.endswith("| not run |") for l in r)


@pytest.mark.parametrize("extra,rc", [([], 0), (["--counted"], 3), (["--count"], 2), (["--counted", "extra"], 2)],
                         ids=["none", "counted", "misspelt", "trailing"])
def test_only_exactly_counted_is_accepted(tmp_path, extra, rc):
    """Any trailing argument other than exactly `--counted` exits 2, so a
    later edit to run.sh's call cannot turn a counted run into an uncounted
    one (D3's N1 on #751). The first two cases are the controls: with one
    capture missing, no flag exits 0 and `--counted` exits 3."""
    out, pcaps = run_dir(tmp_path, {"goose-disturbance-underfrequency"})
    r = main(out, pcaps, *extra)
    assert r.returncode == rc, r.stderr
    if rc == 2:
        assert "usage: table.py public" in r.stderr and r.stdout == ""


def test_an_unreadable_list_fails_every_run(tmp_path):
    """A list that cannot be read is never taken as a list with nothing in
    it: table.py fails, so run.sh fails the job, counted or not."""
    out, pcaps = run_dir(tmp_path, set())
    r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "table.py"), "public", out, pcaps, LISTS[0],
                        str(tmp_path / "absent.tsv")], capture_output=True, text=True)
    assert r.returncode != 0 and "absent.tsv" in r.stderr
