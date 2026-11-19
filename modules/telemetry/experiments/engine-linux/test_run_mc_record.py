"""run.sh's own mc_record function, run under `sh -eu` with the real
mountcheck.py over a made-up check folder of one container (no engine and no
Docker run). Under mode hr23-unit, and under mode dnp3 when it feeds HR-23's
captures (`$hr23` set; run.sh's hr23_feed), the record prints the output
folder's hash and no entry count; under any other mode it prints the count.
The controls are mc_record with its `$mc_count` argument dropped, and with
the dnp3 line dropped, each of which must make the check fail. Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_run_mc_record.py"""
import json
import os
import shutil
import subprocess
import sys

import pytest

import mountcheck as mc

HERE = os.path.dirname(os.path.abspath(__file__))
SH = shutil.which("sh")

pytestmark = pytest.mark.skipif(SH is None, reason="no sh on PATH")


def function():
    """mc_record as run.sh holds it; CR is stripped for a Windows checkout."""
    with open(os.path.join(HERE, "run.sh"), encoding="utf-8") as f:
        lines = f.read().replace("\r", "").split("\n")
    start = lines.index("mc_record() {")
    end = lines.index("}", start)
    text = "\n".join(lines[start:end + 1]) + "\n"
    assert "mountcheck.py\" summary" in text and "$mc_count" in text, text
    return text


def fwd(p):
    return str(p).replace("\\", "/")


def record(work, text, mode, hr23=""):
    """The record mc_record appends for MODE, over one container whose
    output folder holds two files."""
    out = work / "out"
    out.mkdir(parents=True)
    (out / "conn.log").write_text("{}\n")
    (out / "weird.log").write_text("{}\n")
    c = work / "checks" / "1"
    c.mkdir(parents=True)
    (c / "before.json").write_text("{}")
    (c / "create.json").write_text(json.dumps(["--network", "none"]))
    (c / "after.json").write_text(json.dumps({"exit": 0, "path": str(out), "lines": mc.hash_tree(str(out))}))
    (work / f"mountcheck-{mode}.md").write_text("controls\n")
    script = work / "probe.sh"
    script.write_text('set -eu\npython3() { "$PY" "$@"; }\nexec 9>&2\n' + text + 'mc_record "$work/rec.md"\n',
                      newline="\n")
    env = dict(os.environ, PY=fwd(sys.executable), here=fwd(HERE), work=fwd(work), mode=mode,
               mc=fwd(work / "checks"), hr23=hr23)
    r = subprocess.run([SH, fwd(script)], env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return (work / "rec.md").read_text()


def leaks(tmp_path, text):
    """What is wrong with TEXT's records: a count under hr23-unit or under
    dnp3 with HR-23's feed, or none under dnp3 without it."""
    bad = []
    hr = record(tmp_path / "hr23", text, "hr23-unit")
    if "; output " not in hr or "entries" in hr:
        bad.append("hr23-unit: " + hr)
    other = record(tmp_path / "dnp3", text, "dnp3")
    if " entries); " not in other:
        bad.append("dnp3: " + other)
    fed = record(tmp_path / "dnp3-hr23", text, "dnp3", hr23="1")
    if "; output " not in fed or "entries" in fed:
        bad.append("dnp3 with HR-23's feed: " + fed)
    return bad


def test_mc_record_prints_no_entry_count_for_hr23_unit(tmp_path):
    assert leaks(tmp_path, function()) == []


def test_control_mc_record_without_its_count_switch_fails(tmp_path):
    text = function().replace(" $mc_count;", ";")
    assert text != function()
    assert leaks(tmp_path, text)


def test_control_mc_record_without_the_dnp3_feed_line_fails(tmp_path):
    line = '  [ "$mode" != dnp3 ] || [ -z "$hr23" ] || mc_count=--no-count\n'
    assert function().count(line) == 1
    assert leaks(tmp_path, function().replace(line, ""))
