"""D6's N1 on #751: one failed fetch of a `.gz` capture does not stop
fetch_captures.sh before the captures after it are tried, and the failed
capture is left absent. The script runs from a copy over a made-up manifest,
with a stub `curl` first on PATH that serves local files; nothing is
fetched from a network. The unfixed loop (gunzip on every `.gz` name) is the
control and must fail the same checks.
Run: python -m pytest -q modules/telemetry/experiments/ids-coverage/test_fetch_captures.py"""
import gzip
import hashlib
import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
SH = shutil.which("sh")

pytestmark = pytest.mark.skipif(SH is None, reason="no sh on PATH")

CURL = """#!/bin/sh
while [ $# -gt 0 ]; do
  case $1 in -o) out=$2; shift 2 ;; --retry) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac
done
src="$SRC/${url##*/}"
[ -f "$src" ] || exit 22
cp "$src" "$out"
"""

# a.pcap and c.pcap fetch; b.pcap.gz, before them in the list, does not;
# d.pcap.gz fetches and is unpacked.
SERVED = {"a.pcap": b"a", "c.pcap": b"c", "d.pcap.gz": gzip.compress(b"d")}
LISTED = ["a.pcap", "b.pcap.gz", "c.pcap", "d.pcap.gz"]

FIXED = """    echo "ok       $name"
    case "$name" in *.gz) gunzip -kf "$out" ;; esac
  else
    echo "MISMATCH $name (expected $sha)"; fail=1
  fi
"""
UNFIXED = """    echo "ok       $name"
  else
    echo "MISMATCH $name (expected $sha)"; fail=1
  fi
  case "$name" in *.gz) gunzip -kf "$out" ;; esac
"""


def script():
    with open(os.path.join(HERE, "fetch_captures.sh"), encoding="utf-8") as f:
        text = f.read().replace("\r", "")
    assert text.count(FIXED) == 1
    return text


def fetch(tmp_path, text):
    """Runs TEXT as fetch_captures.sh at the same depth below a made-up
    repository root. Returns (exit code, stdout, cache folder)."""
    tmp_path = tmp_path.resolve()
    src, bin_, cache = tmp_path / "src", tmp_path / "bin", tmp_path / "cache"
    for d in (src, bin_):
        d.mkdir()
    for n, b in SERVED.items():
        (src / n).write_bytes(b)
    (bin_ / "curl").write_text(CURL, newline="\n")
    os.chmod(bin_ / "curl", 0o755)
    m = tmp_path / "tests" / "fixtures" / "network" / "public-ot-captures"
    m.mkdir(parents=True)
    rows = ["# name\tsha256\turl\tprotocol\tlabel"]
    for n in LISTED:
        sha = hashlib.sha256(SERVED.get(n, b"never served")).hexdigest()
        rows.append(f"{n}\t{sha}\thttp://capture.invalid/{n}\tx\ty")
    (m / "MANIFEST.tsv").write_text("\n".join(rows) + "\n", newline="\n")
    s = tmp_path / "m" / "t" / "e" / "i"
    s.mkdir(parents=True)
    (s / "fetch_captures.sh").write_text(text, newline="\n")
    env = dict(os.environ, SRC=str(src).replace("\\", "/"), PATH=str(bin_) + os.pathsep + os.environ["PATH"])
    r = subprocess.run([SH, str(s / "fetch_captures.sh").replace("\\", "/"), str(cache).replace("\\", "/")],
                       env=env, capture_output=True, text=True)
    return r.returncode, r.stdout, cache


def failures(tmp_path, text):
    rc, out, cache = fetch(tmp_path, text)
    bad = []
    if rc != 1:
        bad.append(f"exit {rc}")
    for n in ("a.pcap", "c.pcap", "d.pcap.gz"):
        if f"ok       {n}" not in out:
            bad.append(f"{n} not reported ok")
    if "MISMATCH b.pcap.gz" not in out:
        bad.append("b.pcap.gz not reported")
    if (cache / "b.pcap.gz").exists() or (cache / "b.pcap").exists():
        bad.append("the failed capture is present")
    if not (cache / "d.pcap").is_file() or (cache / "d.pcap").read_bytes() != b"d":
        bad.append("d.pcap.gz not unpacked")
    return bad


def test_a_failed_gz_fetch_does_not_stop_the_rest(tmp_path):
    assert failures(tmp_path, script()) == []


def test_control_unfixed_loop_stops_at_the_failed_gz(tmp_path):
    bad = failures(tmp_path, script().replace(FIXED, UNFIXED))
    assert "c.pcap not reported ok" in bad and "d.pcap.gz not unpacked" in bad, bad
