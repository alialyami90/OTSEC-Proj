"""GT-PCAP captures as the test-only C13 source sends them (D6, P4-4-R1).

load() gives one capture's frames, label rows and pinned hash: the frames
from GT-PCAP's own writer (dnp3_cases.py), the rows from the committed label
file, the hash from dnp3.sha256. stream() is the byte stream the Go contract
test reads (tests/contract/c13_source_d6_test.go): four captures, each as a
run of its own, so `seq` starts again and the heartbeats' counters do too.

Usage: python c13_stream.py OUT   (rewrites the committed stream)
"""

import csv
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "gt_pcap"))

import c13_source  # noqa: E402
import dnp3_cases  # noqa: E402

LABELS = os.path.join(HERE, "..", "..", "fixtures", "network", "gt-pcap", "dnp3")
COMMITTED = os.path.join(HERE, "..", "..", "contract", "testdata", "c13-source", "gt-pcap-dnp3.stream")
# A challenged, an aggressive and an unchallenged exchange; a reused
# sequence number; a request with no response; an error from the master.
STREAMED = ("dnp3-sa", "dnp3-reused-seq", "dnp3-unauthorized-operate-no-response", "dnp3-sa-failed-master")


def rows(name):
    with open(os.path.join(LABELS, name + ".tsv"), encoding="utf-8", newline="") as f:
        lines = [ln for ln in f.read().split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def pins():
    with open(os.path.join(LABELS, "dnp3.sha256"), encoding="ascii") as f:
        return {ln.split()[1][: -len(".pcap")]: ln.split()[0] for ln in f if ln.strip().endswith(".pcap")}


def names():
    return [n for n, _, _ in dnp3_cases.cases()]


def load(name):
    """(label rows, frames, the capture's pinned SHA-256)."""
    frames = next(f for n, f, _ in dnp3_cases.cases() if n == name)
    return rows(name), frames, pins()[name]


def run_id(i):
    return c13_source.RUN_ID[:-2] + f"{i:02x}"


def stream():
    out = b""
    for i, name in enumerate(STREAMED):
        records = c13_source.Source(*load(name), run_id=run_id(i)).records()
        out += b"".join(c13_source.frame(r) for r in records)
    return out


if __name__ == "__main__":
    with open(sys.argv[1], "wb") as f:
        f.write(stream())
