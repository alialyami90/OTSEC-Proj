"""The pinned tshark's reading of the dnp3-resync-* captures, beside the builder's labels (D6, P4-4-HR25).

Row judge-labels: the labels come from how each capture was built, and
tshark's reading is reported beside them, never used as a label. This file
fails on two things. The first is the builder's, not a DNP3 reading: an
IPv4, UDP or TCP checksum that tshark does not read as good, since an engine
that checks checksums would drop the packet. The second is a change in
tshark's reading: for each message the builder labels, the function code
tshark reads in the packet that holds its last frame, from the link
direction the message was sent in, is compared with the label, and the list
of differences must be the committed one (D4's N1 on #714). That list names
the cause of each row, one of CAUSES, so a reader can tell an expected
difference from a regression. A difference not in it, or one in it that is
not read, fails the run and is printed; it is never used as a label.

Usage: python resync_tshark.py DIR EXPECTED   (reads DIR/<case>.tsv and the
captures they name, and EXPECTED, the committed list; writes
DIR/tshark-beside.tsv; exits 1 on a checksum, a list that differs from
EXPECTED, or a different tshark)
"""

import collections
import csv
import glob
import os
import subprocess
import sys

from gtlabel import TSHARK

FIELDS = ["frame.number", "ip.checksum.status", "udp.checksum.status", "tcp.checksum.status", "dnp3.ctl.dir",
          "dnp3.al.func", "_ws.malformed"]
COLUMNS = ["capture", "message", "end", "packet", "label_code", "tshark_codes", "note"]
# The causes a committed row may name (D4's sort on #714); the committed
# list's header lines say what each means.
CAUSES = {"no-resync", "throw-code", "no-limit", "insert-rebuild"}


def tshark(path):
    out = subprocess.run(["tshark", "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
                          "-o", "tcp.check_checksum:TRUE", "-r", path, "-T", "fields", "-E", "separator=\t",
                          "-E", "occurrence=a", "-E", "aggregator=,", *sum((["-e", f] for f in FIELDS), [])],
                         check=True, capture_output=True, text=True).stdout
    return {int(r[0]): dict(zip(FIELDS, r)) for r in (ln.split("\t") for ln in out.splitlines())}


def packets(cell):
    """The label's packet runs (a, a-b, a-b/s) as a list."""
    out = []
    for run in cell.split(","):
        if run == "-":
            continue
        span, _, step = run.partition("/")
        a, _, b = span.partition("-")
        out += list(range(int(a), int(b or a) + 1, int(step or 1)))
    return out


def labels(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def expected_rows(path):
    """The committed list's rows, the header first, each split on tabs."""
    with open(path, encoding="utf-8") as f:
        return [ln.split("\t") for ln in f.read().replace("\r\n", "\n").split("\n") if ln and not ln.startswith("#")]


def compare(produced, rows):
    """What keeps the produced list (its lines, the header first) from being
    the committed one (its rows, whose last column, cause, names one of
    CAUSES): an empty list when nothing does."""
    out = [f"a cause not in {sorted(CAUSES)}: {r}" for r in rows[1:] if r[-1] not in CAUSES]
    want = collections.Counter("\t".join(r[:-1]) for r in rows)
    got = collections.Counter(produced)
    out += [f"read, not in the expected list: {x}" for x in (got - want).elements()]
    out += [f"in the expected list, not read: {x}" for x in (want - got).elements()]
    return out


def main(d, expected):
    version = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    if version != TSHARK:
        print(f"resync_tshark: tshark is {version!r}; the pinned reader is {TSHARK!r}")
        return 1
    bad, beside = [], ["\t".join(COLUMNS)]
    for path in sorted(glob.glob(os.path.join(d, "dnp3-resync-*.tsv"))):
        rows = labels(path)
        for cap in dict.fromkeys(r["capture"] for r in rows):
            read = tshark(os.path.join(d, cap + ".pcap"))
            for n, r in read.items():
                l4 = "tcp" if r["tcp.checksum.status"] else "udp"
                if r["ip.checksum.status"] != "1" or r[l4 + ".checksum.status"] != "1":
                    bad.append(f"{cap}: packet {n}: ip checksum {r['ip.checksum.status']!r}, "
                               f"{l4} checksum {r[l4 + '.checksum.status']!r}")
            last = {}
            for r in rows:
                if r["capture"] == cap and r["code"] != "-" and r["packets"] != "-":
                    last[(r["message"], r["end"], r["flow"])] = (packets(r["packets"])[-1], r["code"], r["state"])
            for (msg, end, _), (n, code, state) in last.items():
                r = read.get(n, {})
                dirs = r.get("dnp3.ctl.dir", "").split(",")
                funcs = r.get("dnp3.al.func", "").split(",")
                codes = {c for c, dr in zip(funcs, dirs) if c and (dr in ("1", "True")) == (end == "m")}
                if (code in codes) != (state == "seen"):
                    beside.append("\t".join([cap, msg, end, str(n), code, ",".join(sorted(codes)) or "-",
                                             f"the builder labels it {state}"]))
    with open(os.path.join(d, "tshark-beside.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(beside) + "\n")
    diffs = compare(beside, expected_rows(expected))
    print(f"resync_tshark: {len(beside) - 1} messages where tshark's reading differs from the label; "
          f"{len(diffs)} differences from the expected list")
    for b in bad + diffs:
        print(f"resync_tshark: FAIL {b}")
    return 1 if bad or diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
