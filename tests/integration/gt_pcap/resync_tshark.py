"""The pinned tshark's reading of the dnp3-resync-* captures, beside the builder's labels (D6, P4-4-HR25).

Row judge-labels: the labels come from how each capture was built, and
tshark's reading is reported beside them, never used as a label. So this
file fails on one thing only, which is the builder's and not a DNP3 reading:
an IPv4, UDP or TCP checksum that tshark does not read as good, since an
engine that checks checksums would drop the packet. Everything else is
reported: for each message the builder labels, the function code tshark
reads in the packet that holds its last frame, from the link direction the
message was sent in; a difference is listed in tshark-beside.tsv and
counted on stdout, and the run still passes.

Usage: python resync_tshark.py DIR   (reads DIR/<case>.tsv and the captures
they name; writes DIR/tshark-beside.tsv; exits 1 on a checksum or a
different tshark)
"""

import csv
import glob
import os
import subprocess
import sys

from gtlabel import TSHARK

FIELDS = ["frame.number", "ip.checksum.status", "udp.checksum.status", "tcp.checksum.status", "dnp3.ctl.dir",
          "dnp3.al.func", "_ws.malformed"]


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


def main(d):
    version = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    if version != TSHARK:
        print(f"resync_tshark: tshark is {version!r}; the pinned reader is {TSHARK!r}")
        return 1
    bad, beside = [], ["\t".join(["capture", "message", "end", "packet", "label_code", "tshark_codes", "note"])]
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
    print(f"resync_tshark: {len(beside) - 1} messages where tshark's reading differs from the label (reported)")
    for b in bad:
        print(f"resync_tshark: FAIL {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
