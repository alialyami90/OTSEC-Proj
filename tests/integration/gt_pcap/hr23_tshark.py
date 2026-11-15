"""The pinned tshark's reading of HR-23's stage-2 captures, the malformed set and the false-positive set, beside their labels (D6, P4-4-HR2325S).

The labels come from how each capture was built (hr23_cases.py, fp_set.py),
and tshark's reading is reported beside them, never used as a label, as
resync_tshark.py does for HR-25's captures. Three modes:

- labels DIR EXPECTED: for every message of hr23_cases.py's labels, the
  function codes tshark reads in the packet that holds its last unit,
  whichever way its DIR bit points (a forged DIR is the case, not tshark's
  to settle), against the label's state: seen if tshark reads its code
  there, absent if not.
- fp DIR EXPECTED: for every item of fp_set.py's labels, the function codes
  tshark reads in the item's packets, against the code the item was built
  to carry (classes (3b-data) and (3c)) or none.
- sides OUT EXPECTED PCAP...: the sort of design section 4.7, "Where it
  shows". For each flow of each capture on which tshark reads a DNP3
  application header, the side Zeek gives each end, from the capture's
  first packet of the flow and C0's likely_server_ports (hr23_cases.LIKELY,
  design section 1 items 1 and 2), and how many fragments carry a code
  whose class disagrees with their side: 129 to 131 from the originator,
  any other code from the responder. A flow with none is judged as "does
  not change"; a flow with any, by the twin rule (hr23-conditions.tsv).

Each mode fails on an IPv4, UDP or TCP checksum that tshark does not read as
good, and when its list differs from the committed EXPECTED, whose last
column names a cause from CAUSES (labels and fp) or is the sort itself
(sides). A difference not in it, or one in it no longer read, fails and is
printed; it is never used as a label.

tshark reads port 20001 as DNP3 (-d), O2's port in these captures, and the
false-positive set's own ports of classes (1) to (3c) and (5)'s random
items, so that its reading of their octets is shown.
"""

import collections
import csv
import glob
import os
import subprocess
import sys

from gtlabel import TSHARK
from hr23_cases import LIKELY
from resync_tshark import compare, expected_rows, packets

FIELDS = ["frame.number", "ip.src", "ip.dst", "udp.srcport", "udp.dstport", "tcp.srcport", "tcp.dstport",
          "tcp.flags.syn", "tcp.flags.ack", "ip.checksum.status", "udp.checksum.status", "tcp.checksum.status",
          "dnp3.al.func"]
DECODE = ["tcp.port==20001,dnp3", "udp.port==20001,dnp3"]
FP_DECODE = [f"udp.port=={p},dnp3" for p in (40001, 40002, 40031, 40032, 40033, 40034, 40005)]
RESPONSES = {129, 130, 131}

LABEL_COLUMNS = ["capture", "message", "end", "packet", "label_code", "tshark_codes", "note"]
FP_COLUMNS = ["capture", "item", "packets", "label_code", "tshark_codes", "note"]
SIDE_COLUMNS = ["capture", "l4", "orig", "resp", "how", "apdus", "disagree", "codes"]

# The causes a committed row may name; the committed lists' header lines say what each means.
CAUSES = {"labels": {"reads-malformed", "no-limit"}, "fp": set()}


def tshark(path, decode):
    args = ["tshark", "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE", "-o",
            "tcp.check_checksum:TRUE", "-r", path, "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
            "-E", "aggregator=,"]
    for d in decode:
        args += ["-d", d]
    for f in FIELDS:
        args += ["-e", f]
    out = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    return {int(r[0]): dict(zip(FIELDS, r)) for r in (ln.split("\t") for ln in out.splitlines())}


def bad_checksums(name, read):
    out = []
    for n, r in read.items():
        l4 = "tcp" if r["tcp.srcport"] else "udp"
        if r["ip.checksum.status"] != "1" or r[l4 + ".checksum.status"] != "1":
            out.append(f"{name}: packet {n}: ip checksum {r['ip.checksum.status']!r}, "
                       f"{l4} checksum {r[l4 + '.checksum.status']!r}")
    return out


def codes(r):
    return [c for c in r.get("dnp3.al.func", "").split(",") if c]


def read_labels(path):
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f.read().split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def labels_mode(d):
    bad, beside = [], ["\t".join(LABEL_COLUMNS)]
    for path in sorted(glob.glob(os.path.join(d, "dnp3-*.tsv"))):
        rows = read_labels(path)
        cap = rows[0]["capture"]
        read = tshark(os.path.join(d, cap + ".pcap"), DECODE)
        bad += bad_checksums(cap, read)
        last = {}
        for r in rows:
            if r["code"] != "-":
                last[(r["message"], r["end"])] = (int(r["packets"]), r["code"], r["state"])
        for (msg, end), (n, code, state) in last.items():
            got = codes(read.get(n, {}))
            if (code in got) != (state == "seen"):
                beside.append("\t".join([cap, msg, end, str(n), code, ",".join(sorted(set(got))) or "-",
                                         f"the builder labels it {state}"]))
    return bad, beside


def fp_mode(d):
    bad, beside = [], ["\t".join(FP_COLUMNS)]
    for path in sorted(glob.glob(os.path.join(d, "fp-*.tsv"))):
        rows = read_labels(path)
        cap = rows[0]["capture"]
        read = tshark(os.path.join(d, cap + ".pcap"), FP_DECODE)
        bad += bad_checksums(cap, read)
        for r in rows:
            got = sorted({c for n in packets(r["packets"]) for c in codes(read.get(n, {}))})
            want = [] if r["code"] == "-" else [r["code"]]
            if got != want:
                beside.append("\t".join([cap, r["item"], r["packets"], r["code"], ",".join(got) or "-",
                                         f"class ({r['class']})"]))
    return bad, beside


def zeek_sides(l4, first, flags):
    """(orig, resp, how) for a flow from its first packet's (src, sport,
    dst, dport) and, over TCP, its SYN and ACK flags (design section 1
    item 1; section 4.1 on TCP): a SYN names its sender, a SYN-ACK its
    receiver; otherwise the first sender, swapped when its port is in
    likely_server_ports and the other's is not."""
    src, sport, dst, dport = first
    syn, ack = (v in ("1", "True") for v in flags)
    if l4 == "tcp" and syn and not ack:
        return (src, sport), (dst, dport), "syn"
    if l4 == "tcp" and syn and ack:
        return (dst, dport), (src, sport), "syn-ack"
    s = LIKELY[l4]
    if int(sport) in s and int(dport) not in s:
        return (dst, dport), (src, sport), "first,swapped"
    return (src, sport), (dst, dport), "first"


def sides_rows(path):
    """The sort's rows for one capture. Checksums are not judged here: each
    capture's own job does that, and the PRP pairs' one-octet control
    carries a bad IPv4 header checksum on purpose."""
    name = os.path.basename(path).rsplit(".", 1)[0]
    read = tshark(path, DECODE)
    flows = collections.OrderedDict()
    for n in sorted(read):
        r = read[n]
        l4 = "tcp" if r["tcp.srcport"] else "udp" if r["udp.srcport"] else None
        if l4 is None or not r["ip.src"]:
            continue
        a, b = (r["ip.src"], r[l4 + ".srcport"]), (r["ip.dst"], r[l4 + ".dstport"])
        key = (l4, frozenset((a, b)))
        if key not in flows:
            flows[key] = {"first": (*a, *b), "flags": (r["tcp.flags.syn"], r["tcp.flags.ack"]), "apdus": []}
        flows[key]["apdus"] += [(a, int(c)) for c in codes(r)]
    out = []
    for (l4, _), f in flows.items():
        if not f["apdus"]:
            continue
        orig, resp, how = zeek_sides(l4, f["first"], f["flags"])
        wrong = [c for sender, c in f["apdus"] if (c in RESPONSES) != (sender == resp)]
        out.append([name, l4, f"{orig[0]}:{orig[1]}", f"{resp[0]}:{resp[1]}", how, str(len(f["apdus"])),
                    str(len(wrong)), ",".join(str(c) for c in sorted(set(wrong))) or "-"])
    return out


def main(argv):
    mode = argv[1]
    version = subprocess.run(["tshark", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    if version != TSHARK:
        print(f"hr23_tshark: tshark is {version!r}; the pinned reader is {TSHARK!r}")
        return 1
    if mode in ("labels", "fp"):
        d, expected = argv[2], argv[3]
        bad, beside = labels_mode(d) if mode == "labels" else fp_mode(d)
        out = os.path.join(d, f"tshark-beside-{mode}.tsv")
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(beside) + "\n")
        rows = expected_rows(expected)
        diffs = [x for x in compare(beside, rows) if not x.startswith("a cause not in")]
        diffs += [f"a cause not in {sorted(CAUSES[mode])}: {r}" for r in rows[1:] if r[-1] not in CAUSES[mode]]
        print(f"hr23_tshark {mode}: {len(beside) - 1} rows where tshark's reading differs from the label; "
              f"{len(diffs)} differences from the expected list")
    else:
        out, expected, pcaps = argv[2], argv[3], argv[4:]
        bad, rows = [], ["\t".join(SIDE_COLUMNS)]
        for p in sorted(pcaps):
            rows += ["\t".join(x) for x in sides_rows(p)]
        with open(out, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(rows) + "\n")
        names = {os.path.basename(p).rsplit(".", 1)[0] for p in pcaps}
        want = ["\t".join(r) for r in expected_rows(expected) if r[0] in names or r[0] == "capture"]
        diffs = ([f"read, not in the expected list: {x}" for x in sorted(set(rows) - set(want))]
                 + [f"in the expected list, not read: {x}" for x in sorted(set(want) - set(rows))])
        print(f"hr23_tshark sides: {len(rows) - 1} flows over {len(pcaps)} captures; "
              f"{len(diffs)} differences from the expected list")
    for b in bad + diffs:
        print(f"hr23_tshark: FAIL {b}")
    return 1 if bad or diffs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
