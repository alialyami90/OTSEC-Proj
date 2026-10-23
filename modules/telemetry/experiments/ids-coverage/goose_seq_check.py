"""Deterministic GOOSE state/sequence checks over a capture, scored against
the frame labels in MANIFEST.tsv.

Per gocbRef, each frame is compared with the previous frame from the same
control block. The checks follow the GOOSE retransmission scheme described
in the dataset README (stNum constant and sqNum incrementing between state
changes; a state change increments stNum, resets sqNum, and carries a new t).
Throwaway experiment: it measures whether simple explainable rules separate
the labeled frames, nothing more.
"""
import datetime
import os
import subprocess
import sys

MANIFEST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "../../../../tests/fixtures/network/public-ot-captures/MANIFEST.tsv")


def parse_t(s):
    # tshark renders goose.t like "May  9, 2019 07:41:32.513999998 UTC".
    head, frac = s.replace(" UTC", "").rsplit(".", 1)
    base = datetime.datetime.strptime(" ".join(head.split()), "%b %d, %Y %H:%M:%S")
    return int(base.replace(tzinfo=datetime.timezone.utc).timestamp()) * 10**9 + int(frac.ljust(9, "0")[:9])


def frames(pcap):
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "goose", "-T", "fields", "-E", "separator=\t",
         "-e", "frame.number", "-e", "goose.gocbRef", "-e", "goose.stNum",
         "-e", "goose.sqNum", "-e", "goose.t"],
        capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        num, ref, st, sq, t = line.split("\t")[:5]
        if st and sq and t:
            yield int(num), ref, int(st), int(sq), parse_t(t)


def check(pcap):
    last, flagged = {}, {}
    for num, ref, st, sq, t in frames(pcap):
        p = last.get(ref)
        reasons = []
        if p:
            pst, psq, pt = p
            if st < pst:
                reasons.append("stnum-regress")
            elif st > pst + 1:
                reasons.append("stnum-jump")
            if st > pst:
                if sq != 0:
                    reasons.append("new-state-sqnum-nonzero")
                if t <= pt:
                    reasons.append("new-state-stale-t")
            elif st == pst:
                if sq != psq + 1:
                    reasons.append("sqnum-gap")
                if t != pt:
                    reasons.append("same-state-t-changed")
        if reasons:
            flagged[num] = (ref, reasons)
        last[ref] = (st, sq, t)
    return flagged


def labels(pcap):
    name = os.path.basename(pcap)
    for line in open(MANIFEST):
        cols = line.rstrip("\n").split("\t")
        if cols[0] == name and cols[4].startswith("attack:frames="):
            return {int(x) for x in cols[4].split("=", 1)[1].split(",")}
    return set()


def main(pcap):
    flagged, truth = check(pcap), labels(pcap)
    hit = sorted(truth & flagged.keys())
    other = sorted(flagged.keys() - truth)
    print(f"labeled attack frames: {sorted(truth) or 'none'}")
    print(f"labeled frames flagged: {len(hit)}/{len(truth)}")
    print(f"other flagged frames: {len(other)}")
    for n in sorted(flagged):
        tag = "LABELED" if n in truth else "other"
        print(f"  frame {n:>6} {tag:7} {flagged[n][0]} {','.join(flagged[n][1])}")


if __name__ == "__main__":
    main(sys.argv[1])
