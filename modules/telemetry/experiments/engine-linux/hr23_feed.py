"""HR-23's feed (D4, brief P4-4-HR23-FEED; D4-120 item 3.7): run.sh's dnp3
mode, given HR-23's two builds, runs every capture that hr23_cases.py writes
under C0, C1, C1p and C2, each capture equal to its pin in hr23.sha256.

Some HR-23 rows are held from per-row publication (D4-112 item 1.3; D4-120
item 4). So this script prints, for each capture and configuration, only
whether the configuration ran and its exit code. It reads no log, and no
judgement of a row is made or printed here.

`pin DIR SUMS KEPT` leaves in DIR only the captures named in SUMS whose
SHA-256 equals their pin there: every other file that run.sh's zeek_run
would feed, under any extension in mountcheck.py's CAPTURE (the one list
zeek_run, in-container.sh and mountcheck.py accept), is removed, so that no
engine reads it. It writes the kept captures' names to KEPT, prints how
many are kept, and names each one removed or missing. Capture names are
public (SUMS is committed); no reading is.

`check OUT SUMS KEPT [--counted]` reads OUT/<capture>/<config>/exit-code,
as in-container.sh writes it, for every capture SUMS names and each of the
four configurations, and prints the table. A capture that `pin` did not
keep, a configuration with no exit code, an exit code that is not a number,
a non-zero exit code, and an output folder in OUT of a capture that `pin`
did not keep (fed but not kept) all read as not run cleanly, and are
listed. With --counted (run.sh passes it on refs/heads/main) it exits 3
when any did, so that no counted result is taken from a partial run;
otherwise it exits 0. A name in SUMS or KEPT that is not one plain file
name (mountcheck.py's PLAIN: no path separator, not absolute) is refused,
and `check` exits 1.

Usage: python3 -I hr23_feed.py pin DIR SUMS KEPT
       python3 -I hr23_feed.py check OUT SUMS KEPT [--counted]
"""
import hashlib
import os
import re
import sys

# python3 -I leaves the script's own folder off sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mountcheck import CAPTURE, PLAIN  # noqa: E402

# C0, C1, C1p and C2 (the design's section 4.1), by the names run.sh gives them.
CONFIGS = ("zeek-probe-c0", "zeek-probe", "zeek-probe-c1p", "zeek-probe-c2")


def pins(sums):
    """{capture name without .pcap: SHA-256} from a sha256sum file."""
    out = {}
    with open(sums, encoding="utf-8") as fh:
        for ln in fh:
            f = ln.split()
            if len(f) == 2 and f[1].endswith(".pcap"):
                out[f[1][: -len(".pcap")]] = f[0]
    return out


def pin(d, sums, kept_file):
    want = pins(sums)
    kept, removed, seen = [], [], set()
    for n in sorted(os.listdir(d)):
        if not n.endswith(CAPTURE):
            continue
        p = os.path.join(d, n)
        with open(p, "rb") as fh:
            got = hashlib.sha256(fh.read()).hexdigest()
        name = n[: -len(".pcap")] if n.endswith(".pcap") else None
        if name in want:
            seen.add(name)
            if want[name] == got:
                kept.append(name)
                continue
        os.remove(p)
        removed.append(f"{n} ({'differs from its pin' if name in want else 'not in the pin file'})")
    with open(kept_file, "w", encoding="utf-8") as fh:
        fh.write("".join(k + "\n" for k in kept))
    missing = sorted(set(want) - seen)
    print(f"HR-23's feed: {len(kept)} of {len(want)} pinned captures written and equal to their pins.")
    for r in removed:
        print(f"HR-23's feed: removed, not fed: {r}")
    for m in missing:
        print(f"HR-23's feed: not written: {m}.pcap")
    return 0


def exit_code(d):
    """The exit code in D/exit-code: None when there is none, and "not a
    number" when its text is not one, which is never printed."""
    p = os.path.join(d, "exit-code")
    if not os.path.isfile(p):
        return None
    with open(p, encoding="utf-8") as fh:
        t = fh.read().strip()
    return t if re.fullmatch(r"[0-9]+", t) else "not a number"


def plain(names, what):
    """NAMES, or None after printing that one is not a plain file name."""
    bad = [n for n in names if not PLAIN.fullmatch(n)]
    if bad:
        print(f"HR-23's feed: refused: {len(bad)} name(s) in {what} not one plain file name")
        return None
    return names


def check(out, sums, kept_file, counted):
    caps = plain(sorted(pins(sums)), "the pin file")
    with open(kept_file, encoding="utf-8") as fh:
        kept = plain([ln.strip() for ln in fh if ln.strip()], "the kept list")
    if caps is None or kept is None:
        return 1
    kept = set(kept)
    print("\n## HR-23's captures under C0, C1, C1p and C2 (D4-120 item 3.7): ran or not\n")
    print("Every capture `hr23_cases.py` writes, equal to its pin in `hr23.sha256`, fed to `zeek-probe-c0` (C0), "
          "`zeek-probe` (C1), `zeek-probe-c1p` (C1p) and `zeek-probe-c2` (C2), each with `zeek-patch/viol.zeek`. "
          "Some HR-23 rows are held from per-row publication (D4-112 item 1.3), so this table holds only whether "
          "each configuration ran and its exit code; no log is read here and no row is judged here. The engines' "
          "own output is kept on the runner and is neither printed nor uploaded.\n")
    print("| capture | " + " | ".join(CONFIGS) + " |")
    print("| --- |" + " --- |" * len(CONFIGS))
    bad, unclean = [], set()
    for c in caps:
        cells = []
        for cfg in CONFIGS:
            code = exit_code(os.path.join(out, c, cfg)) if c in kept else None
            cells.append("not run" if code is None else
                         "exit code not a number" if code == "not a number" else f"exit {code}")
            if code != "0":
                bad.append(f"{c} ({cfg}: {cells[-1]})")
                unclean.add(c)
        print(f"| {c} | " + " | ".join(cells) + " |")
    # Fed but not kept: an output folder of a capture that pin did not keep.
    for c in sorted(set(os.listdir(out)) - kept):
        bad.append(f"{c} (fed, but not a capture that pin kept)")
    print(f"\n{len(caps) - len(unclean)} of {len(caps)} captures ran under all four "
          "configurations with exit code 0.")
    if bad:
        print("\n**Not run, or a non-zero exit:** " + "; ".join(bad) + ".")
        print("\n" + ("**This run is on refs/heads/main, so it fails: no counted HR-23 result is taken from a run in "
                      "which a capture did not run under every configuration.**" if counted else
                      "This run is not on refs/heads/main, so it stays green; a counted run fails on this."))
    return 3 if bad and counted else 0


def main(argv):
    if len(argv) == 4 and argv[0] == "pin":
        return pin(argv[1], argv[2], argv[3])
    if len(argv) in (4, 5) and argv[0] == "check" and argv[4:] in ([], ["--counted"]):
        return check(argv[1], argv[2], argv[3], argv[4:] == ["--counted"])
    sys.stderr.write(__doc__.split("Usage:")[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
