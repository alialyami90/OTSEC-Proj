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

The false-positive set (fp_set.py, pinned in fp.sha256) is fed the same
way, by the same two commands with its own SUMS and KEPT (D2's N2 on #769).

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

`extend HR23_SUMS DNP3_SUMS CASES SRC DIR OUT_SUMS` adds the captures of
CASES (hr23-cases.tsv) that hr23_cases.py does not write, which
dnp3_cases.py writes into SRC, to the feed (D1's ruling 3 on #776): it
copies each from SRC into DIR and writes OUT_SUMS, HR23_SUMS's pins and
DNP3_SUMS's pins of those captures, for `pin` and `check`. A case capture
pinned in neither file is named, and `extend` exits 1.

The held list (D1's rulings 7056743490 and 7057468942 on #776, D4-122): for
HR-23's captures (not the false-positive set), `check` reads from the
environment, at run time and never from a committed file, OTSEC_HR23_HELD:
the captures that hold a row held under D4-112 item 1.3, separated by commas
or spaces, and OTSEC_HR23_SALT, the run's salt. The list is accepted only
when every name is a capture of CASES and the HMAC-SHA-256 of the sorted
names, each followed by a newline, keyed by the salt's text, equals the
value committed in DIGEST (`list_digest`). Each held capture's row reads
`held (D4-112 item 1.3)` in every cell and is left out of the count, which
says how many captures are held; if one did not run cleanly, the text says
only that a held capture did not, and a counted run exits 3. Without the
list or the salt no per-capture row is printed, and a counted run exits 3.
A list that fails either check is refused, without printing it, and `check`
exits 1; so is any list on a counted run whose salt is weak (weak_salt: the
repository's test salts among them).

Usage: python3 -I hr23_feed.py pin DIR SUMS KEPT
       python3 -I hr23_feed.py extend HR23_SUMS DNP3_SUMS CASES SRC DIR OUT_SUMS
       python3 -I hr23_feed.py check OUT SUMS KEPT [CASES] [--counted]   (CASES for HR-23's captures)
"""
import hashlib
import hmac
import os
import re
import shutil
import sys

# python3 -I leaves the script's own folder off sys.path.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mountcheck import CAPTURE, PLAIN  # noqa: E402

# C0, C1, C1p and C2 (the design's section 4.1), by the names run.sh gives them.
CONFIGS = ("zeek-probe-c0", "zeek-probe", "zeek-probe-c1p", "zeek-probe-c2")
# The held list and the salt (D1's ruling 7056743490 on #776, D4-122): from
# the environment at run time, never from a committed file.
HELD_ENV, SALT_ENV = "OTSEC_HR23_HELD", "OTSEC_HR23_SALT"
HELD = "held (D4-112 item 1.3)"
# The salt is random: at least 32 bytes from a CSPRNG, given as at least
# SALT_MIN hex characters (for example `openssl rand -hex 32`), new for each
# counted run and never reused after a disclosure (D3's N2 on #776). So the
# printed hash of a few short verdict lines cannot be reversed by trying
# each possible verdict, and the committed list digest says nothing without
# it. Only the form is checked here; no check can show entropy.
SALT_MIN = 64
SALT_FORM = re.compile("[0-9a-f]{%d,}" % SALT_MIN)
# A counted run refuses a salt that is plainly not random (D3's N1 on #776,
# D1's ruling 2): one with a period shorter than half its length (the
# repository's test salts, and all one character, among them), or with
# fewer than SALT_DISTINCT distinct characters. A random 64-character hex
# salt has fewer than 10 distinct characters with a chance below 1e-11.
SALT_DISTINCT = 10
# The list's keyed digest for the counted run's salt, committed through D1
# (D1's ruling 1 on #776): the value's line is its only line that is not
# blank and does not start with #.
DIGEST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hr23-held.hmac")


def list_digest(names, salt):
    """HMAC-SHA-256, keyed by SALT's text, of NAMES sorted and deduplicated,
    each followed by a newline."""
    text = "".join(n + "\n" for n in sorted(set(names)))
    return hmac.new(salt.encode("utf-8"), text.encode("utf-8"), hashlib.sha256).hexdigest()


def committed_digest(path):
    """The value in PATH, or None when it cannot be read or is not one
    SHA-256 in hex."""
    try:
        with open(path, encoding="utf-8") as fh:
            vals = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    except OSError:
        return None
    return vals[0] if len(vals) == 1 and re.fullmatch("[0-9a-f]{64}", vals[0]) else None


def case_captures(cases):
    """The captures hr23-cases.tsv (CASES) names: its first column."""
    with open(cases, encoding="utf-8") as fh:
        rows = [ln.rstrip("\n").split("\t") for ln in fh if ln.strip() and not ln.startswith("#")]
    return {r[0] for r in rows[1:]}


def weak_salt(s):
    """True when S has a period shorter than half its length, or fewer
    than SALT_DISTINCT distinct characters."""
    return len(set(s)) < SALT_DISTINCT or any(s[p:] == s[:-p] for p in range(1, len(s) // 2 + 1))


def held_list(known, env=None, counted=False):
    """(captures, why): the set named by HELD_ENV and None; or None and why
    when the list or the salt is not given; or False and why when the list
    names anything that is not in KNOWN (the case captures), when COUNTED
    and the salt is weak (weak_salt), or when the list does not match the
    committed digest under the salt. No name from the list, and not the
    salt, is ever printed."""
    env = os.environ if env is None else env
    names = env.get(HELD_ENV, "").replace(",", " ").split()
    if not names:
        return None, f"the held list ({HELD_ENV}) was not given"
    if any(not PLAIN.fullmatch(n) or n not in known for n in names):
        return False, f"the held list ({HELD_ENV}) names something that is not a case capture; refused"
    salt = salt_of(env)
    if salt is None:
        return None, (f"the salt ({SALT_ENV}) was not given, or is not at least {SALT_MIN} lowercase hex "
                      "characters")
    if counted and weak_salt(salt):
        return False, (f"the salt ({SALT_ENV}) is a test value or plainly not random, and this run is on "
                       "refs/heads/main; refused")
    want = committed_digest(DIGEST)
    if want is None or not hmac.compare_digest(list_digest(names, salt), want):
        return False, f"the held list ({HELD_ENV}) does not match the committed digest under the salt; refused"
    return set(names), None


def salt_of(env=None):
    """SALT_ENV's value, or None when it is not of SALT_FORM."""
    s = (os.environ if env is None else env).get(SALT_ENV, "")
    return s if SALT_FORM.fullmatch(s) else None


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


def extend(hr23_sums, dnp3_sums, cases, src, d, out_sums):
    own, other = pins(hr23_sums), pins(dnp3_sums)
    extra = sorted(case_captures(cases) - set(own))
    lost = [c for c in extra if c not in other]
    if lost:
        print(f"HR-23's feed: refused: case capture(s) pinned in neither pin file: {', '.join(lost)}")
        return 1
    with open(hr23_sums, encoding="utf-8") as fh:
        text = fh.read()
    with open(out_sums, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text + ("" if text.endswith("\n") or not text else "\n") +
                 "".join(f"{other[c]}  {c}.pcap\n" for c in extra))
    for c in extra:
        if os.path.isfile(os.path.join(src, c + ".pcap")):
            shutil.copyfile(os.path.join(src, c + ".pcap"), os.path.join(d, c + ".pcap"))
    print(f"HR-23's feed: {len(extra)} case capture(s) of dnp3_cases.py added: {', '.join(extra) or 'none'}.")
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


def check(out, sums, kept_file, counted, env=None, cases=None):
    caps = plain(sorted(pins(sums)), "the pin file")
    with open(kept_file, encoding="utf-8") as fh:
        kept = plain([ln.strip() for ln in fh if ln.strip()], "the kept list")
    if caps is None or kept is None:
        return 1
    kept = set(kept)
    fp = os.path.basename(sums) == "fp.sha256"
    held = set()
    if not fp:
        held, why = held_list(case_captures(cases) if cases else set(), env, counted)
        if why:
            print(f"\n## HR-23's captures under C0, C1, C1p and C2: not printed\n\nNo per-capture row is printed: {why}"
                  " (D1's ruling 7056743490 on #776)." +
                  (" **This run is on refs/heads/main, so it fails.**" if counted and held is None else ""))
            return 1 if held is False else (3 if counted else 0)
    print(f"\n## HR-23's {'false-positive set' if fp else 'captures'} under C0, C1, C1p and C2 (D4-120 item 3.7): "
          "ran or not\n")
    what = "Every capture `fp_set.py` writes" if fp else \
        "Every capture `hr23_cases.py` writes, and each capture of `hr23-cases.tsv` that `dnp3_cases.py` writes,"
    print(f"{what} equal to its pin in `{os.path.basename(sums)}`, fed to `zeek-probe-c0` (C0), "
          "`zeek-probe` (C1), `zeek-probe-c1p` (C1p) and `zeek-probe-c2` (C2), each with `zeek-patch/viol.zeek`. "
          "Some HR-23 rows are held from per-row publication (D4-112 item 1.3), so this table holds only whether "
          "each configuration ran and its exit code; no log is read here and no row is judged here. The engines' "
          "own output is kept on the runner and is neither printed nor uploaded.\n")
    print("| capture | " + " | ".join(CONFIGS) + " |")
    print("| --- |" + " --- |" * len(CONFIGS))
    bad, unclean, held_unclean = [], set(), False
    for c in caps:
        cells = []
        for cfg in CONFIGS:
            code = exit_code(os.path.join(out, c, cfg)) if c in kept else None
            cells.append("not run" if code is None else
                         "exit code not a number" if code == "not a number" else f"exit {code}")
            if code != "0" and c in held:
                held_unclean = True
            elif code != "0":
                bad.append(f"{c} ({cfg}: {cells[-1]})")
                unclean.add(c)
        print(f"| {c} | " + " | ".join([HELD] * len(CONFIGS) if c in held else cells) + " |")
    if held_unclean:
        bad.append(f"a held capture (which, and how, is {HELD})")
    # Fed but not kept: an output folder of a capture that pin did not keep.
    for c in sorted(set(os.listdir(out)) - kept):
        bad.append(f"{c} (fed, but not a capture that pin kept)")
    n = len(caps) - len(held)
    print(f"\n{n - len(unclean)} of {n} captures ran under all four configurations with exit code 0" +
          (f"; {len(held)} held captures are left out of this count, and their rows read `{HELD}`." if held else "."))
    if bad:
        print("\n**Not run, or a non-zero exit:** " + "; ".join(bad) + ".")
        print("\n" + ("**This run is on refs/heads/main, so it fails: no counted HR-23 result is taken from a run in "
                      "which a capture did not run under every configuration.**" if counted else
                      "This run is not on refs/heads/main, so it stays green; a counted run fails on this."))
    return 3 if bad and counted else 0


def main(argv):
    if len(argv) == 4 and argv[0] == "pin":
        return pin(argv[1], argv[2], argv[3])
    if len(argv) == 7 and argv[0] == "extend":
        return extend(*argv[1:])
    if argv[:1] == ["check"] and 4 <= len(argv) <= 6:
        counted = argv[-1] == "--counted"
        rest = argv[4:len(argv) - counted]
        if len(rest) <= 1 and not any(r.startswith("-") for r in rest):
            return check(argv[1], argv[2], argv[3], counted, os.environ, rest[0] if rest else None)
    sys.stderr.write(__doc__.split("Usage:")[1])
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
