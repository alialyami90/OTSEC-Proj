"""HR-23's feed (D4, brief P4-4-HR23-FEED; D4-120 item 3.7): run.sh's
hr23_feed function and its call in the dnp3 mode, hr23_feed.py, and
table.py's gt_cases. No engine and no Docker run: zeek_run is a stub that
writes each configuration's exit code, and prints a marker that stands for
an engine's own output, which must reach neither the table nor the job log
(D4-112 item 1.3). The captures are D6's, written by the real
hr23_cases.py and checked against the committed hr23.sha256. Each rule has
a control: a mutant of the shell text that must make a check fail.
Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_hr23_feed.py"""
import os
import shutil
import subprocess
import sys

import pytest

import hr23_feed
import table

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
GT = os.path.join(ROOT, "tests", "fixtures", "network", "gt-pcap")
SUMS = os.path.join(GT, "hr23", "hr23.sha256")
SH = shutil.which("sh")
MARK = "ENGINE-OWN-OUTPUT-MARKER"
needs_sh = pytest.mark.skipif(SH is None, reason="no sh on PATH")


def fwd(p):
    return str(p).replace("\\", "/")


def pinned():
    return sorted(hr23_feed.pins(SUMS))


# table.py's gt_cases: dnp3 mode's tables leave HR-23's captures out.

def test_gt_cases_leaves_out_hr23_and_keeps_dnp3():
    got = table.gt_cases(GT)
    assert len(pinned()) == 81
    assert not set(pinned()) & set(got)
    assert set(hr23_feed.pins(os.path.join(GT, "dnp3", "dnp3.sha256"))) <= set(got)


def test_control_gt_cases_lists_hr23_without_the_rule(monkeypatch):
    monkeypatch.setattr(table, "HR23_DIR", "no-such-folder")
    assert set(pinned()) <= set(table.gt_cases(GT))


# hr23_feed.py on its own.

def test_pin_keeps_only_pinned_captures_at_their_pins(tmp_path, capsys):
    (tmp_path / "a.pcap").write_bytes(b"a")
    (tmp_path / "b.pcap").write_bytes(b"b")
    (tmp_path / "x.pcap").write_bytes(b"x")
    (tmp_path / "a.tsv").write_text("label")
    sums = tmp_path / "s.sha256"
    import hashlib
    sums.write_text(f"{hashlib.sha256(b'a').hexdigest()}  a.pcap\n{'0' * 64}  b.pcap\n{'1' * 64}  c.pcap\n")
    assert hr23_feed.pin(str(tmp_path), str(sums)) == 0
    assert sorted(p.name for p in tmp_path.glob("*.pcap")) == ["a.pcap"]
    out = capsys.readouterr().out
    assert "1 of 3 pinned captures" in out
    assert "b.pcap (differs from its pin)" in out and "x.pcap (not in the pin file)" in out
    assert "not written: c.pcap" in out


def outs(root, caps, skip=(), code="0"):
    """An output folder with each configuration's exit code and a log that
    holds MARK, for every capture but the (capture, config) pairs in SKIP."""
    for c in caps:
        for cfg in hr23_feed.CONFIGS:
            if (c, cfg) in skip:
                continue
            d = root / c / cfg
            d.mkdir(parents=True)
            (d / "exit-code").write_text(code + "\n")
            (d / "weird.log").write_text(MARK + "\n")


CHECKS = [  # (what is missing or bad, counted, expected exit code)
    ((), "0", True, 0),
    ({(0, "zeek-probe-c2")}, "0", True, 3),
    ({(0, "zeek-probe-c2")}, "0", False, 0),
    ((), "1", True, 3),
    ((), "1", False, 0),
]


@pytest.mark.parametrize("skip,code,counted,want", CHECKS)
def test_check_prints_only_ran_or_not_and_fails_a_counted_partial_run(tmp_path, capsys, skip, code, counted, want):
    caps = pinned()
    outs(tmp_path, caps, {(caps[i], cfg) for i, cfg in skip}, code)
    assert hr23_feed.check(str(tmp_path), SUMS, counted) == want
    md = capsys.readouterr().out
    assert MARK not in md
    assert sum(1 for ln in md.splitlines() if ln.startswith("| dnp3-")) == 81
    if skip:
        assert "| not run |" in md and "**Not run, or a non-zero exit:**" in md
    if code != "0":
        assert "| exit 1 |" in md


def test_check_refuses_a_stray_flag(tmp_path):
    assert hr23_feed.main(["check", str(tmp_path), SUMS, "--count"]) == 2


# run.sh's hr23_feed function, under sh -eu, with stubs.

def function():
    """hr23_feed as run.sh holds it; CR is stripped for a Windows checkout."""
    with open(os.path.join(HERE, "run.sh"), encoding="utf-8") as f:
        lines = f.read().replace("\r", "").split("\n")
    start = lines.index("hr23_feed() {")
    end = lines.index("}", start)
    return "\n".join(lines[start:end + 1]) + "\n"


# zeek_run as a stub: every capture in $pcaps gets the configuration's exit
# code 0, except the pair named by SKIP_CAP and SKIP_CFG; it prints MARK to
# stdout and stderr, as an engine's warning would reach the job log.
STUB = r'''
zeek_run() {
  for p in "$pcaps"/*.pcap; do
    n=${p##*/}; n=${n%.pcap}
    echo "$MARK $n $2"; echo "$MARK $n $2" >&2
    [ "$n|$2" = "${SKIP_CAP:-}|${SKIP_CFG:-}" ] && continue
    mkdir -p "$out/$n/$2"; echo 0 > "$out/$n/$2/exit-code"
  done
}
'''


def make_root(tmp_path, bad_pin=None):
    """A copy of the builder and its pin file; BAD_PIN names a capture whose
    pin is changed, so that the builder's capture differs from it."""
    root = tmp_path / "root"
    shutil.copytree(os.path.join(ROOT, "tests", "integration", "gt_pcap"), root / "tests" / "integration" / "gt_pcap",
                    ignore=shutil.ignore_patterns("__pycache__", "*.tsv"))
    d = root / "tests" / "fixtures" / "network" / "gt-pcap" / "hr23"
    d.mkdir(parents=True)
    text = open(SUMS, encoding="utf-8").read().replace("\r", "")
    if bad_pin:
        lines = text.split("\n")
        i = next(k for k, ln in enumerate(lines) if ln.endswith("  " + bad_pin + ".pcap"))
        lines[i] = "0" * 64 + lines[i][64:]
        text = "\n".join(lines)
    (d / "hr23.sha256").write_text(text, newline="\n")
    return root


def run_feed(tmp_path, text, ref=None, skip=None, bad_pin=None):
    work = tmp_path / "work"
    work.mkdir(parents=True)
    root = make_root(tmp_path, bad_pin)
    script = work / "probe.sh"
    script.write_text('set -eu\npython3() { "$PY" "$@"; }\n' + STUB + text
                      + 'rc=0\nhr23_feed > "$work/feed.md" || rc=$?\necho "feed rc $rc"\n', newline="\n")
    env = dict(os.environ, PY=fwd(sys.executable), here=fwd(HERE), root=fwd(root), work=fwd(work), MARK=MARK,
               ZEEK_IMAGE="stock", HR23_C1P_IMAGE="c1p", HR23_C2_IMAGE="c2")
    env.pop("GITHUB_REF", None)
    if ref:
        env["GITHUB_REF"] = ref
    if skip:
        env["SKIP_CAP"], env["SKIP_CFG"] = skip
    r = subprocess.run([SH, fwd(script)], env=env, capture_output=True, text=True)
    md = (work / "feed.md").read_text() if (work / "feed.md").exists() else ""
    rc = int(r.stdout.rsplit("feed rc ", 1)[1].split()[0]) if "feed rc " in r.stdout else None
    return rc, md, r.stdout + r.stderr


ONE = "dnp3-udp-relay-write"
FEEDS = [  # (ref, a pair not run, a capture off its pin, the expected exit code)
    ("refs/heads/main", None, None, 0),
    ("refs/heads/main", (ONE, "zeek-probe-c2"), None, 3),
    ("refs/heads/agent/x", (ONE, "zeek-probe-c2"), None, 0),
    (None, (ONE, "zeek-probe-c0"), None, 0),
    ("refs/heads/main", None, ONE, 3),
]


def feed_failures(tmp_path, text):
    bad = []
    for i, (ref, skip, bad_pin, want) in enumerate(FEEDS):
        rc, md, log = run_feed(tmp_path / str(i), text, ref, skip, bad_pin)
        case = f"ref={ref} skip={skip} bad_pin={bad_pin}"
        if rc != want:
            bad.append(f"{case}: exit {rc}, want {want}")
        if MARK in md or MARK in log:
            bad.append(f"{case}: an engine's own output reached the table or the log")
        if sum(1 for ln in md.splitlines() if ln.startswith("| dnp3-")) != 81:
            bad.append(f"{case}: the table does not list the 81 pinned captures")
        if bad_pin and (f"{bad_pin}.pcap (differs from its pin)" not in md
                        or f"| {bad_pin} | not run | not run | not run | not run |" not in md):
            bad.append(f"{case}: the capture off its pin was fed, or not reported")
        if not skip and not bad_pin and "81 of 81 captures ran" not in md:
            bad.append(f"{case}: not every capture ran: {md[-400:]}")
    return bad


@needs_sh
def test_feed_runs_every_pinned_capture_and_fails_only_a_counted_partial_run(tmp_path):
    assert feed_failures(tmp_path, function()) == []


FEED_MUTANTS = {
    "counted-dropped": (" $hr23_counted\n", "\n"),
    "ref-is-main": ("!= refs/heads/main ]", "!= main ]"),
    "engine-output-printed": ('} > "$work/hr23-engines.txt" 2>&1\n', "}\n"),
    "pin-dropped": ('  python3 -I "$here/hr23_feed.py" pin', '  : python3 -I "$here/hr23_feed.py" pin'),
}


@needs_sh
@pytest.mark.parametrize("old,new", FEED_MUTANTS.values(), ids=FEED_MUTANTS.keys())
def test_feed_mutant_is_killed(tmp_path, old, new):
    text = function()
    assert text.count(old) == 1, old
    assert feed_failures(tmp_path, text.replace(old, new)) != []


# The dnp3 mode's call: the feed's table ends dnp3.md, and a failed feed
# fails the job.

def block():
    with open(os.path.join(HERE, "run.sh"), encoding="utf-8") as f:
        lines = f.read().replace("\r", "").split("\n")
    start = lines.index("    feedrc=0")
    end = lines.index("    fi", lines.index('    if [ "$feedrc" != 0 ]; then', start))
    return "\n".join(lines[start:end + 1]) + "\n"


def run_block(tmp_path, text, hr23, feedrc):
    work = tmp_path / "work"
    work.mkdir(parents=True)
    script = work / "probe.sh"
    script.write_text('set -eu\npython3() { echo TABLE; }\nheader() { echo HEADER; }\n'
                      'hr23_feed() { echo FEED-TABLE; return "$FEEDRC"; }\n' + text + 'echo "after the block"\n',
                      newline="\n")
    env = dict(os.environ, here=fwd(HERE), root=fwd(ROOT), gt=fwd(GT), work=fwd(work), hr23=hr23,
               FEEDRC=str(feedrc))
    r = subprocess.run([SH, fwd(script)], env=env, capture_output=True, text=True)
    md = (work / "dnp3.md").read_text() if (work / "dnp3.md").exists() else ""
    return r.returncode, "after the block" in r.stdout, md


def block_failures(tmp_path, text):
    bad = []
    for i, (hr23, feedrc, fails, shown) in enumerate([("1", 0, False, "FEED-TABLE"), ("1", 3, True, "FEED-TABLE"),
                                                      ("1", 1, True, "FEED-TABLE"), ("", 3, False, "Not fed")]):
        rc, after, md = run_block(tmp_path / str(i), text, hr23, feedrc)
        if (rc != 0) != fails or after == fails:
            bad.append(f"hr23={hr23!r} feed exit {feedrc}: exit {rc}, after={after}")
        if shown not in md or not md.startswith("HEADER"):
            bad.append(f"hr23={hr23!r}: dnp3.md lacks {shown!r}: {md!r}")
    return bad


@needs_sh
def test_dnp3_mode_appends_the_feed_and_fails_on_its_failure(tmp_path):
    assert block_failures(tmp_path, block()) == []


BLOCK_MUTANTS = {
    "status-dropped": ("|| feedrc=$?", "|| true"),
    "exit-0": ("      exit 1\n", "      exit 0\n"),
    "feed-not-appended": ('; cat "$work/hr23-feed.md"; }', "; }"),
}


@needs_sh
@pytest.mark.parametrize("old,new", BLOCK_MUTANTS.values(), ids=BLOCK_MUTANTS.keys())
def test_block_mutant_is_killed(tmp_path, old, new):
    text = block()
    assert text.count(old) == 1, old
    assert block_failures(tmp_path, text.replace(old, new)) != []
