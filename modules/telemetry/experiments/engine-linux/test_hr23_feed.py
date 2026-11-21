"""HR-23's feed (D4, brief P4-4-HR23-FEED; D4-120 item 3.7): run.sh's
hr23_feed function and its call in the dnp3 mode, hr23_feed.py, and
table.py's gt_cases. No engine and no Docker run: run.sh's own zeek_run runs
with mc_run as a stub, which records each container's image, configuration,
capture and arguments, writes the configuration's exit code, and prints a
marker that stands for an engine's own output, which must reach neither the
table nor the job log (D4-112 item 1.3). The captures are D6's, written by
the real hr23_cases.py and checked against the committed hr23.sha256. Each
rule has a control: a named mutant of the shell or Python text that must
make a check fail (D1's rulings 1 and 2 on #769).
Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_hr23_feed.py"""
import hashlib
import importlib.util
import os
import re
import secrets
import shutil
import subprocess
import sys

import pytest

import hr23_feed
import mountcheck
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


def mutate(text, old, new):
    assert text.count(old) == 1, old
    return text.replace(old, new)


def load_feed(tmp_path, old, new):
    """A mutant of hr23_feed.py, as a module of its own."""
    with open(hr23_feed.__file__, encoding="utf-8") as fh:
        text = mutate(fh.read(), old, new)
    p = tmp_path / "mutant_hr23_feed.py"
    p.write_text(text, encoding="utf-8")
    # The committed digest beside it, which the mutant reads as its own.
    shutil.copy(hr23_feed.DIGEST, tmp_path / "hr23-held.hmac")
    spec = importlib.util.spec_from_file_location("mutant_hr23_feed", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# table.py's gt_cases: dnp3 mode's tables leave HR-23's captures out.

def test_gt_cases_leaves_out_hr23_and_keeps_dnp3():
    got = table.gt_cases(GT)
    assert len(pinned()) == 81
    assert not set(pinned()) & set(got)
    assert set(hr23_feed.pins(os.path.join(GT, "dnp3", "dnp3.sha256"))) <= set(got)


def test_control_gt_cases_lists_hr23_without_the_rule(monkeypatch):
    monkeypatch.setattr(table, "HR23_DIR", "no-such-folder")
    assert set(pinned()) <= set(table.gt_cases(GT))


# One capture list (D1's ruling 1 on #769): zeek_run and in-container.sh
# accept the extensions of mountcheck.py's CAPTURE, which hr23_feed.py's pin
# imports. The control drops one extension from zeek_run's text.

def shell_exts(text):
    """The extensions of each `case ... in *.x|*.y) ;;` capture filter."""
    return [tuple(x.strip("*") for x in m.split("|"))
            for m in re.findall(r'case "?\$\w+"? in (\*\.[a-z|*.]+)\) ;;', text)]


def list_mismatches(run_sh, in_container):
    zr = run_sh[run_sh.index("zeek_run() {"):]
    zr = zr[:zr.index("\n}\n")]
    got = {"zeek_run": shell_exts(zr), "in-container.sh": shell_exts(in_container)}
    return [f"{k}: {v}" for k, v in got.items() if v != [mountcheck.CAPTURE]]


def read(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as fh:
        return fh.read().replace("\r", "")


def test_zeek_run_and_in_container_accept_mountchecks_capture_list():
    assert hr23_feed.CAPTURE is mountcheck.CAPTURE
    assert list_mismatches(read("run.sh"), read("in-container.sh")) == []


def test_control_zeek_run_without_cap_fails():
    text = mutate(read("run.sh"), "case $zr_p in *.pcap|*.pcapng|*.cap)", "case $zr_p in *.pcap|*.pcapng)")
    assert list_mismatches(text, read("in-container.sh")) != []


# hr23_feed.py's pin: every file zeek_run would feed that is not a kept
# pinned capture is removed, whatever its extension. The control,
# pin-pcap-only, looks at .pcap files only.

def pin_failures(m, tmp_path):
    d = tmp_path / "feed"
    d.mkdir()
    (d / "a.pcap").write_bytes(b"a")
    (d / "b.pcap").write_bytes(b"b")
    (d / "x.pcap").write_bytes(b"x")
    (d / "a.pcapng").write_bytes(b"a, another")  # a pinned capture under another extension
    (d / "y.cap").write_bytes(b"y")  # an unnamed .cap
    (d / "a.tsv").write_text("label")
    sums = tmp_path / "s.sha256"
    sums.write_text(f"{hashlib.sha256(b'a').hexdigest()}  a.pcap\n{'0' * 64}  b.pcap\n{'1' * 64}  c.pcap\n")
    kept = tmp_path / "kept"
    bad = []
    if m.pin(str(d), str(sums), str(kept)) != 0:
        bad.append("pin did not exit 0")
    left = sorted(p.name for p in d.iterdir())
    if left != ["a.pcap", "a.tsv"]:
        bad.append(f"left in the feed folder: {left}")
    if kept.read_text() != "a\n":
        bad.append(f"kept: {kept.read_text()!r}")
    return bad


def test_pin_keeps_only_pinned_captures_at_their_pins(tmp_path, capsys):
    assert pin_failures(hr23_feed, tmp_path) == []
    out = capsys.readouterr().out
    assert "1 of 3 pinned captures" in out
    assert "b.pcap (differs from its pin)" in out and "x.pcap (not in the pin file)" in out
    assert "a.pcapng (not in the pin file)" in out and "y.cap (not in the pin file)" in out
    assert "not written: c.pcap" in out


def test_control_pin_pcap_only_fails(tmp_path):
    m = load_feed(tmp_path, "if not n.endswith(CAPTURE):", 'if not n.endswith(".pcap"):')
    assert pin_failures(m, tmp_path) != []


# hr23_feed.py's check.

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


def kept_file(d, names):
    """A kept list, in D, which is never an output folder."""
    d.mkdir(parents=True, exist_ok=True)
    p = d / "kept.txt"
    p.write_text("".join(n + "\n" for n in names))
    return str(p)


# A held capture with a neutral name, added to a copy of the pin file and
# of hr23-cases.tsv, and the held list that names it with a salt (D1's
# rulings 7056743490 and 7057468942 on #776). No real capture is named as
# held in any test. A counted run refuses the test salt of hr23-held.hmac's
# committed value (D1's ruling 2), so the salt is new and random for each
# test session, and the committed digest is the tests' own (committed).
HELD = "syn-held"
SALT = secrets.token_hex(32)
TEST_SALT = "0123456789abcdef" * 4
ENV = {hr23_feed.HELD_ENV: HELD, hr23_feed.SALT_ENV: SALT}


def write_digest(d):
    """DIR/hr23-held.hmac: the digest of HELD under SALT, as committed."""
    p = os.path.join(d, "hr23-held.hmac")
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("# test\n" + hr23_feed.list_digest([HELD], SALT) + "\n")
    return p


@pytest.fixture(autouse=True)
def committed(tmp_path_factory, monkeypatch):
    monkeypatch.setattr(hr23_feed, "DIGEST", write_digest(tmp_path_factory.mktemp("digest")))


def here_copy(tmp_path):
    """A copy of this folder, with the tests' committed digest."""
    here = tmp_path / "here"
    shutil.copytree(HERE, here, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    write_digest(here)
    return here
CASES = os.path.join(ROOT, "tests", "integration", "gt_pcap", "hr23-cases.tsv")


def cases_with_held(d):
    """hr23-cases.tsv with one more row, of the held capture."""
    d.mkdir(parents=True, exist_ok=True)
    p = d / "hr23-cases.tsv"
    text = open(CASES, encoding="utf-8").read()
    first = next(ln for ln in text.split("\n")[1:] if ln and not ln.startswith("#") and not ln.startswith("capture\t"))
    p.write_text(text + ("" if text.endswith("\n") else "\n") + HELD + first[first.index("\t"):] + "\n", newline="\n")
    return str(p)


def sums_with_held(d):
    d.mkdir(parents=True, exist_ok=True)
    p = d / "hr23.sha256"
    p.write_text(open(SUMS, encoding="utf-8").read() + f"{'0' * 64}  {HELD}.pcap\n")
    return str(p)


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
    out = tmp_path / "out"
    outs(out, caps + [HELD], {(caps[i], cfg) for i, cfg in skip}, code)
    assert hr23_feed.check(str(out), sums_with_held(tmp_path / "s"), kept_file(tmp_path, caps + [HELD]), counted,
                           ENV, cases_with_held(tmp_path / "cases")) == want
    md = capsys.readouterr().out
    assert MARK not in md
    assert sum(1 for ln in md.splitlines() if ln.startswith("| dnp3-")) == 81
    if skip:
        assert "| not run |" in md and "**Not run, or a non-zero exit:**" in md
    if code != "0":
        assert "| exit 1 |" in md


TEXT = "ENGINE-TEXT-IN-EXIT-CODE"


def check_failures(m, tmp_path, capsys):
    """What is wrong with module M's check over four cases: a capture fed but
    not kept, a pinned capture not kept but fed, an exit code that is not a
    number, and a path separator or absolute name in the pin file or the
    kept list."""
    bad, caps = [], pinned() + [HELD]
    sums = sums_with_held(tmp_path / "s")
    cases = cases_with_held(tmp_path / "cases")
    # Fed but not kept: an output folder of a capture pin did not keep.
    out = tmp_path / "fed"
    outs(out, caps + ["stray"])
    if m.check(str(out), sums, kept_file(tmp_path / "k-fed", caps), True, ENV, cases) != 3:
        bad.append("fed but not kept: not failed")
    capsys.readouterr()
    # Kept but not fed is "not run"; and a pinned capture pin did not keep,
    # though fed, reads "not run".
    out = tmp_path / "notkept"
    outs(out, caps)
    rc = m.check(str(out), sums, kept_file(tmp_path / "k-notkept", caps[1:]), True, ENV, cases)
    md = capsys.readouterr().out
    if rc != 3 or f"| {caps[0]} | not run | not run | not run | not run |" not in md:
        bad.append("a capture pin did not keep reads as run")
    # An exit code that is not a number: never printed, and not run cleanly.
    out = tmp_path / "text"
    outs(out, caps)
    (out / caps[0] / "zeek-probe" / "exit-code").write_text(TEXT + "\n")
    rc = m.check(str(out), sums, kept_file(tmp_path / "k-text", caps), True, ENV, cases)
    md = capsys.readouterr().out
    if rc != 3 or TEXT in md or "exit code not a number" not in md:
        bad.append("a non-numeric exit code was printed, or read as clean")
    # A path separator or an absolute name is refused.
    for i, name in enumerate(("../up", "/abs", "a/b", "a\\b")):
        d = tmp_path / f"name{i}"
        out = d / "out"
        outs(out, caps)
        s2 = d / "s.sha256"
        s2.write_text(open(sums, encoding="utf-8").read() + f"{'0' * 64}  {name}.pcap\n")
        if m.check(str(out), str(s2), kept_file(d, caps), False, ENV, cases) != 1:
            bad.append(f"pin file name {name!r} not refused")
        if m.check(str(out), sums, kept_file(d, caps + [name]), False, ENV, cases) != 1:
            bad.append(f"kept name {name!r} not refused")
        capsys.readouterr()
    return bad


def test_check_judges_the_kept_captures_and_refuses_bad_names(tmp_path, capsys):
    assert check_failures(hr23_feed, tmp_path, capsys) == []


CHECK_MUTANTS = {
    "fed-not-kept-ignored": ("for c in sorted(set(os.listdir(out)) - kept):", "for c in []:"),
    "kept-ignored": ("os.path.join(out, c, cfg)) if c in kept else None", "os.path.join(out, c, cfg))"),
    "exit-code-not-checked": ('return t if re.fullmatch(r"[0-9]+", t) else "not a number"', "return t"),
    "names-not-checked": ("bad = [n for n in names if not PLAIN.fullmatch(n)]", "bad = []"),
}


@pytest.mark.parametrize("old,new", CHECK_MUTANTS.values(), ids=CHECK_MUTANTS.keys())
def test_check_mutant_is_killed(tmp_path, capsys, old, new):
    m = load_feed(tmp_path, old, new)
    assert check_failures(m, tmp_path, capsys) != []


# hr23_feed.py's extend (D1's ruling 3 on #776): the case captures that
# dnp3_cases.py writes join the feed with their dnp3.sha256 pins, and a case
# capture pinned in neither file is refused.

def extend_run(tmp_path, dnp3_names):
    src, d = tmp_path / "src", tmp_path / "d"
    src.mkdir(parents=True)
    d.mkdir()
    for c in EXTRA_CASES:
        (src / f"{c}.pcap").write_bytes(DNP3_BYTES + c.encode())
    dnp3 = tmp_path / "dnp3.sha256"
    dnp3.write_text("".join(f"{'1' * 64}  {c}.pcap\n" for c in dnp3_names))
    out = tmp_path / "feed.sha256"
    rc = hr23_feed.extend(SUMS, str(dnp3), CASES, str(src), str(d), str(out))
    return rc, out, d


def test_extend_adds_the_dnp3_case_captures(tmp_path, capsys):
    assert EXTRA_CASES
    rc, out, d = extend_run(tmp_path / "a", EXTRA_CASES + ["dnp3-not-a-case"])
    pins = hr23_feed.pins(str(out))
    assert rc == 0 and set(pins) == set(pinned()) | set(EXTRA_CASES)
    assert all(pins[c] == "1" * 64 for c in EXTRA_CASES) and sorted(os.listdir(d)) == [c + ".pcap" for c in EXTRA_CASES]
    # Control: one of them pinned in neither file is refused and named.
    rc, out, _ = extend_run(tmp_path / "b", EXTRA_CASES[1:])
    assert rc == 1 and not out.exists() and EXTRA_CASES[0] in capsys.readouterr().out


def test_check_refuses_a_stray_flag(tmp_path):
    assert hr23_feed.main(["check", str(tmp_path), SUMS, str(tmp_path / "k"), "--count"]) == 2


# run.sh's hr23_feed function and its own zeek_run, under sh -eu, with
# mc_run as a stub.

def function(name="hr23_feed"):
    """NAME as run.sh holds it; CR is stripped for a Windows checkout."""
    lines = read("run.sh").split("\n")
    start = lines.index(name + "() {")
    end = lines.index("}", start)
    return "\n".join(lines[start:end + 1]) + "\n"


# mc_run as a stub: it takes the image from the argument before
# `sh /exp/in-container.sh`, records image|config|arguments and the capture
# fed, prints MARK to stdout and stderr, as an engine's warning would reach
# the job log, and writes exit code 0 into the folder in-container.sh would,
# except for the pair named by SKIP_CAP and SKIP_CFG.
STUB = r'''
mc_run() {
  case " $* " in *" /exp/ports.zeek "*)
    # ports.zeek's run (cfg-ports): record the mount check's folder, the
    # captures' mount, image and arguments, write a line to the mount
    # check's fd 9, mark the check failed when PORTS_FAIL is set, and print
    # the two lines ports.zeek would, beside MARK.
    echo "$mc" >> "$work/ports-mc"
    echo "$FD9" >&9
    [ -z "${PORTS_FAIL:-}" ] || { mkdir -p "$mc"; echo x > "$mc/FAILED"; }
    while [ "$1" != zeek ]; do case $1 in *:/pcaps:ro) echo "${1%:/pcaps:ro}" >> "$work/ports-mount" ;; esac; last=$1; shift; done
    echo "$last|$*" >> "$work/ports"
    echo "$MARK"; echo "likely_server_ports at zeek_init, priority -1000: tcp [20000]; udp [20000]"
    echo "likely_server_ports at zeek_done: tcp [20000]; udp [20000]"
    return 0 ;;
  esac
  while [ "$#" -gt 3 ] && ! { [ "$2" = sh ] && [ "$3" = /exp/in-container.sh ]; }; do shift; done
  i=$1; shift 3
  c=$2; p=${3##*/}; shift 3
  n=${p%.*}
  echo "$i|$c|$*" >> "$work/calls"
  echo "$p|$c" >> "$work/fed"
  echo "$MARK $n $c"; echo "$MARK $n $c" >&2
  [ "$n|$c" != "${SKIP_CAP:-}|${SKIP_CFG:-}" ] || return 0
  mkdir -p "$out/$n/$c"; echo 0 > "$out/$n/$c/exit-code"
}
'''

ARGS = "/exp/probe.zeek /exp/zeek-patch/viol.zeek"
WIRING = {"stock|zeek-probe-c0|" + ARGS + " OtsecProbe::log_dir=F", "stock|zeek-probe|" + ARGS,
          "c1p|zeek-probe-c1p|" + ARGS, "c2|zeek-probe-c2|" + ARGS}


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
    # The neutral held capture, which the feed's python3 below writes.
    (d / "hr23.sha256").write_text(text + f"{hashlib.sha256(b'syn').hexdigest()}  {HELD}.pcap\n", newline="\n")
    # The case captures of dnp3_cases.py, as run_feed writes them into
    # WORK/dnp3, pinned in a dnp3.sha256 of their own.
    (d.parent / "dnp3").mkdir()
    (d.parent / "dnp3" / "dnp3.sha256").write_text(
        "".join(f"{hashlib.sha256(DNP3_BYTES + c.encode()).hexdigest()}  {c}.pcap\n" for c in EXTRA_CASES), newline="\n")
    # The judge's inputs: D6's malformed set and cases (with the held
    # capture's row), and the builder's labels.
    shutil.copy(os.path.join(ROOT, "tests", "integration", "gt_pcap", "hr23-malformed.tsv"),
                root / "tests" / "integration" / "gt_pcap")
    shutil.copy(cases_with_held(tmp_path / "cases"), root / "tests" / "integration" / "gt_pcap")
    for f in os.listdir(os.path.join(GT, "hr23")):
        if f.endswith(".tsv"):
            shutil.copy(os.path.join(GT, "hr23", f), d)
    shutil.copytree(os.path.join(GT, "fp"), d.parent / "fp")
    return root


DNP3_BYTES = b"syn-dnp3-"
EXTRA_CASES = sorted(hr23_feed.case_captures(CASES) - set(pinned()))
FD9 = "MOUNT-CHECK-FD9-MARKER"


def run_feed(tmp_path, text, ref=None, skip=None, bad_pin=None, extra=None, here=None, held=True, env_extra=None):
    """hr23_feed in TEXT with run.sh's zeek_run; EXTRA is a shell command
    run on the feed folder after hr23_cases.py writes it, before pin. The
    neutral held capture is written beside hr23_cases.py's, and HELD gives
    the held list (HELD itself, or the string given) and the salt in the
    environment. fd 9 is the job's stderr, as in run.sh. HERE is by default
    a copy of this folder with the tests' committed digest (here_copy)."""
    here = here_copy(tmp_path) if here is None else here
    work = tmp_path / "work"
    (work / "dnp3").mkdir(parents=True)
    for c in EXTRA_CASES:
        (work / "dnp3" / f"{c}.pcap").write_bytes(DNP3_BYTES + c.encode())
    root = make_root(tmp_path, bad_pin)
    script = work / "probe.sh"
    script.write_text('set -eu\nexec 9>&2\nmc=$work/containers-dnp3\n'
                      'python3() {\n  "$PY" "$@" || return $?\n'
                      '  case $1 in */hr23_cases.py) printf syn > "$2/' + HELD + '.pcap"\n'
                      '    [ -z "${EXTRA:-}" ] || sh -c "$EXTRA" sh "$2" ;; esac\n}\n'
                      + STUB + function("zeek_run") + text
                      + 'rc=0\nhr23_feed > "$work/feed.md" || rc=$?\necho "feed rc $rc"\necho "$img" > "$work/img"\n',
                      newline="\n")
    env = dict(os.environ, PY=fwd(sys.executable), here=fwd(here), root=fwd(root), work=fwd(work), MARK=MARK,
               ZEEK_IMAGE="stock", HR23_C1P_IMAGE="c1p", HR23_C2_IMAGE="c2", img="stock", locked="", pkgs="P", FD9=FD9,
               **(env_extra or {}))
    for k in ("GITHUB_REF", hr23_feed.HELD_ENV, hr23_feed.SALT_ENV):
        env.pop(k, None)
    if held:
        env.update({hr23_feed.HELD_ENV: HELD if held is True else held, hr23_feed.SALT_ENV: SALT})
    if ref:
        env["GITHUB_REF"] = ref
    if skip:
        env["SKIP_CAP"], env["SKIP_CFG"] = skip
    if extra:
        env["EXTRA"] = extra
    r = subprocess.run([SH, fwd(script)], env=env, capture_output=True, text=True)

    def text_of(name):
        p = work / name
        return p.read_text() if p.exists() else ""
    rc = int(r.stdout.rsplit("feed rc ", 1)[1].split()[0]) if "feed rc " in r.stdout else None
    return (rc, text_of("feed.md"), r.stdout + r.stderr, text_of("calls"), text_of("fed"), text_of("img").strip(),
            text_of("ports"), text_of("ports-mc"), text_of("ports-mount"))


ONE = "dnp3-udp-relay-write"
# (ref, a pair not run, a capture off its pin, extra files, whether the
# hr23 check fails it as partial). A run on main exits 3 only when partial.
FEEDS = [
    ("refs/heads/main", None, None, None, False),
    ("refs/heads/main", (ONE, "zeek-probe-c2"), None, None, True),
    ("refs/heads/agent/x", (ONE, "zeek-probe-c2"), None, None, False),
    (None, (ONE, "zeek-probe-c0"), None, None, False),
    ("refs/heads/main", None, ONE, None, True),
    # An unnamed .cap.
    ("refs/heads/main", None, None, 'printf x > "$1/stray.cap"', False),
    # A pinned capture rewritten under another extension, with different bytes.
    ("refs/heads/main", None, None, f'mv "$1/{ONE}.pcap" "$1/{ONE}.pcapng"; printf x >> "$1/{ONE}.pcapng"', True),
    # A pinned capture copied under another extension, with different bytes.
    ("refs/heads/main", None, None, f'cp "$1/{ONE}.pcap" "$1/{ONE}.cap"; printf x >> "$1/{ONE}.cap"', False),
]
PARTIAL = "no counted HR-23 result is taken from a run in which a capture did not run"
FP_SUMS = os.path.join(GT, "fp", "fp.sha256")
# The fp capture cfg-ports reads: the first that pin keeps, in file-name order.
FP_FIRST = sorted(p + ".pcap" for p in hr23_feed.pins(FP_SUMS))[0][: -len(".pcap")]
N_FED = len(pinned()) + len(EXTRA_CASES)
PORTS_WIRING = {"stock|zeek -C -r /pcaps/{0}.pcap " + ARGS + " OtsecProbe::log_dir=F /exp/ports.zeek",
                "stock|zeek -C -r /pcaps/{0}.pcap " + ARGS + " /exp/ports.zeek",
                "c1p|zeek -C -r /pcaps/{0}.pcap " + ARGS + " /exp/ports.zeek",
                "c2|zeek -C -r /pcaps/{0}.pcap " + ARGS + " /exp/ports.zeek"}


def feed_failures(tmp_path, text, first=False, here=None):
    bad = []
    for i, (ref, skip, bad_pin, extra, partial) in enumerate(FEEDS):
        rc, md, log, calls, fed, img, ports, ports_mc, ports_mount = run_feed(tmp_path / str(i), text, ref, skip,
                                                                               bad_pin, extra, here)
        case = f"case {i}: ref={ref} skip={skip} bad_pin={bad_pin} extra={extra}"
        want = 3 if ref == "refs/heads/main" and partial else 0
        if rc != want:
            bad.append(f"{case}: exit {rc}, want {want}")
        hr23_md = md.split("## HR-23's false-positive set")[0]
        if (PARTIAL in hr23_md) != (partial and want == 3):
            bad.append(f"{case}: the check's counted failure is {'missing' if partial else 'wrongly there'}")
        if f"| {HELD} | " + " | ".join([hr23_feed.HELD] * 4) + " |" not in hr23_md or "1 held captures" not in hr23_md:
            bad.append(f"{case}: the held capture's row is not held in the check")
        if "salted SHA-256" not in md or "### hr23-cases.tsv's rows" not in md:
            bad.append(f"{case}: the cases' rows were not judged")
        if MARK in md or MARK in log:
            bad.append(f"{case}: an engine's own output reached the table or the log")
        if "10 of 10 captures ran under all four" not in md:
            bad.append(f"{case}: the false-positive set was not fed and checked")
        if set(ports.split("\n")) - {""} != {w.format(FP_FIRST) for w in PORTS_WIRING}:
            bad.append(f"{case}: ports.zeek did not run under each configuration's image and scripts: {ports!r}")
        # D3's N1 on #776: a capture of the false-positive set, the mount
        # check's lines and record off the job log and dnp3.md.
        if set(ports_mount.split("\n")) - {""} != {fwd(tmp_path / str(i) / "work" / "fp")}:
            bad.append(f"{case}: cfg-ports read a capture outside the false-positive set: {ports_mount!r}")
        if set(ports_mc.split("\n")) - {""} != {fwd(tmp_path / str(i) / "work" / "containers-ports")}:
            bad.append(f"{case}: cfg-ports' containers recorded with the mode's: {ports_mc!r}")
        if FD9 in log or FD9 in md:
            bad.append(f"{case}: the mount check's lines for cfg-ports reached the job log or the table")
        if sum(1 for ln in md.splitlines() if ln.startswith("- c") and "tcp 20000; udp 20000" in ln) != 4:
            bad.append(f"{case}: likely_server_ports not printed under every configuration")
        if sum(1 for ln in hr23_md.splitlines() if ln.startswith("| dnp3-")) != N_FED:
            bad.append(f"{case}: the table does not list the {N_FED} pinned captures")
        if set(calls.split("\n")) - {""} != WIRING:
            bad.append(f"{case}: images or arguments differ from C0, C1, C1p and C2's: "
                       f"{sorted(set(calls.split()) - set(' '.join(WIRING).split()))}")
        if img != "stock":
            bad.append(f"{case}: img after the feed is {img!r}, not the stock image")
        fed_names = {ln.split("|")[0] for ln in fed.split("\n") if ln and not ln.startswith("fp-")}
        fp_fed = [ln for ln in fed.split("\n") if ln.startswith("fp-")]
        if sorted({ln.split("|")[0] for ln in fp_fed}) != sorted(p + ".pcap" for p in hr23_feed.pins(FP_SUMS)) \
                or len(fp_fed) != 40:
            bad.append(f"{case}: the false-positive set's classes not each fed once to each configuration")
        want_fed = {p + ".pcap" for p in pinned() + [HELD] + EXTRA_CASES} - ({bad_pin + ".pcap"} if bad_pin else set())
        if extra and ".pcapng" in extra:
            want_fed.discard(ONE + ".pcap")
        if fed_names != want_fed:
            bad.append(f"{case}: fed other than the kept captures: {sorted(fed_names ^ want_fed)}")
        if len([ln for ln in fed.split("\n") if ln and not ln.startswith("fp-")]) != 4 * len(want_fed):
            bad.append(f"{case}: not each kept capture fed once to each configuration")
        if bad_pin and (f"{bad_pin}.pcap (differs from its pin)" not in md
                        or f"| {bad_pin} | not run | not run | not run | not run |" not in md):
            bad.append(f"{case}: the capture off its pin was fed, or not reported")
        if not partial and ref == "refs/heads/main" and f"{N_FED} of {N_FED} captures ran" not in md:
            bad.append(f"{case}: not every capture ran")
        if first and bad:
            break
    return bad


@needs_sh
def test_feed_runs_every_pinned_capture_and_fails_only_a_counted_partial_run(tmp_path):
    assert feed_failures(tmp_path, function()) == []


@needs_sh
def test_feed_without_the_held_list_prints_no_capture_row_and_fails_a_counted_run(tmp_path):
    # Control: test_feed_runs_every_pinned_capture_..., the same feed with
    # the held list and the salt, prints every row.
    for ref, want in (("refs/heads/main", 3), ("refs/heads/agent/x", 0)):
        rc, md = run_feed(tmp_path / str(want), function(), ref, held=False)[:2]
        assert rc == want
        hr23_md, rest = md.split("## HR-23's false-positive set")
        assert "| dnp3-" not in hr23_md and HELD not in md and "No per-capture row is printed" in hr23_md
        cases_md = rest.split("### hr23-cases.tsv's rows")[1]
        assert "Not judged or printed" in cases_md and "| dnp3-" not in cases_md and "SHA-256" not in cases_md
        # D1's ruling 2 on #776: nor does the malformed set print a row.
        assert "| dnp3-" not in rest


FEED_MUTANTS = {
    "counted-dropped": ('hr23-cases.tsv" $hr23_counted', 'hr23-cases.tsv"'),
    "ref-is-main": ("!= refs/heads/main ]", "!= main ]"),
    "engine-output-printed": ('} > "$work/hr23-engines.txt" 2>&1\n', "}\n"),
    "pin-dropped": ('  python3 -I -B "$here/hr23_feed.py" pin "$h"', '  : python3 -I -B "$here/hr23_feed.py" pin "$h"'),
    # D6's N1 on #769: the five wiring mutants.
    "c1p-on-stock": ("    img=$HR23_C1P_IMAGE\n", ""),
    "c2-on-c1p": ("    img=$HR23_C2_IMAGE\n", ""),
    "c2-without-viol": ("zeek-probe-c2 /exp/probe.zeek /exp/zeek-patch/viol.zeek", "zeek-probe-c2 /exp/probe.zeek"),
    "c0-without-log-dir": (" OtsecProbe::log_dir=F\n", "\n"),
    "img-not-restored": ("    img=$ZEEK_IMAGE\n", ""),
    # D2's N2 = D6's G1 on #769: the false-positive set fed and pin-checked.
    "fp-pin-dropped": ('  python3 -I -B "$here/hr23_feed.py" pin "$work/fp"', '  : python3 -I -B "$here/hr23_feed.py" pin "$work/fp"'),
    "fp-not-fed": ('"$work/fp=$work/out-fp"', ""),
    "fp-not-checked": ('  python3 -I -B "$here/hr23_feed.py" check "$work/out-fp"', '  : python3 -I -B "$here/hr23_feed.py" check "$work/out-fp"'),
    # D2's N1 on #769: likely_server_ports under every configuration.
    "ports-c2-on-stock": ('"zeek-probe-c2=$HR23_C2_IMAGE="', '"zeek-probe-c2=$ZEEK_IMAGE="'),
    "ports-c0-without-log-dir": ('"zeek-probe-c0=$ZEEK_IMAGE=OtsecProbe::log_dir=F"', '"zeek-probe-c0=$ZEEK_IMAGE="'),
    "judge-dropped": ('  python3 -I -B "$here/table.py" hr23judge', '  : python3 -I -B "$here/table.py" hr23judge'),
    # D1's ruling 3 on #776: the case captures of dnp3_cases.py fed.
    "extend-dropped": ('  python3 -I -B "$here/hr23_feed.py" extend', '  : python3 -I -B "$here/hr23_feed.py" extend'),
    # D3's N1 on #776: cfg-ports on the false-positive set, off the job log.
    "ports-on-hr23-set": ('-v "$work/fp:/pcaps:ro"', '-v "$h:/pcaps:ro"'),
    "ports-first-hr23": ('first=$(head -n 1 "$work/fp-kept.txt")', 'first=$(head -n 1 "$work/hr23-kept.txt")'),
    "ports-fd9-on-job-log": (' 9>> "$work/ports-hr23/mountcheck.txt"', ""),
    "ports-in-modes-record": ("  mc=$work/containers-ports\n", ""),
}


@needs_sh
@pytest.mark.parametrize("old,new", FEED_MUTANTS.values(), ids=FEED_MUTANTS.keys())
def test_feed_mutant_is_killed(tmp_path, old, new):
    assert feed_failures(tmp_path, mutate(function(), old, new), first=True) != []


# D1's ruling 1 on #776: a held list that is not the committed one, here a
# valid case capture, stops the feed at the check, before any other table.

def refused_failures(tmp_path, text):
    rc, md, log = run_feed(tmp_path, text, "refs/heads/main", held=ONE)[:3]
    bad = []
    if rc != 1:
        bad.append(f"exit {rc}, not 1")
    if "| dnp3-" in md or "false-positive set" in md or "HR-23's judge" in md or ONE in md + log:
        bad.append("a table was printed after the refusal, or the list was echoed")
    return bad


@needs_sh
def test_feed_stops_on_a_refused_held_list(tmp_path):
    assert refused_failures(tmp_path, function()) == []


@needs_sh
def test_control_feed_going_on_after_a_refused_list_is_killed(tmp_path):
    text = mutate(function(), '  [ "$rc" != 1 ] || return 1\n', "")
    assert refused_failures(tmp_path, text) != []


# D3's N1 on #776: a rule of the mount check that failed on a cfg-ports
# container, whose record is kept apart, still stops the run.

def ports_fail_failures(tmp_path, text):
    rc, md, log = run_feed(tmp_path, text, "refs/heads/agent/x", env_extra={"PORTS_FAIL": "1"})[:3]
    if rc is None and "failed on the cfg-ports step; the run stops" in log:
        return []
    return [f"the feed went on (exit {rc})"]


@needs_sh
def test_a_failed_mount_check_on_cfg_ports_stops_the_run(tmp_path):
    assert ports_fail_failures(tmp_path, function()) == []


@needs_sh
@pytest.mark.parametrize("old,new", [('  if [ -e "$work/containers-ports/FAILED" ]; then', "  if false; then"),
                                     ("  mc=$work/containers-ports\n", "")],
                         ids=["not-checked", "mode-folder"])
def test_control_a_failed_mount_check_on_cfg_ports_ignored_is_killed(tmp_path, old, new):
    assert ports_fail_failures(tmp_path, mutate(function(), old, new)) != []


# The pin mutant through the whole feed: hr23_feed.py's pin looks at .pcap
# files only, so the .cap and .pcapng files are fed.
@needs_sh
def test_feed_control_pin_pcap_only_is_killed(tmp_path):
    here = tmp_path / "here"
    here.mkdir()
    shutil.copy(os.path.join(HERE, "mountcheck.py"), here)
    write_digest(here)
    (here / "hr23_feed.py").write_text(mutate(read("hr23_feed.py"), "if not n.endswith(CAPTURE):",
                                              'if not n.endswith(".pcap"):'), encoding="utf-8")
    bad = feed_failures(tmp_path / "f", function(), here=here)
    assert any("case 5:" in b for b in bad) and any("case 6:" in b for b in bad) and any("case 7:" in b for b in bad)


# D6's N1 on #769: hr23_feed.py imports mountcheck.py, so its two calls in
# run.sh must not write __pycache__ into $here, the folder mounted at /exp
# and hashed for every container. The feed runs on a copy of this folder;
# the control is the same feed with -B dropped from both calls.

def here_hash_changed(tmp_path, text):
    here = here_copy(tmp_path)
    before = mountcheck.hash_tree(str(here))
    rc = run_feed(tmp_path, text, here=here)[0]
    assert rc == 0
    return mountcheck.hash_tree(str(here)) != before


@needs_sh
def test_feed_leaves_the_mounted_folder_unchanged(tmp_path):
    assert not here_hash_changed(tmp_path, function())


@needs_sh
def test_control_feed_without_dont_write_bytecode_changes_the_folder(tmp_path):
    text = function()
    assert text.count('python3 -I -B "$here/hr23_feed.py"') == 5
    assert here_hash_changed(tmp_path, text.replace('python3 -I -B "$here/hr23_feed.py"', 'python3 -I "$here/hr23_feed.py"'))


# The dnp3 mode's call: the feed's table ends dnp3.md, and a failed feed
# fails the job.

def block():
    lines = read("run.sh").split("\n")
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
               FEEDRC=str(feedrc), dnp3_counted="")
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
    assert block_failures(tmp_path, mutate(block(), old, new)) != []
