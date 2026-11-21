"""Held captures in HR-23's judge and check (D1's ruling 7056743490 on
#776, D4-122): table.py's cases and hr23_feed.py's check, on synthetic
captures with neutral names (syn-*) and results made up here. No engine
runs, no real capture is named as held, and no log is read. Each rule has a
named control: a mutant of the script's text that must make the rule's
check fail.
Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_hr23_held.py"""
import importlib.util
import sys

import pytest

import hr23_feed
import table

C0, C1, C1P, C2 = table.JUDGED
HOLD, MARK = "syn-held", "HELD-RESULT-MARK"
SALT = "test-only-salt-" + "1" * 32
ENV = {hr23_feed.HELD_ENV: HOLD, hr23_feed.SALT_ENV: SALT}
COLS = ("capture", "condition", "l4", "src", "sport", "dst", "dport", "code", "objects", "sa", "show", "frames",
        "protocol", "direction", "c0", "c1", "c1p", "c2", "fix", "basis")


def load(module, old, new, name):
    """A mutant of MODULE's text, as a module of its own."""
    with open(module.__file__, encoding="utf-8") as fh:
        text = fh.read()
    assert text.count(old) == 1, old
    spec = importlib.util.spec_from_loader(name, loader=None)
    m = importlib.util.module_from_spec(spec)
    m.__file__ = module.__file__
    exec(compile(text.replace(old, new), module.__file__, "exec"), m.__dict__)
    return m


def case(cap, cond="function", code="1", objects="g60v1", fix="a", **cells):
    r = dict(capture=cap, condition=cond, l4="udp", src="192.0.2.14", sport="20000", dst="192.0.2.20",
             dport="20000", code=code, objects=objects, sa="", show="", frames="", protocol="dnp3",
             direction="none", c0="fail", c1="pass", c1p="pass", c2="pass", fix=fix, basis="")
    r.update(cells)
    return r


def make_root(tmp_path, rows, relay=()):
    """A root with ROWS as hr23-cases.tsv, their captures pinned, and a
    builder's label for each capture in RELAY whose first sender is the
    outstation."""
    root = tmp_path / "root"
    gp = root / table.GP
    gp.mkdir(parents=True)
    (gp / "hr23-cases.tsv").write_text("# synthetic\n" + "\t".join(COLS) + "\n" +
                                       "".join("\t".join(r[c] for c in COLS) + "\n" for r in rows))
    gt = root / table.GT / table.HR23_DIR
    gt.mkdir(parents=True)
    (gt / "hr23.sha256").write_text("".join(f"{'0' * 64}  {c}.pcap\n" for c in sorted({r["capture"] for r in rows})))
    for cap in relay:
        (gt / f"{cap}.tsv").write_text("flow\trole\tpackets\nudp 192.0.2.20:20000 > 192.0.2.14:20000\toutstation\t1\n")
    return str(root)


def fake(results):
    """case_results from RESULTS: {capture: {cfg: result}}, one result for
    every row of the capture; a held capture's results carry MARK."""
    def case_results(rows, d, cfg, pcap, ports, want):
        return {n: (results[r["capture"]][cfg], f"cite {r['capture']}") for n, r in rows}
    return case_results


def run(m, monkeypatch, capsys, tmp_path, rows, results, env=ENV, counted=True, relay=(), feed=hr23_feed):
    monkeypatch.setattr(m, "case_results", fake(results))
    monkeypatch.setitem(sys.modules, "hr23_feed", feed)
    rc = m.cases(str(tmp_path / "out"), str(tmp_path / "pcaps"), make_root(tmp_path, rows, relay),
                 {cfg: None for cfg in table.JUDGED}, {}, counted, env)
    return rc, capsys.readouterr().out


ALL = lambda v: {cfg: v for cfg in table.JUDGED}  # noqa: E731
# syn-a: a row that shows fix a. HOLD: two rows whose results would raise a
# judge-control finding and a judge-regression finding naming HOLD.
ROWS = [case("syn-a"), case(HOLD), case(HOLD, "objects")]
RESULTS = {"syn-a": {C0: "fail", C1: "pass", C1P: "pass", C2: "pass"}, HOLD: ALL(f"fail ({MARK})")}
HELD_LINE = f"| {HOLD} | function | 1 | g60v1 | " + " | ".join([hr23_feed.HELD] * 5) + " |"


# Rule 1: every row of a held capture reads held, nothing else of it is
# printed, and it is left out of the counts, which say how many are held.

def held_capture_problems(m, monkeypatch, capsys, tmp_path):
    rc, out = run(m, monkeypatch, capsys, tmp_path, ROWS, RESULTS)
    bad = []
    if rc != 0:
        bad.append(f"exit {rc}")
    if MARK in out or f"cite {HOLD}" in out:
        bad.append("a held capture's result or citation was printed")
    about = [ln for ln in out.splitlines() if HOLD in ln]
    if about != [HELD_LINE, HELD_LINE.replace("| function |", "| objects |")]:
        bad.append(f"lines about the held capture other than its held rows: {len(about)}")
    if "Cells: 4 as pinned, 0 not as pinned, 0 unknown, 0 reported. Fix readings: 1 a shows. " \
       "1 held captures are left out of these counts." not in out:
        bad.append("the counts include the held capture, or do not say how many are held")
    if "| syn-a | function | 1 | g60v1 | as pinned: fail cite syn-a |" not in out or "| a shows |" not in out:
        bad.append("the other capture's row is not printed")
    return bad


def test_every_row_of_a_held_capture_reads_held_and_is_left_out_of_the_counts(monkeypatch, capsys, tmp_path):
    assert held_capture_problems(table, monkeypatch, capsys, tmp_path) == []


HELD_MUTANTS = {
    "rows-not-held": ('        if r["capture"] in held:\n            secret.append', '        if False:\n            secret.append'),
    "findings-not-held": ("shown = [t for caps, t in findings if not caps & held]", "shown = [t for caps, t in findings]"),
}


@pytest.mark.parametrize("old,new", HELD_MUTANTS.values(), ids=HELD_MUTANTS.keys())
def test_control_held_capture_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    m = load(table, old, new, "mutant_table")
    assert held_capture_problems(m, monkeypatch, capsys, tmp_path) != []


# Rule 2: a fix reading of another capture that rests on a held capture
# reads `held (depends on a held row)`. Both rules that read another
# capture's rows are tried, each with a neutral capture in the place of
# the one it reads.

DEP = "held (depends on a held row)"


def objects_case(m, monkeypatch):
    monkeypatch.setattr(m, "OBJ_CONTROL", {"g99v1": HOLD})
    rows = [case("syn-dep", "objects", objects="g99v1", fix="b", c0="fail", c1="fail", c1p="fail"),
            case(HOLD, "objects", objects="g99v1")]
    results = {"syn-dep": {C0: "fail", C1: "fail", C1P: "fail", C2: "pass"}, HOLD: ALL(f"fail ({MARK})")}
    return rows, results, ()


def relay_case(m, monkeypatch):
    monkeypatch.setattr(m, "SWAP", HOLD)
    rows = [case("syn-dep"), case(HOLD, "protocol")]
    return rows, {"syn-dep": RESULTS["syn-a"], HOLD: ALL(f"fail ({MARK})")}, ("syn-dep",)


def dependent_fix(m, monkeypatch, capsys, tmp_path, which):
    rows, results, relay = which(m, monkeypatch)
    rc, out = run(m, monkeypatch, capsys, tmp_path, rows, results, relay=relay)
    line = next(ln for ln in out.splitlines() if ln.startswith("| syn-dep |"))
    return rc, line.rsplit(" | ", 1)[1].rstrip(" |")


@pytest.mark.parametrize("which", [objects_case, relay_case], ids=["objects", "relay"])
def test_a_fix_reading_that_rests_on_a_held_capture_reads_held(monkeypatch, capsys, tmp_path, which):
    assert dependent_fix(table, monkeypatch, capsys, tmp_path, which) == (0, DEP)


DEP_MUTANTS = {
    "objects": (objects_case, "            deps[n].update(OBJ_CONTROL[g] for g in objs if g in OBJ_CONTROL)\n", ""),
    "relay": (relay_case, "            if relay:\n                deps[n].add(SWAP)\n", ""),
}


@pytest.mark.parametrize("which,old,new", DEP_MUTANTS.values(), ids=DEP_MUTANTS.keys())
def test_control_a_dependency_not_tracked_prints_the_reading(monkeypatch, capsys, tmp_path, which, old, new):
    m = load(table, old, new, "mutant_table")
    rc, fix = dependent_fix(m, monkeypatch, capsys, tmp_path, which)
    assert fix.startswith("unknown (judge-")


# Rule 3: one salted SHA-256 over the held captures' verdict lines; the salt
# is never printed.

def digest(out):
    return next(ln for ln in out.splitlines() if "salted SHA-256" in ln).split("`")[1]


def hash_problems(m, monkeypatch, capsys, tmp_path):
    base = run(m, monkeypatch, capsys, tmp_path / "a", ROWS, RESULTS)[1]
    other_salt = run(m, monkeypatch, capsys, tmp_path / "b", ROWS, RESULTS,
                     dict(ENV, **{hr23_feed.SALT_ENV: "another-test-salt-" + "2" * 32}))[1]
    # A held row's C2 result changed, which changes no finding.
    held_changed = run(m, monkeypatch, capsys, tmp_path / "c", ROWS,
                       dict(RESULTS, **{HOLD: dict(ALL(f"fail ({MARK})"), **{C2: f"fail ({MARK} 2)"})}))[1]
    public_changed = run(m, monkeypatch, capsys, tmp_path / "d", ROWS,
                         dict(RESULTS, **{"syn-a": ALL("pass")}))[1]
    bad = []
    if SALT in base or sum("SHA-256" in ln for ln in base.splitlines()) != 1:
        bad.append("the salt printed, or not one hash")
    if digest(base) == digest(other_salt):
        bad.append("the hash does not depend on the salt")
    if digest(base) == digest(held_changed):
        bad.append("the hash does not depend on the held captures' verdict lines")
    if digest(base) != digest(public_changed):
        bad.append("the hash depends on a capture that is not held")
    return bad


def test_one_salted_hash_over_the_held_captures_verdict_lines(monkeypatch, capsys, tmp_path):
    assert hash_problems(table, monkeypatch, capsys, tmp_path) == []


HASH_MUTANTS = {
    "unsalted": ('hashlib.sha256((salt + "\\n" + ', 'hashlib.sha256(("\\n" + '),
    "held-lines-not-hashed": ('            secret.append(head + " | ".join(cells) + f" | {fix[n]} |")\n', ""),
}


@pytest.mark.parametrize("old,new", HASH_MUTANTS.values(), ids=HASH_MUTANTS.keys())
def test_control_hash_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    m = load(table, old, new, "mutant_table")
    assert hash_problems(m, monkeypatch, capsys, tmp_path) != []


# Rule 4: the held list and the salt come from the environment; without
# them no row is judged or printed, and a counted run exits 3. A list naming
# anything but a pinned capture, or a short salt, is refused, and the list
# is never echoed.

GATES = [  # (environment, counted, exit code)
    ({}, True, 3),
    ({}, False, 0),
    ({hr23_feed.HELD_ENV: HOLD}, True, 3),
    ({hr23_feed.SALT_ENV: SALT}, True, 3),
    (dict(ENV, **{hr23_feed.SALT_ENV: "short"}), True, 3),
    (dict(ENV, **{hr23_feed.HELD_ENV: f"{HOLD},syn-unknown-name"}), False, 1),
    (dict(ENV, **{hr23_feed.HELD_ENV: "../syn-held"}), False, 1),
]


def gate_problems(feed, monkeypatch, capsys, tmp_path):
    bad = []
    for i, (env, counted, want) in enumerate(GATES):
        rc, out = run(table, monkeypatch, capsys, tmp_path / str(i), ROWS, RESULTS, env, counted, feed=feed)
        if rc != want or "| syn-" in out or "SHA-256" in out or "syn-unknown-name" in out:
            bad.append(f"gate {i}: exit {rc}, want {want}, or a row, the hash or the list was printed")
    return bad


def test_without_the_held_list_and_the_salt_no_row_is_printed(monkeypatch, capsys, tmp_path):
    assert gate_problems(hr23_feed, monkeypatch, capsys, tmp_path) == []


GATE_MUTANTS = {
    "missing-list-read-as-empty": ('        return None, f"the held list ({HELD_ENV}) was not given"',
                                   "        return set(), None"),
    "unpinned-name-accepted": ("if any(not PLAIN.fullmatch(n) or n not in known for n in names):",
                               "if any(not PLAIN.fullmatch(n) for n in names):"),
    "short-salt-accepted": ("return s if len(s) >= SALT_MIN else None", "return s"),
}


@pytest.mark.parametrize("old,new", GATE_MUTANTS.values(), ids=GATE_MUTANTS.keys())
def test_control_gate_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    assert gate_problems(load(hr23_feed, old, new, "mutant_hr23_feed"), monkeypatch, capsys, tmp_path) != []


# Rule 5: an error while judging prints no text of it, since it may concern
# a held capture, and the step fails.

def test_an_error_in_the_judge_prints_none_of_its_text(monkeypatch, capsys, tmp_path):
    def boom(*a):
        raise ValueError(MARK)
    monkeypatch.setattr(table, "judge_cases", boom)
    rc, out = run(table, monkeypatch, capsys, tmp_path, ROWS, RESULTS)
    assert rc == 1 and MARK not in out and "stopped on an error" in out


def test_control_an_uncaught_error_carries_its_text(monkeypatch, capsys, tmp_path):
    m = load(table, "    except Exception:  # noqa: BLE001", "    except ZeroDivisionError:  # noqa: BLE001", "mutant_table")

    def boom(*a):
        raise ValueError(MARK)
    monkeypatch.setattr(m, "judge_cases", boom)
    with pytest.raises(ValueError, match=MARK):
        run(m, monkeypatch, capsys, tmp_path, ROWS, RESULTS)


# hr23_feed.py's check: a held capture's row reads held in every cell, it is
# left out of the count, and its exit code is never printed; a held capture
# that did not run cleanly fails a counted run without being named.

def check_run(feed, tmp_path, capsys, held_code="139", env=None):
    tmp_path.mkdir(parents=True)
    sums = tmp_path / "hr23.sha256"
    caps = ["syn-a", "syn-b", HOLD]
    sums.write_text("".join(f"{'0' * 64}  {c}.pcap\n" for c in caps))
    for c in caps:
        for cfg in hr23_feed.CONFIGS:
            d = tmp_path / "out" / c / cfg
            d.mkdir(parents=True)
            (d / "exit-code").write_text((held_code if c == HOLD else "0") + "\n")
    kept = tmp_path / "kept.txt"
    kept.write_text("".join(c + "\n" for c in caps))
    rc = feed.check(str(tmp_path / "out"), str(sums), str(kept), True, {hr23_feed.HELD_ENV: HOLD} if env is None else env)
    return rc, capsys.readouterr().out


def check_problems(feed, tmp_path, capsys):
    bad = []
    rc, out = check_run(feed, tmp_path / "a", capsys)
    if rc != 3 or "139" in out or f"| {HOLD} | " + " | ".join([hr23_feed.HELD] * 4) + " |" not in out:
        bad.append("a held capture's exit code printed, or its failure did not fail the counted run")
    if [ln for ln in out.splitlines() if HOLD in ln] != [f"| {HOLD} | " + " | ".join([hr23_feed.HELD] * 4) + " |"]:
        bad.append("the held capture is named outside its held row")
    if "2 of 2 captures ran" not in out or "1 held captures are left out of this count" not in out:
        bad.append("the count includes the held capture")
    rc, out = check_run(feed, tmp_path / "b", capsys, env={})
    if rc != 3 or "| syn-" in out:
        bad.append("without the held list a row was printed, or the counted run passed")
    return bad


def test_check_holds_a_held_capture(tmp_path, capsys):
    assert check_problems(hr23_feed, tmp_path, capsys) == []


CHECK_MUTANTS = {
    "cells-not-held": ('" | ".join([HELD] * len(CONFIGS) if c in held else cells)', '" | ".join(cells)'),
    "failure-named": ("            if code != \"0\" and c in held:\n                held_unclean = True\n            elif",
                      "            if"),
    "no-list-prints-rows": ("    if not fp:\n        held, why", "    if False:\n        held, why"),
}


@pytest.mark.parametrize("old,new", CHECK_MUTANTS.values(), ids=CHECK_MUTANTS.keys())
def test_control_check_mutant_is_caught(tmp_path, capsys, old, new):
    assert check_problems(load(hr23_feed, old, new, "mutant_hr23_feed"), tmp_path, capsys) != []
