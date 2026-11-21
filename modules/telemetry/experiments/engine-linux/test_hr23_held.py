"""Held captures in HR-23's judge and check (D1's rulings 7056743490 and
7057468942 on #776, D4-122): table.py's cases and hr23judge and
hr23_feed.py's held_list and check, on synthetic
captures with neutral names (syn-*) and results made up here. No engine
runs, no real capture is named as held, and no log is read. Each rule has a
named control: a mutant of the script's text that must make the rule's
check fail.
Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_hr23_held.py"""
import importlib.util
import json
import os
import random
import secrets
import shutil
import subprocess
import sys

import pytest

import hr23_feed
import table

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import hr23_cases  # noqa: E402,F401 (hr23judge imports it by name)

C0, C1, C1P, C2 = table.JUDGED
HOLD, MARK = "syn-held", "HELD-RESULT-MARK"
# A capture pinned in hr23.sha256 that is not a capture of hr23-cases.tsv.
PINNED = "syn-pinned"
# The salt under which hr23-held.hmac's committed test value was made, which
# a counted run refuses (D1's ruling 2 on #776).
TEST_SALT = "0123456789abcdef" * 4
# Salts for counted runs: new random ones for each test session, as a
# counted run's salt must be, so that none is in the repository.
SALT, SALT2 = secrets.token_hex(32), secrets.token_hex(32)
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
    (gt / "hr23.sha256").write_text("".join(f"{'0' * 64}  {c}.pcap\n"
                                            for c in sorted({r["capture"] for r in rows} | {PINNED})))
    for cap in relay:
        (gt / f"{cap}.tsv").write_text("flow\trole\tpackets\nudp 192.0.2.20:20000 > 192.0.2.14:20000\toutstation\t1\n")
    return str(root)


def fake(results, cite="cite"):
    """case_results from RESULTS: {capture: {cfg: result}}, one result for
    every row of the capture; a held capture's results carry MARK."""
    def case_results(rows, d, cfg, pcap, ports, want):
        return {n: (results[r["capture"]][cfg], f"{cite} {r['capture']}") for n, r in rows}
    return case_results


def digest_file(tmp_path, monkeypatch, feed, env, digest):
    """The committed digest, as a file of the test's own: DIGEST, or by
    default the value for ENV's list under ENV's salt."""
    p = tmp_path / "held.hmac"
    if digest is None and env.get(hr23_feed.HELD_ENV) and env.get(hr23_feed.SALT_ENV):
        digest = hr23_feed.list_digest(env[hr23_feed.HELD_ENV].replace(",", " ").split(), env[hr23_feed.SALT_ENV])
    tmp_path.mkdir(parents=True, exist_ok=True)
    if digest is not False:
        p.write_text("# test\n" + (digest or "0" * 64) + "\n")
    monkeypatch.setattr(feed, "DIGEST", str(p))


def fed(tmp_path, rows, skip=()):
    """An exit code 0 for every capture of ROWS under every configuration,
    except the (capture, cfg) pairs in SKIP, which were not fed."""
    for c in {r["capture"] for r in rows}:
        for cfg in table.JUDGED:
            if (c, cfg) not in skip:
                d = tmp_path / "out" / c / cfg
                d.mkdir(parents=True, exist_ok=True)
                (d / "exit-code").write_text("0\n")


def run(m, monkeypatch, capsys, tmp_path, rows, results, env=ENV, counted=True, relay=(), feed=hr23_feed,
        digest=None, cite="cite", skip=()):
    monkeypatch.setattr(m, "case_results", fake(results, cite))
    monkeypatch.setitem(sys.modules, "hr23_feed", feed)
    digest_file(tmp_path, monkeypatch, feed, env, digest)
    fed(tmp_path, rows, skip)
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


# Rule 2 (D1's ruling 6 on #776, which withdraws 7057113098): a fix reading
# that reads a held capture's rows reads `held (depends on a held row)`; one
# that reads a capture that is not held prints its reading. Both rules that
# read another capture's rows are tried, each with a neutral capture in the
# place of the one it reads: held (CTL = HOLD), and not held (CTL = syn-ctl,
# with HOLD held and unrelated).

DEP = table.DEP_HELD


def objects_case(m, monkeypatch, ctl=HOLD, dep="pass"):
    monkeypatch.setattr(m, "OBJ_CONTROL", {"g99v1": ctl})
    rows = [case("syn-dep", "objects", objects="g99v1", fix="b", c0="fail", c1="fail", c1p="fail"),
            case(ctl, "objects", objects="g99v1")] + ([] if ctl == HOLD else [case(HOLD)])
    ctl_res = ALL(f"fail ({MARK})") if ctl == HOLD else ALL("pass")
    results = {"syn-dep": {C0: "fail", C1: "fail", C1P: "fail", C2: dep}, ctl: ctl_res, HOLD: ALL(f"fail ({MARK})")}
    return rows, results, ()


def relay_case(m, monkeypatch, ctl=HOLD, dep="pass"):
    monkeypatch.setattr(m, "SWAP", ctl)
    rows = [case("syn-dep"), case(ctl, "protocol")] + ([] if ctl == HOLD else [case(HOLD)])
    ctl_res = ALL(f"fail ({MARK})") if ctl == HOLD else ALL("pass")
    results = {"syn-dep": dict(RESULTS["syn-a"], **{C2: dep}), ctl: ctl_res, HOLD: ALL(f"fail ({MARK})")}
    return rows, results, ("syn-dep",)


def dependent_fix(m, monkeypatch, capsys, tmp_path, which, ctl=HOLD):
    rows, results, relay = which(m, monkeypatch, ctl)
    rc, out = run(m, monkeypatch, capsys, tmp_path, rows, results, relay=relay)
    line = next(ln for ln in out.splitlines() if ln.startswith("| syn-dep |"))
    return rc, line.rsplit(" | ", 1)[1].rstrip(" |")


@pytest.mark.parametrize("which", [objects_case, relay_case], ids=["objects", "relay"])
def test_a_fix_reading_that_reads_a_held_capture_reads_held(monkeypatch, capsys, tmp_path, which):
    assert dependent_fix(table, monkeypatch, capsys, tmp_path, which, HOLD) == (0, DEP)


@pytest.mark.parametrize("which,shown", [(objects_case, "b shows"), (relay_case, "a shows")], ids=["objects", "relay"])
def test_a_fix_reading_that_reads_a_control_not_held_is_printed(monkeypatch, capsys, tmp_path, which, shown):
    assert dependent_fix(table, monkeypatch, capsys, tmp_path, which, "syn-ctl") == (0, shown)


@pytest.mark.parametrize("which", [objects_case, relay_case], ids=["objects", "relay"])
def test_control_the_withdrawn_extension_is_caught(monkeypatch, capsys, tmp_path, which):
    # Every dependent of any control read held: the extension D1 withdrew.
    m = load(table, '(deps[n] - {r["capture"]}) & held', '(deps[n] - {r["capture"]})', "mutant_table")
    assert dependent_fix(m, monkeypatch, capsys, tmp_path, which, "syn-ctl")[1] == DEP


DEP_MUTANTS = {
    "objects": (objects_case, "            deps[n].update(OBJ_CONTROL[g] for g in objs if g in OBJ_CONTROL)\n", ""),
    "relay": (relay_case, "            if relay:\n                deps[n].add(SWAP)\n", ""),
}


@pytest.mark.parametrize("which,old,new", DEP_MUTANTS.values(), ids=DEP_MUTANTS.keys())
def test_control_a_dependency_not_tracked_prints_the_reading(monkeypatch, capsys, tmp_path, which, old, new):
    m = load(table, old, new, "mutant_table")
    rc, fix = dependent_fix(m, monkeypatch, capsys, tmp_path, which)
    assert fix.startswith("unknown (judge-")


# Rule 3: one salted SHA-256 over the held captures' verdict lines, the
# fix readings replaced by DEP and the findings that name a held capture
# (D3's N3), without log-line citations or parser notes (D6's N2); the salt
# is never printed.

def digest(out):
    return next(ln for ln in out.splitlines() if "salted SHA-256" in ln).split("`")[1]


def with_finding(m, monkeypatch, text):
    """judge_cases with one more finding that names the held capture."""
    real = m.judge_cases

    def judge_cases(conds, res, root):
        oc, fix, findings, deps = real(conds, res, root)
        return oc, fix, findings + [({HOLD}, text)], deps
    monkeypatch.setattr(m, "judge_cases", judge_cases)


def dep_digest(m, monkeypatch, capsys, tmp_path, dep):
    """The hash when a fix reading that reads a held, passing control
    changes with DEP, its own C2 result."""
    monkeypatch.setattr(m, "OBJ_CONTROL", {"g99v1": HOLD})
    rows = [case("syn-dep", "objects", objects="g99v1", fix="b", c0="fail", c1="fail", c1p="fail"),
            case(HOLD, "objects", objects="g99v1")]
    results = {"syn-dep": {C0: "fail", C1: "fail", C1P: "fail", C2: dep}, HOLD: ALL("pass")}
    return digest(run(m, monkeypatch, capsys, tmp_path, rows, results)[1])


NOTES = "; parser notes on this flow: {} (filler body refused? D4's inference)"


def hash_problems(m, monkeypatch, capsys, tmp_path):
    base = run(m, monkeypatch, capsys, tmp_path / "a", ROWS, RESULTS)[1]
    other_salt = run(m, monkeypatch, capsys, tmp_path / "b", ROWS, RESULTS,
                     dict(ENV, **{hr23_feed.SALT_ENV: SALT2}))[1]
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
    # D6's N2: the same verdicts with other citations and notes in another order.
    if digest(base) != digest(run(m, monkeypatch, capsys, tmp_path / "e", ROWS, RESULTS, cite="other-cite")[1]):
        bad.append("the hash depends on the held rows' citations")
    cited = [dict(RESULTS, **{HOLD: dict(ALL(f"fail ({MARK})" + NOTES.format(n)),
                                         **{C1: f"pass; objects pass otsec_probe.log:{k}"})})
             for k, n in ((3, "a; b"), (4, "b; a"))]
    if len({digest(run(m, monkeypatch, capsys, tmp_path / f"f{i}", ROWS, r)[1]) for i, r in enumerate(cited)}) != 1:
        bad.append("the hash depends on an objects citation or on the parser notes' order")
    # D3's N3: a fix reading replaced by DEP is in the hash.
    if dep_digest(m, monkeypatch, capsys, tmp_path / "g", "pass") == \
            dep_digest(m, monkeypatch, capsys, tmp_path / "h", "fail"):
        bad.append("a fix reading replaced by the held mark is not in the hash")
    # D6's B3: the findings that name a held capture are in the hash.
    found = []
    for i, text in enumerate(("a finding", "another finding")):
        with_finding(m, monkeypatch, text)
        found.append(digest(run(m, monkeypatch, capsys, tmp_path / f"i{i}", ROWS, RESULTS)[1]))
        monkeypatch.undo()
    if found[0] == found[1]:
        bad.append("a finding that names a held capture is not in the hash")
    return bad


def test_one_salted_hash_over_the_held_captures_verdict_lines(monkeypatch, capsys, tmp_path):
    assert hash_problems(table, monkeypatch, capsys, tmp_path) == []


HASH_MUTANTS = {
    "unsalted": ('hashlib.sha256((salt + "\\n" + ', 'hashlib.sha256(("\\n" + '),
    "held-lines-not-hashed": ('            secret.append(head + " | ".join(f"{oc[n][cfg]}: {verdict_text(',
                              '            (head + " | ".join(f"{oc[n][cfg]}: {verdict_text('),
    "dependents-not-hashed": ('            secret.append(head + f"{f} |")\n', ""),
    "findings-not-hashed": ("    secret += [t for caps, t in findings if caps & held]\n", ""),
    "citations-hashed": ("{verdict_text(res[cfg][n][0])}", "{res[cfg][n][0]} {res[cfg][n][1]}"),
    "objects-citation-hashed": ('    return re.sub(r"objects pass \\S+", "objects pass", result)', "    return result"),
    "notes-hashed": ('    result = re.sub(r"; parser notes on this flow: ', '    result = result or re.sub(r"; parser notes on this flow: '),
}


@pytest.mark.parametrize("old,new", HASH_MUTANTS.values(), ids=HASH_MUTANTS.keys())
def test_control_hash_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    m = load(table, old, new, "mutant_table")
    assert hash_problems(m, monkeypatch, capsys, tmp_path) != []


# Rule 4: the held list and the salt come from the environment; without
# them no row is judged or printed, and a counted run exits 3. The list is
# refused (exit 1, never echoed) when it names anything but a case capture,
# or when its keyed digest under the salt is not the committed one (D3's B1,
# D1's ruling 1 on #776): a wrong but valid capture name is refused too. The
# salt is at least 64 lowercase hex characters (D3's N2).

# 64 hex characters with no period, but only nine distinct ones.
WEAK_NOT_PERIODIC = "".join(random.Random(7).choices("012345678", k=64))

GATES = [  # (environment, counted, exit code, committed digest: None for the list's own)
    ({}, True, 3, None),
    ({}, False, 0, None),
    ({hr23_feed.HELD_ENV: HOLD}, True, 3, None),
    ({hr23_feed.SALT_ENV: SALT}, True, 3, None),
    (dict(ENV, **{hr23_feed.SALT_ENV: "ab" * 16}), True, 3, None),
    (dict(ENV, **{hr23_feed.SALT_ENV: SALT[:-1]}), True, 3, None),  # one hex character short
    (dict(ENV, **{hr23_feed.SALT_ENV: "g" * 64}), True, 3, None),
    (dict(ENV, **{hr23_feed.HELD_ENV: f"{HOLD},syn-unknown-name"}), False, 1, None),
    (dict(ENV, **{hr23_feed.HELD_ENV: "../syn-held"}), False, 1, None),
    # A valid case capture, but not the list the digest was committed for.
    (dict(ENV, **{hr23_feed.HELD_ENV: "syn-a"}), True, 1, hr23_feed.list_digest([HOLD], SALT)),
    # The right list under another salt than the committed digest's.
    (ENV, True, 1, hr23_feed.list_digest([HOLD], SALT2)),
    # No committed digest.
    (ENV, True, 1, False),
    # D6's N1 on #776: a name pinned in hr23.sha256 that is not a case
    # capture, under its own committed digest.
    (dict(ENV, **{hr23_feed.HELD_ENV: PINNED}), True, 1, None),
    # Two committed values, the first the list's own (D6's N1 on #776).
    (ENV, True, 1, hr23_feed.list_digest([HOLD], SALT) + "\n" + "1" * 64),
    # D1's ruling 2 on #776: on a counted run, the repository's test salt and
    # weak salts, each under its own committed digest.
    (dict(ENV, **{hr23_feed.SALT_ENV: TEST_SALT}), True, 1, None),
    (dict(ENV, **{hr23_feed.SALT_ENV: "0" * 64}), True, 1, None),
    (dict(ENV, **{hr23_feed.SALT_ENV: "fedcba9876543210" * 4}), True, 1, None),
    (dict(ENV, **{hr23_feed.SALT_ENV: WEAK_NOT_PERIODIC}), True, 1, None),
]


def gate_problems(feed, monkeypatch, capsys, tmp_path, m=table):
    bad = []
    for i, (env, counted, want, committed) in enumerate(GATES):
        try:
            rc, out = run(m, monkeypatch, capsys, tmp_path / str(i), ROWS, RESULTS, env, counted, feed=feed,
                          digest=committed)
        except Exception as e:  # noqa: BLE001 (a mutant may stop the judge)
            bad.append(f"gate {i}: {type(e).__name__}")
            continue
        if rc != want or "| syn-" in out or "SHA-256" in out or "syn-unknown-name" in out or PINNED in out:
            bad.append(f"gate {i}: exit {rc}, want {want}, or a row, the hash or the list was printed")
    return bad


# The same salts are accepted on a run that is not counted: only a counted
# run refuses them (D1's ruling 2 on #776).
def test_a_rehearsal_accepts_the_test_salt_and_weak_salts(monkeypatch, capsys, tmp_path):
    for i, salt in enumerate((TEST_SALT, "0" * 64, WEAK_NOT_PERIODIC)):
        rc, out = run(table, monkeypatch, capsys, tmp_path / str(i), ROWS, RESULTS,
                      dict(ENV, **{hr23_feed.SALT_ENV: salt}), False)
        assert rc == 0 and HELD_LINE in out and "SHA-256" in out


def test_a_random_salt_is_not_weak():
    assert not hr23_feed.weak_salt(SALT) and not hr23_feed.weak_salt(SALT2)


def test_without_the_held_list_and_the_salt_no_row_is_printed(monkeypatch, capsys, tmp_path):
    assert gate_problems(hr23_feed, monkeypatch, capsys, tmp_path) == []


def test_the_digest_is_hmac_sha256_of_the_sorted_list_keyed_by_the_salt():
    import hashlib
    import hmac
    want = hmac.new(SALT.encode(), b"syn-a\nsyn-held\n", hashlib.sha256).hexdigest()
    assert hr23_feed.list_digest(["syn-held", "syn-a", "syn-held"], SALT) == want


def test_the_committed_value_is_the_synthetic_test_value():
    # D4 commits only a test value (D1's ruling 1 on #776): the synthetic
    # list syn-held under the test salt TEST_SALT. D1 replaces it, and this
    # test, when the value for a counted run's salt is committed.
    assert hr23_feed.committed_digest(hr23_feed.DIGEST) == hr23_feed.list_digest([HOLD], TEST_SALT)


GATE_MUTANTS = {
    "missing-list-read-as-empty": ('        return None, f"the held list ({HELD_ENV}) was not given"',
                                   "        return set(), None"),
    "non-case-name-accepted": ("if any(not PLAIN.fullmatch(n) or n not in known for n in names):",
                               "if any(not PLAIN.fullmatch(n) for n in names):"),
    "short-salt-accepted": ("return s if SALT_FORM.fullmatch(s) else None", "return s"),
    "salt-min-off-by-one": ("SALT_MIN = 64", "SALT_MIN = 63"),
    "non-hex-salt-accepted": ("return s if SALT_FORM.fullmatch(s) else None", "return s if len(s) >= SALT_MIN else None"),
    "digest-not-checked": ("if want is None or not hmac.compare_digest(list_digest(names, salt), want):",
                           "if want is None:"),
    "missing-digest-accepted": ("if want is None or not hmac.compare_digest(list_digest(names, salt), want):",
                                "if want is not None and not hmac.compare_digest(list_digest(names, salt), want):"),
    # D6's N1 on #776.
    "two-values-take-the-first": ("return vals[0] if len(vals) == 1 and re.fullmatch",
                                  "return vals[0] if vals and re.fullmatch"),
    # D1's ruling 2 on #776.
    "weak-salt-not-refused": ("    if counted and weak_salt(salt):", "    if False:"),
    "period-not-checked": (" or any(s[p:] == s[:-p] for p in range(1, len(s) // 2 + 1))", ""),
    "distinct-not-checked": ("return len(set(s)) < SALT_DISTINCT or any(", "return any("),
}


@pytest.mark.parametrize("old,new", GATE_MUTANTS.values(), ids=GATE_MUTANTS.keys())
def test_control_gate_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    assert gate_problems(load(hr23_feed, old, new, "mutant_hr23_feed"), monkeypatch, capsys, tmp_path) != []


# table.py's own call of the gate: over the case captures only (D6's N1 on
# #776), and with the run's counted flag (D1's ruling 2).
TABLE_GATE_MUTANTS = {
    "wider-name-set": ('held, why = hr23_feed.held_list(hr23_feed.case_captures(os.path.join(root, GP, "hr23-cases.tsv")), env, counted)',
                       'held, why = hr23_feed.held_list(set(hr23_feed.pins(os.path.join(root, GT, HR23_DIR, "hr23.sha256"))) | hr23_feed.case_captures(os.path.join(root, GP, "hr23-cases.tsv")), env, counted)'),
    "counted-not-passed": ('hr23_feed.case_captures(os.path.join(root, GP, "hr23-cases.tsv")), env, counted)',
                           'hr23_feed.case_captures(os.path.join(root, GP, "hr23-cases.tsv")), env)'),
}


@pytest.mark.parametrize("old,new", TABLE_GATE_MUTANTS.values(), ids=TABLE_GATE_MUTANTS.keys())
def test_control_table_gate_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    assert gate_problems(hr23_feed, monkeypatch, capsys, tmp_path, load(table, old, new, "mutant_table")) != []


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

def check_run(feed, tmp_path, capsys, monkeypatch, held_code="139", env=None, committed=None):
    tmp_path.mkdir(parents=True)
    sums = tmp_path / "hr23.sha256"
    caps = ["syn-a", "syn-b", HOLD]
    sums.write_text("".join(f"{'0' * 64}  {c}.pcap\n" for c in caps))
    cases = tmp_path / "hr23-cases.tsv"
    cases.write_text("# synthetic\ncapture\tcondition\n" + "".join(f"{c}\tprotocol\n" for c in caps))
    for c in caps:
        for cfg in hr23_feed.CONFIGS:
            d = tmp_path / "out" / c / cfg
            d.mkdir(parents=True)
            (d / "exit-code").write_text((held_code if c == HOLD else "0") + "\n")
    kept = tmp_path / "kept.txt"
    kept.write_text("".join(c + "\n" for c in caps))
    env = ENV if env is None else env
    digest_file(tmp_path, monkeypatch, feed, env, committed)
    rc = feed.check(str(tmp_path / "out"), str(sums), str(kept), True, env, str(cases))
    return rc, capsys.readouterr().out


def check_problems(feed, tmp_path, capsys, monkeypatch):
    bad = []
    rc, out = check_run(feed, tmp_path / "a", capsys, monkeypatch)
    if rc != 3 or "139" in out or f"| {HOLD} | " + " | ".join([hr23_feed.HELD] * 4) + " |" not in out:
        bad.append("a held capture's exit code printed, or its failure did not fail the counted run")
    if [ln for ln in out.splitlines() if HOLD in ln] != [f"| {HOLD} | " + " | ".join([hr23_feed.HELD] * 4) + " |"]:
        bad.append("the held capture is named outside its held row")
    if "2 of 2 captures ran" not in out or "1 held captures are left out of this count" not in out:
        bad.append("the count includes the held capture")
    rc, out = check_run(feed, tmp_path / "b", capsys, monkeypatch, env={})
    if rc != 3 or "| syn-" in out:
        bad.append("without the held list a row was printed, or the counted run passed")
    # D3's B1: a wrong but valid capture name is refused before any row.
    rc, out = check_run(feed, tmp_path / "c", capsys, monkeypatch, env=dict(ENV, **{hr23_feed.HELD_ENV: "syn-a"}),
                        committed=hr23_feed.list_digest([HOLD], SALT))
    if rc != 1 or "| syn-" in out:
        bad.append("a list that is not the committed one was taken, or a row was printed")
    # D1's ruling 2: the committed value's test salt, on a counted run, with
    # the list's digest under it committed.
    rc, out = check_run(feed, tmp_path / "d", capsys, monkeypatch, env=dict(ENV, **{hr23_feed.SALT_ENV: TEST_SALT}))
    if rc != 1 or "| syn-" in out or TEST_SALT in out:
        bad.append("a counted run took the test salt, or a row or the salt was printed")
    return bad


def test_check_holds_a_held_capture(tmp_path, capsys, monkeypatch):
    assert check_problems(hr23_feed, tmp_path, capsys, monkeypatch) == []


CHECK_MUTANTS = {
    "cells-not-held": ('" | ".join([HELD] * len(CONFIGS) if c in held else cells)', '" | ".join(cells)'),
    "failure-named": ("            if code != \"0\" and c in held:\n                held_unclean = True\n            elif",
                      "            if"),
    "no-list-prints-rows": ("    if not fp:\n        held, why", "    if False:\n        held, why"),
    "cases-not-read": ("held_list(case_captures(cases) if cases else set(), env, counted)",
                       "held_list({'syn-a'}, env, counted)"),
    "counted-not-passed": ("held_list(case_captures(cases) if cases else set(), env, counted)",
                           "held_list(case_captures(cases) if cases else set(), env)"),
}


@pytest.mark.parametrize("old,new", CHECK_MUTANTS.values(), ids=CHECK_MUTANTS.keys())
def test_control_check_mutant_is_caught(tmp_path, capsys, monkeypatch, old, new):
    assert check_problems(load(hr23_feed, old, new, "mutant_hr23_feed"), tmp_path, capsys, monkeypatch) != []


# D1's ruling 3 on #776: a case capture not fed under every configuration
# fails a counted run; a held one is not named.

def unfed_problems(m, monkeypatch, capsys, tmp_path):
    bad = []
    rc, out = run(m, monkeypatch, capsys, tmp_path / "a", ROWS, RESULTS, skip={("syn-a", C2)})
    if rc != 3 or "**Case captures not fed under every configuration:** syn-a." not in out:
        bad.append(f"an unfed case capture did not fail the counted run, or was not named (exit {rc})")
    rc, out = run(m, monkeypatch, capsys, tmp_path / "b", ROWS, RESULTS, counted=False, skip={("syn-a", C2)})
    if rc != 0 or "not fed under every configuration" not in out:
        bad.append("a rehearsal failed on an unfed capture, or did not say so")
    rc, out = run(m, monkeypatch, capsys, tmp_path / "c", ROWS, RESULTS, skip={(HOLD, C0)})
    if rc != 3 or "1 held capture(s)" not in out or [ln for ln in out.splitlines() if HOLD in ln and "| held" not in ln]:
        bad.append("an unfed held capture did not fail the counted run, or was named")
    if run(m, monkeypatch, capsys, tmp_path / "d", ROWS, RESULTS)[0] != 0:
        bad.append("a run with every capture fed failed")
    return bad


def test_a_case_capture_not_fed_fails_a_counted_run(monkeypatch, capsys, tmp_path):
    assert unfed_problems(table, monkeypatch, capsys, tmp_path) == []


@pytest.mark.parametrize("old,new", [("    return 3 if unfed and counted else 0", "    return 0"),
                                     ('os.path.join(out, r["capture"], cfg, "exit-code")', 'os.path.join(out, r["capture"])')],
                         ids=["not-failed", "not-read"])
def test_control_unfed_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    assert unfed_problems(load(table, old, new, "mutant_table"), monkeypatch, capsys, tmp_path) != []


# D1's ruling 2 on #776 (D6's B1): the malformed set's table reads the held
# list before it prints: a refused list stops the judge before any table;
# without the list or the salt it prints no row; a held input's row reads
# held in every cell, is left out of the counts, and is in the hash.

MAL_ROWS = [{"input": HOLD}, {"input": "syn-m"}]


def judge_run(m, monkeypatch, capsys, tmp_path, env=ENV, counted=True, held_mal="fail", digest=None):
    monkeypatch.setattr(m, "case_results", fake(RESULTS))
    monkeypatch.setattr(m, "judge_fp", lambda out_fp, root, kept: {})
    monkeypatch.setattr(m, "judge_malformed", lambda out, root, mal, ports_of, want: {
        HOLD: {cfg: (held_mal, MARK) for cfg in table.JUDGED}, "syn-m": {cfg: ("pass", "shown") for cfg in table.JUDGED}})
    monkeypatch.setitem(sys.modules, "hr23_feed", hr23_feed)
    digest_file(tmp_path, monkeypatch, hr23_feed, env, digest)
    fed(tmp_path, ROWS)
    root = make_root(tmp_path, ROWS)
    with open(os.path.join(root, table.GP, "hr23-malformed.tsv"), "w", encoding="utf-8") as fh:
        fh.write("input\n" + "".join(r["input"] + "\n" for r in MAL_ROWS))
    rc = m.hr23judge(str(tmp_path / "out"), str(tmp_path / "out-fp"), str(tmp_path / "k"), root, str(tmp_path / "p"),
                     str(tmp_path / "pcaps"), counted, env)
    return rc, capsys.readouterr().out


def malformed_problems(m, monkeypatch, capsys, tmp_path):
    bad = []
    rc, out = judge_run(m, monkeypatch, capsys, tmp_path / "a")
    held_line = f"| {HOLD} | " + " | ".join([hr23_feed.HELD] * 4) + " |"
    mal = out.split("### The malformed set")[1].split("###")[0]
    if rc != 0 or MARK in out or held_line not in mal or "| syn-m | pass: shown" not in mal:
        bad.append(f"the held input's malformed row was printed, or the other was not (exit {rc})")
    if "Malformed cells: 4 pass, 0 fail, 0 unknown, 0 reported. 1 held inputs are left out" not in mal:
        bad.append("the malformed counts include the held input")
    other = judge_run(m, monkeypatch, capsys, tmp_path / "b", held_mal="pass")[1]
    if digest(out) == digest(other):
        bad.append("the held input's malformed row is not in the hash")
    for i, (counted, want) in enumerate(((True, 3), (False, 0))):
        rc, out = judge_run(m, monkeypatch, capsys, tmp_path / f"c{i}", env={}, counted=counted)
        if rc != want or "| syn-" in out or MARK in out:
            bad.append(f"without the list a malformed row was printed, or exit {rc} (counted={counted})")
    rc, out = judge_run(m, monkeypatch, capsys, tmp_path / "d", env=dict(ENV, **{hr23_feed.HELD_ENV: "syn-a"}),
                        digest=hr23_feed.list_digest([HOLD], SALT))
    if rc != 1 or "| syn-" in out or "### The false-positive set" in out or "### The malformed set" in out:
        bad.append(f"a refused list did not stop the judge before any table (exit {rc})")
    return bad


def test_the_malformed_table_honours_the_held_list(monkeypatch, capsys, tmp_path):
    assert malformed_problems(table, monkeypatch, capsys, tmp_path) == []


MAL_MUTANTS = {
    "held-input-printed": ('            if row["input"] in held:\n                secret.append', '            if False:\n                secret.append'),
    "held-input-not-hashed": ("                secret.append(f\"| {row['input']} | \" + \" | \".join(cells) + \" |\")\n", ""),
    "no-list-prints-rows": ("    held, _, why = held_gate(root, env, counted)\n    import hr23_feed\n",
                            "    held, _, why = held_gate(root, env, counted)\n    import hr23_feed\n    held, why = (set() if held is None else held), (None if held is None else why)\n"),
    "refused-list-goes-on": ("    if held is False:\n        print(f\"Not judged or printed: {why} (D1's ruling 7057468942", "    if held is None and False:\n        print(f\"Not judged or printed: {why} (D1's ruling 7057468942"),
}


@pytest.mark.parametrize("old,new", MAL_MUTANTS.values(), ids=MAL_MUTANTS.keys())
def test_control_malformed_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    assert malformed_problems(load(table, old, new, "mutant_table"), monkeypatch, capsys, tmp_path) != []


# D1's ruling 1 on #776 at 623365aa: every table the dnp3 mode prints
# (table.py dnp3, hr23 and fifo) and the engines' own lines (held-log) leave
# out the held list's captures, or, with no list accepted, every capture of
# hr23-cases.tsv; through table.py's command line, over synthetic captures:
# syn-a (a case capture, not held), HOLD (held) and syn-other (not a case
# capture). HOLD's logs carry MARK. The committed test value (syn-held under
# TEST_SALT) is the list a rehearsal accepts; a counted run refuses it.
SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="no sh on PATH")
OTHER = "syn-other"
DNP3_CAPS = ("syn-a", HOLD, OTHER)
COND_COLS = ("capture", "condition", "l4", "src", "sport", "dst", "dport", "code", "objects", "sa", "show", "frames",
             "protocol", "direction")
ENGINE_LINES = (f"zeek failed on {HOLD} (zeek-probe-c2), exit 139:\n{MARK} tail\n"
                f"zeek {HOLD} (zeek) says: W: {MARK}\n"
                f"zeek failed on {OTHER} (zeek), exit 1:\nother tail\n"
                f"suricata-fifo {HOLD} (suricata-fifo) says: {MARK}\n")


def consts(path, tables):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for name, entries in tables.items():
            fh.write(f"const {name} = {{\n" + "".join(f'  [0x{c:x}] = "{n}",\n' for c, n in entries) + "}\n")


def dnp3_inputs(tmp_path):
    """(root, gt, work, out): a synthetic run of the dnp3 mode."""
    root = make_root(tmp_path, ROWS)
    with open(os.path.join(root, table.CONDITIONS), "w", encoding="utf-8") as fh:
        fh.write("\t".join(COND_COLS) + "\n" + "".join(
            f"{c}\tprotocol\tudp\t192.0.2.14\t20000\t192.0.2.20\t20000\t\t\t\t\t\tdnp3\tclient-server\n" for c in DNP3_CAPS))
    gt = tmp_path / "gt"
    (gt / "syn").mkdir(parents=True)
    (gt / "syn" / "syn.sha256").write_text("".join(f"{'0' * 64}  {c}.pcap\n" for c in DNP3_CAPS))
    work = tmp_path / "work"
    consts(str(work / "zeek-dnp3-consts.zeek"), {"function_codes": [(1, "READ")]})
    consts(str(work / "zeek-modbus-consts.zeek"), {"function_codes": [(3, "READ_HOLDING_REGISTERS")]})
    consts(str(work / "pkgs" / "icsnpp-dnp3" / "scripts" / "consts.zeek"),
           {"function_codes": [(1, "READ")], "dnp3_objects": [(0x100 + i, f"o{i}") for i in range(60)]})
    out = tmp_path / "out"
    for c in DNP3_CAPS + (table.CONTROL,):
        for cfg in table.CONFIGS + table.HR23:
            (out / c / cfg).mkdir(parents=True)
            (out / c / cfg / "exit-code").write_text("0\n")
        for cfg in table.PIPED:
            (tmp_path / "out-pipe" / c / (cfg + "-pipe")).mkdir(parents=True)
            (tmp_path / "out-pipe" / c / (cfg + "-pipe") / "exit-code").write_text("0\n")
        (tmp_path / "out-pipe" / c / "suricata-fifo").mkdir(parents=True)
        (tmp_path / "out-pipe" / c / "suricata-fifo" / "exit-code").write_text("0\n")
    held = out / HOLD
    (held / "zeek-probe-c2" / "weird.log").write_text(json.dumps({"ts": 1.0, "name": "dnp3_" + MARK}) + "\n")
    (held / "zeek-probe-c2" / "only.log").write_text(json.dumps({"ts": 1.0, MARK: 1}) + "\n")
    (held / "suricata" / "exit-code").write_text("1\n")
    (tmp_path / "engines.txt").write_text(ENGINE_LINES)
    return root, str(gt), str(work), str(out)


def run_env(env):
    e = {k: v for k, v in os.environ.items() if k not in (hr23_feed.HELD_ENV, hr23_feed.SALT_ENV, "GITHUB_REF")}
    e.update(env)
    return e


def dnp3_mode(tmp_path, env, counted, here=HERE):
    """Each command the dnp3 mode runs for its tables and engine lines, as
    run.sh calls it. Returns (exit codes, output)."""
    root, gt, work, out = dnp3_inputs(tmp_path)
    flag = ["--counted"] if counted else []
    cmds = [["dnp3", out, gt, work, root], ["hr23", out, root], ["fifo", out, out + "-pipe", root],
            ["held-log", str(tmp_path / "engines.txt"), root]]
    codes, text = [], ""
    for c in cmds:
        r = subprocess.run([sys.executable, "-I", "-B", os.path.join(here, "table.py")] + c + flag,
                           env=run_env(env), capture_output=True, text=True)
        codes.append(r.returncode)
        text += r.stdout + r.stderr
    return codes, text


ACCEPTED = {hr23_feed.HELD_ENV: HOLD, hr23_feed.SALT_ENV: TEST_SALT}
# (environment, counted, whether the list is accepted)
DNP3_RUNS = [(ACCEPTED, False, True), ({}, False, False), ({}, True, False), (ACCEPTED, True, False),
             (dict(ACCEPTED, **{hr23_feed.HELD_ENV: "syn-a"}), False, False)]


def dnp3_problems(tmp_path, here=HERE):
    bad = []
    for i, (env, counted, accepted) in enumerate(DNP3_RUNS):
        codes, text = dnp3_mode(tmp_path / str(i), env, counted, here)
        case = f"run {i} (counted={counted}, list accepted={accepted})"
        if codes != [0, 0, 0, 0]:
            bad.append(f"{case}: exit codes {codes}")
        if HOLD in text or MARK in text:
            bad.append(f"{case}: a held capture's name, row or engine line was printed")
        if ("syn-a" in text) != accepted:
            bad.append(f"{case}: the case capture that is not held {'is missing' if accepted else 'was printed'}")
        if text.count(f"| {OTHER} |") < 10 or "other tail" not in text:
            bad.append(f"{case}: the capture that is not a case capture is missing")
        n = 2 if accepted else 1
        if text.count(f"protocol 0 pass, {n} fail, 0 unknown, of {n}") != len(table.CONFIGS + table.HR23):
            bad.append(f"{case}: a count includes a capture left out")
        if text.count(f"| 0 of {n + 1} | {n} of {n} |") != len(table.PIPED):
            bad.append(f"{case}: the pipe case's count includes a capture left out")
        if text.count("is printed here") < 2:
            bad.append(f"{case}: the note is missing")
    return bad


def test_every_table_of_the_dnp3_mode_honours_the_held_list(tmp_path):
    assert dnp3_problems(tmp_path) == []


DNP3_MUTANTS = {
    "dnp3-cases": ("labdir = {c: d for c, d in gt_cases(gt).items() if c not in hide}", "labdir = gt_cases(gt)"),
    "dnp3-conditions": ('[r for r in tsv(cpath) if r["capture"] not in hide]', "tsv(cpath)"),
    "readings-rows": ("os.path.isdir(os.path.join(out, x)) and x not in hide)", "os.path.isdir(os.path.join(out, x)))"),
    "readings-fields": ('log_fields(out, "zeek-probe-c2", hide)', 'log_fields(out, "zeek-probe-c2")'),
    "fifo": ('os.path.isdir(os.path.join(out_pipe, c, "suricata-fifo")) and c not in hide)',
             'os.path.isdir(os.path.join(out_pipe, c, "suricata-fifo")))'),
    "engine-lines": ("skip = (m.group(1) or m.group(2)) in hide", "skip = False"),
    "no-list-hides-nothing": ('return hr23_feed.case_captures(os.path.join(root, GP, "hr23-cases.tsv")), (',
                              "return set(), ("),
    "counted-ignored": ('hidden(sys.argv[n - 1], sys.argv[n:] == ["--counted"])', "hidden(sys.argv[n - 1], False)"),
}


@pytest.mark.parametrize("old,new", DNP3_MUTANTS.values(), ids=DNP3_MUTANTS.keys())
def test_control_dnp3_mode_mutant_is_caught(tmp_path, old, new):
    here = tmp_path / "here"
    here.mkdir()
    for f in ("hr23_feed.py", "mountcheck.py", "hr23-held.hmac"):
        shutil.copy(os.path.join(HERE, f), here)
    with open(os.path.join(HERE, "table.py"), encoding="utf-8") as fh:
        text = fh.read()
    assert text.count(old) == 1, old
    (here / "table.py").write_text(text.replace(old, new), encoding="utf-8")
    assert dnp3_problems(tmp_path / "run", str(here)) != []


# run.sh's dnp3 mode calls those commands with ROOT and the counted flag,
# and keeps the engines' own lines off the job log but for held-log's copy:
# its text from `counted=` to the fifo table, under sh -eu, with the engines
# as stubs that print ENGINE_LINES.

def run_sh_block():
    with open(os.path.join(HERE, "run.sh"), encoding="utf-8") as fh:
        lines = fh.read().replace("\r", "").split("\n")
    start = lines.index("    dnp3_counted=")
    end = next(i for i in range(start, len(lines)) if 'table.py" fifo' in lines[i])
    return "\n".join(lines[start:end + 1]) + "\n"


def block_problems(tmp_path, text):
    bad = []
    for i, (env, counted, accepted) in enumerate(DNP3_RUNS[:4]):
        d = tmp_path / str(i)
        root, gt, work, out = dnp3_inputs(d)
        os.rename(out, os.path.join(work, "out-dnp3"))
        os.rename(str(d / "out-pipe"), os.path.join(work, "out-dnp3-pipe"))
        stub = (d / "engines.txt").read_text()
        script = d / "block.sh"
        script.write_text("set -eu\npython3() { \"$PY\" \"$@\"; }\nheader() { echo HEADER; }\n"
                          "engines() { printf '%s' \"$LINES\"; }\npipes() { :; }\nfifos() { :; }\n"
                          + text, newline="\n")
        e = run_env(dict(env, PY=sys.executable.replace("\\", "/"), here=HERE.replace("\\", "/"),
                         root=root.replace("\\", "/"), gt=gt.replace("\\", "/"), work=work.replace("\\", "/"),
                         hr23="", LINES=stub, **({"GITHUB_REF": "refs/heads/main"} if counted else {})))
        r = subprocess.run([SH, str(script).replace("\\", "/")], env=e, capture_output=True, text=True)
        md = open(os.path.join(work, "dnp3.md"), encoding="utf-8").read() if os.path.exists(
            os.path.join(work, "dnp3.md")) else ""
        log = r.stdout + r.stderr
        if r.returncode != 0 or f"| {OTHER} |" not in md or "other tail" not in log:
            bad.append(f"block {i}: exit {r.returncode}, or a table or the engine lines are missing")
        if HOLD in md + log or MARK in md + log or ("syn-a" in md + log) != accepted:
            bad.append(f"block {i}: a capture left out reached dnp3.md or the job log")
    return bad


@needs_sh
def test_the_dnp3_mode_calls_every_table_with_the_held_list(tmp_path):
    assert block_problems(tmp_path, run_sh_block()) == []


BLOCK_MUTANTS = {
    "engines-to-the-log": ('engines "$work/dnp3" "$work/out-dnp3" > "$work/dnp3-engines.txt"',
                           'engines "$work/dnp3" "$work/out-dnp3"'),
    "readings-without-root": ('table.py" hr23 "$work/out-dnp3" "$root" $dnp3_counted', 'table.py" hr23 "$work/out-dnp3"'),
    "dnp3-without-counted": ('"$work" "$root" $dnp3_counted', '"$work" "$root"'),
}


@needs_sh
@pytest.mark.parametrize("old,new", BLOCK_MUTANTS.values(), ids=BLOCK_MUTANTS.keys())
def test_control_dnp3_mode_block_mutant_is_caught(tmp_path, old, new):
    text = run_sh_block()
    assert text.count(old) == 1, old
    assert block_problems(tmp_path, text.replace(old, new)) != []
