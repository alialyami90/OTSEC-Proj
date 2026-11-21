"""Held captures in HR-23's judge and check (D1's rulings 7056743490 and
7057468942 on #776, D4-122): table.py's cases and hr23judge and
hr23_feed.py's held_list and check, on synthetic
captures with neutral names (syn-*) and results made up here. No engine
runs, no real capture is named as held, and no log is read. Each rule has a
named control: a mutant of the script's text that must make the rule's
check fail.
Run: python -m pytest -q modules/telemetry/experiments/engine-linux/test_hr23_held.py"""
import importlib.util
import os
import sys

import pytest

import hr23_feed
import table

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import hr23_cases  # noqa: E402,F401 (hr23judge imports it by name)

C0, C1, C1P, C2 = table.JUDGED
HOLD, MARK = "syn-held", "HELD-RESULT-MARK"
# Test salts: hex, as the run's salt must be; never a run's.
SALT = "0123456789abcdef" * 4
SALT2 = "fedcba9876543210" * 4
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
]


def gate_problems(feed, monkeypatch, capsys, tmp_path):
    bad = []
    for i, (env, counted, want, committed) in enumerate(GATES):
        try:
            rc, out = run(table, monkeypatch, capsys, tmp_path / str(i), ROWS, RESULTS, env, counted, feed=feed,
                          digest=committed)
        except Exception as e:  # noqa: BLE001 (a mutant may stop the judge)
            bad.append(f"gate {i}: {type(e).__name__}")
            continue
        if rc != want or "| syn-" in out or "SHA-256" in out or "syn-unknown-name" in out:
            bad.append(f"gate {i}: exit {rc}, want {want}, or a row, the hash or the list was printed")
    return bad


def test_without_the_held_list_and_the_salt_no_row_is_printed(monkeypatch, capsys, tmp_path):
    assert gate_problems(hr23_feed, monkeypatch, capsys, tmp_path) == []


def test_the_digest_is_hmac_sha256_of_the_sorted_list_keyed_by_the_salt():
    import hashlib
    import hmac
    want = hmac.new(SALT.encode(), b"syn-a\nsyn-held\n", hashlib.sha256).hexdigest()
    assert hr23_feed.list_digest(["syn-held", "syn-a", "syn-held"], SALT) == want


def test_the_committed_value_is_the_synthetic_test_value():
    # D4 commits only a test value (D1's ruling 1 on #776): the synthetic
    # list syn-held under the test salt SALT. D1 replaces it, and this test,
    # when the value for a counted run's salt is committed.
    assert hr23_feed.committed_digest(hr23_feed.DIGEST) == hr23_feed.list_digest([HOLD], SALT)


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
    return bad


def test_check_holds_a_held_capture(tmp_path, capsys, monkeypatch):
    assert check_problems(hr23_feed, tmp_path, capsys, monkeypatch) == []


CHECK_MUTANTS = {
    "cells-not-held": ('" | ".join([HELD] * len(CONFIGS) if c in held else cells)', '" | ".join(cells)'),
    "failure-named": ("            if code != \"0\" and c in held:\n                held_unclean = True\n            elif",
                      "            if"),
    "no-list-prints-rows": ("    if not fp:\n        held, why", "    if False:\n        held, why"),
    "cases-not-read": ("held_list(case_captures(cases) if cases else set(), env)", "held_list({'syn-a'}, env)"),
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
    "no-list-prints-rows": ("    held, _, why = held_gate(root, env)\n    import hr23_feed\n",
                            "    held, _, why = held_gate(root, env)\n    import hr23_feed\n    held, why = (set() if held is None else held), (None if held is None else why)\n"),
    "refused-list-goes-on": ("    if held is False:\n        print(f\"Not judged or printed: {why} (D1's ruling 7057468942", "    if held is None and False:\n        print(f\"Not judged or printed: {why} (D1's ruling 7057468942"),
}


@pytest.mark.parametrize("old,new", MAL_MUTANTS.values(), ids=MAL_MUTANTS.keys())
def test_control_malformed_mutant_is_caught(monkeypatch, capsys, tmp_path, old, new):
    assert malformed_problems(load(table, old, new, "mutant_table"), monkeypatch, capsys, tmp_path) != []
