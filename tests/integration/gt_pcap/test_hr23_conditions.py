"""HR-23's stage-2 cases and pass conditions are pinned (D6, brief P4-4-HR2325S, deliverable 1).

hr23-cases.tsv, hr23-malformed.tsv and hr23-conditions.tsv are what HR-23's
counted run is judged by, written before it from brief P4-4-HR23 and
docs/phase4/D4-hr23-design.md section 4. A later edit must be visible, so
this test pins the three files' SHA-256 (LF line endings, as Git stores
them), as pins.env will pin them for the run (row judge-counted). It also
checks what the pins must hold, each check with a named control that must
fail: the cases' rows are what hr23_cases.py built and what
engine-pass-conditions.tsv holds for the two existing captures; a row the
control passes reads unknown for the fix (the brief's rule); a fix of part
(a) or (b) has the cells that show it; C1p equals C1 on every row (design
4.1); every case the brief and the design name is there; each malformed
input is a capture whose packets are its build cell; and every row id a
cell or header names exists.
"""

import csv
import hashlib
import os
import re

import pytest

import hr23_cases as hc

HERE = os.path.dirname(os.path.abspath(__file__))
CASES = os.path.join(HERE, "hr23-cases.tsv")
MALFORMED = os.path.join(HERE, "hr23-malformed.tsv")
CONDITIONS = os.path.join(HERE, "hr23-conditions.tsv")
ENGINE = os.path.join(HERE, "engine-pass-conditions.tsv")
SHA256 = {
    CASES: "eb6a2f2a567c28d8135d22fbbaa0a7f13e34d24624fa86fc96ca9475e4d43d7e",
    MALFORMED: "e2e0516838c3d61c6cdc541d67d17f67fa7931612f1a544957a4698968bbd084",
    CONDITIONS: "708f6c3a6e86aaedc64693e63fff6c46fa931035ffcdac39f6d625760aa93fee",
}
CONFIGS = ("c0", "c1", "c1p", "c2")
FIXES = {"a", "b", "unknown", "premise", "control", "r1"}
# The cases brief P4-4-HR23 (stage 2) and the design's section 4.2 name.
NAMED = {"dnp3-udp-temp-port", "dnp3-udp-unsolicited", "dnp3-udp-relay-write", "dnp3-udp-relay-restart",
         "dnp3-udp-master-short", "dnp3-udp-dir-spoof", "dnp3-udp-swap-control", "dnp3-tcp-master-short",
         "dnp3-tcp-dir-spoof"}
EXISTING = ("dnp3-udp-temp-port", "dnp3-udp-unsolicited")


def content(path):
    with open(path, "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def rows(path):
    lines = [ln for ln in content(path).decode("utf-8").split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def header_lines(path):
    return [ln for ln in content(path).decode("utf-8").split("\n") if ln.startswith("#")]


_BUILT = []


def built():
    if not _BUILT:
        _BUILT.append({c.name: c for c in hc.captures()})
    return _BUILT[0]


def test_the_files_are_the_pinned_ones():
    for path, digest in SHA256.items():
        assert hashlib.sha256(content(path)).hexdigest() == digest, os.path.basename(path)


# --- the checks ------------------------------------------------------------

def check_whole(rs, cols):
    assert rs and list(rs[0]) == cols
    for r in rs:
        assert None not in r and None not in r.values(), r


def check_cells(rs):
    """Each cell in the vocabulary of judge-cells and judge-fix."""
    for r in rs:
        for c in CONFIGS:
            v = r[c]
            assert v in ("pass", "fail", "present") or re.fullmatch(r"fail \(.+\)", v), (r["capture"], c, v)
        assert r["fix"] in FIXES, r
        assert r["basis"], r


def check_fix(rs):
    """The brief's rule and judge-fix: a row that C0 passes reads unknown for
    the fix unless it is the premise, a control or R-1's report; a fix of
    part (a) needs C0 fail and C1, C1p and C2 pass; of part (b), C0, C1 and
    C1p fail and C2 pass."""
    for r in rs:
        c0, c1, c1p, c2 = (r[c].split(" (")[0] for c in CONFIGS)
        if c0 == "pass" and r["fix"] not in ("premise", "control", "r1"):
            assert r["fix"] == "unknown", r
        if r["fix"] == "a":
            assert (c0, c1, c1p, c2) == ("fail", "pass", "pass", "pass"), r
        if r["fix"] == "b":
            assert (c0, c1, c1p, c2) == ("fail", "fail", "fail", "pass"), r
        if r["fix"] == "unknown":
            assert c0 == "pass", r


def check_c1p(rs):
    """C1p is expected to equal C1 on every row (design 4.1)."""
    for r in rs:
        assert r["c1p"] == r["c1"], r


def check_named(rs):
    caps = {r["capture"] for r in rs}
    assert NAMED <= caps, NAMED - caps
    for r in rs:
        # Case ids name their transport, and none of the strings table.py tags by (design 4, opening).
        assert re.fullmatch(r"dnp3-(udp|tcp)-[a-z0-9-]+", r["capture"]), r["capture"]
        assert r["capture"].startswith(f"dnp3-{r['l4']}-"), r
        assert not r["capture"].endswith("-udp") and "moved-port" not in r["capture"], r
    # dnp3-udp-temp-port's service row and dnp3-udp-unsolicited's five rows (the brief).
    svc = [r for r in rs if r["capture"] == "dnp3-udp-temp-port" and r["condition"] == "service"]
    assert len(svc) == 1 and svc[0]["fix"] == "a", svc
    five = [r for r in rs if r["capture"] == "dnp3-udp-unsolicited" and r["condition"] != "objects"]
    assert sorted((r["condition"], r["code"]) for r in five) == [
        ("function", "1"), ("function", "2"), ("function", "5"), ("protocol", ""), ("service", "")]


def check_built_rows(rs, caps):
    """The rows of hr23_cases.py's captures are exactly what it built, and
    the two existing captures' rows are engine-pass-conditions.tsv's, each
    function row with its objects row."""
    with open(ENGINE, encoding="utf-8") as f:
        engine = [r for r in csv.reader(f, delimiter="\t") if r and r[0] in EXISTING]
    want = []
    for r in engine:
        want.append(r)
        if r[0] == "dnp3-udp-unsolicited" and r[1] == "function":
            want.append([r[0], "objects"] + r[2:])
    for name, cap in caps.items():
        if cap.kind == "case":
            want += hc.case_rows(cap)
    got = [[r[c] for c in hc.E_COLUMNS] for r in rs]
    assert got == want


def check_malformed(ms, caps):
    """Every input is a malformed capture or a dir-spoof case; its build
    cell is the builder's packets; its side is the label's; its cells use
    mal-judge's tokens; same means c2 =c1p; only len-1 to -3 expect a
    reporter error."""
    names = [m["input"] for m in ms]
    assert names == [n for n, _ in hc.MALFORMED] + ["dnp3-udp-dir-spoof", "dnp3-tcp-dir-spoof"]
    token = re.compile(r"(viol=(0|1|\?)|err=target|[A-Za-z0-9()]+=(seen|absent|\?)|weird=dnp3_[a-z_]+)")
    for m in ms:
        cap = caps[m["input"]]
        assert m["build"] == hc.build_cell(cap), m["input"]
        assert m["l4"] == cap.flows[0].l4, m
        assert m["side"] in ("orig", "resp"), m
        assert m["judge"] in ("same", "twin", "unknown"), m
        for cell in (m["c0"], m["c2"]):
            if cell == "=c1p":
                continue
            for t in cell.split("; "):
                assert token.fullmatch(t), (m["input"], t)
        assert (m["c2"] == "=c1p") == (m["judge"] == "same"), m
        assert ("err=target" in m["c0"]) == bool(re.fullmatch(r"dnp3-mal-udp-len-[123]", m["input"])), m
        assert m["basis"], m


def check_sides(ms, caps):
    """A malformed input's side is the side its own unit was built on."""
    own = {"dnp3-mal-udp-len-5-trail": "L", "dnp3-mal-udp-longer": "W", "dnp3-mal-udp-two-frames": "W",
           "dnp3-mal-udp-dir-both": "R(P)", "dnp3-mal-udp-dir-change": "R(W)", "dnp3-udp-dir-spoof": "W",
           "dnp3-tcp-dir-spoof": "W"}
    for m in ms:
        cap = caps[m["input"]]
        want = own.get(m["input"])
        u = next(u for units, _ in cap.sent for u in units if u.name in ((want,) if want else ("X", "X/1")))
        assert m["side"] == u.flow.side[u.end], m["input"]


ROW_ID = re.compile(r"(?<![\w-])(?:judge|mal|fp|rerun|report|pin|cfg)-[a-z0-9]+(?:-[a-z0-9]+)*")


def check_ids(cond_rows):
    """Every row id that a header, a rule or a basis names is a row of the
    conditions file, and no id is used twice."""
    ids = [r["id"] for r in cond_rows]
    assert len(set(ids)) == len(ids)
    texts = (header_lines(CASES) + header_lines(MALFORMED) + [r["rule"] for r in cond_rows]
             + [m["basis"] for m in rows(MALFORMED)] + [r["basis"] for r in rows(CASES)])
    named = {n for t in texts for n in ROW_ID.findall(t)}
    missing = named - set(ids)
    assert not missing, missing


def check_conditions(cond_rows):
    check_whole(cond_rows, ["id", "subject", "op", "value", "rule"])
    for r in cond_rows:
        assert r["rule"], r
        assert (r["op"] == "") == (r["value"] == ""), r
        assert r["op"] in ("", "=", "<=", ">="), r
    by = {r["id"]: r for r in cond_rows}
    assert by["fp-1245"]["value"] == "0" and by["fp-6"]["value"] == "0"


def test_the_cases_are_whole_and_their_cells_read():
    rs = rows(CASES)
    check_whole(rs, hc.E_COLUMNS + ["c0", "c1", "c1p", "c2", "fix", "basis"])
    check_cells(rs)


def test_a_row_the_control_passes_reads_unknown_for_the_fix():
    check_fix(rows(CASES))


def test_c1p_equals_c1_on_every_row():
    check_c1p(rows(CASES))


def test_every_named_case_is_there_and_names_its_transport():
    check_named(rows(CASES))


def test_the_cases_rows_are_what_was_built():
    check_built_rows(rows(CASES), built())


def test_every_malformed_input_is_its_capture():
    check_malformed(rows(MALFORMED), built())
    check_sides(rows(MALFORMED), built())


def test_the_conditions_are_whole_and_every_named_row_exists():
    cs = rows(CONDITIONS)
    check_conditions(cs)
    check_ids(cs)


# --- the controls: named mutants that each check must fail -----------------

def edited(rs, capture, condition, **cells):
    out = [dict(r) for r in rs]
    r = next(r for r in out if r["capture"] == capture and r["condition"] == condition)
    r.update(cells)
    return out


def control_fix_b_on_a_row_c0_passes(mp):
    """relay-write's function row, which C0 passes, read as b for the fix."""
    rs = edited(rows(CASES), "dnp3-udp-relay-write", "function", fix="b")
    return lambda: check_fix(rs)


def control_fix_a_with_c1_failing(mp):
    """temp-port's service row read as a with C1 failing it."""
    rs = edited(rows(CASES), "dnp3-udp-temp-port", "service", c1="fail")
    return lambda: check_fix(rs)


def control_cell_out_of_vocabulary(mp):
    rs = edited(rows(CASES), "dnp3-udp-relay-write", "protocol", c2="passes")
    return lambda: check_cells(rs)


def control_c1p_differs(mp):
    rs = edited(rows(CASES), "dnp3-udp-relay-restart", "service", c1p="fail")
    return lambda: check_c1p(rs)


def control_named_case_dropped(mp):
    rs = [r for r in rows(CASES) if r["capture"] != "dnp3-udp-relay-restart"]
    return lambda: check_named(rs)


def control_unsolicited_row_dropped(mp):
    rs = [r for r in rows(CASES) if not (r["capture"] == "dnp3-udp-unsolicited" and r["code"] == "5"
                                         and r["condition"] == "function")]
    return lambda: check_named(rs)


def control_built_packet_moved(mp):
    """A case's function row naming another packet than the one built."""
    rs = edited(rows(CASES), "dnp3-udp-relay-write", "function", frames="2,4")
    return lambda: check_built_rows(rs, built())


def control_existing_row_changed(mp):
    """An engine-pass-conditions.tsv row of dnp3-udp-unsolicited with another code."""
    rs = edited(rows(CASES), "dnp3-udp-unsolicited", "service", dport="20001")
    return lambda: check_built_rows(rs, built())


def control_builder_changes_a_port(mp):
    """The builder putting swap-control's master on 20000: its rows no longer the pinned ones."""
    built()
    mp.setattr(hc, "CASES", [(n, hc.relay_write(20000) if n == "dnp3-udp-swap-control" else b) for n, b in hc.CASES])
    caps = {c.name: c for c in hc.captures()}
    return lambda: check_built_rows(rows(CASES), caps)


def control_malformed_build_changed(mp):
    ms = [dict(m) for m in rows(MALFORMED)]
    ms[0]["build"] = ms[0]["build"].replace("X | Q", "Q | X")
    return lambda: check_malformed(ms, built())


def control_malformed_same_with_own_c2(mp):
    ms = [dict(m) for m in rows(MALFORMED)]
    m = next(m for m in ms if m["judge"] == "same")
    m["c2"] = "viol=0; Q=seen"
    return lambda: check_malformed(ms, built())


def control_reporter_error_expected_elsewhere(mp):
    ms = [dict(m) for m in rows(MALFORMED)]
    m = next(m for m in ms if m["input"] == "dnp3-mal-udp-len-0")
    m["c0"] = "viol=0; err=target; Q=absent"
    return lambda: check_malformed(ms, built())


def control_malformed_side_flipped(mp):
    ms = [dict(m) for m in rows(MALFORMED)]
    m = next(m for m in ms if m["input"] == "dnp3-mal-udp-short-0-resp")
    m["side"] = "orig"
    return lambda: check_sides(ms, built())


def control_condition_id_missing(mp):
    cs = [r for r in rows(CONDITIONS) if r["id"] != "judge-link"]
    return lambda: check_ids(cs)


def control_condition_threshold_without_op(mp):
    cs = [dict(r) for r in rows(CONDITIONS)]
    next(r for r in cs if r["id"] == "fp-1245")["op"] = ""
    return lambda: check_conditions(cs)


CONTROLS = {name[len("control_"):].replace("_", "-"): f for name, f in globals().items() if name.startswith("control_")}


@pytest.mark.parametrize("control", sorted(CONTROLS))
def test_each_check_fails_its_named_control(control, monkeypatch):
    check = CONTROLS[control](monkeypatch)
    with pytest.raises(AssertionError):
        check()
