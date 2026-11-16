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

The malformed set's cells are checked against the design's rules, derived
here from the builder's units and never from a run (D4-112 item 5): rule
(A) gives each input's judge (mal-twin) and its reqhdr under each
configuration (mal-reqhdr); a frame whose DIR disagrees with its side names
the weird (design 1 item 4); each cell reads as one of mal-states' states;
and (B') sets the record of a stop on a flow's first datagram (mal-bprime).
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
    CASES: "f66f7952a398c0fc420507dfb125c00f1bd3538399305f24fe1c5b2727420687",
    MALFORMED: "51e8285f4ee8b0fe46ddffe87098ee8e2e9b479dee970e35dd3375b41a43701e",
    CONDITIONS: "695f9ee6512fb449e7781f9bbd373da58102500958de85011a184e032b127e51",
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
    token = re.compile(r"(viol=(0|1|\?)|err=target|[A-Za-z0-9()]+=(seen|code|absent|\?)|weird=dnp3_[a-z_]+"
                       r"|reqhdr=[0-9]+|svc=(dnp3|removed))")
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


# --- the design's rules, derived from the builder's units --------------------

RESPONSES = {129, 130, 131}
A_CODES = {129, 130, 131}   # rule (A): the codes it sends to the response parser
BOUND = 4                   # rule (A): from this many application octets


def messages(cap):
    """Each message the capture's units carry, once, in the order sent, with
    its units, its code (None for one of 0 or 1 octets) and its side."""
    out = {}
    for units, _ in cap.sent:
        for u in units:
            if u.msg is not None:
                out.setdefault(id(u.msg), (u.msg, u.flow.side[u.end], []))[2].append(u)
    return [(m, side, us, m.code if isinstance(m.code, int) and m.app >= 2 else None) for m, side, us in out.values()]


def c2_response(code, n):
    """Rule (A): C2's response parser exactly for BOUND or more octets with code 129 to 131."""
    return n >= BOUND and code in A_CODES


def on_the_list(code, n, side):
    """Design 2.3's list: C2's parser differs from C1p's, which picks the response parser for the responder."""
    return c2_response(code, n) != (side == "resp")


def unknown_ground(cap):
    """mal-unknown's grounds, from the build: a header held at a TCP
    connection's end, a link length of 4 with FIR, a frame of 6 (no
    application octet) or a fragment of 0 or 1 octets, and a fragment of
    more than one frame (design 4.7 items 1 and 2)."""
    if cap.name.startswith("dnp3-mal-tcp-eof-"):
        return True
    if any(u.label.startswith("len(4)+FIR") for units, _ in cap.sent for u in units):
        return True
    return any("/" in us[0].name or m.app <= 1 for m, _, us, _ in messages(cap))


def want_judge(cap):
    if unknown_ground(cap):
        return "unknown"
    return "twin" if any(on_the_list(code, m.app, side) for m, side, _, code in messages(cap)) else "same"


def want_reqhdr(cap, config):
    """mal-reqhdr: the 129 to 131 raised as a request header. Under C0, C1
    and C1p, those from the originator; under C2, those under rule (A)'s bound."""
    return sum(1 for m, side, _, code in messages(cap) if code in RESPONSES
               and (not c2_response(code, m.app) if config == "c2" else side == "orig"))


def tokens(cell):
    return dict(t.split("=", 1) if "=" in t and not t.startswith("weird=") else (t, "") for t in cell.split("; "))


def cells(m):
    """(config, tokens) for the c0 cell and, unless it is =c1p, the c2 cell."""
    out = [("c0", tokens(m["c0"]))]
    if m["c2"] != "=c1p":
        out.append(("c2", tokens(m["c2"])))
    return out


def x_carries_129_131(cap):
    return any(code in RESPONSES for m, _, _, code in messages(cap) if m.name == "X")


def check_judge(ms, caps):
    """mal-twin: an input's judge is twin exactly when it has a fragment on
    design 2.3's list and no mal-unknown ground; unknown on such a ground."""
    for m in ms:
        assert m["judge"] == want_judge(caps[m["input"]]), m["input"]


def check_reqhdr(ms, caps):
    """mal-reqhdr: every input whose X carries 129 to 131 names reqhdr in
    each cell, with the value rule (A) gives under that configuration, and
    a c2 of =c1p only where rule (A) gives C2 C1p's value; no other input
    names it."""
    for m in ms:
        cap = caps[m["input"]]
        for config, t in cells(m):
            if x_carries_129_131(cap):
                assert t.get("reqhdr") == str(want_reqhdr(cap, config)), (m["input"], config)
            else:
                assert "reqhdr" not in t, (m["input"], config)
        if m["c2"] == "=c1p" and x_carries_129_131(cap):
            assert want_reqhdr(cap, "c2") == want_reqhdr(cap, "c0"), m["input"]


def check_x_objects(ms, caps):
    """mal-seen: where a cell names X and X carries whole objects, C2 parses
    them (rule (A) gives 4 octets or more its own code's parser), and C0, C1
    and C1p read its code without them exactly when X is on design 2.3's
    list (design 1 item 5; D4's N2 on #718)."""
    for m in ms:
        cap = caps[m["input"]]
        xs = [(x, side, code) for x, side, _, code in messages(cap) if x.name == "X"]
        if not xs or xs[0][0].objects == "-" or xs[0][0].state != "seen":
            continue
        x, side, code = xs[0]
        for config, t in cells(m):
            if t.get("X", "?") != "?":
                want = "seen" if config == "c2" or not on_the_list(code, x.app, side) else "code"
                assert t["X"] == want, (m["input"], config)


W_DIR = "weird=dnp3_unexpected_flow_direction"


def dir_against_side(cap):
    """A frame whose DIR, as built, disagrees with its end's side: Zeek
    raises dnp3_unexpected_flow_direction for it (design 1 item 4)."""
    return any(u.dir in ("0", "1") and (u.dir == "1") != (u.flow.side[u.end] == "orig")
               for units, _ in cap.sent for u in units)


def check_dir_weird(ms, caps):
    """Each cell names the weird exactly when a frame's DIR disagrees with its side (D2's N3 on #718)."""
    for m in ms:
        want = dir_against_side(caps[m["input"]])
        for config, t in cells(m):
            assert (W_DIR in t) == want, (m["input"], config)


def state(t, order):
    """mal-states: parsed on, recorded or silent, read from a cell's tokens;
    weird or err for a stop those record; None where viol is not judged."""
    if t.get("viol") == "?":
        return None
    named = [n for n in order if n in t and t[n] != "?"]
    if not named or t[named[-1]] in ("seen", "code"):
        assert t["viol"] == "0" and t.get("svc", "dnp3") == "dnp3", t
        return "on"
    if t["viol"] == "1":
        assert t.get("svc", "removed") == "removed", t
        return "recorded"
    if "err" in t or any(k.startswith("weird=") for k in t):
        assert "svc" not in t, t
        return "weird"
    assert t.get("svc") == "dnp3", f"a stop with no record must say svc=dnp3 (a silent stop): {t}"
    return "silent"


def order_of(cap):
    return [m.name for m, _, _, _ in messages(cap)]


def check_states(ms, caps):
    """Each judged cell reads as exactly one of mal-states' states."""
    for m in ms:
        for _, t in cells(m):
            state(t, order_of(caps[m["input"]]))


def x_first(cap):
    return cap.sent[0][0][0].name == "X"


def check_bprime(ms, caps):
    """mal-bprime, for an input whose X is its 5-tuple's first data: on UDP a
    stop is silent under C0, C1 and C1p and recorded under C2, with the
    service removed; on TCP a stop is recorded under all four. An input whose
    X comes later has no silent stop."""
    for m in ms:
        cap = caps[m["input"]]
        for config, t in cells(m):
            s = state(t, order_of(cap))
            if s in (None, "on", "weird"):
                continue
            if x_first(cap) and m["l4"] == "udp":
                assert s == ("recorded" if config == "c2" else "silent"), (m["input"], config, s)
                assert config != "c2" or t.get("svc") == "removed", (m["input"], config)
            else:
                assert s == "recorded", (m["input"], config, s)


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


def test_the_malformed_cells_follow_rules_a_and_bprime():
    ms, caps = rows(MALFORMED), built()
    check_judge(ms, caps)
    check_reqhdr(ms, caps)
    check_x_objects(ms, caps)
    check_dir_weird(ms, caps)
    check_states(ms, caps)
    check_bprime(ms, caps)


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


def malformed_edited(name, **cells_):
    ms = [dict(m) for m in rows(MALFORMED)]
    next(m for m in ms if m["input"] == name).update(cells_)
    return ms


def control_short_129_from_the_originator_as_twin(mp):
    """The pin before rule (A): an originator's 2-octet 129 judged twin, C2 stopping."""
    ms = malformed_edited("dnp3-mal-udp-fc129-2-orig", c2="viol=1; Q=absent; reqhdr=0", judge="twin")
    return lambda: check_judge(ms, built())


def control_limit_judged_same(mp):
    """D4's B2 on #718: the fragment of 413 frames judged same."""
    ms = malformed_edited("dnp3-mal-udp-limit", c2="=c1p", judge="same")
    return lambda: check_judge(ms, built())


def control_rule_a_bound_above_4(mp):
    """A rule whose bound is more than 4 octets: the pinned edges must refuse it."""
    mp.setitem(globals(), "BOUND", 5)
    return lambda: check_reqhdr(rows(MALFORMED), built())


def control_rule_a_without_131(mp):
    """A rule that sends a 131 of 4 octets to the request parser: the pinned edges must refuse it."""
    mp.setitem(globals(), "A_CODES", {129, 130})
    return lambda: check_reqhdr(rows(MALFORMED), built())


def control_reqhdr_value(mp):
    ms = malformed_edited("dnp3-mal-udp-fc129-4-orig", c2="viol=0; Q=seen; reqhdr=1")
    return lambda: check_reqhdr(ms, built())


def control_x_objects_seen_under_c0(mp):
    """D4's N2: fc2-resp's X read with its objects under C0, where the response header's default arm reads none."""
    ms = malformed_edited("dnp3-mal-tcp-fc2-resp-dirset",
                          c0="viol=0; X=seen; Q=seen; weird=dnp3_unexpected_flow_direction")
    return lambda: check_x_objects(ms, built())


def control_dir_weird_dropped(mp):
    """D2's N3: X's DIR set from the responder, with no weird pinned."""
    ms = malformed_edited("dnp3-mal-tcp-fc0-resp-dirset", c0="viol=1; Q=absent")
    return lambda: check_dir_weird(ms, built())


def control_dir_weird_where_dir_agrees(mp):
    ms = malformed_edited("dnp3-mal-tcp-fc0-resp-dirclear", c0="viol=1; Q=absent; weird=dnp3_unexpected_flow_direction")
    return lambda: check_dir_weird(ms, built())


def control_stop_with_no_state(mp):
    """A stop with no violation, weird, reporter error or svc: none of mal-states' states."""
    ms = malformed_edited("dnp3-mal-udp-fc129-2-resp", c0="viol=0; Q=absent; reqhdr=0")
    return lambda: check_states(ms, built())


def control_recorded_stop_keeps_the_service(mp):
    ms = malformed_edited("dnp3-mal-udp-fc129-badobj-first", c2="viol=1; svc=dnp3; P=absent; Q=absent; reqhdr=0")
    return lambda: check_states(ms, built())


def control_bprime_udp_first_datagram_silent(mp):
    """C2 without (B'): the stop on the first datagram left silent, as the stock catch leaves it."""
    ms = malformed_edited("dnp3-mal-udp-fc129-badobj-first", c2="viol=0; svc=dnp3; P=absent; Q=absent; reqhdr=0")
    return lambda: check_bprime(ms, built())


def control_bprime_tcp_silent(mp):
    ms = malformed_edited("dnp3-mal-tcp-fc129-badobj-first", c2="viol=0; svc=dnp3; P=absent; Q=absent; reqhdr=0")
    return lambda: check_bprime(ms, built())


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
