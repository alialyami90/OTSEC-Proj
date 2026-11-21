"""HR-23's judge (D4, brief P4-4-HR23-JUDGE; D4-113 item 3.2): table.py's
hr23judge and the rules it applies from hr23-conditions.tsv, on logs made
up here. No engine runs and no engine output is read: every log below is
synthetic. Each rule has a named control, a case on which the rule must
give the other answer, or a mutant of table.py's text that must make a
check fail. Run: python -m pytest -q
modules/telemetry/experiments/engine-linux/test_hr23_rules.py"""
import collections
import copy
import importlib.util
import json
import os
import sys

import pytest

import table

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "integration", "gt_pcap"))
import hr23_cases  # noqa: E402
import pcapfile  # noqa: E402

LIKELY = hr23_cases.LIKELY
PORTS = {cfg: copy.deepcopy(LIKELY) for cfg in table.JUDGED}
C0, C1, C1P, C2 = table.JUDGED


def mutant(tmp_path, old, new):
    """A mutant of table.py, as a module of its own."""
    with open(table.__file__, encoding="utf-8") as fh:
        text = fh.read()
    assert text.count(old) == 1, old
    p = tmp_path / "mutant_table.py"
    p.write_text(text.replace(old, new), encoding="utf-8")
    spec = importlib.util.spec_from_file_location("mutant_table", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def write_logs(d, conn=(), probe=(), analyzer=(), weird=(), reporter=(), code="0"):
    d.mkdir(parents=True, exist_ok=True)
    for name, rows in (("conn", conn), ("otsec_probe", probe), ("analyzer", analyzer), ("weird", weird),
                       ("reporter", reporter)):
        if rows:
            (d / f"{name}.log").write_text("".join(json.dumps(r) + "\n" for r in rows))
    if code is not None:
        (d / "exit-code").write_text(code + "\n")


def conn(uid, l4, o, p, service):
    return {"ts": 1.0, "uid": uid, "proto": l4, "id.orig_h": o[0], "id.orig_p": int(o[1]),
            "id.resp_h": p[0], "id.resp_p": int(p[1]), "service": service}


def fc(uid, is_orig, code, ts=1.0, request_header=None):
    req = code not in (129, 130, 131) if request_header is None else request_header
    return {"ts": ts, "uid": uid, "is_orig": is_orig, "kind": "fc", "fc": code,
            "ev": "dnp3_application_request_header" if req else "dnp3_application_response_header"}


def obj(uid, is_orig, g, v):
    return {"ts": 1.0, "uid": uid, "is_orig": is_orig, "kind": "obj", "group": g, "variation": v}


# cfg-ports.

def test_read_ports_takes_zeek_dones_line(tmp_path):
    p = tmp_path / "p.txt"
    p.write_text("likely_server_ports at zeek_init, priority -1000: tcp [1]; udp [2]\n"
                 "likely_server_ports at zeek_done: tcp [20000, 502]; udp []\n")
    assert table.read_ports(str(p)) == {"tcp": {20000, 502}, "udp": set()}


def test_control_ports_not_printed_read_as_none(tmp_path):
    assert table.read_ports(str(tmp_path / "missing.txt")) is None
    p = tmp_path / "p.txt"
    p.write_text("something else\n")
    assert table.read_ports(str(p)) is None


def test_a_flow_on_a_moved_port_reads_unknown_and_its_control_does_not():
    moved = copy.deepcopy(LIKELY)
    moved["udp"].discard(20000)
    assert table.sides_moved(moved, LIKELY, "udp", ("20000", "41019")).startswith("unknown")
    # Control: the same flow on the pinned set, and a port that did not move.
    assert table.sides_moved(LIKELY, LIKELY, "udp", ("20000", "41019")) is None
    assert table.sides_moved(moved, LIKELY, "udp", ("41018", "41019")) is None
    assert table.sides_moved(None, LIKELY, "udp", ("41018",)).startswith("unknown")


def test_a_row_with_no_source_port_is_judged_on_its_other_port(tmp_path):
    # A service row names no source port; the moved port still turns it unknown.
    moved = copy.deepcopy(LIKELY)
    moved["udp"].discard(20000)
    assert table.sides_moved(moved, LIKELY, "udp", ("", "20000")).startswith("unknown")
    assert table.sides_moved(LIKELY, LIKELY, "udp", ("", "20000")) is None
    # Control: without the empty-port rule the row stops the judge.
    m = mutant(tmp_path, "for p in flow_ports if p and (", "for p in flow_ports if (")
    with pytest.raises(ValueError):
        m.sides_moved(LIKELY, LIKELY, "udp", ("", "20000"))


# The cases (judge-rows, judge-cells, judge-link, judge-fix and the rest),
# on made-up rows: none of hr23-cases.tsv's rows is judged here.
M, O = ("192.0.2.14", "20000"), ("192.0.2.20", "20000")


def row(cap, cond, code="", objects="", show="", **cells):
    r = {"capture": cap, "condition": cond, "l4": "udp", "src": M[0], "sport": M[1], "dst": O[0], "dport": O[1],
         "code": code, "objects": objects, "sa": "", "show": show, "frames": "", "protocol": "dnp3",
         "direction": "none", "c0": "pass", "c1": "pass", "c1p": "pass", "c2": "pass", "fix": "unknown", "basis": ""}
    r.update(cells)
    return r


def master_logs(d, with_objects=True, code="0"):
    probe = [fc("C1", True, 1)] + ([obj("C1", True, 60, 1)] if with_objects else [])
    write_logs(d, [conn("C1", "udp", M, O, "dnp3_udp")], probe, code=code)


def test_a_function_and_its_objects_row_pass_on_one_message(tmp_path):
    rows = [(0, row("x", "function", "1", "g60v1")), (1, row("x", "objects", "1", "g60v1"))]
    master_logs(tmp_path / "a")
    res = table.case_results(rows, str(tmp_path / "a"), C1, "", PORTS[C1], LIKELY)
    assert res[0][0].startswith("pass") and res[1][0] == "pass"
    # Control: the message logged without its object fails the objects row only.
    master_logs(tmp_path / "b", with_objects=False)
    res = table.case_results(rows, str(tmp_path / "b"), C1, "", PORTS[C1], LIKELY)
    assert res[0][0].startswith("pass") and res[1][0] == "fail"


def test_a_row_whose_engine_did_not_run_is_unknown_never_pass(tmp_path):
    rows = [(0, row("x", "function", "1", "g60v1")), (1, row("x", "objects", "1", "g60v1"))]
    master_logs(tmp_path / "crash", code="139")
    write_logs(tmp_path / "none", code=None)
    for d in ("crash", "none"):
        res = table.case_results(rows, str(tmp_path / d), C1, "", PORTS[C1], LIKELY)
        assert all(r.startswith("unknown") for r, _ in res.values()), res
        assert table.outcome("pass", res[0][0]) == "unknown"


def test_control_judge_without_the_ran_check_passes_an_unrun_row(tmp_path):
    m = mutant(tmp_path, "    why = ran(d)\n    if why:\n        return {n: (f\"unknown ({why})\", \"\") for n, _ in rows}\n",
               "    why = None\n")
    master_logs(tmp_path / "crash", code="139")
    res = m.case_results([(0, row("x", "function", "1", "g60v1"))], str(tmp_path / "crash"), C1, "", PORTS[C1], LIKELY)
    assert res[0][0].startswith("pass")


def test_cfg_ports_turns_a_case_row_unknown(tmp_path):
    moved = copy.deepcopy(LIKELY)
    moved["udp"].discard(20000)
    master_logs(tmp_path / "a")
    rows = [(0, row("x", "function", "1", "g60v1"))]
    assert table.case_results(rows, str(tmp_path / "a"), C1, "", moved, LIKELY)[0][0].startswith("unknown")
    assert table.case_results(rows, str(tmp_path / "a"), C1, "", PORTS[C1], LIKELY)[0][0].startswith("pass")


def link_case(tmp_path, ts, is_orig=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    pcap = tmp_path / "x.pcap"
    pcapfile.write(str(pcap), [pcapfile.Frame(n * 1_000_000_000 + 250_000_000, b"\0" * 60) for n in (1, 2, 3)])
    d = tmp_path / "out"
    write_logs(d, [conn("C1", "udp", M, O, "dnp3_udp")],
               [{"ts": ts, "uid": "C1", "is_orig": is_orig, "kind": "link", "link_dir": True}])
    r = row("x", "link", show="a link row with is_orig true stamped with packet 3's time")
    return table.link_present(str(d), r, str(pcap))[0]


def test_judge_link_finds_the_row_stamped_with_the_named_packet(tmp_path):
    assert link_case(tmp_path / "a", 3.25) == "present"
    # Control: the same row stamped with packet 2's time.
    assert link_case(tmp_path / "b", 2.25) == "absent"


def results(rows, per_cfg):
    """RES for judge_cases: per_cfg[cfg] is a list of results, one per row."""
    return {cfg: {n: (per_cfg[cfg][n], "") for n in range(len(rows))} for cfg in table.JUDGED}


def judge(rows, per_cfg, root=ROOT):
    oc, fix, findings, _ = table.judge_cases(rows, results(rows, per_cfg), root)
    return oc, fix, [t for _, t in findings]


def test_fix_a_shows_when_c0_fails_and_c1_c1p_pass(tmp_path):
    rows = [row("x", "service", c0="fail", fix="a")]
    _, fix, findings = judge(rows, {C0: ["fail"], C1: ["pass"], C1P: ["pass"], C2: ["pass"]})
    assert fix[0] == "a shows" and findings == []
    # Control (judge-control): C0 passes where its pin says fail.
    _, fix, findings = judge(rows, {C0: ["pass"], C1: ["pass"], C1P: ["pass"], C2: ["pass"]})
    assert fix[0].startswith("unknown (judge-control") and findings[0].startswith("judge-control")


def test_fix_b_shows_only_when_c2_shows_its_pinned_pass(tmp_path):
    rows = [row("x", "function", "1", c0="fail", c1="fail", c1p="fail", fix="b")]
    assert judge(rows, {C0: ["fail"], C1: ["fail"], C1P: ["fail"], C2: ["pass"]})[1][0] == "b shows"
    # Control: C2 fails too; and a regression is not claimed (its c2 pin is pass, so it is one, of the build).
    _, fix, findings = judge(rows, {C0: ["fail"], C1: ["fail"], C1P: ["fail"], C2: ["fail"]})
    assert fix[0] == "b does not show"
    assert any("C2 fails, of the build" in f for f in findings)


def test_fix_unknown_and_r1_are_never_a_pass():
    rows = [row("x", "protocol", fix="unknown"), row("x", "service", fix="r1", c1="fail (x)")]
    _, fix, _ = judge(rows, {cfg: ["pass", "pass"] for cfg in table.JUDGED})
    assert fix[0].startswith("unknown") and fix[1].startswith("r1") and "never a pass" in fix[1]


def test_a_row_not_run_under_one_configuration_reads_unknown_for_the_fix():
    rows = [row("x", "function", "1", c0="fail", c1="fail", c1p="fail", fix="b")]
    oc, fix, _ = judge(rows, {C0: ["fail"], C1: ["unknown (not run)"], C1P: ["fail"], C2: ["pass"]})
    assert oc[0][C1] == "unknown" and fix[0].startswith("unknown")


def swap_rows(c0_result):
    """A relay-started case (dnp3-udp-relay-write, by its labels) with a fix b
    row, and the swap's control row."""
    rows = [row("dnp3-udp-relay-write", "function", "2", c0="fail", c1="fail", c1p="fail", fix="b"),
            row(table.SWAP, "protocol", fix="control")]
    return judge(rows, {C0: ["fail", c0_result], C1: ["fail", "pass"], C1P: ["fail", "pass"], C2: ["pass", "pass"]})


def test_judge_swap_makes_relay_started_cases_unknown_when_the_control_fails():
    assert swap_rows("fail")[1][0].startswith("unknown (judge-swap")
    # Control: the swap's control passes under C0.
    assert swap_rows("pass")[1][0] == "b shows"


def test_relay_started_reads_the_builders_labels():
    assert table.relay_started(ROOT, "dnp3-udp-relay-write")
    assert table.relay_started(ROOT, "dnp3-udp-unsolicited")
    # Controls: master-started cases.
    assert not table.relay_started(ROOT, "dnp3-udp-master-short")
    assert not table.relay_started(ROOT, "dnp3-udp-temp-port")


def objects_rows(ctl_c0):
    rows = [row("y", "objects", "5", "g12v1", c0="fail", c1="fail", c1p="fail", fix="b"),
            row(table.OBJ_CONTROL["g12v1"], "objects", "5", "g12v1")]
    return judge(rows, {C0: ["fail", ctl_c0], C1: ["fail", "pass"], C1P: ["fail", "pass"], C2: ["pass", "pass"]})


def test_judge_objects_needs_the_objects_own_control_to_pass_under_c0():
    assert objects_rows("fail")[1][0].startswith("unknown (judge-objects")
    assert objects_rows("pass")[1][0] == "b shows"


def test_judge_link_absent_under_c1_makes_c1s_service_pass_unknown():
    rows = [row("z", "service", c0="fail", fix="a"), row("z", "link", c0="present", c1="present", c1p="present",
                                                          c2="present", fix="control")]
    per = {C0: ["fail", "present"], C1: ["pass", "absent"], C1P: ["pass", "present"], C2: ["pass", "present"]}
    oc, fix, _ = judge(rows, per)
    assert oc[0][C1] == "unknown" and fix[0].startswith("unknown")
    per[C1] = ["pass", "present"]
    assert judge(rows, per)[1][0] == "a shows"


def test_premise_and_part_a_regression_are_findings():
    rows = [row(table.PREMISE, "function", "1", fix="premise"), row("w", "service", fix="unknown")]
    _, _, findings = judge(rows, {C0: ["fail", "pass"], C1: ["pass", "fail"], C1P: ["pass", "pass"], C2: ["pass", "pass"]})
    assert any(f.startswith("premise") for f in findings)
    assert any("C1 fails, of part (a)" in f for f in findings)
    _, _, findings = judge(rows, {cfg: ["pass", "pass"] for cfg in table.JUDGED})
    assert findings == []


# The malformed set (mal- rows), on one input's labels:
# dnp3-mal-udp-fc129-badobj-mid, flow udp 192.0.2.14:20000 > 192.0.2.20:20000,
# P (1, g60v1) and Q (1, g60v2..4) and X (129) from the master.
INP = "dnp3-mal-udp-fc129-badobj-mid"
MAL = next(r for r in table.tsv(os.path.join(ROOT, table.GP, "hr23-malformed.tsv")) if r["input"] == INP)


def mal_logs(d, svc="dnp3_udp", viol=0, x="code", q=True, reqhdr=1, other_analyzer=False, reporter=(), code="0",
             weird=(), link=(), other_flow_viol=0):
    probe = [fc("C1", True, 1), obj("C1", True, 60, 1), fc("C1", False, 129)]
    if x in ("code", "seen"):
        probe += [fc("C1", True, 129, request_header=reqhdr > 0)]
        if x == "seen":
            probe += [obj("C1", True, 60, 1)]
    if q:
        probe += [fc("C1", True, 1), obj("C1", True, 60, 2), obj("C1", True, 60, 3), obj("C1", True, 60, 4)]
    probe += [{"ts": 1.0, "uid": "C1", "is_orig": io, "kind": "link", "link_dir": ld} for io, ld in link]
    an = [{"uid": "C1", "analyzer_name": "DNP3_UDP", "failure_reason": "r"}] * viol
    an += [{"uid": "C9", "analyzer_name": "DNP3_UDP", "failure_reason": "r"}] * other_flow_viol
    if other_analyzer:
        an.append({"uid": "C1", "analyzer_name": "PIA_UDP", "failure_reason": "r"})
    write_logs(d, [conn("C1", "udp", M, ("192.0.2.20", "20000"), svc)], probe, an,
               [{"uid": "C1", "name": w} for w in weird], list(reporter), code=code)


def judge_mal(tmp_path, per_cfg, mal=MAL, ports=PORTS):
    out = tmp_path / "out"
    for cfg, kw in per_cfg.items():
        if kw is not None:
            mal_logs(out / mal["input"] / cfg, **kw)
    return table.judge_malformed(str(out), ROOT, [mal], ports, LIKELY)[mal["input"]]


GOOD = {C0: {}, C1: {}, C1P: {}, C2: dict(svc="", viol=1, x="none", q=False, reqhdr=0)}


def test_the_pinned_shapes_pass(tmp_path):
    res = judge_mal(tmp_path, GOOD)
    assert all(v == "pass" for v, _ in res.values()), res


@pytest.mark.parametrize("cfg,kw,token", [
    (C1, dict(x="none"), "X=code"),  # X not parsed at all
    (C1P, dict(reqhdr=0), "reqhdr=1"),  # X raised as a response header
    (C0, dict(svc=""), "svc=dnp3"),  # the service removed
    (C2, dict(svc="dnp3_udp", viol=1, x="none", q=False, reqhdr=0), "svc=removed"),
    (C2, dict(svc="", viol=0, x="none", q=False, reqhdr=0), "viol=1"),
    (C2, dict(svc="", viol=2, x="none", q=False, reqhdr=0), "viol=1"),  # off by one, above
    (C2, dict(svc="", viol=1, x="none", q=True, reqhdr=0), "Q=absent"),
    (C0, dict(q=False), "Q=seen"),
])
def test_each_token_has_a_control_that_fails_it(tmp_path, cfg, kw, token):
    per = dict(GOOD)
    per[cfg] = kw
    v, detail = judge_mal(tmp_path, per)[cfg]
    assert v == "fail" and token in detail, detail


def test_the_fourth_state_and_an_unnamed_reporter_error_fail(tmp_path):
    per = dict(GOOD)
    per[C0] = dict(other_analyzer=True)
    per[C1] = dict(reporter=[{"level": "Reporter::ERROR", "message": "something else"}])
    res = judge_mal(tmp_path, per)
    assert res[C0][0] == "fail" and "fourth state" in res[C0][1]
    assert res[C1][0] == "fail" and "mal-errors" in res[C1][1]
    # Control: a warning is not an error.
    per[C1] = dict(reporter=[{"level": "Reporter::WARNING", "message": "something else"}])
    assert judge_mal(tmp_path / "w", per)[C1][0] == "pass"


def test_err_target_allows_only_its_own_error(tmp_path):
    mal = dict(MAL, c0="viol=0; err=target", c2="=c1p", judge="same")
    err = [{"level": "Reporter::ERROR", "message": "dnp3 invalid target length: 8 - 11"}]
    per = {cfg: dict(reporter=err) for cfg in table.JUDGED}
    assert all(v == "pass" for v, _ in judge_mal(tmp_path, per, mal).values())
    # Control: the error missing fails err=target; under a cell without err=target it fails mal-errors.
    per[C1] = {}
    assert judge_mal(tmp_path / "b", per, mal)[C1][0] == "fail"
    mal2 = dict(mal, c0="viol=0")
    per = {cfg: dict(reporter=err) for cfg in table.JUDGED}
    assert judge_mal(tmp_path / "c", per, mal2)[C0][0] == "fail"


def test_same_compares_c2_with_c1p(tmp_path):
    mal = dict(MAL, c0="viol=0", c2="=c1p", judge="same")
    per = {cfg: {} for cfg in table.JUDGED}
    assert judge_mal(tmp_path, per, mal)[C2] == ("pass", "equals C1p")
    # Control: one more weird under C2 than under C1p.
    per[C2] = dict(weird=["dnp3_unexpected_flow_direction"])
    v, detail = judge_mal(tmp_path / "b", per, mal)[C2]
    assert v == "fail" and "weirds" in detail


def test_unknown_reports_c2_but_still_fails_a_crash(tmp_path):
    mal = dict(MAL, c2="viol=?; Q=?", judge="unknown")
    per = {cfg: {} for cfg in table.JUDGED}
    per[C2] = dict(viol=3)
    assert judge_mal(tmp_path, per, mal)[C2][0] == "reported"
    per[C2] = dict(code="134")
    assert judge_mal(tmp_path / "b", per, mal)[C2][0] == "fail"


def test_an_input_not_run_is_unknown_never_pass(tmp_path):
    per = dict(GOOD)
    per[C1] = None
    assert judge_mal(tmp_path, per)[C1] == ("unknown", "not run")


def test_cfg_ports_turns_a_malformed_input_unknown(tmp_path):
    moved = dict(PORTS)
    moved[C0] = copy.deepcopy(LIKELY)
    moved[C0]["udp"].discard(20000)
    assert judge_mal(tmp_path, GOOD, ports=moved)[C0][0] == "unknown"
    moved[C0] = None
    assert judge_mal(tmp_path / "b", GOOD, ports=moved)[C0][0] == "unknown"


def test_absent_counts_a_message_beyond_the_others_and_its_control():
    msgs = {"P": ("m", 1, frozenset({"g60v1"})), "Q": ("m", 1, frozenset({"g60v2"}))}
    one = [("m", 1, frozenset({"g60v1"}))]
    two = one + [("m", 1, frozenset({"g60v2"}))]
    assert table.msg_states(msgs, [("Q", "absent")], one)["Q"] == "holds"
    assert table.msg_states(msgs, [("Q", "absent")], two)["Q"] == "does not hold"
    # Q's own objects on the only row: P is not named, so the row is Q's.
    assert table.msg_states(msgs, [("Q", "absent")], [("m", 1, frozenset({"g60v2"}))])["Q"] == "does not hold"


# The false-positive set: an unfed or unrun class is never read as zero.

def fp_out(tmp_path, cap, named=False, link=False, skip=()):
    out = tmp_path / "out-fp"
    for cfg in table.JUDGED:
        if cfg in skip:
            continue
        probe = [{"ts": 1.0, "uid": "C1", "is_orig": True, "kind": "link", "link_dir": False}] if link else []
        write_logs(out / cap / cfg, [conn("C1", "udp", ("192.0.2.100", "50000"), ("192.0.2.200", "40001"),
                                           "dnp3_udp" if named else "dns")], probe)
    return str(out)


def fp_rules(res, cls):
    return dict(res[cls]["rules"])


def test_an_unfed_class_is_not_run_never_zero(tmp_path):
    out = fp_out(tmp_path, "fp-udp-1")
    res = table.judge_fp(out, ROOT, {"fp-udp-1"})
    assert fp_rules(res, "1")["fp-1245 c0 conn"].startswith("pass (0")
    # Unfed: not in the kept list, though its folder holds clean logs.
    res = table.judge_fp(out, ROOT, set())
    assert all(v.startswith("not run") for k, v in fp_rules(res, "1").items() if k.startswith("fp-1245")), res["1"]
    # Not run under one configuration.
    res = table.judge_fp(fp_out(tmp_path / "b", "fp-udp-1", skip=(C2,)), ROOT, {"fp-udp-1"})
    assert fp_rules(res, "1")["fp-1245 c2 conn"].startswith("not run")
    assert fp_rules(res, "1")["fp-b conn"] == "not run"


def test_control_an_fp_judge_that_reads_unfed_as_zero_is_caught(tmp_path):
    m = mutant(tmp_path, 'why = "not fed" if cap not in kept else ran(d)', "why = ran(d)")
    res = m.judge_fp(fp_out(tmp_path, "fp-udp-1"), ROOT, set())
    assert fp_rules(res, "1")["fp-1245 c0 conn"].startswith("pass")


def test_a_named_flow_fails_the_zero_bound(tmp_path):
    res = table.judge_fp(fp_out(tmp_path, "fp-udp-2", named=True, link=True), ROOT, {"fp-udp-2"})
    r = fp_rules(res, "2")
    assert r["fp-1245 c0 conn"].startswith("fail (1") and r["fp-1245 c2 link"].startswith("fail (1")
    assert "fp-1245 c0 link" not in r  # C0 has no link-row reading


def test_fp_b_fails_a_flow_named_by_c2_alone(tmp_path):
    out = fp_out(tmp_path, "fp-udp-3b-data")
    write_logs(tmp_path / "out-fp" / "fp-udp-3b-data" / C2,
               [conn("C1", "udp", ("192.0.2.100", "50000"), ("192.0.2.200", "40001"), "dnp3_udp")])
    r = fp_rules(table.judge_fp(out, ROOT, {"fp-udp-3b-data"}), "3b-data")
    assert r["fp-b conn"].startswith("fail") and r["fp-3bdata C2 equals C1p"].startswith("fail")
    assert fp_rules(table.judge_fp(fp_out(tmp_path / "c", "fp-udp-3b-data"), ROOT, {"fp-udp-3b-data"}),
                    "3b-data")["fp-b conn"] == "pass"


# The mode: likely_server_ports under every configuration, and the cases'
# rows withheld from a run without the held list and the salt.

def test_hr23judge_prints_every_configurations_ports_and_fails_a_counted_run(tmp_path, capsys):
    ports = tmp_path / "ports"
    ports.mkdir()
    for cfg in table.JUDGED:
        (ports / f"{cfg}.txt").write_text("likely_server_ports at zeek_done: tcp [20000]; udp [20000]\n")
    args = (str(tmp_path / "o"), str(tmp_path / "f"), str(tmp_path / "k"), ROOT, str(ports), str(tmp_path / "p"))
    assert table.hr23judge(*args, True, {}) == 3
    md = capsys.readouterr().out
    assert sum(1 for ln in md.splitlines() if ln.startswith("- c") and "tcp 20000; udp 20000" in ln) == 4
    assert "hr23-cases.tsv's rows" in md and "no counted HR-23 result is taken without the cases' rows" in md
    assert table.hr23judge(*args, False, {}) == 0
    # No row of hr23-cases.tsv is printed.
    cases = {r["capture"] for r in table.tsv(os.path.join(ROOT, table.GP, "hr23-cases.tsv"))}
    mal = {r["input"] for r in table.tsv(os.path.join(ROOT, table.GP, "hr23-malformed.tsv"))}
    printed = {ln.split(" | ")[0][2:] for ln in capsys.readouterr().out.splitlines() if ln.startswith("| dnp3-")}
    assert not (printed & (cases - mal))


# D6's B3 on #776: one test for each rule whose mutant survived at 4d7bab3b,
# each with its control (the case on which the rule gives the other answer).

def test_fix_a_does_not_need_c2():
    rows = [row("x", "service", c0="fail", fix="a")]
    assert judge(rows, {C0: ["fail"], C1: ["pass"], C1P: ["pass"], C2: ["unknown (not run)"]})[1][0] == "a shows"
    # Control: fix b reads C2, so C2 not run leaves it unknown.
    rows = [row("x", "function", "1", c0="fail", c1="fail", c1p="fail", fix="b")]
    assert judge(rows, {C0: ["fail"], C1: ["fail"], C1P: ["fail"], C2: ["unknown (not run)"]})[1][0].startswith("unknown")


def reading(**kw):
    r = {"viol": collections.Counter(), "weirds": collections.Counter(), "reporter": collections.Counter(), "fn": [],
         "link": [], "reqhdr": 0, "svc": set()}
    r.update(kw)
    return r


def test_reqhdr_above_its_pin_fails():
    assert table.judge_mal_cell("reqhdr=1", reading(reqhdr=2), {})[1] == ["reqhdr=1"]
    assert table.judge_mal_cell("reqhdr=1", reading(reqhdr=1), {})[1] == []


def test_a_weird_token_needs_the_weird():
    assert table.judge_mal_cell("weird=dnp3_x", reading(), {})[1] == ["weird=dnp3_x"]
    assert table.judge_mal_cell("weird=dnp3_x", reading(weirds=collections.Counter({"dnp3_x": 1})), {})[1] == []


def test_code_needs_a_row_without_the_labelled_objects():
    msgs = {"X": ("m", 129, frozenset({"g60v1"}))}
    assert table.msg_states(msgs, [("X", "code")], [("m", 129, frozenset({"g60v1"}))])["X"] == "does not hold"
    assert table.msg_states(msgs, [("X", "code")], [("m", 129, frozenset())])["X"] == "holds"


def test_judge_link_reads_is_orig(tmp_path):
    assert link_case(tmp_path / "a", 3.25, is_orig=False) == "absent"
    assert link_case(tmp_path / "b", 3.25, is_orig=True) == "present"


def test_mal_same_compares_link_rows_except_on_mal_link(tmp_path, monkeypatch):
    mal = dict(MAL, c0="viol=0", c2="=c1p", judge="same")
    per = {cfg: {} for cfg in table.JUDGED}
    per[C2] = dict(link=[(True, True)])
    v, detail = judge_mal(tmp_path / "a", per, mal)[C2]
    assert v == "fail" and "link" in detail
    # Control: an input of mal-link, whose link rows are reported, not judged.
    monkeypatch.setattr(table, "MAL_LINK", (INP,))
    assert judge_mal(tmp_path / "b", per, mal)[C2] == ("pass", "equals C1p")


def both_out(tmp_path, caps):
    for c in caps:
        for cfg in table.JUDGED:
            write_logs(tmp_path / c / cfg, [conn("C1", "udp", M, O, "dnp3_udp")],
                       [{"ts": 1.0, "uid": "C1", "is_orig": True, "kind": "link", "link_dir": d} for d in (True, False)])
    return str(tmp_path)


def test_judge_both_finds_both_ends_outside_the_expected_pair(tmp_path):
    found = table.both_findings(both_out(tmp_path, ["syn-x", table.BOTH_EXPECTED[0]]), ["syn-x", table.BOTH_EXPECTED[0]])
    assert sorted(t for _, t in found) == [f"judge-both: syn-x under {c}" for c in (C1, C1P, C2)]


def test_fp_3blink_bounds_link_rows(tmp_path):
    r = fp_rules(table.judge_fp(fp_out(tmp_path / "a", "fp-udp-3b-link", link=True), ROOT, {"fp-udp-3b-link"}), "3b-link")
    assert r["fp-3blink c1 link"].startswith("fail (1")
    r = fp_rules(table.judge_fp(fp_out(tmp_path / "b", "fp-udp-3b-link"), ROOT, {"fp-udp-3b-link"}), "3b-link")
    assert r["fp-3blink c1 link"].startswith("pass (0")


def test_fp_3c_bound_is_one_violation_for_each_item(tmp_path):
    n = len(table.tsv(os.path.join(ROOT, table.GT, "fp", "fp-udp-3c.tsv")))
    for k, want in ((n, "pass"), (0, "fail")):
        out = fp_out(tmp_path / str(k), "fp-udp-3c")
        for cfg in table.JUDGED:
            (tmp_path / str(k) / "out-fp" / "fp-udp-3c" / cfg / "analyzer.log").write_text(
                "".join(json.dumps({"uid": "C1", "analyzer_name": "DNP3_UDP"}) + "\n" for _ in range(k)))
        r = fp_rules(table.judge_fp(out, ROOT, {"fp-udp-3c"}), "3c")
        assert r["fp-3c c0 viol"].startswith(f"{want} ({k}, bound {n})")


def test_fp_6_hole_is_bounded_at_zero(tmp_path):
    r = fp_rules(table.judge_fp(fp_out(tmp_path / "a", "fp-tcp-6-hole"), ROOT, {"fp-tcp-6-hole"}), "6-hole")
    assert r["fp-6 c0 conn"].startswith("pass (0")
    r = fp_rules(table.judge_fp(fp_out(tmp_path / "b", "fp-tcp-6-hole", named=True), ROOT, {"fp-tcp-6-hole"}), "6-hole")
    assert r["fp-6 c0 conn"].startswith("fail (1")


def test_mal_unknown_c2_still_fails_an_unnamed_reporter_error(tmp_path):
    mal = dict(MAL, c2="viol=?; Q=?", judge="unknown")
    per = {cfg: {} for cfg in table.JUDGED}
    per[C2] = dict(reporter=[{"level": "Reporter::ERROR", "message": "something else"}])
    v, detail = judge_mal(tmp_path / "a", per, mal)[C2]
    assert v == "fail" and "mal-errors" in detail
    per[C2] = dict(reporter=[{"level": "Reporter::WARNING", "message": "something else"}])
    assert judge_mal(tmp_path / "b", per, mal)[C2][0] == "reported"


def test_same_still_fails_an_unnamed_reporter_error(tmp_path):
    mal = dict(MAL, c0="viol=0", c2="=c1p", judge="same")
    err = dict(reporter=[{"level": "Reporter::ERROR", "message": "something else"}])
    per = {C0: {}, C1: {}, C1P: err, C2: err}
    v, detail = judge_mal(tmp_path / "a", per, mal)[C2]
    assert v == "fail" and "mal-errors" in detail
    per = {C0: {}, C1: {}, C1P: {}, C2: {}}
    assert judge_mal(tmp_path / "b", per, mal)[C2] == ("pass", "equals C1p")


def test_viol_counts_only_the_inputs_flow(tmp_path):
    per = dict(GOOD)
    per[C0] = dict(other_flow_viol=2)
    assert judge_mal(tmp_path / "a", per)[C0][0] == "pass"
    # Control: the same rows on the input's own flow.
    per[C0] = dict(viol=2)
    assert judge_mal(tmp_path / "b", per)[C0][0] == "fail"


def test_fp_b_reads_the_link_rows(tmp_path):
    out = fp_out(tmp_path, "fp-udp-3b-data")
    write_logs(tmp_path / "out-fp" / "fp-udp-3b-data" / C2,
               [conn("C1", "udp", ("192.0.2.100", "50000"), ("192.0.2.200", "40001"), "dns")],
               [{"ts": 1.0, "uid": "C1", "is_orig": True, "kind": "link", "link_dir": False}])
    r = fp_rules(table.judge_fp(out, ROOT, {"fp-udp-3b-data"}), "3b-data")
    assert r["fp-b link"].startswith("fail") and r["fp-b conn"] == "pass"


# D6's N1 on #776: a cell made only of ? tokens reads reported, never pass;
# mal-errors and the fourth state still fail it.

def test_a_cell_of_only_question_marks_reads_reported(tmp_path):
    mal = dict(MAL, c0="viol=?; Q=?", c2="=c1p", judge="same")
    per = {cfg: {} for cfg in table.JUDGED}
    assert judge_mal(tmp_path / "a", per, mal)[C0][0] == "reported"
    per[C0] = dict(other_analyzer=True)
    assert judge_mal(tmp_path / "b", per, mal)[C0][0] == "fail"
    # Control: a ? beside a judged token still passes.
    mal = dict(mal, c0="viol=0; Q=?")
    assert judge_mal(tmp_path / "c", {cfg: {} for cfg in table.JUDGED}, mal)[C0][0] == "pass"


def test_control_a_question_mark_cell_read_as_pass_is_caught(tmp_path):
    m = mutant(tmp_path, 'only_q = bool(toks) and all(h == "reported" for _, h in toks)', "only_q = False")
    mal = dict(MAL, c0="viol=?; Q=?", c2="=c1p", judge="same")
    out = tmp_path / "out"
    for cfg in table.JUDGED:
        mal_logs(out / mal["input"] / cfg)
    assert m.judge_malformed(str(out), ROOT, [mal], PORTS, LIKELY)[mal["input"]][C0][0] == "pass"


# D2's N1 on #776: the flow's first sender is the sender of the earliest
# unit, whether or not that unit carries a message (the label header).

def first_sender_labels(tmp_path):
    d = tmp_path / table.GT / table.HR23_DIR
    d.mkdir(parents=True)
    flow = "udp 192.0.2.20:20000>192.0.2.14:20000"
    (d / "syn-mal.tsv").write_text("flow\tend\tpackets\tmessage\tcode\tobjects\n"
                                   f"{flow}\to\t1\t-\t-\t-\n{flow}\tm\t2\tP\t1\tg60v1\n")
    return str(tmp_path)


def test_the_first_sender_is_the_earliest_units(tmp_path):
    msgs = table.mal_labels(first_sender_labels(tmp_path), "syn-mal")[0]
    assert msgs["P"][0] == "192.0.2.14"
    # Control: the earliest unit that carries a message, as at 4d7bab3b.
    m = mutant(tmp_path, 'first = min((r for r in rows if r["packets"]', 'first = min((r for r in units if r["packets"]')
    assert m.mal_labels(str(tmp_path), "syn-mal")[0]["P"][0] == "192.0.2.20"
