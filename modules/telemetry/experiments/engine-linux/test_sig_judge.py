"""P4-4-E2 (D4): table.py's judging of the held-out and det- rows, on made-up
rows, for D6's B1, N2 and N3 on #643. Run: python -m pytest -q
modules/telemetry/experiments/engine-linux/test_sig_judge.py"""
import table

PASS = ("pass (named)", "conn.log:1")
FAIL = ("fail (not named)", "")
UNRUN = ("unknown (not run)", "")


def row(r, control):
    return ("protocol", "", r, control)


def test_fail_with_control_passing_fails():
    assert table.judge_held([row(FAIL, PASS)])[0] == "fail"


def test_fail_with_control_not_run_is_unknown_never_pass():
    # D6's B1: S0 fails while the control on 502 did not run.
    state, ctl_pass, lines = table.judge_held([row(FAIL, UNRUN), row(PASS, PASS)])
    assert state == "unknown"
    assert not ctl_pass
    assert "did not run" in lines[0]


def test_fail_with_control_failing_is_listed_not_pass():
    # D6's N3: every row also fails on 502, so the flow is listed, not a pass.
    state, _, lines = table.judge_held([row(FAIL, FAIL)])
    assert state == "listed"
    assert lines == ["protocol: fail (also fails on port 502)"]


def test_held_other_has_no_control():
    assert table.judge_held([row(FAIL, None)])[0] == "fail"
    assert table.judge_held([row(PASS, None)])[0] == "pass"
    assert table.judge_held([row(UNRUN, None)])[0] == "unknown"


def flow(state):
    return {"state": state, "cap": "c", "lab": {"src": "192.0.2.1", "sport": "1"}} if state else {"cap": "c", "lab": {}}


def test_tally_keeps_listed_out_of_pass():
    v, detail = table.held_tally([flow("pass"), flow("listed"), flow(None)])
    assert v == "pass"
    assert detail.startswith("1 pass, 0 fail, 0 unknown, 2 listed, of 3")


def test_tally_unknown_beats_pass_and_fail_beats_unknown():
    assert table.held_tally([flow("pass"), flow("unknown")])[0] == "unknown"
    assert table.held_tally([flow("fail"), flow("unknown")])[0] == "fail"
    assert table.held_tally([flow("listed")])[0].startswith("unknown")


def test_det_rows_follow_the_control():
    # D6's N2: a det- row never keeps its pass when its control fails or did not run.
    assert table.det_verdict("pass x", True, False, False) == "pass"
    assert table.det_verdict("pass x", False, False, False) == "fail (also fails on port 502)"
    assert table.det_verdict("pass x", False, True, False).startswith("unknown")
    assert table.det_verdict("pass x", True, False, True).startswith("unknown")


def test_held_count_makes_both_rows_unknown():
    # D6's N2: with held-count not met, a failing held- row is unknown too.
    v = {"held-count": ("unknown (fewer)", ""), "held-502": ("fail", "a"), "held-other": ("pass", "b")}
    table.held_count_gate(v)
    assert v["held-502"][0].startswith("unknown") and v["held-other"][0].startswith("unknown")
    v = {"held-count": ("pass", ""), "held-502": ("fail", "a"), "held-other": ("pass", "b")}
    table.held_count_gate(v)
    assert v["held-502"][0] == "fail" and v["held-other"][0] == "pass"


def test_gt_pcap_members_are_synthesized():
    # D6's N1: GT-PCAP's source reads `GT-PCAP (D6), synthesized`.
    assert table.synthesized("GT-PCAP (D6), synthesized")
    assert table.synthesized("synthesized (D4)")
    assert not table.synthesized("zeek/zeek v9.0.1")
