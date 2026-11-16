"""HR-23 (D4, brief P4-4-HR23 stage 3): dispatch_unit.py's verdicts on
made-up logs (D6's N3 on #715). Each row reads C2 against its control C1p;
a configuration that did not run makes the row unknown, and one whose Zeek
exited non-zero fails it, so a crash is never read as a silent stop. Run:
python -m pytest -q modules/telemetry/experiments/engine-linux/zeek-patch"""
import json

import pytest

import dispatch_unit as du

MET = lambda m, l, v: m == []  # noqa: E731  (met when no header was logged)


def cfg_dir(tmp_path, cfg, rc="0", headers=0):
    d = tmp_path / cfg
    d.mkdir()
    if rc is not None:
        (d / "exit-code").write_text(rc + "\n")
    rows = [{"kind": "fc", "is_orig": True, "fc": 1, "ev": "dnp3_application_request_header"}] * headers
    (d / "otsec_probe.log").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return str(d)


def test_state_reads_met_not_met_exit_and_not_run(tmp_path):
    assert du.state(cfg_dir(tmp_path, "a"), MET) == "met"
    assert du.state(cfg_dir(tmp_path, "b", headers=1), MET) == "not met"
    # A crash after partial logs: the logs alone would read `met`.
    assert du.state(cfg_dir(tmp_path, "c", rc="134"), MET) == "exit 134"
    assert du.state(cfg_dir(tmp_path, "d", rc=None), MET) == "not run"
    assert du.state(str(tmp_path / "missing"), MET) == "not run"


def test_fix_passes_only_when_c2_meets_it_and_the_control_does_not():
    assert du.verdict("fix", "met", "not met") == "pass"
    assert du.verdict("fix", "met", "met") == "fail"  # the control meets it too
    assert du.verdict("fix", "not met", "not met") == "fail"
    assert du.verdict("fix-negative", "met", "not met") == "pass"


def test_same_passes_only_when_both_meet_it():
    assert du.verdict("same", "met", "met") == "pass"
    assert du.verdict("same", "met", "not met") == "fail"  # the control column is read
    assert du.verdict("same", "not met", "met") == "fail"


def test_not_run_is_unknown_and_a_non_zero_exit_fails():
    assert du.verdict("same", "not run", "met") == "unknown (not run)"
    assert du.verdict("fix", "met", "not run") == "unknown (not run)"
    assert du.verdict("same", "exit 134", "met") == "fail"
    assert du.verdict("fix", "met", "exit 1") == "fail"


# (B')'s judge (D1's ruling on #715, condition 2): each state with a test and
# a control, on made-up logs for the builder's ordinary-path case: the
# master's READ, the truncated READ (the stop, message 1), then three whole
# messages, five frames in all.
FLOW = du.cases()["d4u-short-request-second"]
UID = "Ctest"


def logs(tmp_path, name, fc=5, pkts=5, service="dnp3_udp", analyzer=(), raised=(), weird=(), reporter=0, rc="0"):
    """A configuration's logs: the first `fc` builder messages as `fc` rows,
    conn.log with `pkts` packets, analyzer.log rows (name, reason),
    otsec_viol.log rows (analyzer names), weird names, reporter rows."""
    d = tmp_path / name
    d.mkdir()
    (d / "exit-code").write_text(rc + "\n")

    def put(log, rs):
        (d / log).write_text("".join(json.dumps(r) + "\n" for r in rs))
    put("otsec_probe.log", [{"kind": "fc", "is_orig": o, "fc": c, "uid": UID,
                             "ev": "dnp3_application_request_header" if o else "dnp3_application_response_header"}
                            for o, c in FLOW.msgs[:fc]])
    put("conn.log", [{"uid": UID, "orig_pkts": pkts - 2, "resp_pkts": 2, "service": service}])
    put("analyzer.log", [{"uid": UID, "analyzer_name": n, "failure_reason": r, "failure_data": "never read"}
                         for n, r in analyzer])
    put("otsec_viol.log", [{"uid": UID, "analyzer": n, "reason": "x"} for n in raised])
    put("weird.log", [{"uid": UID, "name": n} for n in weird])
    put("reporter.log", [{"message": "m"}] * reporter)
    return str(d)


REC = dict(fc=2, service="", analyzer=[("DNP3_UDP", "Binpac exception: x")], raised=["DNP3_UDP"])


def state_of(tmp_path, name, **kw):
    return du.judge(logs(tmp_path, name, **kw), FLOW)[0]


def test_parsed_on_and_its_controls(tmp_path):
    assert state_of(tmp_path, "a") == "parsed on"
    # Control: the trailing messages parsed, but a DNP3 violation raised.
    assert state_of(tmp_path, "b", raised=["DNP3_UDP"]) != "parsed on"
    # Control: the last trailing message missing.
    assert state_of(tmp_path, "c", fc=4) != "parsed on"


def test_recorded_stop_and_its_controls(tmp_path):
    assert state_of(tmp_path, "a", **REC) == "recorded stop"
    # Exactly one violation raised: a catch that raises and rethrows raises two.
    assert state_of(tmp_path, "b", **dict(REC, raised=["DNP3_UDP", "DNP3_UDP"])) != "recorded stop"
    assert state_of(tmp_path, "c", **dict(REC, raised=[])) != "recorded stop"
    # Exactly one analyzer.log row, with a reason.
    assert state_of(tmp_path, "d", **dict(REC, analyzer=[])) != "recorded stop"
    assert state_of(tmp_path, "e", **dict(REC, analyzer=[("DNP3_UDP", "")])) != "recorded stop"
    assert state_of(tmp_path, "f", **dict(REC, analyzer=REC["analyzer"] * 2)) != "recorded stop"
    # The service removed from conn.log.
    assert state_of(tmp_path, "g", **dict(REC, service="dnp3_udp")) != "recorded stop"
    # Boundary: one fc row after the stop's message is not a stop.
    assert state_of(tmp_path, "h", **dict(REC, fc=3)) != "recorded stop"


def test_silent_stop_and_its_controls(tmp_path):
    assert state_of(tmp_path, "a", fc=2) == "silent stop"
    assert state_of(tmp_path, "b", fc=1) == "silent stop"
    # The flow-direction weird is raised on DIR, never on a stop.
    assert state_of(tmp_path, "c", fc=2, weird=[du.FLOW_DIRECTION]) == "silent stop"
    # Controls: any record of the stop makes it not silent.
    assert state_of(tmp_path, "d", fc=2, weird=["dnp3_corrupt_chunk_checksum"]) != "silent stop"
    assert state_of(tmp_path, "e", fc=2, reporter=1) != "silent stop"
    assert state_of(tmp_path, "f", fc=2, raised=["DNP3_UDP"]) != "silent stop"
    assert state_of(tmp_path, "g", fc=2, analyzer=[("DNP3_UDP", "r")]) != "silent stop"
    # Boundary: one fc row after the stop's message.
    assert state_of(tmp_path, "h", fc=3) != "silent stop"


def test_a_row_naming_another_analyzer_is_the_fourth_state(tmp_path):
    assert state_of(tmp_path, "a", fc=2, analyzer=[("PIA_UDP", "r")]) == "recorded elsewhere"
    assert state_of(tmp_path, "b", **dict(REC, analyzer=REC["analyzer"] + [("PIA_UDP", "r")])) \
        == "recorded elsewhere"
    # Control: the DNP3 row alone.
    assert state_of(tmp_path, "c", **REC) != "recorded elsewhere"
    # A violation raised under another analyzer, with no log row, is printed only.
    assert state_of(tmp_path, "d", **dict(REC, raised=["DNP3_UDP", "PIA_UDP"])) == "recorded stop"


def test_the_frames_must_have_arrived_and_the_run_must_have_run(tmp_path):
    assert state_of(tmp_path, "a", fc=2, pkts=4).startswith("unclassified")
    assert state_of(tmp_path, "b", fc=2, pkts=6).startswith("unclassified")
    assert state_of(tmp_path, "c", fc=2, pkts=5) == "silent stop"
    assert state_of(tmp_path, "d", rc="134") == "exit 134"
    assert du.judge(str(tmp_path / "missing"), FLOW)[0] == "not run"


def test_a_stop_case_needs_two_trailing_messages(tmp_path):
    f = du.Flow("master")
    f.send(True, bytes([0xC0, 1, 60]), bad=True)
    f.send(False, bytes([0xC0, 129, 0, 0]))
    with pytest.raises(ValueError):
        du.judge(logs(tmp_path, "a", fc=1, pkts=2), f)


def test_stop_and_control_verdicts():
    assert du.stop_verdict("recorded stop", "parsed on", "recorded stop", "parsed on", True) == "pass"
    assert du.stop_verdict("recorded stop", "parsed on", "recorded stop", "recorded stop", True) == "fail"
    assert du.stop_verdict("recorded stop", "silent stop", "silent stop", "silent stop", True) == "fail"
    assert du.stop_verdict("recorded stop", "recorded stop", "recorded stop", "recorded stop", False) \
        == "fail (reasons differ)"
    assert du.stop_verdict("recorded stop", "parsed on", "not run", "parsed on", True) == "unknown (not run)"
    assert du.stop_verdict("recorded stop", "parsed on", "exit 134", "parsed on", True) == "fail"
    want = {"4.1": "recorded stop", "4.2": "recorded stop"}
    assert du.control_verdict({"4.1": "silent stop", "4.2": "silent stop"}, want) == "killed"
    assert du.control_verdict({"4.1": "silent stop", "4.2": "recorded stop"}, want) == "fail (survived)"
    assert du.control_verdict({"4.1": "not run", "4.2": "silent stop"}, want) == "unknown (not run)"


def test_every_stop_row_names_a_built_stop_case_and_each_control_a_stop_row():
    flows = du.cases()
    ids = {r[0] for r in du.STOPS}
    for rid, case, kind, _, want2, want1, _ in du.STOPS:
        assert flows[case].bad is not None and len(flows[case].trailing()) >= 2
        assert want2 in du.STATES and want1 in du.STATES
        assert (kind == "fix") == (want2 != want1)
    for _, rids, _ in du.CONTROLS:
        assert set(rids) <= ids
