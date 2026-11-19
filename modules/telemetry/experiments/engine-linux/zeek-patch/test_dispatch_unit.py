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


def logs(tmp_path, name, fc=5, pkts=5, service="dnp3_udp", analyzer=(), raised=(), weird=(), reporter=0, rc="0",
         msgs=None):
    """A configuration's logs: the first `fc` builder messages as `fc` rows
    (or `msgs`, as (is_orig, fc), when given), conn.log with `pkts` packets,
    analyzer.log rows (name, reason), otsec_viol.log rows (analyzer names),
    weird names, reporter rows."""
    d = tmp_path / name
    d.mkdir()
    (d / "exit-code").write_text(rc + "\n")

    def put(log, rs):
        (d / log).write_text("".join(json.dumps(r) + "\n" for r in rs))
    put("otsec_probe.log", [{"kind": "fc", "is_orig": o, "fc": c, "uid": UID,
                             "ev": "dnp3_application_request_header" if o else "dnp3_application_response_header"}
                            for o, c in (FLOW.msgs[:fc] if msgs is None else msgs)])
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


# D6's N13 on #715: a control is killed only when each of its rows reads the
# state named for it; a crash, a run that did not happen, or any other
# reading fails it.
def test_a_control_is_killed_only_by_the_state_named_for_it():
    want = {"4.1": "silent stop", "4.2": "silent stop"}
    assert du.control_verdict({"4.1": "silent stop", "4.2": "silent stop"}, want) == "killed"
    assert du.control_verdict({"4.1": "silent stop", "4.2": "recorded stop"}, want) == "fail"
    assert du.control_verdict({"4.1": "silent stop", "4.2": "exit 134"}, want) == "fail"
    assert du.control_verdict({"4.1": "not run", "4.2": "silent stop"}, want) == "fail"
    assert du.control_verdict({"4.1": "silent stop", "4.2": "unclassified (1 conn.log rows)"}, want) == "fail"
    assert du.control_verdict({"4.1": "silent stop"}, want) == "fail"
    twice = {"4.3": du.unrecorded_stop(2)}
    assert du.control_verdict({"4.3": du.unrecorded_stop(2)}, twice) == "killed"
    assert du.control_verdict({"4.3": du.unrecorded_stop(3)}, twice) == "fail"
    assert du.control_verdict({"4.3": "unclassified (neither parsed on nor stopped)"}, twice) == "fail"
    assert du.control_verdict({"4.3": "exit 134"}, twice) == "fail"


def test_the_controls_name_the_states_the_rules_give_them():
    named = {cfg: rids for cfg, rids, _ in du.CONTROLS}
    assert named[du.M_STOCK] == {"4.1": "silent stop", "4.2": "silent stop"}
    assert named[du.M_NOVIOL] == {"4.1": "silent stop", "4.2": "silent stop", "4.3": "silent stop"}
    assert named[du.M_RERAISE] == {"4.3": du.unrecorded_stop(2)}


def test_a_raise_and_rethrow_reads_its_own_state(tmp_path):
    assert state_of(tmp_path, "a", **dict(REC, raised=["DNP3_UDP", "DNP3_UDP"])) == du.unrecorded_stop(2)


# D6's N12 on #715: a stop is read from which messages the `fc` rows are,
# not how many. D6's probe: the stop's message leaves no `fc` row and the
# first trailing message (the relay's 129) is parsed.
PROBE = [(True, 1), (False, 129)]


def test_a_trailing_message_parsed_in_the_stops_place_is_no_stop(tmp_path):
    assert state_of(tmp_path, "a", **dict(REC, msgs=PROBE)) not in ("recorded stop", "silent stop")
    assert state_of(tmp_path, "b", fc=2, msgs=PROBE) not in ("recorded stop", "silent stop")
    # Controls: the builder's own prefixes still read as stops.
    assert state_of(tmp_path, "c", **dict(REC, msgs=FLOW.msgs[:2])) == "recorded stop"
    assert state_of(tmp_path, "d", fc=2, msgs=FLOW.msgs[:1]) == "silent stop"
    # A row out of order, or on the wrong side, is no prefix.
    assert state_of(tmp_path, "e", fc=2, msgs=[(False, 1)]) not in ("recorded stop", "silent stop")


def test_every_stop_row_names_a_built_stop_case_and_each_control_a_stop_row():
    flows = du.cases()
    ids = {r[0] for r in du.STOPS}
    for rid, case, kind, _, want2, want1, _ in du.STOPS:
        assert flows[case].bad is not None and len(flows[case].trailing()) >= 2
        if kind == "unchanged":
            assert want2 == du.SAME_AS_STOCK and (want1 in du.STATES or want1 == du.SAME_AS_C2)
            continue
        assert want2 in du.STATES and want1 in du.STATES
        assert (kind == "fix") == (want2 != want1)
    for _, rids, _ in du.CONTROLS:
        assert set(rids) <= ids


def test_unchanged_rows_read_c2_against_c2_with_the_stock_catch():
    rec = ("unclassified (neither parsed on nor stopped)", "fc rows [...]; violations raised ['DNP3_TCP']")
    other = ("recorded stop", "fc rows [...]")
    assert du.unchanged_verdict(rec, rec, ("parsed on", "x"), "parsed on") == "pass"
    # Control: (B') changed TCP, in its state or only in what the judge read.
    assert du.unchanged_verdict(other, rec, ("parsed on", "x"), "parsed on") == "fail (changed by (B'))"
    assert du.unchanged_verdict((rec[0], "other detail"), rec, ("parsed on", "x"), "parsed on") \
        == "fail (changed by (B'))"
    # C1p is read too.
    assert du.unchanged_verdict(rec, rec, ("silent stop", "x"), "parsed on") == "fail"
    assert du.unchanged_verdict(rec, rec, rec, du.SAME_AS_C2) == "pass"
    assert du.unchanged_verdict(rec, rec, (rec[0], "other"), du.SAME_AS_C2) == "fail"
    # A crash in both is never "unchanged".
    assert du.unchanged_verdict(("exit 134", ""), ("exit 134", ""), ("parsed on", "x"), "parsed on") == "fail"
    assert du.unchanged_verdict(rec, ("not run", ""), ("parsed on", "x"), "parsed on") == "unknown (not run)"


def _tcp_data(f):
    """Each data segment of a TCP input, read from its bytes: (source port,
    destination port, DIR bit, application octets as hex). Each segment is
    read by its IP total length, and the link frame's user data without its
    block CRCs, from which the transport octet is dropped."""
    out = []
    for fr in f.conv.frames:
        ip = fr.data[14:]
        t = ip[(ip[0] & 15) * 4:int.from_bytes(ip[2:4], "big")]
        p = t[(t[12] >> 4) * 4:]
        if not p:
            continue
        assert p[:2] == b"\x05\x64"
        n, user, i = p[2] - 5, b"", 10
        while len(user) < n:
            k = min(16, n - len(user))
            user += p[i:i + k]
            i += k + 2
        out.append((int.from_bytes(t[0:2], "big"), int.from_bytes(t[2:4], "big"), p[3] >> 7, user[1:].hex(" ")))
    return out


def test_tcp_stop_inputs_follow_the_orders_of_718s_tcp_cells():
    """D4-115 item 4: the replay pair is on 20001 (outside
    likely_server_ports) with X then the same end's P first; the mid-flow
    pair is on 20000 with the responder's 2-octet X after P R. Every data
    segment's ports, DIR bit and application octets are pinned (D6's N1 on
    #739), as design 2.3 states them."""
    flows = du.cases()
    for case in du.EXPERIMENT:
        assert case in flows
    m, o = (40001, 20001), (20001, 40001)
    p_rp_q_rq = [(*m, 1, "c1 01 3c 01 06"), (*o, 0, "c1 81 00 00"),
                 (*m, 1, "c2 01 3c 01 06"), (*o, 0, "c2 81 00 00")]
    want = {
        "d4u-tcp-replay-same-end": [(*m, 1, "c0 01 3c")] + p_rp_q_rq,
        "d4u-tcp-replay-same-end-badobj": [(*m, 1, "c0 81 00 00 01")] + p_rp_q_rq,
    }
    m, o = (40001, 20000), (20000, 40001)
    for name, x in (("fc0", "d0 00"), ("fc13", "c0 0d")):
        for dn, dirbit in (("", 0), ("-dirset", 1)):
            want[f"d4u-tcp-resp-{name}-mid{dn}"] = [
                (*m, 1, "c0 01 3c 01 06"), (*o, 0, "c0 81 00 00"), (*o, dirbit, x),
                (*m, 1, "c1 01 3c 01 06"), (*o, 0, "c1 81 00 00")]
    for case, rows in want.items():
        assert _tcp_data(flows[case]) == rows, case
    # The builder's names, which `judge` reads: X is the stop.
    for sfx in ("", "-badobj"):
        f = flows["d4u-tcp-replay-same-end" + sfx]
        assert f.bad == 0 and [o for o, _ in f.msgs] == [True, True, False, True, False]
    for case in du.EXPERIMENT[-4:]:
        assert flows[case].bad == 2
        assert [o for o, _ in flows[case].msgs] == [True, False, False, True, False]
    # Each ends with the FIN exchange: the handshake's 3 frames, each
    # message and its bare ACK, then FIN, FIN and ACK.
    for case in du.EXPERIMENT[-6:]:
        assert len(flows[case].conv.frames) == 3 + 2 * 5 + 3


# D4-116 item 6: #718's dnp3-tcp-master-short, written only when it equals
# its pin in the committed hr23.sha256 (test), and refused, leaving no file,
# under a pin it does not equal (control).
def test_gt_capture_equals_its_pin_and_is_refused_under_another(tmp_path):
    times = du.gt_capture(str(tmp_path))
    assert (tmp_path / (du.GT_CASE + ".pcap")).exists()
    assert len(times) == 24 and times == sorted(times)
    wrong = tmp_path / "wrong.sha256"
    wrong.write_text("0" * 64 + "  " + du.GT_CASE + ".pcap\n")
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(SystemExit):
        du.gt_capture(str(other), str(wrong))
    assert not (other / (du.GT_CASE + ".pcap")).exists()


# A configuration with no exit code, or a non-zero one, on the capture is
# named, and fails `check` (tests); with all four at 0, none is (control).
def test_gt_not_run_names_each_missing_configuration(tmp_path):
    for cfg in du.GT_CFGS:
        d = tmp_path / du.GT_CASE / cfg
        d.mkdir(parents=True)
        (d / "exit-code").write_text("0\n")
    assert du.gt_not_run(str(tmp_path)) == []
    (tmp_path / du.GT_CASE / du.C1 / "exit-code").unlink()
    assert du.gt_not_run(str(tmp_path)) == [du.C1]
    (tmp_path / du.GT_CASE / du.C2 / "exit-code").write_text("139\n")
    assert du.gt_not_run(str(tmp_path)) == [du.C1, du.C2]


# quote_gt prints, per configuration, only whether it ran and its exit code,
# never a log or probe row (test); the control is that the same logs, read
# by rows(), do hold rows, so their absence from the output is the filter's.
def test_quote_gt_prints_no_row(tmp_path, capsys):
    marker = "otsec-row-marker"
    for cfg in du.GT_CFGS:
        d = tmp_path / du.GT_CASE / cfg
        d.mkdir(parents=True)
        (d / "exit-code").write_text("0\n")
        for log in ("conn", "analyzer", "otsec_viol", "weird", "reporter", "otsec_probe"):
            (d / (log + ".log")).write_text(json.dumps({"ts": 1.0, "kind": "fc", "note": marker}) + "\n")
    assert du.rows(str(tmp_path / du.GT_CASE / du.C2 / "conn.log"))
    assert du.quote_gt(str(tmp_path)) == []
    out = capsys.readouterr().out
    assert marker not in out and "{" not in out
    for cfg in du.GT_CFGS:
        assert f"- {cfg}: ran, exit code 0" in out
