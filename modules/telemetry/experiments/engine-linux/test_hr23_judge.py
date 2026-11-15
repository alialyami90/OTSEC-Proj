"""HR-23 part (a) (D4, brief P4-4-HR23 stage 3): table.py's DNP3 servers
from the link rows' DIR bit, on made-up logs. Each test of the new reading
has its control: the same logs under zeek-probe-c0 (C0), which keeps
conn.log's responder. Run: python -m pytest -q
modules/telemetry/experiments/engine-linux/test_hr23_judge.py"""
import json
import os

import pytest

import table

R, M = ("192.0.2.20", "20000"), ("192.0.2.14", "20000")
T = {"zeek_fc": {}, "zeek_modbus_fc": {}}


def logs(tmp_path, cfg, probe, service="dnp3_udp", orig=R, resp=M):
    d = tmp_path / cfg
    d.mkdir(parents=True, exist_ok=True)
    conn = {"ts": 1.0, "uid": "C1", "proto": "udp", "id.orig_h": orig[0], "id.orig_p": int(orig[1]),
            "id.resp_h": resp[0], "id.resp_p": int(resp[1]), "service": service}
    (d / "conn.log").write_text(json.dumps(conn) + "\n")
    rows = []
    for k, (kind, is_orig, val) in enumerate(probe):
        r = {"ts": 1.0 + k, "uid": "C1", "is_orig": is_orig, "kind": kind, "ev": "x"}
        if kind == "link":
            if val is not None:
                r["link_dir"] = val
        elif kind == "fc":
            r["fc"] = val
            r["ev"] = "dnp3_application_response_header" if val in (129, 130, 131) else "dnp3_application_request_header"
        rows.append(json.dumps(r))
    (d / "otsec_probe.log").write_text("\n".join(rows) + "\n")
    (d / "exit-code").write_text("0\n")
    return str(d)


def service(s, server, other):
    """judge_flow's Service row for `server`, on a capture whose one
    labelled flow runs between server and other."""
    flow = {"condition": "protocol", "l4": "udp", "src": other[0], "sport": other[1], "dst": server[0], "dport": server[1]}
    svc = dict(flow, condition="service")
    return table.judge_flow(svc, s, [flow], [svc])[0]


# A flow the relay starts (relay is the originator): its 129 with DIR clear,
# the master's confirm with DIR set.
RELAY_START = [("link", True, False), ("fc", True, 129), ("link", False, True), ("fc", False, 0)]


def test_server_of_dir_clear_names_sender_and_dir_set_names_other_end():
    assert table.server_of(R, M, True, False) == R
    assert table.server_of(R, M, False, False) == M
    assert table.server_of(R, M, True, True) == M
    assert table.server_of(R, M, False, True) == R


def test_dir_set_to_broadcast_or_multicast_names_no_server():
    assert table.server_of(M, ("255.255.255.255", "20000"), True, True) is None
    assert table.server_of(M, ("224.0.0.1", "20000"), True, True) is None
    assert table.server_of(M, ("ff02::1", "20000"), True, True) is None
    # A DIR-clear frame from that end still names it: only DIR set is excepted.
    assert table.server_of(M, ("224.0.0.1", "20000"), False, False) == ("224.0.0.1", "20000")


def test_broadcast_limits():
    assert table.broadcast("255.255.255.255")
    assert not table.broadcast("192.0.2.255")  # a directed broadcast is not known (a stated limit)
    assert not table.broadcast("not an address")


def test_relay_started_flow_names_the_relay_under_part_a_and_the_master_under_c0(tmp_path):
    a = table.zeek(logs(tmp_path, "zeek-probe", RELAY_START), "zeek-probe", T)
    assert a.flows[0]["dnp3_servers"] == {R}
    assert service(a, R, M) == "pass"
    # Control: C0 reads conn.log's responder, the master, so the row fails.
    c0 = table.zeek(logs(tmp_path, "zeek-probe-c0", [("link", True, None), ("fc", True, 129)]), "zeek-probe-c0", T)
    assert service(c0, R, M).startswith("fail (service also at 192.0.2.14")


def test_the_server_never_comes_from_the_responder(tmp_path):
    # Linked, but the frames carry no DIR (log_dir off): no server is named,
    # although conn.log names the flow dnp3_udp with the relay as responder.
    s = table.zeek(logs(tmp_path, "zeek-probe", [("link", True, None)], orig=M, resp=R), "zeek-probe", T)
    assert s.flows[0]["dnp3_servers"] == set()
    assert service(s, R, M) == "fail"


def test_both_ends_named_fails_the_service_row_and_is_counted(tmp_path):
    # One frame from the master with DIR clear: the master is named too.
    probe = RELAY_START + [("link", False, False), ("fc", False, 5)]
    d = logs(tmp_path, "zeek-probe", probe)
    s = table.zeek(d, "zeek-probe", T)
    assert s.flows[0]["dnp3_servers"] == {R, M}
    assert service(s, R, M) == "fail (service also at 192.0.2.14 udp/20000)"
    assert table.hr23_readings(d, "zeek-probe")["both"] == 1


def test_no_link_row_names_no_server(tmp_path):
    s = table.zeek(logs(tmp_path, "zeek-probe-c2", [("fc", True, 129)]), "zeek-probe-c2", T)
    assert service(s, R, M) == "fail"


def test_modbus_service_rows_keep_the_responder(tmp_path):
    s = table.zeek(logs(tmp_path, "zeek-probe", [], service="modbus", orig=M, resp=R), "zeek-probe", T)
    assert table.served(s.flows[0], s, "modbus") == {R}


def disagree(tmp_path, pairs):
    probe = []
    for dir_set, fc in pairs:
        probe += [("link", True, dir_set), ("fc", True, fc)]
    return table.zeek(logs(tmp_path, "zeek-probe", probe), "zeek-probe", T).dir_disagree


def test_dir_against_code_counts_at_the_class_boundaries(tmp_path):
    assert disagree(tmp_path, [(True, 1), (False, 129), (True, 0)]) == 0
    assert disagree(tmp_path, [(True, 129)]) == 1
    assert disagree(tmp_path, [(True, 131)]) == 1
    assert disagree(tmp_path, [(True, 132)]) == 0  # above 131 is a request code
    assert disagree(tmp_path, [(False, 128)]) == 1  # below 129 is a request code
    assert disagree(tmp_path, [(False, 2)]) == 1


def test_one_link_row_is_matched_with_one_header(tmp_path):
    # A second header on the same side without its own link row is not
    # counted against the earlier frame's DIR.
    probe = [("link", True, True), ("fc", True, 1), ("fc", True, 129)]
    assert table.zeek(logs(tmp_path, "zeek-probe", probe), "zeek-probe", T).dir_disagree == 0


def test_present_lists_hr23_configurations_only_when_they_ran(tmp_path):
    (tmp_path / "cap" / "zeek-probe-c0").mkdir(parents=True)
    got = table.present(str(tmp_path))
    assert "zeek-probe-c0" in got and "zeek-probe-c2" not in got
    (tmp_path / "cap" / "zeek-probe-c2").mkdir()
    assert "zeek-probe-c2" in table.present(str(tmp_path))
    assert table.present(os.path.join(str(tmp_path), "missing")) == table.CONFIGS


# D6's B1 on #715: the relay-start reading over every configuration that
# loads part (a), each named here rather than read from table.LINKED, so
# that dropping one from LINKED fails. C0 is the control.
@pytest.mark.parametrize("cfg", ["zeek-probe", "zeek-modbus-sig", "zeek-probe-c1p", "zeek-probe-c2"])
def test_relay_start_names_the_relay_under_every_linked_configuration(tmp_path, cfg):
    s = table.zeek(logs(tmp_path, cfg, RELAY_START), cfg, T)
    assert service(s, R, M) == "pass"
    c0 = table.zeek(logs(tmp_path, "zeek-probe-c0", RELAY_START), "zeek-probe-c0", T)
    assert service(c0, R, M).startswith("fail (service also at 192.0.2.14")


def test_link_rows_name_the_server_when_conn_log_names_no_service(tmp_path):
    # The analyzer was removed, so conn.log's service is empty; the frames
    # still named the relay (design section 3 item 7). Control: C0.
    s = table.zeek(logs(tmp_path, "zeek-probe-c2", RELAY_START, service=None), "zeek-probe-c2", T)
    assert service(s, R, M) == "pass"
    c0 = table.zeek(logs(tmp_path, "zeek-probe-c0", RELAY_START, service=None), "zeek-probe-c0", T)
    assert service(c0, R, M) == "fail"


# D6's N2 on #715.
def test_dir_is_paired_with_the_code_on_its_own_side(tmp_path):
    # The two sides' rows interleaved: the relay's DIR clear with its 129,
    # the master's DIR set with its READ. Neither disagrees; pairing by uid
    # alone would read the master's DIR against the relay's 129.
    probe = [("link", True, False), ("link", False, True), ("fc", True, 129), ("fc", False, 1)]
    assert table.zeek(logs(tmp_path, "zeek-probe", probe), "zeek-probe", T).dir_disagree == 0


def test_a_flow_that_names_one_server_is_not_counted_as_both_ends(tmp_path):
    d = logs(tmp_path, "zeek-probe", RELAY_START)
    assert table.hr23_readings(d, "zeek-probe")["both"] == 0


# D6's N1 on #715: the record and field check of C2 against C1 and C1p.
def fields_out(tmp_path, extra):
    out = tmp_path / "out"
    for cfg in ("zeek-probe", "zeek-probe-c1p", "zeek-probe-c2"):
        logs(out / "cap", cfg, RELAY_START)
    if extra:
        d = out / "cap" / "zeek-probe-c2"
        conn = json.loads((d / "conn.log").read_text())
        conn["only_c2"] = 1
        (d / "conn.log").write_text(json.dumps(conn) + "\n")
        (d / "c2only.log").write_text(json.dumps({"ts": 1.0, "f": 1}) + "\n")
    return str(out)


def test_record_and_field_check_lists_what_only_c2_emits(tmp_path, capsys):
    table.hr23(fields_out(tmp_path, True))
    got = capsys.readouterr().out
    assert "- against zeek-probe: c2only.log:f, c2only.log:ts, conn.log:only_c2" in got
    assert "- against zeek-probe-c1p: c2only.log:f, c2only.log:ts, conn.log:only_c2" in got


def test_record_and_field_check_prints_none_on_equal_logs(tmp_path, capsys):
    table.hr23(fields_out(tmp_path, False))
    got = capsys.readouterr().out
    assert "- against zeek-probe: none" in got and "- against zeek-probe-c1p: none" in got


# D6's N6 on #715: reporter.log in the readings, by level and message.
def test_reporter_rows_are_read_by_level_and_message(tmp_path):
    d = logs(tmp_path, "zeek-probe-c2", RELAY_START)
    assert table.hr23_readings(d, "zeek-probe-c2")["reporter"] == {}
    with open(os.path.join(d, "reporter.log"), "w") as fh:
        fh.write(json.dumps({"ts": 1.0, "level": "Reporter::ERROR", "message": "m", "location": "x"}) + "\n")
    assert table.hr23_readings(d, "zeek-probe-c2")["reporter"] == {"Reporter::ERROR: m": 1}


# D6's held item on #715: the regression C2 against C1p, and C1 against C0,
# by reg-rows' rule.
def test_hr23_regression_names_a_row_the_reference_passes_and_the_new_one_fails(monkeypatch, capsys):
    rows = [{"capture": "cap", "condition": "service", "code": ""}, {"capture": "cap", "condition": "function", "code": "2"}]
    res = {"zeek-probe-c0": ["fail", "pass"], "zeek-probe": ["pass", "pass"],
           "zeek-probe-c1p": ["pass", "pass"], "zeek-probe-c2": ["pass", "fail"]}
    monkeypatch.setattr(table, "CONFIGS", tuple(res))
    monkeypatch.setattr(table, "evaluate", lambda conds, loaded, cfg: [(r, v, "") for r, v in zip(rows, res[cfg])])
    table.hr23_regression(rows, {})
    got = capsys.readouterr().out
    assert "- zeek-probe against zeek-probe-c0: pass; rows lost: none" in got
    assert "- zeek-probe-c2 against zeek-probe-c1p: fail; rows lost: cap function 2" in got
