"""HR-23 part (a) (D4, brief P4-4-HR23 stage 3): table.py's DNP3 servers
from the link rows' DIR bit, on made-up logs. Each test of the new reading
has its control: the same logs under zeek-probe-c0 (C0), which keeps
conn.log's responder. Run: python -m pytest -q
modules/telemetry/experiments/engine-linux/test_hr23_judge.py"""
import json
import os

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
