"""The engine run's pass conditions follow the committed labels (D6, P4-4-R1).

engine-pass-conditions.tsv is what brief P4-4-S2's table is judged by. It
must be exactly what engine_conditions.py derives from the label files, so
it can't drift from them, and nothing in it can come from an engine."""

import collections
import os

import pytest

import engine_conditions

HERE = os.path.dirname(os.path.abspath(__file__))
LABELS = os.path.join(HERE, "..", "..", "fixtures", "network", "gt-pcap", "dnp3")


def table():
    with open(os.path.join(HERE, "engine-pass-conditions.tsv"), encoding="utf-8") as f:
        return f.read()


def rows():
    return [dict(zip(engine_conditions.COLUMNS, r)) for r in engine_conditions.conditions(LABELS)]


def test_the_committed_table_is_derived_from_the_labels():
    assert table() == engine_conditions.render(engine_conditions.conditions(LABELS))


def test_every_capture_has_its_protocol_service_and_function_rows():
    by = collections.defaultdict(collections.Counter)
    for r in rows():
        by[r["capture"]][r["condition"]] += 1
    assert len(by) == 25  # 22 labelled DNP3 cases, the two R6.2 series, and the derived Modbus capture
    for name, n in by.items():
        assert n["protocol"] >= 1 and n["service"] >= 1 and n["function"] >= 1, name


def test_group_120_rows_cover_the_five_sa_captures_and_every_outcome():
    g120 = [r for r in rows() if r["condition"] == "g120"]
    # The captures are found from the labels' sa values, and pinned here by name.
    assert {r["capture"] for r in g120} == {"dnp3-sa", "dnp3-sa-failed-outstation", "dnp3-sa-failed-before-ack",
                                            "dnp3-sa-failed-unauthorized", "dnp3-sa-failed-master"}
    assert {r["sa"] for r in g120} == {"none", "challenged", "aggressive", "failed"}
    # One row per message: a failed exchange asks for its challenge and for its error.
    assert len(g120) == 11
    by = collections.defaultdict(list)
    for r in g120:
        by[r["capture"]].append(r["show"].split(" from ")[0])
    assert by["dnp3-sa-failed-outstation"] == ["131:g120v1", "131:g120v7"]
    assert by["dnp3-sa-failed-master"] == ["131:g120v1", "33:g120v7"]
    # Both ends that can send the error are asked for, each with its function code.
    shown = {r["show"].split(" from ")[0] for r in g120}
    assert {"131:g120v1", "5:g120v3", "131:g120v7", "33:g120v7"} <= shown
    for r in g120:
        sender = r["show"].rsplit(" ", 1)[1]
        assert r["sa"] == "none" or sender in (r["src"], r["dst"]), r


def test_the_moved_port_and_udp_rows():
    got = collections.defaultdict(list)
    for r in rows():
        got[r["capture"]].append(r)
    moved, udp = got["dnp3-moved-port"], got["dnp3-udp"]
    assert {(r["l4"], r["dport"]) for r in moved} == {("tcp", "20001")}
    assert {(r["l4"], r["dport"]) for r in udp} == {("udp", "20000")}
    for case in (moved, udp):
        assert sorted(r["code"] for r in case if r["condition"] == "function") == ["1", "5"]
    # Every other DNP3 capture is on TCP 20000, so these five are the only
    # DNP3 rows that tell a port-only or TCP-only decoder apart.
    udp_cases = ("dnp3-udp", "dnp3-udp-moved-port", "dnp3-udp-temp-port", "dnp3-udp-req-port")
    rest = {(r["l4"], r["dport"]) for n, rs in got.items() if n not in ("dnp3-moved-port",) + udp_cases for r in rs
            if r["protocol"] == "dnp3"}
    assert rest == {("tcp", "20000")}


def test_the_three_udp_arrangements_of_p4_d6_gt2():
    got = collections.defaultdict(list)
    for r in rows():
        got[r["capture"]].append(r)
    for name in ("dnp3-udp-moved-port", "dnp3-udp-temp-port", "dnp3-udp-req-port"):
        assert {r["l4"] for r in got[name]} == {"udp"}, name
        assert sorted(r["code"] for r in got[name] if r["condition"] == "function") == ["1", "5"], name
        assert [r["dport"] for r in got[name] if r["condition"] == "service"] == [
            "20001" if name == "dnp3-udp-moved-port" else "20000"], name
        assert {r["src"] for r in got[name] if r["condition"] == "function"} == {"192.0.2.14"}, name
    # D2's note 1 on #637: no row of the moved case is on 20000, at either end.
    assert "20000" not in {p for r in got["dnp3-udp-moved-port"] for p in (r["sport"], r["dport"])}
    # The temporary-port case is two flows: the requests' and the responses',
    # whose first datagram is the outstation's. Its one service is the
    # outstation's end, never the master's port 20000.
    flows = [(r["src"], r["sport"], r["dst"], r["dport"]) for r in got["dnp3-udp-temp-port"] if r["condition"] == "protocol"]
    assert flows == [("192.0.2.14", "41017", "192.0.2.20", "20000"), ("192.0.2.20", "20000", "192.0.2.14", "20000")]
    assert [(r["dst"], r["dport"]) for r in got["dnp3-udp-temp-port"] if r["condition"] == "service"] == [
        ("192.0.2.20", "20000")]


def test_the_derived_modbus_capture_has_its_rows_off_port_502():
    got = [r for r in rows() if r["capture"] == "modbus-moved-port"]
    assert [r["condition"] for r in got] == ["protocol", "service", "function"]
    assert {(r["protocol"], r["l4"], r["dport"]) for r in got} == {("modbus", "tcp", "15020")}
    assert got[2]["code"] == "3"
    # It is the only Modbus capture, and no DNP3 row is on its port.
    assert {r["capture"] for r in rows() if r["protocol"] == "modbus"} == {"modbus-moved-port"}


def test_an_unknown_sa_value_is_refused():
    with pytest.raises(ValueError):
        engine_conditions.g120_shows({"src": "a", "dst": "b", "code": "5", "objects": "", "sa": "", "sa_error_from": ""})


def test_a_failed_aggressive_exchange_asks_for_the_request_and_the_error():
    row = {"src": "m", "dst": "o", "code": "5", "objects": "g120v3,g120v9,g12v1", "sa": "failed", "sa_error_from": "master"}
    assert engine_conditions.g120_shows(row) == ["5:g120v3 from m", "33:g120v7 from m"]


def test_a_capture_gets_g120_rows_only_when_its_labels_show_secure_authentication():
    fn = lambda sa: {"kind": "function", "sa": sa}  # noqa: E731
    assert not engine_conditions.holds_sa([fn("none"), fn(""), {"kind": "flow", "sa": ""}])
    for sa in ("challenged", "aggressive", "failed"):
        assert engine_conditions.holds_sa([fn("none"), fn(sa)])
