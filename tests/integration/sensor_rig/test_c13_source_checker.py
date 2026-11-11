"""The test-only C13 source and the checker, each against the other and
against planted faults (D6, P4-4-R1 deliverables 3 and 4). The checker must
pass the source's records for every labelled case, and must fail on each
wrong record planted below, naming it. Stdlib only, no root: these run in
the pytest job. The product's own decoder reads the source's stream in
tests/contract/c13_source_d6_test.go."""

import base64
import copy
import hashlib
import socket
import threading

import pytest

import c13_source
import c13_stream
import gt_checker

import dnp3_cases  # c13_stream puts GT-PCAP's folder on the path


def records(name):
    return c13_source.Source(*c13_stream.load(name)).records()


@pytest.mark.parametrize("name", c13_stream.names())
def test_the_checker_passes_the_sources_records_for_every_labelled_case(name):
    rows, frames, sha = c13_stream.load(name)
    recs = c13_source.Source(rows, frames, sha).records()
    got = gt_checker.check(rows, recs)
    assert got["problems"] == []
    assert got["recall"] == 1 and got["precision"] == 1 and got["extra"] == 0
    assert got["labelled"] == sum(r["kind"] in ("flow", "service", "function") for r in rows) > 0
    # The stream's own form: heartbeats around the capture, seq from 1, and
    # every first sight's bytes hashing to what it cites.
    assert recs[0]["type"] == recs[-1]["type"] == "heartbeat"
    assert [r["seq"] for r in recs] == [str(i) for i in range(1, len(recs) + 1)]
    assert recs[-1]["counters"]["packets"] == len(frames)
    for r in recs[1:-1]:
        assert r["citation"]["capture_id"] == "file:" + sha
        assert ("frames" in r) == r["first_sight"]
        for f, c in zip(r.get("frames", []), r["citation"]["frames"]):
            assert hashlib.sha256(base64.b64decode(f["data"])).hexdigest() == c["sha256"] and f["n"] == c["n"]


def test_the_reused_sequence_number_reaches_the_closing_heartbeat():
    recs = records("dnp3-reused-seq")
    assert recs[0]["counters"]["dnp3_seq_reused"] == 0 and recs[-1]["counters"]["dnp3_seq_reused"] == 1
    assert records("dnp3-sa")[-1]["counters"]["dnp3_seq_reused"] == 0


def test_the_records_cross_a_real_byte_stream_unchanged():
    """C13's framing over a TCP connection on loopback: what the reader
    takes off the stream is what the source built."""
    recs = records("dnp3-sa")
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    got = []

    def reader():
        conn, _ = server.accept()
        with conn:
            buf = b""
            while chunk := conn.recv(65536):
                buf += chunk
        got.extend(c13_source.read(buf))

    t = threading.Thread(target=reader)
    t.start()
    with socket.create_connection(server.getsockname()) as c:
        c13_source.write(c, recs)
    t.join(10)
    server.close()
    assert got == recs
    assert all(len(c13_source.frame(r)) - 4 <= 64 * 1024 for r in recs)  # MaxChannelFrame


def test_the_committed_stream_is_what_the_source_sends():
    with open(c13_stream.COMMITTED, "rb") as f:
        assert f.read() == c13_stream.stream()


def find(recs, kind, **body):
    return next(r for r in recs if r.get("kind") == kind and all(r[kind].get(k) == v for k, v in body.items()))


def drop_service(recs):
    recs.remove(find(recs, "service"))


def wrong_sa(recs):
    find(recs, "function", sa="challenged")["function"]["sa"] = "none"


def wrong_port(recs):
    find(recs, "service")["ip"]["dport"] = 20001


def doubled_packets(recs):
    end = find(recs, "flow", phase="end")
    end["flow"]["packets"] *= 2  # as a sensor that counts both PRP copies would


def wrong_citation(recs):
    find(recs, "function", sa="aggressive")["citation"]["frames"][0]["sha256"] = "0" * 64


def wrong_frame_number(recs):
    find(recs, "function", sa="aggressive")["citation"]["frames"][0]["n"] += 1


def extra_function(recs):
    cold = copy.deepcopy(find(recs, "function", code=1))
    cold["function"] = {"code": 13, "objects": []}  # a cold restart nobody sent
    recs.insert(-1, cold)


def response_as_function(recs):
    reply = copy.deepcopy(find(recs, "function", code=1))
    reply["function"]["code"] = 129
    recs.insert(-1, reply)


def missing_objects(recs):
    find(recs, "function", sa="aggressive")["function"]["objects"] = ["g12v1"]  # the group 120 headers lost


def reversed_client(recs):
    for r in recs:
        if r.get("kind") == "flow":
            ip = r["ip"]
            ip["src"], ip["dst"], ip["sport"], ip["dport"] = ip["dst"], ip["src"], ip["dport"], ip["sport"]


def no_end(recs):
    recs.remove(find(recs, "flow", phase="end"))


PLANTED = [
    (drop_service, "missed service"), (wrong_sa, "recorded with sa none"), (wrong_port, "missed service"),
    (doubled_packets, "packets and"), (wrong_citation, "does not show it"), (wrong_frame_number, "the label has that frame as"),
    (extra_function, "extra function"), (response_as_function, "extra function"), (missing_objects, "missed function"),
    (reversed_client, "the client is recorded as"), (no_end, "no end record"),
]


@pytest.mark.parametrize("plant,says", PLANTED, ids=[p.__name__ for p, _ in PLANTED])
def test_the_checker_fails_on_a_planted_wrong_record(plant, says):
    rows, frames, sha = c13_stream.load("dnp3-sa")
    recs = c13_source.Source(rows, frames, sha).records()
    assert gt_checker.check(rows, recs)["problems"] == []
    plant(recs)
    got = gt_checker.check(rows, recs)
    assert any(says in p for p in got["problems"]), got["problems"]
    assert got["recall"] < 1 or got["precision"] < 1 or got["problems"]


def test_recall_and_precision_count_what_was_missed_and_what_was_extra():
    rows, frames, sha = c13_stream.load("dnp3-sa")
    recs = c13_source.Source(rows, frames, sha).records()
    drop_service(recs)
    extra_function(recs)
    got = gt_checker.check(rows, recs)
    n = got["labelled"]
    assert got["matched"] == n - 1 and got["recall"] == (n - 1) / n
    assert got["extra"] == 1 and got["precision"] == (got["observations"] - 1) / got["observations"]


def test_a_service_found_by_port_alone_fails_only_where_the_port_was_moved():
    rows, frames, sha = c13_stream.load("dnp3-authorized-operate")
    recs = c13_source.Source(rows, frames, sha).records()
    find(recs, "service")["service"]["basis"] = "port"
    assert gt_checker.check(rows, recs)["problems"] == []
    bad = gt_checker.check(rows, recs, moved_port=True)["problems"]
    assert len(bad) == 1 and "not by content, on a moved port" in bad[0]


def test_every_authorized_writer_resolves_or_the_checker_stops():
    net = dnp3_cases.NET
    got = gt_checker.writers(net)
    assert ("192.0.2.10", "192.0.2.20", "control") in got and len(got) == len(net["authorized_writers"])
    # A second relay, named only under `outstations`, resolves too.
    more = {**net, "outstations": {**net.get("outstations", {}), "O9": {"ip": "192.0.2.29"}},
            "authorized_writers": net["authorized_writers"] + [["M1", "O9", "control"]]}
    assert ("192.0.2.10", "192.0.2.29", "control") in gt_checker.writers(more)
    # A name in no table stops the check; it is never dropped.
    with pytest.raises(KeyError):
        gt_checker.writers({**net, "authorized_writers": [["M1", "O7", "control"]]})
    with pytest.raises(KeyError):
        gt_checker.writers({**net, "authorized_writers": [["M8", "O1", "write"]]})


def test_a_service_recorded_against_the_wrong_asset_fails():
    rows, frames, sha = c13_stream.load("dnp3-authorized-operate")
    recs = c13_source.Source(rows, frames, sha).records()
    svc = find(recs, "service")
    svc["node"] = {"dst_asset": next(r["asset"] for r in rows if r["kind"] == "service")}
    assert gt_checker.check(rows, recs)["problems"] == []
    svc["node"]["dst_asset"] = "asset-unresolved"
    assert any("recorded against asset-unresolved" in p for p in gt_checker.check(rows, recs)["problems"])
