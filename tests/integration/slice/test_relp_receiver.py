"""The slice's RELP receiver does what the forwarder tests rely on (A6).

Ground truth: the RELP frame grammar (librelp doc/relp.html, as C6 relp.go
reads it) and the receiver's own stated contract: a "200 OK" only after the
message is fsynced to the log, and fault injection exactly at the Nth frame.
"""

import base64

import pytest

import harness
from relp_client import Client

MSG = b'<109>1 2026-10-24T12:00:00.000001Z node otsec - SER [x@1 a="1"] row\nwith LF'


@pytest.fixture
def plain(tmp_path):
    log = str(tmp_path / "recv.jsonl")
    p = harness.start_receiver(log)
    yield p, log
    p.stop()


def syslogs(log):
    return [r for r in harness.read_log(log) if r["event"] == "syslog"]


def test_open_offers_syslog(plain):
    p, log = plain
    c = Client(p.port)
    txnr, cmd, data = c.open()
    assert (txnr, cmd) == (1, "rsp")
    assert data.startswith(b"200 OK\n") and b"commands=syslog" in data.split(b"\n")
    c.close()


def test_ack_only_after_durable_write(plain):
    p, log = plain
    c = Client(p.port)
    c.open()
    t = c.send("syslog", MSG)
    assert c.response() == (t, "rsp", b"200 OK")
    # The acknowledgement came after the fsync, so the record is already in
    # the file when the client reads the 200.
    recs = syslogs(log)
    assert len(recs) == 1 and base64.b64decode(recs[0]["b64"]) == MSG and recs[0]["octets"] == len(MSG)
    c.close()


def test_pipelined_window_answers_each_txnr(plain):
    p, log = plain
    c = Client(p.port)
    c.open()
    sent = [c.send("syslog", MSG + b" %d" % i) for i in range(20)]
    got = [c.response() for _ in sent]
    assert [g[0] for g in got] == sent and all(g[1:] == ("rsp", b"200 OK") for g in got)
    assert [base64.b64decode(r["b64"]) for r in syslogs(log)] == [MSG + b" %d" % i for i in range(20)]
    c.close()


def test_close_gets_empty_rsp(plain):
    p, _ = plain
    c = Client(p.port)
    c.open()
    t = c.send("close")
    assert c.response() == (t, "rsp", b"")
    assert c.response() is None


@pytest.mark.parametrize("frame,why", [
    (b"01 syslog 3 abc\n", "leading zero in TXNR"),
    (b"2 syslog 5 abc\n", "DATALEN longer than the data"),
    (b"2 syslog 3 abcX", "no LF trailer"),
    (b"2 bogus 0\n", "command not offered"),
    (b"2 syslog 0 \n", "DATALEN 0 then SP"),
])
def test_bad_frame_serverclose(plain, frame, why):
    p, log = plain
    c = Client(p.port)
    c.open()
    c.raw(frame)
    r = c.response()
    # The receiver ends the session; it never acknowledges a bad frame.
    assert r in (None, (0, "serverclose", b"")), why
    assert not syslogs(log), why
    assert any(x["event"] == "frame_error" for x in harness.read_log(log)) or r is None, why
    c.close()


def test_syslog_before_open_refused(plain):
    p, log = plain
    c = Client(p.port)
    c.send("syslog", MSG)
    assert c.response() in (None, (0, "serverclose", b""))
    assert not syslogs(log)


@pytest.mark.parametrize("flag,expect", [
    ("--close-after", None),
    ("--serverclose-after", (0, "serverclose", b"")),
    ("--reject-after", "500"),
])
def test_fault_injection_at_nth_frame(tmp_path, flag, expect):
    log = str(tmp_path / "recv.jsonl")
    p = harness.start_receiver(log, extra=[flag, "3"])
    try:
        c = Client(p.port)
        c.open()
        for i in (1, 2):
            t = c.send("syslog", b"m%d" % i)
            assert c.response() == (t, "rsp", b"200 OK")
        t3 = c.send("syslog", b"m3")
        r = c.response()
        if expect == "500":
            assert r[0] == t3 and r[2].startswith(b"500")
            # The session goes on; the next frame is stored.
            t4 = c.send("syslog", b"m4")
            assert c.response() == (t4, "rsp", b"200 OK")
            want = [b"m1", b"m2", b"m4"]
        else:
            assert r == expect
            want = [b"m1", b"m2"]
        c.close()
        assert [base64.b64decode(x["b64"]) for x in syslogs(log)] == want
        un = [x for x in harness.read_log(log) if x["event"] == "unacked"]
        assert len(un) == 1 and un[0]["txnr"] == t3 and un[0]["reason"] == flag[2:]
    finally:
        p.stop()


def test_tls_mutual(tmp_path, tls):
    log = str(tmp_path / "recv.jsonl")
    p = harness.start_receiver(log, tls=tls)
    try:
        c = Client(p.port, tls=tls, cert=tls.client_cert, key=tls.client_key)
        c.open()
        t = c.send("syslog", MSG)
        assert c.response() == (t, "rsp", b"200 OK")
        c.close()
        opens = [x for x in harness.read_log(log) if x["event"] == "session_open"]
        assert opens[0]["tls"]["client_subject"] == {"commonName": "a6-slice-node"}
        assert opens[0]["tls"]["version"] in ("TLSv1.2", "TLSv1.3")
    finally:
        p.stop()


@pytest.mark.parametrize("who", ["no client certificate", "a certificate the CA did not sign"])
def test_tls_refuses_unknown_client(tmp_path, tls, who):
    log = str(tmp_path / "recv.jsonl")
    p = harness.start_receiver(log, tls=tls)
    try:
        cert = (None, None) if who.startswith("no") else (tls.other_cert, tls.other_key)
        try:
            c = Client(p.port, tls=tls, cert=cert[0], key=cert[1])
            c.send("open", b"relp_version=0\ncommands=syslog")
            c.send("syslog", MSG)
            r = c.response()
        except (OSError, ConnectionError):
            r = None
        assert r is None, who
        harness.wait_for(lambda: any(x["event"] == "session_close" for x in harness.read_log(log)), 5)
        assert not syslogs(log), who
    finally:
        p.stop()

