"""The Linux leg's upstream collector, rsyslog with imrelp over TLS, works
with the configuration the integration job uses (A6, D2-3)."""

import pytest

import harness
from conftest import need
from relp_client import Client

MSG = b'<133>1 2026-10-24T12:00:05.123456Z site-a6 otsec - SER [otsec@32473 eid="a:b:1" evc="simulated"] ser'


@pytest.fixture
def rsyslog(tmp_path, tls):
    need(harness.rsyslogd(), "rsyslogd not installed (the Linux integration leg needs rsyslog with imrelp)")
    r = harness.Rsyslog(str(tmp_path), tls)
    yield r
    r.stop()


def test_rsyslog_relp_tls_delivers(rsyslog, tls):
    c = Client(rsyslog.port, tls=tls, cert=tls.client_cert, key=tls.client_key)
    txnr, cmd, data = c.open()
    assert cmd == "rsp" and data.startswith(b"200 OK") and b"commands=syslog" in data.split(b"\n")
    sent = [MSG + b" %d" % i for i in range(10)]
    for m in sent:
        t = c.send("syslog", m)
        assert c.response() == (t, "rsp", b"200 OK")
    # Each 200 came after the write: the lines are already in the file.
    assert rsyslog.lines() == sent
    c.close()


@pytest.mark.parametrize("who", ["no certificate", "a stranger's certificate", "a self-signed one with the client's name"])
def test_rsyslog_refuses_unknown_client(rsyslog, tls, who):
    cert = {"no certificate": (None, None), "a stranger's certificate": (tls.other_cert, tls.other_key),
            "a self-signed one with the client's name": (tls.impostor_cert, tls.impostor_key)}[who]
    try:
        c = Client(rsyslog.port, tls=tls, cert=cert[0], key=cert[1])
        c.send("open", b"relp_version=0\ncommands=syslog")
        c.send("syslog", MSG)
        r = c.response()
    except OSError:
        r = None
    assert r is None or not r[2].startswith(b"200 OK"), who
    assert rsyslog.lines() == [], who
