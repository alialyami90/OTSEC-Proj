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


def test_rsyslog_san_path_accepted(rsyslog, tls):
    # librelp's name mode reads the SAN dNSName when there is one: a
    # certificate whose CN is another name but whose SAN is the permitted
    # peer is accepted.
    c = Client(rsyslog.port, tls=tls, cert=tls.san_client_cert, key=tls.san_client_key)
    c.open()
    t = c.send("syslog", MSG + b" san")
    assert c.response() == (t, "rsp", b"200 OK")
    assert rsyslog.lines() == [MSG + b" san"]
    c.close()


def test_rsyslog_cn_matches_despite_other_san(rsyslog, tls):
    # Finding (A6, simulated, rsyslogd 8.2312.0, librelp 1.11.0 over GnuTLS,
    # 2026-10-24): name mode also accepts a CA-signed certificate whose SAN
    # dNSName is another node when its CN is the permitted peer. librelp
    # checks the CN even when a SAN is present, unlike RFC 6125. The Python
    # receiver keeps the stricter rule (SAN, else CN), so the oracle is never
    # looser than the collector. The consequence for commissioning: the CA
    # must not issue a certificate whose CN is a node's name to anything but
    # that node. If this test starts failing, librelp changed; update the
    # finding.
    c = Client(rsyslog.port, tls=tls, cert=tls.san_shadow_cert, key=tls.san_shadow_key)
    c.open()
    t = c.send("syslog", MSG + b" shadow")
    assert c.response() == (t, "rsp", b"200 OK")
    c.close()


# The V-S6 three refusals and a stranger, as the Python receiver also makes
# them (test_relp_receiver.REFUSED).
REFUSED = {
    "no certificate": None,
    "a stranger's certificate": "other",
    "a self-signed one with the client's name": "impostor",
    "a CA-signed certificate for another name": "wrongname",
}


@pytest.mark.parametrize("who", list(REFUSED))
def test_rsyslog_refuses_unknown_client(rsyslog, tls, who):
    which = REFUSED[who]
    cert = (getattr(tls, which + "_cert"), getattr(tls, which + "_key")) if which else (None, None)
    try:
        c = Client(rsyslog.port, tls=tls, cert=cert[0], key=cert[1])
        c.send("open", b"relp_version=0\ncommands=syslog")
        c.send("syslog", MSG)
        r = c.response()
    except OSError:
        r = None
    assert r is None or not r[2].startswith(b"200 OK"), who
    assert rsyslog.lines() == [], who
