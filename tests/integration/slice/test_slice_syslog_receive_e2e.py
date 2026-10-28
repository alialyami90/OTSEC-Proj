"""Received Syslog end to end, on the real binaries (A6; #150, #154).

The slice as in test_slice_e2e.py, with two Syslog listeners on the node:
syslog-udp (plaintext, by the operator's per-listener setting, D3-5) and
syslog-tls with a sender certificate required, the run's test CA being the
sender CA set. The SEL-751 asset has inbound Syslog endpoints at 127.0.0.2,
so test sockets bound to 127.0.0.2 are the device and 127.0.0.3 is a host
no asset claims.

The oracle is the sender's bytes, message by message, as they arrive at
A6's upstream RELP receiver after the node stored and forwarded them:
  - dtext (or dtext_b64) equals the bytes sent, without their framing,
    and rsha256 and rlen are their SHA-256 and length;
  - the device's messages name the asset, bound by sender-address, with
    auth tls-mutual on TLS and none on UDP, evidence class simulated;
  - the unknown host's messages arrive with no asset, flag
    asset-unresolved, and one syslog.unknown-source health event whose
    related ID is the first of them;
  - a TLS sender without a certificate, or with one from another CA, is
    refused and nothing it sent arrives;
  - the plaintext listener is a node.posture_change in the audit chain and
    PLAINTEXT in otsec health;
  - the recording check still passes: Syslog adds no line to the device.

Evidence class: simulated. Senders are test sockets on loopback.
"""

import base64
import datetime
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time

import pytest

import harness
from conftest import need
from reconcile import first, parse_rfc5424
from slicerun import CHECK, REGISTER, SERVICE, Slice

DEVICE, STRANGER = "127.0.0.2", "127.0.0.3"


def _tls_frames():
    """Octet-counted and LF frames on one connection, with bytes that must
    travel as base64 (NUL, invalid UTF-8, a CR before the LF)."""
    msgs = [
        b"<165>1 2026-10-26T12:00:00.123456Z sel751-a6 app 1 ID1 - first over TLS",
        b"<14>Oct 26 2026 12:00:01 SEL-751 counted frame with a \n inside",
        b"<13>bad utf8 \xff\xfe and nul \x00",
        b"<13>ends with CR\r",
        b"<13>" + b"y" * 1500,
    ]
    wire = b""
    for i, m in enumerate(msgs):
        if b"\n" in m or i % 2:
            wire += str(len(m)).encode() + b" " + m
        else:
            wire += m + b"\n"
    return msgs, wire


UDP = [b"<13>udp one", b"<13>udp two\nwith a line feed\n", b"<13>udp \xc3\x28 invalid", b"<13>udp one"]
STRANGE = [b"<13>who is this 1", b"<13>who is this 2"]


def _client(layout, cert=True, ca=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(layout["ca"])
    ctx.check_hostname = False
    if cert:
        ctx.load_cert_chain(layout["sender_cert"], layout["sender_key"])
    if ca:
        ctx.load_cert_chain(*ca)
    return ctx


def _send_tls(layout, wire, ctx):
    host, port = layout["syslog_tls"].rsplit(":", 1)
    raw = socket.create_connection((host, int(port)), timeout=10, source_address=(DEVICE, 0))
    try:
        s = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        s.sendall(wire)
        # Let the listener read before closing.
        time.sleep(0.5)
        try:
            s.unwrap()
        except (ssl.SSLError, OSError):
            pass
        return True
    except (ssl.SSLError, OSError):
        return False
    finally:
        raw.close()


def _refused_tls(layout, wire, ctx):
    """A sender the listener must refuse. TLS 1.3 completes the client's
    side before the server checks its certificate, so the write may
    succeed; nothing of it may be stored."""
    host, port = layout["syslog_tls"].rsplit(":", 1)
    raw = socket.create_connection((host, int(port)), timeout=10, source_address=(DEVICE, 0))
    try:
        s = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        s.sendall(wire)
        s.settimeout(5)
        try:
            s.recv(1)
        except (ssl.SSLError, OSError):
            pass
    except (ssl.SSLError, OSError):
        pass
    finally:
        raw.close()


def _send_udp(layout, src, msgs):
    host, port = layout["syslog_udp"].rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((src, 0))
    try:
        for m in msgs:
            s.sendto(m, (host, int(port)))
            time.sleep(0.05)
    finally:
        s.close()


def _other_ca(d):
    """A CA and a client certificate the node never configured."""
    key, crt = os.path.join(d, "intruder.key"), os.path.join(d, "intruder.crt")
    out = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                          "-nodes", "-keyout", key, "-out", crt, "-days", "1", "-subj", "/CN=intruder"],
                         capture_output=True)
    return (crt, key) if out.returncode == 0 else None


def _forwarded(s):
    """Upstream messages of the listener streams, by stream, in seq order:
    (seq, params)."""
    out = {}
    for m in s.received():
        try:
            p = parse_rfc5424(m)
        except ValueError:
            continue
        ps = p["sd"].get("otsec@32473", [])
        eid = first(ps, "eid") or ""
        node, stream, seq = eid.rsplit(":", 2) if eid.count(":") >= 2 else ("", "", "0")
        if stream.startswith(("syslog/a6-", "syslog-unknown/a6-")):
            out.setdefault(stream, {})[int(seq)] = ps
    return {k: [v[q] for q in sorted(v)] for k, v in out.items()}


def _health(s, htype):
    out = []
    for m in s.received():
        try:
            ps = parse_rfc5424(m)["sd"].get("otsec@32473", [])
        except ValueError:
            continue
        if first(ps, "htype") == htype:
            out.append(ps)
    return out


def _audit(path):
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [json.loads(ev) for (ev,) in db.execute("SELECT event FROM events WHERE stream = 'audit' ORDER BY seq")]
    finally:
        db.close()


def _native(ps):
    t = first(ps, "dtext")
    if t is not None:
        return t.encode("utf-8")
    b = first(ps, "dtext_b64")
    return None if b is None else base64.b64decode(b)


@pytest.fixture(scope="module")
def got(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt" or SERVICE, "the Windows leg of the end-to-end run is the PC run (D1-26)")
    d = str(tmp_path_factory.mktemp("slice-syslog"))
    s = Slice(d)
    s.build()
    udp, tls_port = harness.free_port(), harness.free_port()
    out = {}
    try:
        s.start(setup_extra=("-syslog-udp", str(udp), "-syslog-tls", str(tls_port)))
        layout = s.layout
        ok = harness.wait_for(lambda: "listener a6-tls" in s.health() and "listener a6-udp" in s.health(), 60, step=1.0)
        assert ok, s.health() + s.text("node")
        msgs, wire = _tls_frames()
        # Refused first: nothing of these may ever arrive.
        _refused_tls(layout, b"<13>no certificate\n", _client(layout, cert=False))
        other = _other_ca(d)
        out["intruder_tested"] = other is not None
        if other:
            _refused_tls(layout, b"<13>wrong CA\n", _client(layout, cert=False, ca=other))
        out["tls_sent"] = _send_tls(layout, wire, _client(layout))
        _send_udp(layout, DEVICE, UDP)
        _send_udp(layout, STRANGER, STRANGE)
        want = {"syslog/a6-tls": len(msgs), "syslog/a6-udp": len(UDP), "syslog-unknown/a6-udp": len(STRANGE)}
        out["arrived"] = harness.wait_for(
            lambda: all(len(_forwarded(s).get(k, [])) >= n for k, n in want.items()) and _health(s, "syslog.unknown-source"),
            90, step=1.0)
        time.sleep(3)
        out["fwd"] = _forwarded(s)
        out["unknown_alarms"] = _health(s, "syslog.unknown-source")
        out["omitted"] = _health(s, "forward.text-omitted")
        # Listener status is published with the 10 s forwarding check.
        out["health_current"] = harness.wait_for(lambda: f"{len(msgs)} received, {len(msgs)} stored" in s.health(), 30, step=1.0)
        out["health"] = s.health()
        out["msgs"] = msgs
        out["layout"] = layout
        out["all_received"] = s.received()
    finally:
        s.stop()
    out["audit"] = _audit(os.path.join(s.layout["store_dir"], "audit.db"))
    out["sim_logs"] = list(s.sim_logs)
    print(out["health"])
    return out


def _check(ps, sent, omitted=False):
    """omitted: the record is over what fits the target's 2048 octets, so
    C6 sends dtext_omitted="size" with its hash and length instead."""
    got = _native(ps)
    if omitted:
        assert got is None and ("dtext_omitted", "size") in ps, ps
    else:
        assert got == sent, (got, sent)
    assert first(ps, "rsha256") == hashlib.sha256(sent).hexdigest()
    assert first(ps, "rlen") == str(len(sent))
    assert first(ps, "evc") == "simulated"


def test_tls_messages_arrive_byte_for_byte(got):
    assert got["tls_sent"], "the certified sender could not send"
    fwd = got["fwd"].get("syslog/a6-tls", [])
    assert len(fwd) == len(got["msgs"]), [first(p, "eid") for p in fwd]
    for i, (ps, sent) in enumerate(zip(fwd, got["msgs"])):
        _check(ps, sent, omitted=len(sent) > 1400)
        assert first(ps, "asset") == got["layout"]["asset_id"]
        assert first(ps, "abind") == "sender-address/configured"
        assert first(ps, "auth") == "tls-mutual"
        assert first(ps, "sender") == DEVICE
        assert first(ps, "flag") is None, ps


def test_text_omitted_is_reported(got):
    """The long message's bytes stay in the node's store; the forwarder says
    so with forward.text-omitted naming the event (C6 size rule)."""
    long_eid = first(got["fwd"]["syslog/a6-tls"][4], "eid")
    named = [first(h, "hrel") for h in got["omitted"]]
    assert long_eid in named, (long_eid, named)


def _leaf_sha256(path):
    """SHA-256 of the DER of the first certificate in a PEM file: the
    certificate the test's sender presents, hashed here, never read back
    from the node."""
    pem = open(path).read()
    block = pem[pem.index("-----BEGIN CERTIFICATE-----"):pem.index("-----END CERTIFICATE-----") + 25]
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(block)).hexdigest()


def test_forwarded_tls_events_name_the_sender_certificate(got):
    """C6 0.3 (A4, #170): every forwarded tls-mutual event carries tlsleaf,
    the SHA-256 of the certificate the sender presented, the long one whose
    text was omitted included; UDP events carry none; v is 0.3."""
    want = _leaf_sha256(got["layout"]["sender_cert"])
    tls = got["fwd"].get("syslog/a6-tls", [])
    udp = got["fwd"].get("syslog/a6-udp", []) + got["fwd"].get("syslog-unknown/a6-udp", [])
    assert tls and udp
    for ps in tls:
        assert [v for n, v in ps if n == "tlsleaf"] == [want], ps
    assert ("dtext_omitted", "size") in tls[4] and first(tls[4], "tlsleaf") == want
    for ps in udp:
        assert first(ps, "tlsleaf") is None, ps
    for ps in tls + udp:
        assert first(ps, "v") == "otsec.syslog/0.3", ps


def test_refused_senders_left_nothing(got):
    for m in got["all_received"]:
        assert b"no certificate" not in m and b"wrong CA" not in m
        # dtext_b64 would hide them from a plain search.
        for n, v in parse_rfc5424(m)["sd"].get("otsec@32473", []) if m.startswith(b"<") else []:
            if n == "dtext_b64":
                assert b"no certificate" not in base64.b64decode(v) and b"wrong CA" not in base64.b64decode(v)
    assert got["health_current"], got["health"]
    assert "refused" in got["health"] and "tls" in got["health"], got["health"]


def test_udp_device_and_stranger(got):
    """HR-11, C5 0.4: the device's datagrams are in the listener's stream and
    the stranger's in the listener's syslog-unknown stream, never the other
    way round."""
    fwd = got["fwd"].get("syslog/a6-udp", []) + got["fwd"].get("syslog-unknown/a6-udp", [])
    assert all(first(ps, "sender") == DEVICE for ps in got["fwd"].get("syslog/a6-udp", []))
    assert all(first(ps, "sender") == STRANGER for ps in got["fwd"].get("syslog-unknown/a6-udp", []))
    by_sender = {}
    for ps in fwd:
        by_sender.setdefault(first(ps, "sender"), []).append(ps)
    dev, strange = by_sender.get(DEVICE, []), by_sender.get(STRANGER, [])
    assert len(dev) == len(UDP) and len(strange) == len(STRANGE), sorted(by_sender)
    for ps, sent in zip(dev, UDP):
        _check(ps, sent)
        assert first(ps, "asset") == got["layout"]["asset_id"] and first(ps, "auth") == "none"
    # The duplicate datagram is kept, with the same hash.
    assert first(dev[0], "rsha256") == first(dev[3], "rsha256") and first(dev[0], "eid") != first(dev[3], "eid")
    for ps, sent in zip(strange, STRANGE):
        _check(ps, sent)
        assert first(ps, "asset") is None and first(ps, "abind") is None, ps
        assert ("flag", "asset-unresolved") in ps


def test_one_unknown_source_alarm_for_the_stranger(got):
    alarms = got["unknown_alarms"]
    assert len(alarms) == 1, alarms
    first_eid = first([p for p in got["fwd"]["syslog-unknown/a6-udp"] if first(p, "sender") == STRANGER][0], "eid")
    assert first(alarms[0], "hrel") == first_eid, alarms[0]
    assert ("hd", f"sender={STRANGER}") in alarms[0], alarms[0]


def test_plaintext_listener_is_audited_and_shown(got):
    posture = [r for r in got["audit"] if r.get("action") == "node.posture_change"
               and r.get("reason_code") == "plaintext_listener"]
    assert posture and all("a6-udp" in r.get("detail", "") for r in posture), [r.get("action") for r in got["audit"]]
    assert not any("a6-tls" in r.get("detail", "") for r in posture)
    assert "PLAINTEXT" in got["health"], got["health"]


def test_only_read_only_lines_reached_the_device(got):
    for log in got["sim_logs"]:
        out = subprocess.run([sys.executable, CHECK, "--log", log, "--register", REGISTER],
                             capture_output=True, text=True)
        report = json.loads(out.stdout)
        assert out.returncode == 0 and report["pass"], (log, report)
