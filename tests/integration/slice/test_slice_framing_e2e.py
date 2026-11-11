"""R4.1's last clause on the real binaries: malformed messages are stored
raw and flagged, never dropped (D6, P4-D6-H5).

The slice with three Syslog listeners on the node: syslog-tcp (RFC 6587,
plaintext), syslog-tls (RFC 5425, sender certificate required) and
syslog-udp. Test sockets bound to 127.0.0.2, the asset's sender address,
send to each. The upstream collector is a stock rsyslog (rsyslogrun.py).

On each stream listener, in this order, on one connection:
  1. an RFC 5424 message, LF-framed;
  2. a line 808 octets over the listener's 8192-octet frame limit;
  3. an RFC 3164 message, LF-framed;
  4. a mis-framed message: an octet count followed by no space;
  5. a message with no PRI, which is neither RFC 3164 nor RFC 5424;
  6. a message whose PRI is out of range, octet-counted;
  7. an RFC 5424 message, octet-counted;
  8. an octet count above the frame limit, with its message;
then on a second connection:
  9. an RFC 3164 message, LF-framed;
  10. an octet-counted message cut short by the end of the connection.
On UDP: an RFC 5424 datagram, one with no PRI, one with a PRI out of
range, and an RFC 3164 datagram.

The oracle is the bytes the test sent. What must hold is read from the
node's store, directly: the syslog database and its write-ahead log are
copied after the node is SIGKILLed, and the copy is opened with Python's
sqlite3. For each listener's stream the store must hold exactly the
messages sent, in the order sent, so no message before or after a fault
was lost:
  - a well-formed message: its bytes, no flag, parse status ok;
  - 2 and 8: the first 8192 octets, flag frame-truncated;
  - 10: the octets that arrived, flag frame-truncated;
  - 4: its octets up to the LF, flag frame-invalid;
  - 5 and 6, and the two UDP datagrams: their bytes, parse status failed.
A frame fault's parse status is not ok. The flags and the limit are the
listener's documented ones (modules/telemetry/receive, package doc;
docs/phase3/A4-syslog-receive.md).

The same is then read from the file rsyslog wrote: each event forwarded
with the hash and length of those bytes, its flags and its parse status,
so the flag reaches the upstream collector too.

Evidence class: simulated. The senders are test sockets on loopback: no
device fixture exists. Linux only: rsyslog does not run on Windows.
"""

import base64
import hashlib
import json
import os
import shutil
import socket
import sqlite3
import ssl
import time

import pytest

import harness
import reconcile
from conftest import need
from rsyslogrun import (  # noqa: F401  the checks every rsyslog leg makes
    RsyslogSlice, test_rsyslog_reads_every_message_as_rfc5424, test_the_upstream_is_a_stock_rsyslog)
from test_slice_interruptions_e2e import test_only_read_only_lines_reached_any_device  # noqa: F401

DEVICE = "127.0.0.2"
MAX = 8192  # the stream listeners' frame limit
TRUNCATED, INVALID = "frame-truncated", "frame-invalid"
STREAMS = {"tcp": "syslog/a6-tcp", "tls": "syslog/a6-tls", "udp": "syslog/a6-udp"}


def _counted(m):
    return str(len(m)).encode() + b" " + m


def _stream_case(tag):
    """(the first connection's bytes, the second's, what the store must
    hold in order) for a stream listener. Each entry of the last is
    (stored bytes, flags, parse status), the status "not ok" for a frame
    fault."""
    t = tag.encode()
    first5424 = b"<165>1 2026-11-11T12:00:00.123456Z sel751-d6 app 1 ID1 - " + t + b" RFC 5424, before the faults"
    long_line = b"<13>" + t + b" a line over the frame limit " + b"L" * (MAX + 808)
    after_long = b"<14>Nov 11 12:00:01 sel751-d6 app: " + t + b" RFC 3164, after the over-long line"
    misframed = b"17x<13>" + t + b" an octet count with no space after it"
    no_pri = t + b" no PRI: neither RFC 3164 nor RFC 5424"
    bad_pri = b"<999>" + t + b" a PRI out of range"
    counted = b"<165>1 2026-11-11T12:00:02Z sel751-d6 app 1 ID2 - " + t + b" RFC 5424, octet-counted, after the faults"
    over_count = b"<13>" + t + b" an octet count above the frame limit " + b"C" * (MAX + 808)
    new_conn = b"<14>Nov 11 12:00:03 sel751-d6 app: " + t + b" RFC 3164, on a new connection"
    cut = b"<13>" + t + b" cut short by the end of the connection"
    conn1 = b"".join([first5424 + b"\n", long_line + b"\n", after_long + b"\n", misframed + b"\n", no_pri + b"\n",
                      _counted(bad_pri), _counted(counted), _counted(over_count)])
    conn2 = new_conn + b"\n" + str(len(cut) + 100).encode() + b" " + cut
    want = [(first5424, [], "ok"), (long_line[:MAX], [TRUNCATED], "not ok"), (after_long, [], "ok"),
            (misframed, [INVALID], "not ok"), (no_pri, [], "failed"), (bad_pri, [], "failed"), (counted, [], "ok"),
            (over_count[:MAX], [TRUNCATED], "not ok"), (new_conn, [], "ok"), (cut, [TRUNCATED], "not ok")]
    return conn1, conn2, want


UDP = [(b"<165>1 2026-11-11T12:00:04Z sel751-d6 app 1 ID3 - udp RFC 5424, before", [], "ok"),
       (b"udp no PRI: neither RFC 3164 nor RFC 5424", [], "failed"),
       (b"<192>udp a PRI out of range", [], "failed"),
       (b"<14>Nov 11 12:00:05 sel751-d6 app: udp RFC 3164, after", [], "ok")]


def _connect(layout, tls):
    host, port = layout["syslog_tls" if tls else "syslog_tcp"].rsplit(":", 1)
    sock = socket.create_connection((host, int(port)), timeout=15, source_address=(DEVICE, 0))
    if not tls:
        return sock
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(layout["ca"])
    ctx.check_hostname = False
    ctx.load_cert_chain(layout["sender_cert"], layout["sender_key"])
    return ctx.wrap_socket(sock, server_hostname="127.0.0.1")


def _send_stream(layout, tls, conn1, conn2):
    """Sends the two connections. Returns whether the listener closed the
    first after the octet count above its limit."""
    sock = _connect(layout, tls)
    try:
        sock.sendall(conn1)
        closed = sock.recv(1) == b""
    except TimeoutError:
        closed = False
    except OSError:  # a reset, or TLS torn down: closed by the listener
        closed = True
    finally:
        sock.close()
    sock = _connect(layout, tls)
    try:
        sock.sendall(conn2)
        time.sleep(0.5)  # let the listener read before the end
        if tls:
            try:
                sock.unwrap()
            except OSError:
                pass
        else:
            sock.shutdown(socket.SHUT_WR)
    finally:
        sock.close()
    return closed


def _send_udp(layout, msgs):
    host, port = layout["syslog_udp"].rsplit(":", 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((DEVICE, 0))
    try:
        for m in msgs:
            s.sendto(m, (host, int(port)))
            time.sleep(0.05)
    finally:
        s.close()


def _forwarded(s):
    """{stream: {seq: params}} of the listener streams, from the file
    rsyslog wrote. A message D6's parser cannot read is left to
    test_rsyslog_reads_every_message_as_rfc5424."""
    out = {}
    for m in s.received():
        try:
            ps = reconcile.parse_rfc5424(m)["sd"].get(reconcile.SDID, [])
        except ValueError:
            continue
        _, _, rest = (reconcile.first(ps, "eid") or "").partition(":")
        stream, _, seq = rest.rpartition(":")
        if stream in STREAMS.values():
            out.setdefault(stream, {})[int(seq)] = ps
    return out


def _stored(path, stream):
    db = sqlite3.connect(path)
    try:
        return [(seq, json.loads(ev)) for seq, ev in
                db.execute("SELECT seq, event FROM events WHERE stream = ? ORDER BY seq", (stream,))]
    finally:
        db.close()


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    need(os.name != "nt", "rsyslog does not run on Windows")
    need(harness.rsyslogd() and harness.imrelp(), "rsyslogd with imrelp not installed (rsyslog and rsyslog-relp)")
    s = RsyslogSlice(str(tmp_path_factory.mktemp("slice-framing")))
    s.build()
    udp, tcp, tls = harness.free_port(), harness.free_port(), harness.free_port()
    try:
        s.start(setup_extra=("-syslog-udp", str(udp), "-syslog-tcp", str(tcp), "-syslog-tls", str(tls)))
        up = lambda: all(f"listener a6-{name}" in s.health() for name in STREAMS)
        assert harness.wait_for(up, 60, step=1.0), s.health() + s.text("node")
        s.want, s.closed = {"udp": UDP}, {}
        for name in ("tcp", "tls"):
            conn1, conn2, s.want[name] = _stream_case(name)
            s.closed[name] = _send_stream(s.layout, name == "tls", conn1, conn2)
        _send_udp(s.layout, [m for m, _, _ in UDP])
        # Forwarded: every message sent is in rsyslog's file. A message that
        # was lost would hold this until the timeout; the checks below then
        # say which.
        s.arrived = harness.wait_for(
            lambda: all(len(_forwarded(s).get(STREAMS[k], {})) >= len(v) for k, v in s.want.items()), 90, step=1.0)
        time.sleep(3)
        s.health_text = s.health()
        s.kill("node")
        s.store = s.store_copy("syslog", "store-syslog")
        yield s
    finally:
        s.stop()


def _problems(name, got, want):
    """got: [(seq, bytes or None, sha256, length, flags, parse status)] in
    seq order. bytes is None where the view does not carry them."""
    problems = []
    if [g[0] for g in got] != list(range(1, len(want) + 1)):
        problems.append(f"{name}: events {[g[0] for g in got]}, want 1 to {len(want)}")
    for (seq, data, sha, length, flags, status), (sent, wflags, wstatus) in zip(got, want):
        what = f"{name} event {seq} ({sent[:60]!r})"
        if data is not None and data != sent:
            problems.append(f"{what}: holds {data[:60]!r}, {len(data)} octets, want {len(sent)}")
        if sha != hashlib.sha256(sent).hexdigest() or int(length) != len(sent):
            problems.append(f"{what}: hash or length {length} is not that of the {len(sent)} octets sent")
        if flags != wflags:
            problems.append(f"{what}: flags {flags}, want {wflags}")
        if status != wstatus and not (wstatus == "not ok" and status in ("partial", "failed")):
            problems.append(f"{what}: parse status {status!r}, want {wstatus}")
    return problems


def test_the_store_holds_every_message_raw_and_flagged(run, capsys):
    problems = []
    counts = {}
    for name, want in run.want.items():
        got = []
        for seq, ev in _stored(run.store, STREAMS[name]):
            n = ev.get("native", {})
            got.append((seq, base64.b64decode(n.get("bytes", "")), n.get("record_sha256"), n.get("record_length", -1),
                        ev.get("flags", []), ev.get("collection", {}).get("parse_status")))
            if ev.get("source", {}).get("sender", {}).get("address") != DEVICE:
                problems.append(f"{name} event {seq}: sender {ev.get('source', {}).get('sender')}")
        counts[name] = len(got)
        problems += _problems(name, got, want)
    with capsys.disabled():
        print(f"\nstored events by listener: {counts}; the listener closed the connection after the octet count "
              f"above its limit: {run.closed}")
    assert problems == [], problems


def test_rsyslogs_file_holds_every_message_with_its_flags(run):
    assert run.arrived, f"not every message was forwarded in 90 s\n{run.health_text}"
    fwd = _forwarded(run)
    problems = []
    for name, want in run.want.items():
        got = []
        for seq, ps in sorted(fwd.get(STREAMS[name], {}).items()):
            text = reconcile.first(ps, "dtext")
            b64 = reconcile.first(ps, "dtext_b64")
            data = text.encode("utf-8") if text is not None else base64.b64decode(b64) if b64 is not None else None
            got.append((seq, data, reconcile.first(ps, "rsha256"), reconcile.first(ps, "rlen") or -1,
                        [v for n, v in ps if n == "flag"], reconcile.first(ps, "parse")))
        problems += _problems(name, got, want)
    assert problems == [], problems


def test_the_check_fails_on_a_lost_flag_a_lost_message_and_other_bytes():
    """_problems on views made here, each broken in one way. No slice
    runs."""
    _, _, want = _stream_case("tcp")
    status = {"ok": "ok", "failed": "failed", "not ok": "partial"}
    good = [(i + 1, sent, hashlib.sha256(sent).hexdigest(), len(sent), flags, status[st])
            for i, (sent, flags, st) in enumerate(want)]
    assert _problems("tcp", good, want) == []

    def one(i, **changed):
        g = dict(zip(("seq", "data", "sha", "length", "flags", "status"), good[i]), **changed)
        return _problems("tcp", good[:i] + [tuple(g.values())] + good[i + 1:], want)

    # The over-long line, the octet count with no space and the cut frame,
    # each kept without its flag; and a fault read as ok.
    assert len(one(1, flags=[])) == 1 and len(one(3, flags=[])) == 1 and len(one(9, flags=[])) == 1
    assert len(one(1, status="ok")) == 1
    # A message with no PRI that is not marked failed, and a good message
    # that is flagged.
    assert len(one(4, status="ok")) == 1 and len(one(4, status="partial")) == 1
    assert len(one(0, flags=[TRUNCATED])) == 1 and len(one(0, status="partial")) == 1
    # Other bytes under the right hash, and the over-long line kept whole.
    assert len(one(2, data=good[2][1] + b"x")) == 1
    long_line = want[1][0] + b"L" * 808
    assert len(one(1, data=long_line, sha=hashlib.sha256(long_line).hexdigest(), length=len(long_line))) == 2
    # The message after the over-long line lost: the later events move up.
    lost = good[:2] + [(seq - 1, *rest) for seq, *rest in good[3:]]
    assert _problems("tcp", lost, want)
    assert _problems("tcp", good[:-1], want) and _problems("tcp", [], want)
