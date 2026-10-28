"""Unknown senders fill their class across an upstream outage, on the real
binaries (B6; HR-11's open condition after C5 0.4, #291 and #296).

Run twice, once for each kind of listener: a syslog-udp listener (datagrams)
and a syslog-tls listener (a stream; the sender certificate the run's CA
issued, so the stranger is told apart by address alone). Each slice has its
syslog-unknown class quota set to 256 KiB (under the listener's hourly
unknown budget, so the class fills before the budget runs out; over TLS each
message costs the budget more, and the budget may stop the stranger after the
class has filled).
The upstream RELP receiver is killed first: nothing the node stores can be
confirmed, so nothing is pruned and every byte the stranger stores stays.
Then, during the outage:
  - a host no asset claims (127.0.0.3) floods the listener at 60 messages a
    second, under the per-sender rate, until the listener has dropped at
    least 50 of them as unknown-full (over TLS, on one connection, which
    the listener keeps reading at the quota);
  - the SEL-751's address (127.0.0.2) sends 300 short messages over the
    same time, under its rate (over TLS, on one connection of its own).
Then the receiver comes back.

What must hold (HR-11):
  - the syslog-unknown class never holds more than its quota: sampled from
    the store's own class_bytes throughout, and at the end;
  - the class fills: the listener counts unknown-full, and the store raises
    syslog-unknown-full;
  - every one of the device's 300 datagrams is stored during the outage, in
    the listener's own stream (syslog/a6-udp or syslog/a6-tls), and the
    listener drops nothing
    of the device's: its only drop reasons are the stranger's (unknown-full,
    unknown-budget, and unknown-queue-full, D4-21's share of the queue, which
    a brief store stall can reach on a slow disk; queue-full, which would
    fall on the device too, is not one of them);
  - once the receiver is back, the device's 300 arrive upstream, each once
    by event ID, in the order sent, with the bytes sent; and every unknown
    record the node stored arrives too, so the fill lost nothing that was
    stored.

The oracle is the store read with sqlite and the receiver's log, not the
node's own counters, except for the drop reasons, which only the listener
knows.

Evidence class: simulated (loopback senders, simulated upstream outage).
A TCP listener without TLS is not run: the slice's setup offers syslog-udp
and syslog-tls, and the stream path past the handshake is the same.
"""

import base64
import json
import os
import shutil
import socket
import sqlite3
import ssl
import threading
import time

import pytest

import harness
from conftest import need
from reconcile import first, parse_rfc5424
from slicerun import Slice, read_live

DEVICE, STRANGER = "127.0.0.2", "127.0.0.3"
QUOTA = 256 << 10   # the syslog-unknown class
KNOWN = 300         # the device's datagrams during the outage
FULL = 50           # unknown-full drops that show the class stayed full
MSG = 900           # bytes of message text per stranger message
RATE = 60           # stranger messages a second, under the per-sender rate (100)
# The listener's drop reasons that fall only on a sender no asset claims.
STRANGER_DROPS = {"unknown-full", "unknown-budget", "unknown-queue-full"}


def _status(s):
    return json.loads(read_live(os.path.join(s.layout["store_dir"], "status.json")))


def _listener(s, kind):
    return (_status(s).get("listeners") or {}).get("a6-" + kind) or {}


def _db(s):
    return os.path.join(s.layout["store_dir"], "syslog.db")


def _class_bytes(s):
    db = sqlite3.connect(f"file:{_db(s)}?mode=ro", uri=True)
    try:
        row = db.execute("SELECT bytes FROM class_bytes WHERE class = 'syslog-unknown'").fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0
    finally:
        db.close()


def _texts(s, stream):
    """The native text of each event of stream, in seq order."""
    db = sqlite3.connect(f"file:{_db(s)}?mode=ro", uri=True)
    try:
        rows = db.execute("SELECT seq, event FROM events WHERE stream = ? ORDER BY seq", (stream,)).fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        db.close()
    out = []
    for seq, ev in rows:
        e = json.loads(ev if isinstance(ev, bytes) else ev.encode("utf-8"))
        out.append((seq, _native_bytes(e)))
    return out


def _native_bytes(e):
    return base64.b64decode(e["native"]["bytes"])


def _forwarded(s, kind):
    """Upstream messages of the listener's two streams, by stream, keyed by
    seq (a resend after the outage has the same event ID): {seq: params}."""
    out = {"syslog/a6-" + kind: {}, "syslog-unknown/a6-" + kind: {}}
    for m in s.received():
        try:
            ps = parse_rfc5424(m)["sd"].get("otsec@32473", [])
        except ValueError:
            continue
        eid = first(ps, "eid") or ""
        if eid.count(":") < 2:
            continue
        _, stream, seq = eid.rsplit(":", 2)
        if stream in out:
            out[stream].setdefault(int(seq), []).append(ps)
    return out


def _dtext(ps):
    t = first(ps, "dtext")
    if t is not None:
        return t.encode("utf-8")
    b = first(ps, "dtext_b64")
    if b is not None:
        return base64.b64decode(b)
    return None


def _known(i):
    return f"<13>a6 fill known {i:05d}".encode()


class Sender:
    """One sender's messages to the listener, from src: datagrams on UDP,
    LF-framed on one TLS connection (reopened if the listener closes it)."""

    def __init__(self, s, kind, src):
        self.kind, self.src, self.layout = kind, src, s.layout
        self.host, port = s.layout["syslog_" + kind].rsplit(":", 1)
        self.port = int(port)
        self.conn = None
        self.reconnects = 0

    def _tls(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(self.layout["ca"])
        ctx.check_hostname = False
        ctx.load_cert_chain(self.layout["sender_cert"], self.layout["sender_key"])
        raw = socket.create_connection((self.host, self.port), timeout=10, source_address=(self.src, 0))
        return ctx.wrap_socket(raw, server_hostname="127.0.0.1")

    def send(self, msg):
        if self.kind == "udp":
            if self.conn is None:
                self.conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.conn.bind((self.src, 0))
            self.conn.sendto(msg, (self.host, self.port))
            return
        for attempt in range(2):
            try:
                if self.conn is None:
                    self.conn = self._tls()
                self.conn.sendall(msg + b"\n")
                return
            except (ssl.SSLError, OSError):
                self.close()
                self.reconnects += 1
                if attempt:
                    raise

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
            self.conn = None


class Flood:
    """Messages from the stranger at RATE a second until stopped."""

    def __init__(self, s, kind):
        self.sender = Sender(s, kind, STRANGER)
        self.sent = 0
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        try:
            while not self.stop.is_set():
                self.sender.send(f"<13>a6 fill stranger {self.sent:06d} ".encode() + b"u" * MSG)
                self.sent += 1
                time.sleep(1 / RATE)
        finally:
            # Let the listener read what was sent before closing.
            time.sleep(0.5)
            self.sender.close()

    def __enter__(self):
        self.t.start()
        return self

    def __exit__(self, *exc):
        self.stop.set()
        self.t.join(5)


def _device(s, kind, done, out):
    sender = Sender(s, kind, DEVICE)
    try:
        for i in range(KNOWN):
            sender.send(_known(i))
            time.sleep(1 / 50)
        time.sleep(0.5)
    finally:
        sender.close()
        out["device_reconnects"] = sender.reconnects
        done.set()


@pytest.fixture(scope="module", params=["udp", "tls"])
def got(request, tmp_path_factory):
    need(shutil.which("go"), "go not on PATH (needed to build the binaries)")
    kind = request.param
    if kind == "tls":
        need(shutil.which("openssl"), "openssl not on PATH (needed for the run's sender CA)")
    stream, unknown_stream = "syslog/a6-" + kind, "syslog-unknown/a6-" + kind
    s = Slice(str(tmp_path_factory.mktemp("slice-unknown-fill-" + kind)))
    s.build()
    port = harness.free_port()
    out = {"kind": kind, "stream": stream, "class_max": 0}
    listener = lambda: _listener(s, kind)
    try:
        s.start(setup_extra=("-syslog-" + kind, str(port), "-quota", f"syslog-unknown={QUOTA}"))
        assert harness.wait_for(lambda: listener().get("open") and (listener().get("unknown") or {}).get("hourly_bytes"),
                                60, step=0.5), _status(s)
        out["hourly"] = listener()["unknown"]["hourly_bytes"]

        # The outage: nothing is confirmed from here on, so nothing is pruned.
        s.kill("receiver")

        def sample():
            out["class_max"] = max(out["class_max"], _class_bytes(s))
            return out["class_max"]

        done = threading.Event()
        with Flood(s, kind) as f:
            dev = threading.Thread(target=_device, args=(s, kind, done, out), daemon=True)
            dev.start()
            # The class is full once the listener counts unknown-full
            # drops; the tests below say what failed if it never is.
            harness.wait_for(
                lambda: sample() >= 0 and done.is_set()
                and (listener().get("dropped") or {}).get("unknown-full", 0) >= FULL,
                180, step=0.5)
        out["flood_sent"] = f.sent
        out["stranger_reconnects"] = f.sender.reconnects
        dev.join(5)
        # The listener's status is published every 10 s; wait for one that
        # has every message sent counted as stored or dropped.
        sent = out["flood_sent"] + KNOWN
        harness.wait_for(lambda: sample() >= 0 and listener().get("received", 0) >= sent
                         and listener().get("stored", 0) + sum((listener().get("dropped") or {}).values()) >= sent,
                         60, step=1.0)
        sample()
        out["listener"] = listener()
        out["alarms"] = [a for a in _status(s).get("alarms") or [] if a.get("database") == "syslog"]
        out["class_end"] = _class_bytes(s)
        out["known_stored"] = _texts(s, stream)
        out["unknown_stored"] = _texts(s, unknown_stream)

        # Upstream back: everything stored is forwarded.
        s.start_receiver()
        want_unknown = {seq for seq, _ in out["unknown_stored"]}
        out["forwarded_all"] = harness.wait_for(
            lambda: len(_forwarded(s, kind)[stream]) >= KNOWN and want_unknown <= set(_forwarded(s, kind)[unknown_stream]),
            240, step=2.0)
        out["forwarded"] = _forwarded(s, kind)
        out["unknown_fwd"] = out["forwarded"][unknown_stream]
    finally:
        s.stop()
    print(json.dumps({k: v for k, v in out.items() if k not in ("known_stored", "unknown_stored", "forwarded", "unknown_fwd")},
                     indent=1, default=str))
    return out


def test_the_class_never_passes_its_quota(got):
    assert got["class_max"] <= QUOTA, got["class_max"]
    assert got["class_end"] <= QUOTA, got["class_end"]


def test_the_class_fills(got):
    # Not vacuous: the stranger was stopped by the class, not by the budget
    # or by a slow flood.
    assert got["hourly"] > 2 * QUOTA, got["hourly"]
    assert got["listener"]["dropped"].get("unknown-full", 0) >= FULL, got["listener"]
    # Not vacuous either way: everything the stranger sent was read.
    assert got["listener"]["received"] >= got["flood_sent"] + KNOWN, got["listener"]
    assert got["unknown_stored"], "the stranger stored nothing"
    assert any(a["code"] == "syslog-unknown-full" for a in got["alarms"]), got["alarms"]


def test_the_device_stores_every_datagram_during_the_outage(got):
    texts = [t for _, t in got["known_stored"]]
    assert texts == [_known(i) for i in range(KNOWN)], (len(texts), texts[:3], texts[-3:])
    # The listener dropped only the stranger's datagrams: unknown-queue-full
    # (D4-21) is the stranger's quarter of the queue, reached in a store stall
    # (F-016); queue-full would fall on the device too and fails here.
    assert set(got["listener"]["dropped"]) <= STRANGER_DROPS, got["listener"]["dropped"]
    # And stored none of the stranger's in the device's stream.
    assert not any(b"stranger" in t for t in texts)
    # Over TLS the device's one connection was never closed on it.
    assert got.get("device_reconnects", 0) == 0, got.get("device_reconnects")


def test_after_the_outage_everything_stored_is_forwarded(got):
    assert got["forwarded_all"], {k: len(v) for k, v in got["forwarded"].items()}
    fwd = got["forwarded"][got["stream"]]
    # Each of the device's events once by event ID, in the order sent, with
    # the bytes sent (a resend repeats an event ID with the same bytes).
    assert sorted(fwd) == [seq for seq, _ in got["known_stored"]], sorted(fwd)[:5]
    for i, seq in enumerate(sorted(fwd)):
        texts = {_dtext(ps) for ps in fwd[seq]}
        assert texts == {_known(i)}, (seq, texts)
    unknown = got["unknown_fwd"]
    for seq, text in got["unknown_stored"]:
        assert seq in unknown, seq
        assert {_dtext(ps) for ps in unknown[seq]} == {text}, seq
