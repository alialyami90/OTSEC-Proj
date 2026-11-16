"""GT-PCAP's false-positive set, built once for HR-23's and HR-25's counted runs (D6, brief P4-4-HR2325S, deliverable 1).

HR-23's design (docs/phase4/D4-hr23-design.md section 4.3, "The UDP
false-positive set") names the UDP classes (1) to (5), and HR-25's pinned
rows fp-* of resync-conditions.tsv add class (6), non-DNP3 TCP flows on
tcp/20000, with the floors and the redraw rule (fp-redraw) both runs use.
One generator serves both (D4-111 item 5.2), so the set is built here once,
and hr23-conditions.tsv states HR-23's bounds on it.

Every item is on its own 5-tuple, and every class is one capture. The label
of each item is how it was built: its class, its datagrams or streams, the
offset of the one header it was built to hold, its function code and side
where it has one, and how many draws the redraw rule took. Nothing here comes
from an engine, and tshark's reading is reported beside it by hr23_tshark.py.

The redraw rule (fp-redraw, made exact here): every generator computes the
DNP3 header CRC at every offset of every datagram, and of each end's stream
and each run of it between holes over TCP, where 05 64 occurs with 8 more
octets after it, and draws the item again when one passes at an offset the
class does not name. A class (4) item is drawn again by changing a field
outside its first two octets that keeps it valid for its protocol: the flags
of a DNS, NetBIOS or LLMNR query, the authenticator of a RADIUS response.

Stdlib only. Nothing here sends a packet. Addresses are TEST-NET-1, and the
one multicast group is LLMNR's own. Evidence class: simulated.

Usage: python fp_set.py OUTDIR   (writes <capture>.pcap and <capture>.tsv
for every class, and fp.sha256)
"""

import hashlib
import os
import struct
import sys

import dnp3
import pcapfile
import synth

# The two ends of every item. The client sends first; its port is the item's own.
CLIENT_IP, CLIENT_MAC = "192.0.2.100", "02:00:00:00:00:64"
SERVER_IP, SERVER_MAC = "192.0.2.200", "02:00:00:00:00:c8"
LLMNR_IP, LLMNR_MAC = "224.0.0.252", "01:00:5e:00:00:fc"   # RFC 4795's group

T_BASE = 1_763_300_000_000_000_000   # the first class's clock, 2025-11-16T13:33:20Z (a choice)
CLASS_SPACING = 3_600_000_000_000    # one hour between classes' clocks
UDP_ITEM_NS = 10_000_000             # 10 ms between UDP items
TCP_ITEM_NS = 100_000_000            # 100 ms between TCP flows

# HR-25's rows (resync-conditions.tsv): val-O and the floors fp-1-floor to fp-6-hole-floor.
O_BUDGET = 2048
O_MARGIN = 32         # class (6) totals keep this far from O, so a held partial candidate cannot move the label
MSS = 1460

# arm-3bdata (resync-conditions.tsv): DNP3_Request's empty arms, and the codes of its default arm used here.
EMPTY_ARM = (0, 13, 14, 15, 19, 23, 24)
DEFAULT_ARM = (34, 40, 50, 60, 64, 70, 80, 90, 100, 110, 120, 128, 132, 140, 160, 180, 200, 220, 240, 250, 255)
# Codes whose request arm parses objects (arm-3bdata's (3c) list).
OBJECT_ARM = tuple(range(1, 13)) + (16, 17, 18, 20, 21, 22) + tuple(range(25, 34))
# Link status request, link status, reset link states, ACK, and test link states with FCV set, as it is sent
# (D2's N1 on #718; IEEE 1815 not held, inference).
LINK_ONLY = (0xC9, 0x0B, 0xC0, 0x00, 0xD2)


# --- deterministic draws ---------------------------------------------------

class Draw:
    """Octets and integers from SHA-256 in counter mode over a label: the
    same on every run and every Python."""

    def __init__(self, label):
        self.label, self.i, self.buf = label, 0, b""

    def octets(self, n):
        while len(self.buf) < n:
            self.buf += hashlib.sha256(f"{self.label}:{self.i}".encode()).digest()
            self.i += 1
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def below(self, n):
        """An integer in [0, n), by rejection on 32 bits."""
        limit = (1 << 32) - (1 << 32) % n
        while True:
            x = struct.unpack(">I", self.octets(4))[0]
            if x < limit:
                return x % n

    def between(self, a, b):
        return a + self.below(b - a + 1)

    def no05(self, n):
        """n octets with no 05 octet, so no 05 64 anywhere in them."""
        out = bytearray()
        while len(out) < n:
            out += bytes(b for b in self.octets(n) if b != 0x05)
        return bytes(out[:n])


def passing_headers(buf):
    """Every offset at which 05 64 starts a 10-octet header whose CRC passes,
    whatever its length octet (stricter than a candidate)."""
    out, i = [], buf.find(b"\x05\x64")
    while i >= 0:
        if i + 10 <= len(buf) and dnp3.crc(buf[i:i + 8]) == buf[i + 8:i + 10]:
            out.append(i)
        i = buf.find(b"\x05\x64", i + 1)
    return out


def frame(ctrl, dest, src, user, chunk_crc_ok=True, draw=None):
    """A link frame of user data with a passing header CRC. With chunk_crc_ok
    false, every chunk CRC is drawn so that it fails."""
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5 + len(user), ctrl, dest, src)
    out = hdr + dnp3.crc(hdr)
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        good = dnp3.crc(blk)
        c = good
        while not chunk_crc_ok and c == good:
            c = draw.octets(2)
        out += blk + c
    return out


# --- the items --------------------------------------------------------------

class Item:
    """One item: its datagrams (UDP) or its two streams (TCP), the offsets
    the class names in each datagram, and the label's facts."""

    def __init__(self, cls, k, sport, dport, dst_ip=SERVER_IP, dst_mac=SERVER_MAC, server_first=False):
        self.cls, self.k, self.sport, self.dport = cls, k, sport, dport
        self.dst_ip, self.dst_mac, self.server_first = dst_ip, dst_mac, server_first
        self.datagrams, self.named = [], []
        self.code, self.side, self.dir, self.facts, self.draws = "-", "-", "-", "-", 0
        self.streams = None   # TCP: {"c": [segments], "s": [segments]}, each segment (octets, lost)


def udp_item_ok(it):
    return all(set(passing_headers(d)) <= set(n) for d, n in zip(it.datagrams, it.named))


def drawn(gen, cls, k):
    """The item, drawn again until the redraw rule passes. A generator
    returns None for a draw its own class rule refuses."""
    d = 0
    while True:
        it = gen(k, Draw(f"fp:{cls}:{k}:{d}"), d)
        if it is not None and (udp_item_ok(it) if it.streams is None else tcp_item_ok(it)):
            it.draws = d
            return it
        d += 1


def port(cls_index, k):
    return 50000 + 1000 * cls_index + k


def class1(k, D, d):
    """05 64 and 0 to 8 more octets (fp-1-floor: at least 33 of each length)."""
    it = Item("1", k, port(0, k), 40001)
    more = k % 9
    it.datagrams, it.named = [b"\x05\x64" + D.octets(more)], [()]
    it.facts = f"more={more}"
    return it


def class2(k, D, d):
    """A header CRC that fails, in a datagram of 11 to 1,472 octets (fp-2-floor)."""
    it = Item("2", k, port(1, k), 40002)
    n = 11 if k == 0 else 1472 if k == 1 else D.between(11, 1472)
    six = D.octets(6)
    good = dnp3.crc(b"\x05\x64" + six)
    bad = good
    while bad == good:
        bad = D.octets(2)
    it.datagrams, it.named = [b"\x05\x64" + six + bad + D.octets(n - 10)], [()]
    it.facts = "header_crc=fails"
    return it


def class3a(k, D, d):
    """A header whose CRC passes, then non-DNP3 octets in the same datagram
    whose chunk CRCs fail. The transport octet has FIR and FIN, so the
    first chunk's CRC is what fails."""
    it = Item("3a", k, port(2, k), 40031)
    length = D.between(6, 255)
    user = bytes([0xC0 | D.below(64)]) + D.octets(length - 6)
    ctrl = (0x44, 0xC4)[k % 2]
    f = frame(ctrl, D.below(65536), D.below(65536), user, chunk_crc_ok=False, draw=D)
    it.datagrams, it.named = [f], [(0,)]
    it.dir = "1" if ctrl & 0x80 else "0"
    it.side = "orig"
    it.facts = f"link_length={length};chunk_crc=fails"
    return it


def class3b_data(k, D, d):
    """A whole frame with an application fragment and FIN, then a later
    datagram on the flow without the magic (arm-3bdata: an empty-arm code
    with 2 application octets, or a default-arm code with 2 or more)."""
    it = Item("3b-data", k, port(3, k), 40032)
    if k < 3 * len(EMPTY_ARM):
        code, extra = EMPTY_ARM[k % len(EMPTY_ARM)], b""
    else:
        code = DEFAULT_ARM[k - 3 * len(EMPTY_ARM)]
        extra = D.octets(D.between(0, 20))
    app = bytes([0xC0 | D.below(16), code]) + extra
    user = bytes([0xC0 | D.below(64)]) + app
    f = frame(0xC4, D.below(65536), D.below(65536), user)
    tail = D.no05(D.between(11, 200))
    it.datagrams, it.named = [f, tail], [(0,), ()]
    it.code, it.side, it.dir = str(code), "orig", "1"
    it.facts = f"app_octets={len(app)};arm={'empty' if code in EMPTY_ARM else 'default'}"
    return it


def class3b_link(k, D, d):
    """A link-only frame, then a later datagram without the magic, then a
    third of 11 octets or more without the magic."""
    it = Item("3b-link", k, port(4, k), 40033)
    ctrl = LINK_ONLY[k % len(LINK_ONLY)]
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5, ctrl, D.below(65536), D.below(65536))
    it.datagrams = [hdr + dnp3.crc(hdr), D.no05(D.between(1, 40)), D.no05(D.between(11, 200))]
    it.named = [(0,), (), ()]
    it.dir = "1" if ctrl & 0x80 else "0"
    it.side = "orig"
    it.facts = f"link_ctrl={ctrl:02X}h"
    return it


def class3c(k, D, d):
    """A whole frame with valid chunk CRCs whose application part is too
    short for its parser: a code whose request arm parses objects, with
    exactly 1 object octet (arm-3bdata)."""
    it = Item("3c", k, port(5, k), 40034)
    code = OBJECT_ARM[k % len(OBJECT_ARM)]
    app = bytes([0xC0 | D.below(16), code]) + D.octets(1)
    user = bytes([0xC0 | D.below(64)]) + app
    it.datagrams, it.named = [frame(0xC4, D.below(65536), D.below(65536), user)], [(0,)]
    it.code, it.side, it.dir = str(code), "orig", "1"
    it.facts = "app_octets=3;arm=objects"
    return it


DNS_FLAGS = (0x0100, 0x0000, 0x0110, 0x0120, 0x0010, 0x0020)
NBNS_FLAGS = (0x0110, 0x0100)
LLMNR_FLAGS = (0x0000, 0x0100)


def dns_name(*labels):
    return b"".join(bytes([len(x)]) + x for x in labels) + b"\x00"


def nbns_encode(name, suffix):
    """RFC 1001 first-level encoding: each nibble as 'A' plus its value."""
    raw = name.ljust(15)[:15].encode() + bytes([suffix])
    enc = bytearray()
    for c in raw:
        enc += bytes([0x41 + (c >> 4), 0x41 + (c & 0x0F)])
    return b"\x20" + bytes(enc) + b"\x00"


def class4(k, D, d):
    """Real UDP protocols whose first two octets are free and can be 05 64:
    DNS, NetBIOS name service and LLMNR queries with ID 0564h, and RADIUS
    Accounting-Responses (code 5, identifier 64h), 76 of each. A draw that
    fails the redraw rule changes the flags or the authenticator."""
    proto = ("dns", "nbns", "llmnr", "radius")[k // 76]
    j = k % 76
    hdr = lambda flags: struct.pack(">HHHHHH", 0x0564, flags, 1, 0, 0, 0)
    if proto == "dns":
        it = Item("4", k, port(6, k), 53)
        q = dns_name(b"q%d" % j, b"gt-pcap", b"example") + struct.pack(">HH", (1, 28, 16, 15)[j % 4], 1)
        it.datagrams = [hdr(DNS_FLAGS[d % len(DNS_FLAGS)]) + q]
    elif proto == "nbns":
        it = Item("4", k, port(6, k), 137)
        q = nbns_encode("GTPCAP%03d" % j, (0x00, 0x20)[j % 2]) + struct.pack(">HH", 0x0020, 1)
        it.datagrams = [hdr(NBNS_FLAGS[d % len(NBNS_FLAGS)]) + q]
    elif proto == "llmnr":
        it = Item("4", k, port(6, k), 5355, dst_ip=LLMNR_IP, dst_mac=LLMNR_MAC)
        q = dns_name(b"gtpcap%d" % j) + struct.pack(">HH", (1, 28)[j % 2], 1)
        it.datagrams = [hdr(LLMNR_FLAGS[d % len(LLMNR_FLAGS)]) + q]
    else:
        # The server's response, from 1813 to the client's port: the client is the server here.
        it = Item("4", k, 1813, port(6, k), server_first=True)
        it.datagrams = [struct.pack(">BBH", 5, 0x64, 20) + D.octets(16)]
    if proto != "radius" and d >= 6:
        raise AssertionError(f"class (4) {proto} item {j}: no flags left to draw")
    it.named = [()]
    it.facts = f"proto={proto}"
    return it


def ntp(D):
    return bytes([0x23, 0x00, 0x06, 0xEC]) + bytes(36) + D.octets(8)


def syslog(j, D):
    t = D.below(3600)
    return ("<134>1 2025-11-16T%02d:%02d:%02d.%03dZ gt-host-%03d gtapp %d - - message %d"
            % (10 + t // 3600, (t // 60) % 60, t % 60, D.below(1000), j, 1000 + D.below(9000), j)).encode()


def snmp(D):
    """An SNMPv2c GetRequest for sysDescr.0, with a test community string."""
    community = b"gtpcap-test"
    varbind = b"\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00"
    pdu_body = b"\x02\x04" + D.octets(4) + b"\x02\x01\x00\x02\x01\x00" + b"\x30" + bytes([len(varbind)]) + varbind
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    body = b"\x02\x01\x01\x04" + bytes([len(community)]) + community + pdu
    return b"\x30" + bytes([len(body)]) + body


def class5(k, D, d):
    """Random payloads forced to start 05 64, and NTP, Syslog and SNMP
    payloads forced to start that way, 76 of each."""
    kind = ("random", "ntp", "syslog", "snmp")[k // 76]
    j = k % 76
    if kind == "random":
        it = Item("5", k, port(7, k), 40005)
        body = D.octets(D.between(11, 1472))
    elif kind == "ntp":
        it = Item("5", k, port(7, k), 123)
        body = ntp(D)
    elif kind == "syslog":
        it = Item("5", k, port(7, k), 514)
        body = syslog(j, D)
    else:
        it = Item("5", k, port(7, k), 161)
        body = snmp(D)
    it.datagrams, it.named = [b"\x05\x64" + body[2:]], [()]
    it.facts = f"kind={kind}"
    return it


# --- class (6): non-DNP3 TCP flows on tcp/20000 ----------------------------

# Map any octet to a lower-case letter, for text bodies.
TEXT = bytes(0x61 + (b % 26) for b in range(256))


def http(n, client, D):
    """A request with a padding header, or a response whose Content-Length
    is its body's, cut to n octets where n is shorter than the head."""
    if client:
        head = b"GET /gt/%d HTTP/1.1\r\nHost: gt-pcap.invalid\r\nUser-Agent: gtpcap\r\nX-Pad: " % D.below(10000)
        pad = D.octets(max(0, n - len(head) - 4)).translate(TEXT)
        return (head + pad + b"\r\n\r\n")[:n]
    body_len = n
    for _ in range(3):
        head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % body_len
        body_len = max(0, n - len(head))
    return (head + D.octets(body_len).translate(TEXT))[:n]


def tls(n, client, D):
    out = b""
    first = b"\x16\x03\x01" if client else b"\x16\x03\x03"
    while len(out) < n:
        body = D.octets(D.between(40, 600))
        out += (first if not out else b"\x17\x03\x03") + struct.pack(">H", len(body)) + body
    return out[:n]


def ssh(n, client, D):
    banner = b"SSH-2.0-gtpcap_%s_%d\r\n" % (b"c" if client else b"s", D.below(1000))
    return (banner + D.octets(n))[:n]


def rand(n, client, D):
    first = D.octets(1)
    while first == b"\x05":
        first = D.octets(1)
    return first + D.octets(n - 1)


KINDS6 = (("http", http), ("tls", tls), ("ssh", ssh), ("random", rand))


def runs_of(segs):
    """Each run of a stream between holes."""
    out, cur = [], b""
    for data, lost in segs:
        if lost:
            out.append(cur)
            cur = b""
        else:
            cur += data
    return out + [cur]


def tcp_item_ok(it):
    for segs in it.streams.values():
        whole = b"".join(s for s, _ in segs)
        if passing_headers(whole) or any(passing_headers(r) for r in runs_of(segs)):
            return False
    return True


def split(stream, size):
    return [stream[i:i + size] for i in range(0, len(stream), size)]


def class6(hole):
    """HTTP/1.1 text, TLS-shaped records, an SSH banner then random octets,
    or random octets, 50 to 5,000 per end (fp-6-floor), an even flow at
    most 1,000 per end so that about half stay under O. With hole, one middle segment of
    one end is lost and the peer's ACK past it kept (judge-r3). A flow's
    label says whether its delivered octets reach O: totals within
    O_MARGIN of O are drawn again, so the label holds whatever a held
    partial candidate does at an end."""
    def gen(k, D, d):
        name, fn = KINDS6[k % 4]
        it = Item("6-hole" if hole else "6", k, port(9 if hole else 8, k), 20000)
        # Even flows stay under O (at most 1,000 an end); odd ones draw up to 5,000 an end.
        top = 1000 if k % 2 == 0 else 5000
        nc, ns = D.between(50, top), D.between(50, top)
        c, s = fn(nc, True, D), fn(ns, False, D)
        streams = {"c": [(x, False) for x in split(c, MSS)], "s": [(x, False) for x in split(s, MSS)]}
        hole_end = "-"
        if hole:
            hole_end = "cs"[k % 2]
            data = c if hole_end == "c" else s
            a, b = len(data) // 3, 2 * len(data) // 3
            streams[hole_end] = [(data[:a], False), (data[a:b], True), (data[b:], False)]
        it.streams = streams
        delivered = sum(len(x) for segs in streams.values() for x, lost in segs if not lost)
        if abs(delivered - O_BUDGET) < O_MARGIN:
            return None
        lost =sum(len(x) for segs in streams.values() for x, l in segs if l)
        it.facts = (f"kind={name};octets=c:{nc},s:{ns};delivered={delivered};hole={hole_end}"
                    + (f":{lost}" if hole else "") + f";reaches={'O' if delivered >= O_BUDGET else 'none'}")
        it.side = "orig"
        return it
    return gen


# The classes, in order: (capture, class, generator, count, l4).
CLASSES = [
    ("fp-udp-1", "1", class1, 306, "udp"),
    ("fp-udp-2", "2", class2, 300, "udp"),
    ("fp-udp-3a", "3a", class3a, 32, "udp"),
    ("fp-udp-3b-data", "3b-data", class3b_data, 3 * len(EMPTY_ARM) + len(DEFAULT_ARM), "udp"),
    ("fp-udp-3b-link", "3b-link", class3b_link, 32, "udp"),
    ("fp-udp-3c", "3c", class3c, 2 * len(OBJECT_ARM), "udp"),
    ("fp-udp-4", "4", class4, 4 * 76, "udp"),
    ("fp-udp-5", "5", class5, 4 * 76, "udp"),
    ("fp-tcp-6", "6", class6(False), 104, "tcp"),
    ("fp-tcp-6-hole", "6-hole", class6(True), 32, "tcp"),
]


# --- the captures and labels -------------------------------------------------

class Built:
    def __init__(self, name, cls, l4, index):
        self.name, self.cls, self.l4 = name, cls, l4
        self.t0 = T_BASE + index * CLASS_SPACING
        self.items, self.frames, self.packets = [], [], {}


def build_udp(b, it, start):
    client = synth.Host(CLIENT_MAC, CLIENT_IP, it.sport)
    server = synth.Host(it.dst_mac, it.dst_ip, it.dport)
    if it.server_first:
        client, server = synth.Host(SERVER_MAC, SERVER_IP, it.sport), synth.Host(CLIENT_MAC, CLIENT_IP, it.dport)
    conv = synth.UDPConv(client, server, synth.Clock(start_ns=start), ident=1 + it.k)
    for d in it.datagrams:
        conv.send(True, d)
    return conv.frames


def build_tcp(b, it, start):
    client = synth.Host(CLIENT_MAC, CLIENT_IP, it.sport)
    server = synth.Host(SERVER_MAC, SERVER_IP, it.dport)
    conv = synth.TCPConv(client, server, synth.Clock(start_ns=start), isn_c=1000, isn_s=51000, ident=1 + it.k)
    conv.handshake()
    for end in ("c", "s"):
        for data, lost in it.streams[end]:
            out = conv.send(end == "c", data)
            if lost:
                conv.frames.remove(out[0])
    conv.close()
    return conv.frames


def built():
    out = []
    for index, (name, cls, gen, count, l4) in enumerate(CLASSES):
        b = Built(name, cls, l4, index)
        for k in range(count):
            it = drawn(gen, cls, k)
            start = b.t0 + k * (UDP_ITEM_NS if l4 == "udp" else TCP_ITEM_NS)
            frames = (build_udp if l4 == "udp" else build_tcp)(b, it, start)
            b.packets[k] = (len(b.frames) + 1, len(b.frames) + len(frames))
            b.frames += frames
            b.items.append(it)
        out.append(b)
    return out


COLUMNS = ["capture", "class", "item", "l4", "src", "sport", "dst", "dport", "packets", "datagrams", "header_at",
           "code", "side", "dir", "draws", "facts"]


def label_rows(b):
    rows = []
    for it in b.items:
        a, z = b.packets[it.k]
        src, sport, dst, dport = CLIENT_IP, it.sport, it.dst_ip, it.dport
        if it.server_first:
            src, dst = SERVER_IP, CLIENT_IP
        if it.streams is None:
            sizes = ",".join(str(len(d)) for d in it.datagrams)
            at = ",".join("/".join(str(x) for x in n) or "-" for n in it.named)
        else:
            sizes = ";".join(f"{e}:" + "+".join(f"({len(x)})" if lost else str(len(x)) for x, lost in it.streams[e])
                             for e in ("c", "s"))
            at = "-"
        rows.append([b.name, b.cls, str(it.k), b.l4, src, str(sport), dst, str(dport), f"{a}-{z}", sizes, at,
                     it.code, it.side, it.dir, str(it.draws), it.facts])
    return rows


def header(b):
    return [
        f"# GT-PCAP labels for {b.name}: the false-positive set's class ({b.cls}) (D6, brief P4-4-HR2325S, deliverable 1). "
        "The builder's, from how each item was made; tshark's reading is reported beside them by hr23_tshark.py, "
        "never used as a label.",
        "# one row per item, each on its own 5-tuple: src is the first sender. packets: the item's 1-based packet "
        "numbers. datagrams: the octets of each datagram, or for TCP each end's segments, c the client's and s the "
        "server's, a lost one in parentheses (its ACK is kept).",
        "# header_at: per datagram, the offsets at which the item was built to hold a header whose CRC passes; - for "
        "none. No other offset holds one (the redraw rule; draws counts the draws it took).",
        "# code and side: the function code a class (3b-data) or (3c) item's fragment carries, and the side it is "
        "sent from (orig: the first sender, by the design's section 1 item 1 with C0's likely_server_ports). dir: the "
        "link header's DIR bit as built.",
        "\t".join(COLUMNS),
    ]


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    sums = []
    for b in built():
        path = os.path.join(outdir, b.name + ".pcap")
        pcapfile.write(path, b.frames)
        with open(path, "rb") as f:
            sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {b.name}.pcap")
        with open(os.path.join(outdir, b.name + ".tsv"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(header(b) + ["\t".join(r) for r in label_rows(b)]) + "\n")
    with open(os.path.join(outdir, "fp.sha256"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sums) + "\n")
    print(f"fp_set: {len(sums)} captures")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
