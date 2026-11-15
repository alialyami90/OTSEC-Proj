"""GT-PCAP's dnp3-resync-* captures for HR-25's counted run (D6, brief P4-4-HR25, deliverable 3).

resync-cases.tsv pins 112 cases and the twins each names, and the builder-*
rows of resync-conditions.tsv pin how every message and every failure is
made (docs/phase4/D6-hr25-resync-conditions.md section 3). This file writes
every case and every twin, frame by frame, with dnp3.py and synth.py, and
the label of each capture: every link-layer unit as valid or as the failure
it carries, and every message as seen, absent or lost (row judge-labels).
The labels are the builder's, never tshark's: resync_tshark.py reports the
pinned tshark's reading beside them.

A build cell in the regular notation of section 3.1 is read token by token
(interpret below), so the cell itself is the build. The cells written in
prose are in IRREGULAR, each with its own function here. Every choice that
the rows leave open is made in one place below, with a comment, and listed
in tests/fixtures/network/gt-pcap/resync/SOURCE.md.

What a message's label means (seen, absent, lost) is the builder's record of
how it was made, not the expectation under C2A: seen when every frame of it
is on the wire whole and valid (over UDP, each in one datagram), its frames
are contiguous on its end apart from link-only frames and exact link-layer
retries between them, and it was built to parse; lost when an octet of it is
in a TCP hole; absent otherwise, with the reason. A case's a cell is the
expectation under C2A, and it is where the budget or the bound blinds a
message that was built whole.

Stdlib only. Nothing here sends a packet. Evidence class: simulated.

Usage: python resync_cases.py OUTDIR   (writes <capture>.pcap for every
capture, <case>.tsv for every case, and resync.sha256)
"""

import csv
import hashlib
import os
import re
import struct
import sys

import dnp3
import pcapfile
import synth

HERE = os.path.dirname(os.path.abspath(__file__))
CASES_TSV = os.path.join(HERE, "resync-cases.tsv")
CONDITIONS_TSV = os.path.join(HERE, "resync-conditions.tsv")


def read_tsv(path):
    with open(path, "rb") as f:
        text = f.read().replace(b"\r\n", b"\n").decode("utf-8")
    lines = [ln for ln in text.split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


CASES = read_tsv(CASES_TSV)
CONDITIONS = {r["id"]: r for r in read_tsv(CONDITIONS_TSV)}

# builder-msgs: the endpoints and link addresses.
MASTER = {"udp": ("02:00:00:00:00:14", "192.0.2.14", 5),   # M5, from UDP 20000
          "tcp": ("02:00:00:00:00:10", "192.0.2.10", 1)}   # M1, a port from 41100 up
O1 = ("02:00:00:00:00:20", "192.0.2.20", 20000, 10)
UDP_PORT = 20000
FIRST_TCP_PORT = 41100

# Choices the rows leave open (SOURCE.md lists them).
T_BASE = 1_763_200_000_000_000_000   # the first case's clock, 2025-11-15T09:46:40Z
SPACING = 3_600_000_000_000          # one hour between cases' clocks
MSS = 1460                           # "in N segments" fills segments to the MSS
NOFIR_DATA = b"\x3c\x02\x06\x3c\x03\x06"  # nofir's "6 octets of object data": g60v2 and g60v3 headers

FIR, FIN = 0x40, 0x80
DIRECT_OPERATE_NR = 6
APP_PER_FRAME = 249                  # application octets in a full frame (250 user octets less the transport octet)


def pinned(row_id):
    return bytes.fromhex(CONDITIONS[row_id]["value"])


# --- bytes -----------------------------------------------------------------

def link_frame(ctrl, dest, src, user=b""):
    """dnp3.link with another control octet: link-only frames and confirmed
    user data. The test checks it equals dnp3.link for control C4h and 44h."""
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5 + len(user), ctrl, dest, src)
    out = hdr + dnp3.crc(hdr)
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + dnp3.crc(blk)
    return out


def garbage(label, n):
    """n octets with no 05 octet (builder-failures), the same on every run
    and every Python: SHA-256 in counter mode, 05 octets dropped."""
    out, i = bytearray(), 0
    while len(out) < n:
        out += bytes(b for b in hashlib.sha256(f"{label}:{i}".encode()).digest() if b != 0x05)
        i += 1
    return bytes(out[:n])


def candidate(buf, i):
    """The design's candidate (2.1, 2.2): 05 64, a passing header CRC, a link length of 5 to 255."""
    h = buf[i:i + 10]
    return len(h) == 10 and h[:2] == b"\x05\x64" and h[2] >= 5 and dnp3.crc(h[:8]) == h[8:]


def candidates(buf):
    out, i = [], buf.find(b"\x05\x64")
    while i >= 0:
        if candidate(buf, i):
            out.append(i)
        i = buf.find(b"\x05\x64", i + 1)
    return out


def chunk_crc_offsets(frame):
    """Offsets of each chunk CRC's first octet in a frame."""
    out, i = [], 10
    while i < len(frame):
        n = min(16, len(frame) - i - 2)
        out.append(i + n)
        i += n + 2
    return out


def invert_first_crc_octet(frame, chunk):
    at = chunk_crc_offsets(frame)[chunk]
    return frame[:at] + bytes([frame[at] ^ 0xFF]) + frame[at + 1:]


def sizes(n, how):
    """Application octets per frame. one: 249 a frame, the last the
    remainder (builder-limit, builder-join). two: the application control
    octet, then the rest, as W1 and W2 (builder-msgs). three: the control
    octet, then the rest in two halves, the first rounded up (a choice: the
    rows split W1c to W3c and G3a to G3c without saying where). overlimit:
    411 frames of 249, one of 61 and one of 249 (builder-limit)."""
    if how == "one":
        return [APP_PER_FRAME] * (n // APP_PER_FRAME) + ([n % APP_PER_FRAME] if n % APP_PER_FRAME else [])
    if how == "two":
        return [1, n - 1]
    if how == "three":
        h = -(-(n - 1) // 2)
        return [1, h, n - 1 - h]
    if how == "overlimit":
        return [APP_PER_FRAME] * 411 + [61, APP_PER_FRAME]
    raise ValueError(how)


def s5_7_frame(l4):
    """One frame of S5 input (7) (builder-s5-7): m's header of link length
    255, 05 64 repeated over its offsets 10 to 281, then the row's 10 octets
    at 282 to 291. S5's inputs are measurements, not cases, so no capture of
    them is written here."""
    dest, src = O1[3], MASTER[l4][2]
    hdr = b"\x05\x64" + struct.pack("<BBHH", 255, 0xC4, dest, src)
    return hdr + dnp3.crc(hdr) + b"\x05\x64" * 136 + pinned("builder-s5-7")


# --- the messages of builder-msgs ------------------------------------------

def _read(*objs):
    return lambda s: dnp3.request(s, dnp3.READ, b"".join(objs))


def _operate(index, fc=dnp3.DIRECT_OPERATE):
    return lambda s: dnp3.request(s, fc, dnp3.crob(index))


def _c0(*rest):
    """An application control octet written C0h: FIR, FIN and the running sequence (builder-msgs)."""
    return lambda s: bytes([0xC0 | (s & 0x0F)]) + b"".join(rest)


_G60 = {v: dnp3.all_objects(60, v) for v in (1, 2, 3, 4)}

# name: (APDU from the application sequence, function code, objects, why it is not built to parse)
REQUESTS = {
    "P": (_read(_G60[1]), 1, "g60v1", None),
    "Q": (_read(_G60[2], _G60[3], _G60[4]), 1, "g60v2,g60v3,g60v4", None),
    "W": (_operate(0), 5, "g12v1", None),
    "W5": (_operate(5), 5, "g12v1", None),
    "Wb": (_operate(1), 5, "g12v1", None),
    "W6": (_operate(0, DIRECT_OPERATE_NR), 6, "g12v1", None),
    "G0": (_c0(b"\x01\x00\xfe\x06"), 1, "g0v254", None),
    "G0r": (_c0(b"\x01\x00\xfe\x00\x00\x00"), 1, "g0v254", None),
    "B400": (_c0(b"\x01", b"\x3c\x01\x06" * 34131, b"\x3c\x02\x00\x00\x00"), 1, "g60v1,g60v2", None),
    "B401": (_c0(b"\x01", b"\x3c\x01\x06" * 34133), 1, "g60v1", "over the limit"),
    "throw": (_c0(b"\x01\x3c"), 1, "-", "throws"),
    "overlimit": (_c0(b"\x01", b"\x3c\x01\x06" * 34214, b"\x3c\x02\x00\x00\x00"), 1, "g60v1,g60v2",
                  "over the limit"),
}
REQUESTS["G"] = REQUESTS["Q"]   # a second read of Q's content
for _k in range(2, 12):
    REQUESTS[f"P{_k}"] = REQUESTS["P"]   # further class 0 polls
W_FAMILY = {"W", "W5", "Wb", "W6"}


class Unit:
    """One link-layer unit on one end: a frame, a link-only frame, a retry
    of a frame, or the octets of a failure. named lists the offsets in it at
    which the case names a candidate (the design's 2.1); the builder checks
    that no other offset of the capture holds one (builder-failures, its
    last sentence)."""

    __slots__ = ("name", "end", "data", "label", "fail", "msg", "kind", "named", "pieces", "sent")

    def __init__(self, name, end, data, label="valid", fail="-", msg=None, kind="frame", named=(0,)):
        self.name, self.end, self.data, self.label, self.fail = name, end, bytes(data), label, fail
        self.msg, self.kind, self.named = msg, kind, tuple(named)
        self.pieces, self.sent = [], 0


class Msg:
    __slots__ = ("name", "end", "code", "objects", "seq", "apdu", "frames", "units", "why", "flow", "done")

    def __init__(self, name, end, code, objects, seq, apdu, why, flow):
        self.name, self.end, self.code, self.objects, self.seq = name, end, code, objects, seq
        self.apdu, self.why, self.flow = apdu, why, flow
        self.frames, self.units, self.done = [], [], False


SKIPPED = object()   # a request left out of a nowrite twin, still owed its response's place


class Delivery:
    __slots__ = ("flow", "end", "pieces", "frame", "lost")

    def __init__(self, flow, end, pieces, frame, lost):
        self.flow, self.end, self.pieces, self.frame, self.lost = flow, end, pieces, frame, lost


class Capture:
    def __init__(self, case, twin, l4, index, tcp_port):
        self.case, self.twin, self.l4 = case, twin, l4
        self.name = case if twin is None else f"{case}--{twin}"
        self.t0 = T_BASE + index * SPACING
        self.clock = synth.Clock(start_ns=self.t0)
        self.tcp_port = tcp_port
        self.flows, self.deliveries = [], []

    def at(self, seconds):
        return self.t0 + round(seconds * 1_000_000_000)

    def frames(self):
        """Every frame of every flow, in time order (a stable sort keeps each flow's own order)."""
        for f in self.flows:
            ns = [fr.ns for fr in f.conv.frames]
            assert ns == sorted(ns), (self.name, f.port)
        return sorted((fr for f in self.flows for fr in f.conv.frames), key=lambda fr: fr.ns)


class Flow:
    """One 5-tuple: M5 or M1 (m) and O1 (o), with each end's transport
    sequence, the master's application sequence and the requests owed a
    response."""

    def __init__(self, cap, port=None, handshake=True, ident=1000):
        self.cap, self.l4 = cap, cap.l4
        mac, ip, mlink = MASTER[cap.l4]
        self.port = port if port is not None else (UDP_PORT if cap.l4 == "udp" else cap.tcp_port)
        m, o = synth.Host(mac, ip, self.port), synth.Host(O1[0], O1[1], O1[2])
        if self.l4 == "udp":
            self.conv = synth.UDPConv(m, o, cap.clock, ident=ident)
        else:
            self.conv = synth.TCPConv(m, o, cap.clock, isn_c=ident, isn_s=ident + 50_000, ident=ident)
        self.addr = {"m": (O1[3], mlink, True), "o": (mlink, O1[3], False)}
        self.app, self.tseq, self.fcb = 0, {"m": 0, "o": 0}, 0
        self.pending, self.last, self.skipped = [], None, False
        self.msgs, self.stash, self.units = {}, {}, {}
        cap.flows.append(self)
        if self.l4 == "tcp" and handshake:
            self.conv.handshake()

    # Frames. A message's frames take consecutive transport sequence
    # numbers when it is built (builder-msgs: per frame from 0, mod 64).
    def _frames(self, end, apdu, how="one", take=None, confirmed=False):
        dest, src, master = self.addr[end]
        szs = sizes(len(apdu), how)
        out, i = [], 0
        for k in range(len(szs) if take is None else take):
            t = (FIR if k == 0 else 0) | (FIN if k == len(szs) - 1 else 0) | self.tseq[end]
            self.tseq[end] = (self.tseq[end] + 1) & 0x3F
            user = bytes([t]) + apdu[i:i + szs[k]]
            i += szs[k]
            if confirmed:
                # Confirmed user data (link function 3, FCV set) after Rst:
                # the first carries FCB 1, and each new frame toggles it.
                self.fcb ^= 1
                out.append(link_frame(0xD3 | self.fcb << 5, dest, src, user))
            else:
                out.append(dnp3.link(dest, src, master, user))
        return out

    def request(self, name, end="m", how="one", take=None, confirmed=False, base=None):
        fn, code, objects, why = REQUESTS[base or name]
        seq, self.app = self.app, (self.app + 1) & 0x0F
        msg = Msg(name, end, code, objects, seq, fn(seq), why, self)
        msg.frames = self._frames(end, msg.apdu, how, take, confirmed)
        if take is not None and take < len(sizes(len(msg.apdu), how)):
            msg.why = msg.why or "partial: only its first frame is sent"
        self.last = msg
        self.msgs[name] = msg
        return msg

    def response(self, to, name=None, iin=0, how="one"):
        """R: code 129, IIN 0, its request's sequence, no objects, except that
        R to a direct operate echoes its g12v1 with status 0."""
        echo = to.apdu[2:] if to.code in (dnp3.DIRECT_OPERATE, DIRECT_OPERATE_NR) else b""
        msg = Msg(name or f"R({to.name})", "o", dnp3.RESPONSE, "g12v1" if echo else "-", to.seq,
                  dnp3.response(to.seq, iin=iin, objects=echo), None, self)
        msg.frames = self._frames("o", msg.apdu, how)
        self.msgs[msg.name] = msg
        return msg

    def answer(self):
        """The most recent complete request that has no response yet."""
        return self.pending.pop() if self.pending else None

    def last_seq(self):
        return self.last.seq if self.last else 0

    def frame_units(self, msg, names=None):
        """One unit per frame of msg: the token's names, else the message's
        name for one frame and <name>/<k> for more."""
        n = len(msg.frames)
        names = names or ([msg.name] if n == 1 else [f"{msg.name}/{k}" for k in range(1, n + 1)])
        out = []
        for fr, nm in zip(msg.frames, names):
            u = Unit(nm, msg.end, fr, msg=msg)
            msg.units.append(u)
            out.append(u)
        return out

    def link_only(self, name):
        """L and Lo: link status request (function 9). Lm: link status
        (function 11), the master's. Ls: O1's link status (function 11), the
        keep-alive's other-end twin, which builder-msgs does not name. Rst:
        Reset Link States (function 0, PRM set). A: O1's ACK (function 0)."""
        end, ctrl = {"L": ("m", 0xC9), "Lo": ("o", 0x49), "Lm": ("m", 0x8B), "Ls": ("o", 0x0B),
                     "Rst": ("m", 0xC0), "A": ("o", 0x00)}[name]
        dest, src, _ = self.addr[end]
        if name == "Rst":
            self.fcb = 0
        return Unit(name, end, link_frame(ctrl, dest, src), kind="link")

    def failure(self, spec, end, name):
        """The units of one failure (builder-failures), as delivery groups:
        a list of lists, each inner list one datagram or segment. From o, a
        failure whose content is a request carries a response of the same
        kind (judge-twins), in the most recent request's sequence."""
        dest, src, master = self.addr[end]
        ctrl = 0xC4 if master else 0x44

        def hdr(length):
            return b"\x05\x64" + struct.pack("<BBHH", length, ctrl, dest, src)

        def raw(data, named=()):
            return [[Unit(name, end, data, label=spec, fail=spec, kind="raw", named=named)]]

        def message(base, how="one", take=None, o_apdu=None, o_objects="-"):
            """The failure's message: from m the request base; from o the
            response o_apdu, by default an empty one."""
            if end == "m":
                return self.request(name, base=base, how=how, take=take)
            seq = self.last_seq()
            apdu = o_apdu(seq) if o_apdu else dnp3.response(seq)
            msg = Msg(name, "o", dnp3.RESPONSE, o_objects, seq, apdu, None, self)
            msg.frames = self._frames("o", apdu, how, take)
            if take is not None:
                msg.why = "partial: only its first frame is sent"
            self.msgs[name] = msg
            return msg

        def units(msg, names=None):
            us = self.frame_units(msg, names)
            for u in us:
                u.fail = spec
            return us

        m = re.fullmatch(r"(garbage|zeros|len|crcmagic)\((\d+)\)", spec)
        if m and m.group(1) == "garbage":
            return raw(garbage(f"{self.cap.case}:{name}:{end}", int(m.group(2))))
        if m and m.group(1) == "zeros":
            return raw(bytes(int(m.group(2))))
        if m and m.group(1) == "len":
            h = hdr(int(m.group(2)))
            return raw(h + dnp3.crc(h) + bytes(6))
        if m and m.group(1) == "crcmagic":
            assert end == "m"
            return raw(pinned(f"builder-c1-{self.l4}-{m.group(2)}"))
        if spec in ("badhdr", "holds"):
            # badhdr: "05 64, six header octets of the sender": those of the
            # sender's own P (length 11, from m) or empty R (length 10, from
            # o), a choice. Both: the header CRC with its first octet inverted.
            h = hdr(53 if spec == "holds" else 0x0B if master else 0x0A)
            c = dnp3.crc(h)
            return raw(h + bytes([c[0] ^ 0xFF, c[1]]) + bytes(3 if spec == "holds" else 6))
        if spec == "falsemagic":
            return raw(b"\x05\x64")
        if spec == "P":
            # I:P, a whole read: the a cells call its message P and its response R(I).
            msg = message("P")
            msg.name = "P"
            return [units(msg, [name])]
        if spec == "throw":
            # From o: C0h 81h 00h, short of the 4-octet response header (judge-twins).
            msg = message("throw", o_apdu=lambda s: bytes([0xC0 | s, 0x81, 0x00]))
            msg.why = "throws"
            return [units(msg, [name])]
        if spec in ("badchunk", "cut"):
            # badchunk: P's frame (an empty response from o), its chunk CRC's
            # first octet inverted. cut: Q's frame (an empty response's from
            # o), cut after 14 octets.
            msg = message("P" if spec == "badchunk" else "Q")
            (u,) = units(msg, [name])
            if spec == "badchunk":
                u.data, u.label = invert_first_crc_octet(u.data, 0), "badchunk"
            else:
                u.data, u.label = u.data[:14], "cut(14)"
            msg.why = "damaged"
            return [[u]]
        if spec in ("open+badchunk", "firopen"):
            # A two-frame read, split as W1 and W2 (a choice: P's read, the
            # control octet in frame 1); from o an empty response so split.
            msg = message("P", how="two", take=1 if spec == "firopen" else None)
            us = units(msg, [f"{name}/1", f"{name}/2"][:len(msg.frames)])
            if spec == "open+badchunk":
                us[1].data, us[1].label, msg.why = invert_first_crc_octet(us[1].data, 0), "badchunk", "damaged"
            return [[u] for u in us]
        if spec == "nofir":
            t = FIN | self.tseq[end]
            self.tseq[end] = (self.tseq[end] + 1) & 0x3F
            # From o, an empty response's APDU in the same framing (judge-twins).
            body = NOFIR_DATA if end == "m" else dnp3.response(self.last_seq())
            return [[Unit(name, end, dnp3.link(dest, src, master, bytes([t]) + body), fail=spec)]]
        if spec == "overlimit":
            # From o: 129, IIN 0 and 3Ch 01h 06h 34,215 times, framed as overlimit (judge-twins).
            msg = message("overlimit", how="overlimit", o_objects="g60v1",
                          o_apdu=lambda s: dnp3.response(s, objects=b"\x3c\x01\x06" * 34215))
            msg.why = "over the limit"
            return [[u] for u in units(msg)]
        m = re.fullmatch(r"(embed|embedtail)\(W5\)(?:\[(frame|after)\])?", spec)
        if m and m.group(2) == "after":
            return [[self.stash.pop(name)]]
        if m:
            # The content: W5 from m; from o, the response to such an operate,
            # which echoes its g12v1 at index 5 (judge-twins: a response of the
            # same kind). It is inside the failure, so never owed a response.
            if end == "m":
                inner = self.request("W5")
            else:
                inner = Msg("W5", "o", dnp3.RESPONSE, "g12v1", self.last_seq(),
                            dnp3.response(self.last_seq(), objects=dnp3.crob(5)), None, self)
                inner.frames = self._frames("o", inner.apdu)
            inner.why, inner.done = f"inside {name}", True
            w5 = inner.frames[0]
            h = hdr(53)
            if m.group(1) == "embed":
                # A frame of link length 53 with W5's frame at its octets 20 on, and 00 elsewhere.
                body = bytearray(54)
                body[10:10 + len(w5)] = w5
                u = Unit(name, end, h + dnp3.crc(h) + bytes(body), label=spec, fail=spec, msg=inner, named=(0, 20))
                inner.units.append(u)
                return [[u]]
            # embedtail: three chunks of 16; the last ends with W5's first two
            # octets, and its CRC octets are W5's next two, so it fails; the
            # other octets are 00 (as embed's) and the first two CRCs valid.
            label = "embedtail(W5)"
            zeros = bytes(16)
            frame = (h + dnp3.crc(h) + zeros + dnp3.crc(zeros) + zeros + dnp3.crc(zeros)
                     + bytes(14) + w5[:4])
            u = Unit(f"{name}[frame]" if m.group(2) else name, end, frame, label=label, fail=label, msg=inner,
                     named=(0, 60))
            after = Unit(f"{name}[after]", end, w5[4:], label="after", fail=label, msg=inner, kind="raw", named=())
            inner.units += [u, after]
            if m.group(2) == "frame":
                self.stash[name] = after
                return [[u]]
            return [[u, after]]
        raise ValueError(f"no builder for the failure {spec!r}")

    def send(self, pieces, lost=False, at=None):
        """One datagram or segment holding pieces: Units, or (Unit, a, b)
        slices. A lost segment is left out of the capture, and the peer's ACK
        past it is kept (judge-r3)."""
        pieces = [(p, 0, len(p.data)) if isinstance(p, Unit) else p for p in pieces]
        ends = {u.end for u, _, _ in pieces}
        assert len(ends) == 1, [u.name for u, _, _ in pieces]
        end = ends.pop()
        if at is not None:
            self.cap.clock.ns = at
        data = b"".join(u.data[a:b] for u, a, b in pieces)
        out = self.conv.send(end == "m", data, gap_ns=None if at is None else 0)
        frame = out[0]
        if lost:
            assert self.l4 == "tcp"
            self.conv.frames.remove(out[0])
            frame = out[1]
        d = Delivery(self, end, pieces, frame, lost)
        self.cap.deliveries.append(d)
        stream = self.units.setdefault(end, [])
        for u, a, b in pieces:
            u.pieces.append((d, a, b))
            u.sent += b - a
            if u not in stream:
                stream.append(u)
        for u, _, _ in pieces:
            self._complete(u.msg)
        return d

    def _complete(self, msg):
        """A request is owed its response once all of its frames are sent."""
        if msg is None or msg.done or msg.end != "m":
            return
        frames = [u for u in msg.units if u.kind == "frame"]
        if len(frames) == len(msg.frames) and all(u.sent >= len(u.data) for u in frames):
            msg.done = True
            self.pending.append(msg)

    def close(self):
        if self.l4 == "tcp":
            self.conv.close()


# --- the regular notation (section 3.1) ------------------------------------

TOKEN = re.compile(r"(?P<name>(?:[A-Z][a-z]?:)?[A-Za-z0-9+]+(?:\([^)]*\))?(?:\[[^\]]*\])?)"
                   r"(?P<retry> \(retry, same FCB\))?(?P<rep> x\d+)?(?P<frm> from [mo])?"
                   r"(?P<lost> lost, ACKed past)?(?P<segs> in \d+ segments)?")
SUFFIXES = (", one datagram", ", one segment", ", all within 30 s", " (handshake first, FIN exchange last)")
MARKERS = {"handshake", "fresh 5-tuple", "fresh 5-tuple, capture start", "(no response)"}
FRAME_TOKENS = {"W1": ("W", 0, "two"), "W2": ("W", 1, "two"), "W6a": ("W6", 0, "two"), "W6b": ("W6", 1, "two"),
                "Qa": ("Q", 0, "two"), "Qb": ("Q", 1, "two"), "W1c": ("W", 0, "c"), "W2c": ("W", 1, "c"),
                "W3c": ("W", 2, "c"), "G3a": ("G", 0, "three"), "G3b": ("G", 1, "three"), "G3c": ("G", 2, "three")}
LINKS = {"L", "Lo", "Lm", "Ls", "Rst", "A"}
OTHER_END_LINK = {"L": "Lo", "Lo": "L", "Lm": "Ls"}   # R4's failure from the outstation's side


def parse_part(part):
    """A part between |s: a list of items, each (token match, joined to the next)."""
    for s in SUFFIXES:
        if part.endswith(s):
            part = part[:-len(s)]
    m = re.fullmatch(r"\((.+)\) x(\d+)", part)
    if m:
        return parse_part(" ".join([m.group(1)] * int(m.group(2))))
    items, pos = [], 0
    while pos < len(part):
        t = TOKEN.match(part, pos)
        if not t or t.end() == pos:
            raise ValueError(f"cannot read {part[pos:]!r}")
        pos = t.end()
        joined = part.startswith(" + ", pos)
        if joined:
            pos += 3
        elif part.startswith(" ", pos):
            pos += 1
        elif pos != len(part):
            raise ValueError(f"cannot read {part[pos:]!r}")
        items.append((t, joined))
    return items


def parse(build):
    """The build cell as a list of parts: a marker, a wait in seconds, or items."""
    out = []
    for part in build.split(" | "):
        m = re.fullmatch(r"~(\d+)s", part)
        if part in MARKERS:
            out.append(("marker", part))
        elif m:
            out.append(("wait", int(m.group(1))))
        else:
            out.append(("items", parse_part(part)))
    return out


def w_family(name):
    return name in W_FAMILY or re.fullmatch(r"W\[.*\]|W[123]c?|W6[ab]", name) is not None


def completes(name, build):
    """Whether the token sends the last octets of its message."""
    return (name in ("W", "W2", "W6b", "W3c") or (name == "W2c" and "W3c" not in build)
            or re.fullmatch(r"W\[\d+:\]", name) is not None)


def interpret(cap, build):
    """A regular cell: TCP opens with the handshake and ends with the FIN
    exchange (builder-msgs; Flow and close do both), markers change nothing,
    ~Ns waits N seconds, and each token is sent as section 3.1 says."""
    f = Flow(cap)
    last_frame = {}
    for kind, part in parse(build):
        if kind == "marker":
            continue
        if kind == "wait":
            cap.clock.ns += part * 1_000_000_000
            continue
        held = None   # a group held for the next token's " + "
        for t, joined in part:
            g = token_groups(f, t, cap.twin, build, last_frame)
            is_lost = bool(t.group("lost")) and cap.twin != "nofail"
            groups = [(x, is_lost) for x in g]
            if held and groups:
                groups[0] = (held[0] + groups[0][0], held[1] or is_lost)
            elif held:
                groups = [held]
            held = groups.pop() if joined and groups else None
            for x, lo in groups:
                f.send(x, lost=lo)
            if f.skipped and held is None:
                f.pending.append(SKIPPED)   # where the left-out W would have become owed
                f.skipped = False
        if held:
            f.send(held[0], lost=held[1])
        if f.skipped:
            f.pending.append(SKIPPED)
            f.skipped = False
    f.close()


def token_groups(f, t, twin, build, last_frame):
    """The delivery groups of one token, after the twin's change."""
    name = t.group("name")
    rep = int(t.group("rep")[2:]) if t.group("rep") else None
    end = t.group("frm")[-1] if t.group("frm") else None
    segs = int(t.group("segs").split()[1]) if t.group("segs") else None
    m = re.fullmatch(r"([A-Z][a-z]?):(.+)", name)
    if m:
        prefix, spec = m.groups()
        if twin == "nofail" and prefix in ("X", "I"):
            return []
        end = end or {"Xm": "m", "Xo": "o"}.get(prefix) or ("o" if twin == "otherend" and prefix == "X" else "m")
        out = []
        for k in range(1, (rep or 1) + 1):
            out += f.failure(spec, end, f"{prefix}{k}" if rep else prefix)
        if rep and t.string[t.end():].startswith(" + "):
            out = [[u for g in out for u in g]]   # "x15 + W": every repeat in the one delivery
        if segs:
            (u,), = out
            out = [[(u, a, min(a + MSS, len(u.data)))] for a in range(0, len(u.data), MSS)]
            assert len(out) == segs, (name, len(out), segs)
        return out
    if name == "R(I)":
        if "I" not in f.msgs:
            return []
        # R(I) to I:throw, a malformed read, carries IIN 0004h (builder-msgs).
        i = f.msgs["I"]
        return [f.frame_units(f.response(i, name="R(I)", iin=0x0004 if i.why == "throws" else 0))]
    if name == "R":
        to = f.answer()
        assert to is not None, "R with no request owed a response"
        if to is SKIPPED:
            return []
        return [[u] for u in f.frame_units(f.response(to))]
    if name in LINKS:
        if twin == "nofail" and name in ("L", "Lo", "Lm"):
            return []
        if twin == "otherend":
            name = OTHER_END_LINK.get(name, name)
        return [[f.link_only(name)]]
    if twin == "nowrite" and w_family(name):
        f.skipped = f.skipped or completes(name, build)
        return []
    if t.group("retry"):
        prev = last_frame[name]
        u = Unit("retry", prev.end, prev.data, msg=prev.msg, kind="retry")
        prev.msg.units.append(u)
        return [[u]]
    if name in FRAME_TOKENS:
        base, k, how = FRAME_TOKENS[name]
        if how == "c":
            how = "three" if "W3c" in build else "two"
        msg = f.msgs.get(base) if k else None
        if msg is None:
            msg = f.request(base, how=how, confirmed=name.endswith("c"))
        u = Unit(name, "m", msg.frames[k], msg=msg)
        msg.units.append(u)
        last_frame[name] = u
        return [[u]]
    s = re.fullmatch(r"([A-Z][A-Za-z0-9]*)\[(\d*):(\d*)\]", name)
    if s:
        base, a, b = s.group(1), s.group(2), s.group(3)
        msg = f.msgs.get(base)
        if msg is None or not a or int(a) == 0:
            msg = f.request(base)
            f.frame_units(msg)
        (u,) = msg.units
        return [[(u, int(a or 0), int(b) if b else len(u.data))]]
    if name in REQUESTS:
        msg = f.request(name)
        return [[u] for u in f.frame_units(msg)]
    raise ValueError(f"no builder for the token {name!r}")


# --- the cells written in prose ---------------------------------------------

def send_all(f, groups, lost=False, at=None):
    for g in groups:
        f.send(g, lost=lost, at=at)
        at = None


def req(f, name):
    send_all(f, [[u] for u in f.frame_units(f.request(name))])


def reply(f, at=None):
    to = f.answer()
    if to is not SKIPPED and to is not None:
        send_all(f, [[u] for u in f.frame_units(f.response(to))], at=at)


def udp_weird_burst(cap):
    """X1 to X2000 spread evenly from X1 to X1 + 50 s; W at X1 + 52 s and
    Q at X1 + 54 s, each answered 1 ms later."""
    f = Flow(cap)
    req(f, "P")
    reply(f)
    x1 = cap.clock.ns + 1_000_000
    end = "o" if cap.twin == "otherend" else "m"
    if cap.twin != "nofail":
        for i in range(2000):
            send_all(f, f.failure("garbage(16)", end, f"X{i + 1}"), at=x1 + i * 50_000_000_000 // 1999)
    for name, s in (("W", 52), ("Q", 54)):
        if cap.twin == "nowrite" and name == "W":
            continue
        send_all(f, [f.frame_units(f.request(name))], at=x1 + s * 1_000_000_000)
        reply(f, at=x1 + s * 1_000_000_000 + 1_000_000)
    f.close()


def previous(f, end, name):
    """A whole message sent before the capture's first frame, in the
    sequence numbers just before 0, so the capture's own numbering starts at
    0 (a choice): from m a P, from o an empty R."""
    save = (f.app, dict(f.tseq), f.last)
    f.app, f.tseq[end] = 15, 63
    if end == "m":
        msg = f.request(name, base="P")
    else:
        msg = Msg(name, "o", dnp3.RESPONSE, "-", 15, dnp3.response(15), None, f)
        msg.frames = f._frames("o", msg.apdu)
    f.app, f.tseq, f.last = save
    f.msgs.pop(name, None)
    msg.why = "partial: the capture starts inside its frame"
    return msg


def tcp_r2_midstream(cap):
    """No handshake. m's first segment is the last 7 octets of m's frame
    before it, then P; o's first is R. The other end's twin moves the tail
    to o's first segment, before R."""
    f = Flow(cap, handshake=False)
    tail_end = "o" if cap.twin == "otherend" else "m"
    tail = None
    if cap.twin != "nofail":
        before = previous(f, tail_end, "before")
        tail = Unit("X", tail_end, before.frames[0][-7:], label="tail(7)", fail="tail(7)", msg=before, kind="raw",
                    named=())
        before.units.append(tail)
    p = f.frame_units(f.request("P"))
    f.send(([tail] if tail_end == "m" and tail else []) + p)
    to = f.answer()
    f.send(([tail] if tail_end == "o" and tail else []) + f.frame_units(f.response(to)))
    for name in ("W", "Q"):
        if cap.twin == "nowrite" and name == "W":
            continue
        req(f, name)
        reply(f)
    f.close()


def tcp_r2_midstream_both(cap):
    """No handshake. o: the last 7 octets of frame 1 of a 2-frame empty
    response, then its frame 2; m: the last 9 octets of Qa, then Qb, of a Q
    sent before the capture (the sensor starts inside frame 1 on each end)."""
    f = Flow(cap, handshake=False)
    f.app, f.tseq = 15, {"m": 62, "o": 62}
    q = f.request("Qprev", base="Q", how="two")
    r = Msg("Rprev", "o", dnp3.RESPONSE, "-", 14, dnp3.response(14), None, f)
    r.frames = f._frames("o", r.apdu, "two")
    assert f.app == 0 and f.tseq == {"m": 0, "o": 0}
    o_tail = Unit("Xo", "o", r.frames[0][-7:], label="tail(7)", fail="tail(7)", msg=r, kind="raw", named=())
    o_rest = Unit("Rprev/2", "o", r.frames[1], msg=r)
    m_tail = Unit("Xm", "m", q.frames[0][-9:], label="tail(9)", fail="tail(9)", msg=q, kind="raw", named=())
    m_rest = Unit("Qprev/2", "m", q.frames[1], msg=q)
    r.units, q.units = [o_tail, o_rest], [m_tail, m_rest]
    q.why = r.why = "partial: the capture starts inside its first frame"
    f.send([o_tail, o_rest])
    f.send([m_tail, m_rest])
    f.pending.clear()
    for name in ("P", "W", "Q"):
        req(f, name)
        reply(f)
    f.close()


def join_response(cap):
    """O1's 2,048-octet response in 9 frames, sent from frame 2 (builder-join)."""
    f = Flow(cap, handshake=False)
    objects = bytes([1, 2, 0x01]) + struct.pack("<HH", 0, 2036) + b"\x01" * 2037
    big = Msg("Rbig", "o", dnp3.RESPONSE, "g1v2", 15, dnp3.response(15, objects=objects),
              "partial: the capture starts at its frame 2", f)
    big.frames = f._frames("o", big.apdu)
    assert len(big.frames) == 9 and len(big.apdu) == 2048
    for k, fr in enumerate(big.frames[1:], 2):
        u = Unit(f"Rbig/{k}", "o", fr, msg=big)
        big.units.append(u)
        f.send([u])
    for name in ("P", "W", "Q"):
        req(f, name)
        reply(f)
    f.close()


def budget_split_ends(n):
    def build(cap):
        f = Flow(cap)
        for i in range(n):
            send_all(f, f.failure("badhdr", "mo"[i % 2], f"X{i + 1}"))
        for name in ("P", "W", "Q"):
            req(f, name)
            reply(f)
    return build


def udp_budget_over_10k(cap):
    f = Flow(cap)
    for i in range(1100):
        u = f.link_only("L")
        u.name = f"L{i + 1}"
        f.send([u])
    for i in range(8):
        send_all(f, f.failure("badhdr", "m", f"X{i + 1}"))
    for name in ("P", "W", "Q"):
        req(f, name)
        reply(f)


def tcp_gap(split, frames3=False):
    """A TCP hole in G's frame, or with frames3 in G's middle frame; G is
    answered by R. nofail: nothing lost. otherend: G whole in the same
    segments, and the hole in R(G), split at the same offsets (judge-twins:
    an empty response of the same framing)."""
    def build(cap):
        f = Flow(cap)
        req(f, "P")
        reply(f)
        g = f.request("G", how="three" if frames3 else "one")
        if frames3:
            gs = f.frame_units(g, ["G3a", "G3b", "G3c"])
            parts = [[(u, 0, len(u.data))] for u in gs]
        else:
            (u,) = f.frame_units(g)
            parts = [[(u, a, b if b is not None else len(u.data))] for a, b in split]
        for k, p in enumerate(parts):
            f.send(p, lost=(k == 1 and cap.twin is None))
        to = f.answer()
        r = f.response(to, how="three" if frames3 and cap.twin == "otherend" else "one")
        if cap.twin == "otherend":
            if frames3:
                rs = f.frame_units(r, ["R3a", "R3b", "R3c"])
                rparts = [[(u, 0, len(u.data))] for u in rs]
            else:
                (u,) = f.frame_units(r)
                rparts = [[(u, a, min(b, len(u.data)) if b is not None else len(u.data))] for a, b in split]
            for k, p in enumerate(rparts):
                f.send(p, lost=(k == 1))
        else:
            send_all(f, [[u] for u in f.frame_units(r)])
        for name in ("W", "Q"):
            if cap.twin == "nowrite" and name == "W":
                continue
            req(f, name)
            reply(f)
        f.close()
    return build


def tcp_gap_non_dnp3(cap):
    f = Flow(cap)
    for k in range(3):
        send_all(f, f.failure("garbage(100)", "m", f"X{k + 1}"), lost=(k == 1 and cap.twin is None))
    send_all(f, f.failure("garbage(200)", "o", "Xo"))
    f.close()


def udp_report_interval(cap):
    """P at 5, 25, ..., 205 s, each answered 1 ms later; X:badchunk at 10,
    40, 100 and 160 s (seconds from the capture's start)."""
    f = Flow(cap)
    events = [(5 + 20 * k, "P") for k in range(11)]
    if cap.twin != "nofail":
        events += [(s, "X") for s in (10, 40, 100, 160)]
    xs = 0
    for s, what in sorted(events):
        if what == "X":
            xs += 1
            send_all(f, f.failure("badchunk", "m", f"X{xs}"), at=cap.at(s))
        else:
            n = sum(1 for t, w in events if w == "P" and t <= s)
            send_all(f, [f.frame_units(f.request("P" if n == 1 else f"P{n}"))], at=cap.at(s))
            reply(f, at=cap.at(s) + 1_000_000)


def udp_report_cap(cap):
    """T0 is 30 s after the capture's clock start. Flow i (port 40000 + i)
    is confirmed by P R in a round before T0 and polled in five more, 30 s
    apart, so that the last response, flow 200's, is the capture's last
    packet at T0 + 125 s: round k's P is at T0 + 5 s + 30 s x k - (200 - i)
    x 10 ms - 1 ms, its R 1 ms later (a choice: the row fixes only the
    period and the end)."""
    t0 = cap.at(30)
    flows = [Flow(cap, port=40000 + i, ident=1000 + i) for i in range(201)]
    budget = Flow(cap, port=41000, ident=900)
    events = []   # (time, order, action)
    for i in range(201):
        for k in range(-1, 5):
            p = t0 + 5_000_000_000 + 30_000_000_000 * k - (200 - i) * 10_000_000 - 1_000_000
            events.append((p, 0, ("poll", i, k)))
    for i in range(101):
        events.append((t0 + i * 100_000_000, 1, ("x", i)))
    for i in range(101, 201):
        events.append((t0 + 60_500_000_000 + (i - 101) * 100_000_000, 1, ("x", i)))
    for j in range(8):
        events.append((t0 + 20_000_000_000 + j * 1_000_000, 1, ("budget", j)))
    for at, _, ev in sorted(events):
        if ev[0] == "poll":
            f, k = flows[ev[1]], ev[2]
            send_all(f, [f.frame_units(f.request("P" if k < 0 else f"P{k + 2}"))], at=at)
            reply(f, at=at + 1_000_000)
        elif ev[0] == "x":
            send_all(flows[ev[1]], flows[ev[1]].failure("badchunk", "m", "X"), at=at)
        else:
            send_all(budget, budget.failure("badhdr", "m", f"X{ev[1] + 1}"), at=at)
    assert cap.frames()[-1].ns == t0 + 125_000_000_000


def udp_report_mark_state(n):
    def build(cap):
        for i in range(n):
            f = Flow(cap, port=40000 + i, ident=1000 + i)
            send_all(f, f.failure("badchunk", "m", "X"))
            send_all(f, f.failure("throw", "m", "T"))
    return build


IRREGULAR = {
    "dnp3-resync-udp-weird-burst": udp_weird_burst,
    "dnp3-resync-tcp-r2-midstream": tcp_r2_midstream,
    "dnp3-resync-tcp-r2-midstream-both": tcp_r2_midstream_both,
    "dnp3-resync-udp-join-response": join_response,
    "dnp3-resync-tcp-join-response": join_response,
    "dnp3-resync-udp-budget-split-ends-minus-1": budget_split_ends(7),
    "dnp3-resync-udp-budget-split-ends": budget_split_ends(8),
    "dnp3-resync-udp-budget-over-10k": udp_budget_over_10k,
    "dnp3-resync-tcp-gap-header": tcp_gap([(0, 3), (3, 7), (7, None)]),
    "dnp3-resync-tcp-gap-data": tcp_gap([(0, 12), (12, 16), (16, None)]),
    "dnp3-resync-tcp-gap-middle-frame": tcp_gap(None, frames3=True),
    "dnp3-resync-tcp-gap-non-dnp3": tcp_gap_non_dnp3,
    "dnp3-resync-udp-report-interval": udp_report_interval,
    "dnp3-resync-udp-report-cap": udp_report_cap,
    "dnp3-resync-udp-report-mark-state": udp_report_mark_state(1000),
}
# Captures that are neither a case nor a twin: the mark-state case's control
# capture, flow 0 only (its a cell).
EXTRA = {"dnp3-resync-udp-report-mark-state": {"control": udp_report_mark_state(1)}}


# --- labels ----------------------------------------------------------------

def message_state(msg, cap):
    units = [u for u in msg.units if u.kind == "frame"]
    if msg.why:
        return "absent", msg.why
    if any(d.lost for u in msg.units for d, _, _ in u.pieces):
        return "lost", "an octet of it is in a TCP hole"
    if len(units) < len(msg.frames) or any(u.sent < len(u.data) for u in units):
        return "absent", "partial"
    bad = [u for u in units if u.label != "valid"]
    if bad:
        return "absent", f"damaged: {bad[0].name} is {bad[0].label}"
    split = [u for u in units if len(u.pieces) > 1]
    if cap.l4 == "udp" and split:
        return "absent", f"{split[0].name} is split across datagrams"
    stream = msg.flow.units[msg.end]
    first, last = stream.index(units[0]), stream.index(units[-1])
    for v in stream[first:last + 1]:
        if v.msg is not msg and v.kind not in ("link", "retry"):
            return "absent", f"interrupted by {v.name}"
    return "seen", "-"


def check_candidates(cap):
    """No offset of any end's stream holds a candidate the case does not
    name, and every named candidate that is whole there is one (the last
    sentence of builder-failures). A UDP stream is one datagram; a TCP
    stream runs from one hole to the next."""
    streams = {}
    for d in cap.deliveries:
        runs_ = streams.setdefault((d.flow.port, d.end), [[]])
        if d.lost or cap.l4 == "udp":
            runs_.append([])
        if not d.lost:
            runs_[-1].extend(d.pieces)
    for key, runs_ in streams.items():
        for run in runs_:
            buf, named, pos = b"", set(), 0
            for u, a, b in run:
                for n in u.named:
                    if a <= n < b:
                        named.add(pos + n - a)
                buf += u.data[a:b]
                pos += b - a
            named = {n for n in named if n + 10 <= len(buf)}
            found = set(candidates(buf))
            if found != named:
                raise AssertionError(f"{cap.name} {key}: candidates at {sorted(found - named)} not named, "
                                     f"named at {sorted(named - found)} not found")


def runs(nums):
    """1-based packet numbers as runs: a, a-b, or a-b/s for every s-th."""
    out, i = [], 0
    while i < len(nums):
        j = i + 1
        if j < len(nums):
            step = nums[j] - nums[i]
            while j + 1 < len(nums) and nums[j + 1] - nums[j] == step:
                j += 1
            if step > 0 and j - i >= 2:
                out.append(f"{nums[i]}-{nums[j]}" + (f"/{step}" if step != 1 else ""))
                i = j + 1
                continue
        out.append(str(nums[i]))
        i += 1
    return ",".join(out) or "-"


COLUMNS = ["capture", "flow", "end", "unit", "label", "fail", "packets", "octets", "message", "code", "objects",
           "state", "why"]


def label_rows(cap):
    numbers = {id(fr): n for n, fr in enumerate(cap.frames(), 1)}
    states = {}
    rows, seen = [], set()
    multi = len(cap.flows) > 1
    for d in cap.deliveries:
        for u, _, _ in d.pieces:
            if id(u) in seen:
                continue
            seen.add(id(u))
            pk = sorted({numbers[id(e.frame)] for e, _, _ in u.pieces if not e.lost})
            msg = u.msg
            if msg is not None and id(msg) not in states:
                states[id(msg)] = message_state(msg, cap)
            st, why = states[id(msg)] if msg is not None else ("-", "-")
            rows.append({"capture": cap.name, "flow": d.flow.port, "end": u.end, "unit": u.name, "label": u.label,
                         "fail": u.fail, "packets": pk, "octets": len(u.data),
                         "message": msg.name if msg else "-", "code": msg.code if msg else "-",
                         "objects": msg.objects if msg else "-", "state": st, "why": why})
        if d.lost:
            rows.append({"capture": cap.name, "flow": d.flow.port, "end": d.end, "unit": "gap",
                         "label": f"lost({sum(b - a for _, a, b in d.pieces)})", "fail": "-",
                         "packets": [numbers[id(d.frame)]], "octets": sum(b - a for _, a, b in d.pieces),
                         "message": "-", "code": "-", "objects": "-", "state": "-",
                         "why": "the peer's ACK past the hole is this packet; the hole held "
                                + ", ".join(f"{u.name}[{a}:{b}]" for u, a, b in d.pieces)})
    if multi:
        order = {}
        for r in rows:
            order.setdefault(r["unit"], len(order))
        rows.sort(key=lambda r: (order[r["unit"]], r["flow"]))
    return merge(rows, multi)


def _index(name):
    m = re.fullmatch(r"(.*?)(\d+)", name)
    return (m.group(1), int(m.group(2))) if m else (name, None)


def merge(rows, multi):
    """Consecutive rows that differ only in a repeat index (X1, X2; Rbig/2,
    Rbig/3) or, in a capture of many flows, only in the flow, are one row."""
    fixed = ("capture", "end", "label", "fail", "octets", "code", "objects", "state", "why")
    out = []
    for r in rows:
        r = dict(r, units=[r["unit"]], flows=[r["flow"]], messages=[r["message"]])
        p = out[-1] if out else None
        if p and all(p[k] == r[k] for k in fixed):
            same_unit = p["units"][-1] == r["unit"] and p["messages"][-1] == r["message"]
            ub, ui = _index(p["units"][-1])
            rb, ri = _index(r["unit"])
            next_unit = ui is not None and ub == rb and ri == ui + 1
            mb, mi = _index(p["messages"][-1])
            nb, ni = _index(r["message"])
            next_msg = p["messages"][-1] == r["message"] or (mi is not None and mb == nb and ni == mi + 1)
            if (multi and same_unit and r["flow"] == p["flows"][-1] + 1) or (
                    p["flows"][-1] == r["flow"] and next_unit and next_msg):
                p["units"].append(r["unit"])
                p["flows"].append(r["flow"])
                p["messages"].append(r["message"])
                p["packets"] = sorted(set(p["packets"]) | set(r["packets"]))
                continue
        out.append(r)
    lines = []
    for r in out:
        span = lambda xs: str(xs[0]) if xs[0] == xs[-1] else f"{xs[0]}..{xs[-1]}"
        r["unit"], r["flow"], r["message"] = span(r["units"]), span(r["flows"]), span(r["messages"])
        r["packets"] = runs(r["packets"])
        lines.append("\t".join(str(r[c]) for c in COLUMNS))
    return lines


def header(case):
    row = next(r for r in CASES if r["case"] == case)
    l4 = row["l4"]
    m = MASTER[l4]
    ends = (f"m is M5 {m[1]}:{UDP_PORT} (link {m[2]})" if l4 == "udp"
            else f"m is M1 {m[1]}, its port in the flow column (link {m[2]})")
    return [
        f"# GT-PCAP labels for {case} and its twins (D6, brief P4-4-HR25, deliverable 3). The builder's, from how "
        "each capture was made (judge-labels); tshark's reading is reported beside them by resync_tshark.py, "
        "never used as a label.",
        f"# build: {row['build']}",
        f"# {ends}; o is O1 {O1[1]}:{O1[2]} (link {O1[3]}). A capture is the case, or <case>--<twin> "
        "(section 3.3), or <case>--control.",
        "# one row per link-layer unit, in the order sent (by unit, then flow, in a capture of many flows). "
        "label: valid, or the damage the unit's octets carry. fail: the case's failure the unit belongs to.",
        "# packets: 1-based packet numbers, a-b for a run and a-b/s for every s-th; - for none. A gap row is a "
        "TCP hole left out of the capture: its packet is the peer's ACK past it (judge-r3).",
        "# state: the builder's record of the message: seen when every frame is whole and valid (over UDP, each "
        "in one datagram), contiguous on its end apart from link-only frames and exact retries, and built to "
        "parse; lost when an octet is in a hole; absent otherwise, and why. The case's a cell is the expectation "
        "under C2A.",
        "# a row whose unit is a..b, or whose flow is a..b, stands for that run of units or flows, each as "
        "the row says.",
        "\t".join(COLUMNS),
    ]


# --- the captures ----------------------------------------------------------

def captures():
    """Every capture as (case, Capture): the case first, then its twins in
    the cell's order, then any control. Each is checked for candidates."""
    tcp_ports = {}
    for r in CASES:
        if r["l4"] == "tcp":
            tcp_ports[r["case"]] = FIRST_TCP_PORT + len(tcp_ports)
    out = []
    for index, r in enumerate(CASES):
        case = r["case"]
        twins = [] if r["twins"] == "-" else r["twins"].split(",")
        for twin in [None] + twins:
            cap = Capture(case, twin, r["l4"], index, tcp_ports.get(case))
            if case in IRREGULAR:
                IRREGULAR[case](cap)
            else:
                interpret(cap, r["build"])
            check_candidates(cap)
            out.append((case, cap))
        for extra, build in EXTRA.get(case, {}).items():
            cap = Capture(case, extra, r["l4"], index, tcp_ports.get(case))
            build(cap)
            check_candidates(cap)
            out.append((case, cap))
    return out


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    labels, sums = {}, []
    for case, cap in captures():
        frames = cap.frames()
        path = os.path.join(outdir, cap.name + ".pcap")
        pcapfile.write(path, frames)
        with open(path, "rb") as f:
            sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {cap.name}.pcap")
        labels.setdefault(case, header(case)).extend(label_rows(cap))
    for case, lines in labels.items():
        with open(os.path.join(outdir, case + ".tsv"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
    with open(os.path.join(outdir, "resync.sha256"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sums) + "\n")
    print(f"resync_cases: {len(sums)} captures, {len(labels)} label files")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
