"""GT-PCAP's HR-23 stage-2 cases and HR-23's malformed set (D6, brief P4-4-HR2325S, deliverable 1).

Brief P4-4-HR23's stage 2 and docs/phase4/D4-hr23-design.md section 4 name
the cases: dnp3-udp-relay-write and dnp3-udp-relay-restart (D4-100 item 3),
dnp3-udp-master-short, dnp3-udp-dir-spoof, dnp3-udp-swap-control,
dnp3-tcp-master-short and dnp3-tcp-dir-spoof (design sections 4.1 and 4.2),
and two D6 adds to measure the design's section 1 item 2: the third
unswapped arrangement, and the one with neither port in likely_server_ports.
dnp3-udp-temp-port and dnp3-udp-unsolicited are dnp3_cases.py's, unchanged.
Section 4.3 names the malformed DNP3 inputs (D4-100 item 2), each its own
capture here, and #718's reviews add rule (A)'s edges and D3's M1, a 129
that the response parser rejects as the flow's first datagram (D1's
6907176282 and 6907928324). hr23-cases.tsv and hr23-malformed.tsv pin what
each configuration is expected to do on them.

The labels are the builder's, from how each capture was made: every
link-layer unit with the end that sent it, its role (master or outstation,
whatever its DIR bit says), the DIR bit as built, the side Zeek gives that
end (section 1 items 1 and 2, with C0's likely_server_ports), and every
message as seen or absent, with why. A forged DIR takes its label from the
builder's role (design section 4, opening). tshark's reading is reported
beside them by hr23_tshark.py, never used as a label.

Stdlib only. Nothing here sends a packet. TEST-NET-1 addresses and locally
administered MACs, the hosts of dnp3_cases.py. Evidence class: simulated.

Usage: python hr23_cases.py OUTDIR   (writes <capture>.pcap and
<capture>.tsv for every case and input, and hr23.sha256)
"""

import hashlib
import os
import struct
import sys

import dnp3
import pcapfile
import synth

# The hosts, as dnp3_cases.NET has them: (MAC, IPv4, link address).
M1 = ("02:00:00:00:00:10", "192.0.2.10", 1)
M5 = ("02:00:00:00:00:14", "192.0.2.14", 5)
O1 = ("02:00:00:00:00:20", "192.0.2.20", 10)
O2 = ("02:00:00:00:00:21", "192.0.2.21", 11)

# C0's likely_server_ports: the zeek-probe line of run 43373373987's ports.zeek
# (CI-Linux, 2026-11-13), which the design's section 1 item 2 cites.
LIKELY = {
    "tcp": {21, 22, 25, 53, 79, 80, 81, 88, 135, 139, 143, 389, 443, 445, 465, 502, 514, 563, 585, 587, 614, 631,
            636, 989, 990, 992, 993, 995, 1080, 1434, 1883, 2811, 3128, 3268, 3306, 3389, 5222, 5223, 5269, 5432,
            6379, 6666, 6667, 6668, 6669, 8000, 8080, 8888, 20000},
    "udp": {53, 67, 88, 123, 137, 161, 162, 389, 443, 514, 1812, 2123, 2152, 3389, 3544, 4011, 4754, 4789, 5060,
            5072, 5353, 5355, 6081, 20000},
}

T_BASE = 1_763_400_000_000_000_000   # the first capture's clock, 2025-11-17T17:20:00Z (a choice)
SPACING = 3_600_000_000_000          # one hour between captures' clocks
FIR, FIN = 0x40, 0x80                # transport octet
CON = 0x20                           # application control octet
COLD_RESTART, RECORD_CURRENT_TIME = 13, 24
FIRST_TCP_PORT = 41300               # M1's ports, one per TCP capture, in order (resync's run from 41100)

G60 = {v: dnp3.all_objects(60, v) for v in (1, 2, 3, 4)}
P_OBJ, Q_OBJ = G60[1], G60[2] + G60[3] + G60[4]


def zeek_orig(l4, first_port, other_port, syn):
    """Which end Zeek takes as the originator (design section 1 items 1
    and 2): the first sender, unless no SYN was seen and its port is in
    likely_server_ports while the other's is not."""
    if l4 == "tcp" and syn:
        return "first"
    s = LIKELY[l4]
    return "other" if first_port in s and other_port not in s else "first"


def link(ctrl, dest, src, user):
    """A link frame with any control octet; equal to dnp3.link for 44h and C4h."""
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5 + len(user), ctrl, dest, src)
    out = hdr + dnp3.crc(hdr)
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + dnp3.crc(blk)
    return out


def header_only(length, ctrl, dest, src):
    hdr = b"\x05\x64" + struct.pack("<BBHH", length, ctrl, dest, src)
    return hdr + dnp3.crc(hdr)


def response(seq, iin=0, objects=b"", con=False):
    return bytes([0xC0 | (CON if con else 0) | (seq & 0x0F), dnp3.RESPONSE]) + struct.pack(">H", iin) + objects


def no05(label, n):
    """n octets with no 05 octet: SHA-256 in counter mode, 05 octets dropped."""
    out, i = bytearray(), 0
    while len(out) < n:
        out += bytes(b for b in hashlib.sha256(f"{label}:{i}".encode()).digest() if b != 0x05)
        i += 1
    return bytes(out[:n])


class Unit:
    __slots__ = ("flow", "end", "name", "data", "dir", "label", "msg")

    def __init__(self, flow, end, name, data, dirbit="-", label="valid", msg=None):
        self.flow, self.end, self.name, self.data, self.dir = flow, end, name, data, dirbit
        self.label, self.msg = label, msg


class Msg:
    __slots__ = ("name", "end", "code", "objects", "app", "state", "why")

    def __init__(self, name, end, code, objects, app, state="seen", why="-"):
        self.name, self.end, self.code, self.objects, self.app = name, end, code, objects, app
        self.state, self.why = state, why


class Capture:
    def __init__(self, name, index, kind):
        self.name, self.kind = name, kind
        self.clock = synth.Clock(start_ns=T_BASE + index * SPACING)
        self.flows, self.sent = [], []   # sent: (Unit list, frame) per packet that carries data


class Flow:
    """One 5-tuple between a master (m) and an outstation (o). first is the
    end whose packet the capture holds first. Each end's transport sequence
    and the master's application sequence run from the values given."""

    def __init__(self, cap, l4, master, mport, outstation, oport, first="m", handshake=True, tseq=(0, 0), app=0,
                 isn=(1000, 51000)):
        self.cap, self.l4, self.first = cap, l4, first
        self.handshake = l4 == "tcp" and handshake
        self.host = {"m": master, "o": outstation}
        self.port = {"m": mport, "o": oport}
        other = "o" if first == "m" else "m"
        c = synth.Host(self.host[first][0], self.host[first][1], self.port[first])
        s = synth.Host(self.host[other][0], self.host[other][1], self.port[other])
        if l4 == "udp":
            self.conv = synth.UDPConv(c, s, cap.clock, ident=isn[0])
        else:
            self.conv = synth.TCPConv(c, s, cap.clock, isn_c=isn[0], isn_s=isn[1], ident=isn[0])
            if handshake:
                self.conv.handshake()
        orig = first if zeek_orig(l4, self.port[first], self.port[other], l4 == "tcp" and handshake) == "first" \
            else other
        self.side = {orig: "orig", ("o" if orig == "m" else "m"): "resp"}
        self.tseq = {"m": tseq[0], "o": tseq[1]}
        self.app = app
        self.name = f"{l4} {self.host[first][1]}:{self.port[first]}>{self.host[other][1]}:{self.port[other]}"
        cap.flows.append(self)

    # --- units ---
    def frames(self, end, apdu, dirbit=None, sizes=None):
        """The link frames of one APDU from end: FIR on the first, FIN on the
        last, one transport octet each. dirbit defaults to the end's role."""
        dest, src = (self.host["o"][2], self.host["m"][2]) if end == "m" else (self.host["m"][2], self.host["o"][2])
        d = (end == "m") if dirbit is None else dirbit
        sizes = sizes or [len(apdu)]
        out, i = [], 0
        for k, n in enumerate(sizes):
            t = (FIR if k == 0 else 0) | (FIN if k == len(sizes) - 1 else 0) | self.tseq[end]
            self.tseq[end] = (self.tseq[end] + 1) & 0x3F
            out.append(link((0x80 if d else 0) | 0x44, dest, src, bytes([t]) + apdu[i:i + n]))
            i += n
        return out, ("1" if d else "0")

    def message(self, end, name, code, objects, apdu, dirbit=None, sizes=None, state="seen", why="-"):
        msg = Msg(name, end, code, objects, len(apdu), state, why)
        frames, d = self.frames(end, apdu, dirbit, sizes)
        names = [name] if len(frames) == 1 else [f"{name}/{k}" for k in range(1, len(frames) + 1)]
        return [Unit(self, end, n, fr, d, msg=msg) for n, fr in zip(names, frames)]

    def request(self, name, code, objects="-", body=b"", dirbit=None, end="m", sizes=None, state="seen", why="-"):
        seq, self.app = self.app, (self.app + 1) & 0x0F
        apdu = bytes([0xC0 | seq, code]) + body
        self.last = seq
        return self.message(end, name, code, objects, apdu, dirbit, sizes, state, why)

    def reply(self, name, iin=0, objects="-", body=b"", con=False, dirbit=None, seq=None):
        seq = self.last if seq is None else seq
        return self.message("o", name, dnp3.RESPONSE, objects, response(seq, iin, body, con), dirbit)

    def raw(self, end, name, data, label, dirbit="-"):
        return [Unit(self, end, name, data, dirbit, label=label)]

    # --- packets ---
    def send(self, units, gap_ns=None):
        """Each unit in a packet of its own."""
        for u in units:
            self.put([u], gap_ns)
            gap_ns = None

    def put(self, units, gap_ns=None):
        """One datagram or segment holding units, all from one end."""
        end = units[0].end
        assert all(u.end == end for u in units)
        data = b"".join(u.data for u in units)
        out = self.conv.send(end == self.first, data, gap_ns=gap_ns)
        self.cap.sent.append((units, out[0]))

    def close(self):
        if self.l4 == "tcp":
            self.conv.close()


# --- the stage-2 cases (design sections 4.1 and 4.2) -----------------------

def deadband():
    """W34: a deadband write (code 2, g34v1 index 0), dnp3-udp-unsolicited's write."""
    return dict(code=dnp3.WRITE, objects="g34v1", body=dnp3.deadband16(0, 100))


def iin_clear():
    """W80: the write of g80v1 index 7 that clears IIN1.7 (device restart)."""
    return dict(code=dnp3.WRITE, objects="g80v1", body=dnp3.iin_clear_restart())


def time_write(cap):
    """WT: a write of the time (code 2, g50v1), as GT-PCAP's time-sync cases write it."""
    return dict(code=dnp3.WRITE, objects="g50v1", body=dnp3.time_sync(cap.clock.ns // 1_000_000))


def relay_first(f, con=False):
    """R0: the relay's solicited 129, CON clear, answering a request the
    sensor missed (application sequence 0, the master's transport frame 0):
    the flow's first datagram, which needs no confirm (design section 4.2).
    With con, CON is set, for the malformed set's confirm on that side."""
    f.send(f.reply("R0", seq=0, con=con))


def relay_write(master_port):
    def build(cap):
        f = Flow(cap, "udp", M5, master_port, O1, 20000, first="o", tseq=(1, 0), app=1)
        relay_first(f)
        f.send(f.request("W34", **deadband()))
        f.send(f.reply("R(W34)"))
    return build


def relay_restart(cap):
    f = Flow(cap, "udp", M5, 20000, O1, 20000, first="o", tseq=(1, 0), app=1)
    relay_first(f)
    f.send(f.request("CR", COLD_RESTART))
    # An empty response: a real relay's carries a time delay object (g52), left
    # out so that no unmeasured object parser sits before the restart's effect.
    f.send(f.reply("R(CR)"))
    f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ), gap_ns=5_000_000_000)
    f.send(f.reply("R(P)", iin=0x8000))   # IIN1.7, device restart
    f.send(f.request("W80", **iin_clear()))
    f.send(f.reply("R(W80)"))


def master_short(cap):
    f = Flow(cap, "udp", M5, 20000, O1, 20000)
    f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ))
    # CON set with no objects, so that the confirm is owed and no unmeasured
    # object parser sits before it (a choice: a relay sets CON for events).
    f.send(f.reply("R(P)", con=True))
    f.send(f.message("m", "C", dnp3.CONFIRM, "-", bytes([0xC0 | f.last, dnp3.CONFIRM])))
    f.send(f.request("Q", dnp3.READ, "g60v2,g60v3,g60v4", Q_OBJ))
    f.send(f.reply("R(Q)"))
    f.send(f.request("CR", COLD_RESTART))
    f.send(f.reply("R(CR)"))
    f.send(f.request("W80", **iin_clear()))
    f.send(f.reply("R(W80)"))
    f.send(f.request("RCT", RECORD_CURRENT_TIME))
    f.send(f.reply("R(RCT)"))
    f.send(f.request("WT", **time_write(cap)))
    f.send(f.reply("R(WT)"))


def dir_spoof(l4):
    """A flow the master starts, with one frame from the master's address
    with DIR clear and a valid CRC: a direct operate with a control block."""
    def build(cap):
        f = Flow(cap, l4, M5 if l4 == "udp" else M1, 20000 if l4 == "udp" else cap.tcp_port, O1, 20000)
        f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ))
        f.send(f.reply("R(P)"))
        f.send(f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(0), dirbit=False))
        f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(0)))
        f.send(f.request("Q", dnp3.READ, "g60v2,g60v3,g60v4", Q_OBJ))
        f.send(f.reply("R(Q)"))
        f.close()
    return build


def tcp_master_short(cap):
    """A TCP connection whose originator is the outstation, O2 on 20001, and
    M1 on a port outside likely_server_ports: a sensor joining mid-stream, so
    the capture holds no SYN and no SYN-ACK. O2's one frame before M1's first
    is within the PIA's 1,024 octets and 100 packets."""
    f = Flow(cap, "tcp", M1, cap.tcp_port, O2, 20001, first="o", handshake=False, tseq=(1, 0), app=1,
             isn=(700_000, 900_000))
    f.send(f.reply("R1", con=True, seq=0))
    f.send(f.message("m", "C", dnp3.CONFIRM, "-", bytes([0xC0, dnp3.CONFIRM])))
    f.send(f.request("W34", **deadband()))
    f.send(f.reply("R(W34)"))
    f.send(f.request("CR", COLD_RESTART))
    f.send(f.reply("R(CR)"))
    f.send(f.request("W80", **iin_clear()))
    f.send(f.reply("R(W80)"))
    f.send(f.request("RCT", RECORD_CURRENT_TIME))
    f.send(f.reply("R(RCT)"))
    f.send(f.request("WT", **time_write(cap)))
    f.send(f.reply("R(WT)"))


def unsolicited_arrangement(mport, outstation, oport):
    """dnp3-udp-unsolicited's messages on another port arrangement (design
    section 1 item 2): O's unsolicited 130 first, M5's confirm, then M5's
    poll, direct operate and deadband write, each answered."""
    def build(cap):
        f = Flow(cap, "udp", M5, mport, outstation, oport, first="o")
        f.send(f.message("o", "U", dnp3.UNSOL_RESPONSE, "g2v2",
                         dnp3.unsolicited(0, objects=dnp3.binary_event(0, cap.clock.ns // 1_000_000))))
        f.send(f.message("m", "C", dnp3.CONFIRM, "-", dnp3.confirm(0)))
        f.send(f.request("P", dnp3.READ, "g60v1,g60v2,g60v3,g60v4", INTEGRITY))
        f.send(f.reply("R(P)"))
        f.send(f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(3)))
        f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(3)))
        f.send(f.request("W34", **deadband()))
        f.send(f.reply("R(W34)"))
    return build


INTEGRITY = G60[2] + G60[3] + G60[4] + G60[1]   # dnp3_cases.INTEGRITY

CASES = [
    ("dnp3-udp-relay-write", relay_write(20000)),
    ("dnp3-udp-relay-restart", relay_restart),
    ("dnp3-udp-master-short", master_short),
    ("dnp3-udp-dir-spoof", dir_spoof("udp")),
    ("dnp3-udp-swap-control", relay_write(41019)),
    ("dnp3-tcp-master-short", tcp_master_short),
    ("dnp3-tcp-dir-spoof", dir_spoof("tcp")),
    # D6's additions (design section 1 item 2): the third unswapped arrangement,
    # O2 off the set and M5 on 20000; and neither port in the set.
    ("dnp3-udp-relay-off-set", unsolicited_arrangement(20000, O2, 20001)),
    ("dnp3-udp-relay-both-off-set", unsolicited_arrangement(41021, O2, 20001)),
]


# --- the malformed set (design section 4.3) ---------------------------------

def opening(f):
    """P R: a read and its empty response, which confirm the flow."""
    f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ))
    f.send(f.reply("R(P)"))


def closing(f, name="Q"):
    """Q R: a read of classes 1 to 3 and its response, to show whether parsing goes on."""
    f.send(f.request(name, dnp3.READ, "g60v2,g60v3,g60v4", Q_OBJ))
    f.send(f.reply(f"R({name})"))


def udp_m(cap):
    return Flow(cap, "udp", M5, 20000, O1, 20000)


def udp_relay(cap, con=False):
    """A flow the relay starts, both ends on 20000: R0 first, as in the relay cases."""
    f = Flow(cap, "udp", M5, 20000, O1, 20000, first="o", tseq=(1, 0), app=1)
    relay_first(f, con)
    return f


def x_raw(data, label, end="m"):
    def build(cap):
        f = udp_m(cap)
        opening(f)
        f.send(f.raw(end, "X", data(f), label))
        closing(f)
    return build


def octets(n):
    """1 to 3 octets: the first octets of a header, a truncated header."""
    return x_raw(lambda f: (b"\x05\x64\x0b")[:n], f"truncated({n})")


def len_k(k, tail=b"\x00" * 6, label=None):
    """A header of link length k with a passing CRC (from m, DIR set), then tail."""
    def data(f):
        return header_only(k, 0xC4, f.host["o"][2], f.host["m"][2]) + tail
    return x_raw(data, label or f"len({k})")


def len_4_transport(t, label):
    """A header of link length 4 with a passing CRC, then one transport octet: 11 octets."""
    def data(f):
        tt = t | f.tseq["m"]
        f.tseq["m"] = (f.tseq["m"] + 1) & 0x3F
        return header_only(4, 0xC4, f.host["o"][2], f.host["m"][2]) + bytes([tt])
    return x_raw(data, label)


def len_5_trail(cap):
    """A link-only frame (M5's link status request) and W's whole frame in one datagram."""
    f = udp_m(cap)
    opening(f)
    lo = f.raw("m", "L", header_only(5, 0xC9, f.host["o"][2], f.host["m"][2]), "link-only")
    w = f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(0))
    f.put(lo + w)
    f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(0)))
    closing(f)


def len_6(cap):
    """A frame of link length 6: a transport octet and no application octet."""
    f = udp_m(cap)
    opening(f)
    f.send(f.message("m", "X", "-", "-", b"", state="absent", why="no application octet"))
    closing(f)


def app_octets(end, body, code, why, objects="-", state="absent"):
    """X: an APDU from end of the given octets after its control octet."""
    def build(cap):
        f = udp_m(cap)
        opening(f)
        seq = f.last
        f.send(f.message(end, "X", code, objects, bytes([0xC0 | seq]) + body, state=state, why=why))
        closing(f)
    return build


def hdr_crc(cap):
    """badhdr, as resync's builder-failures makes it: 05 64, the six header
    octets of M5's own P, a header CRC with its first octet inverted, six 00."""
    f = udp_m(cap)
    opening(f)
    h = b"\x05\x64" + struct.pack("<BBHH", 0x0B, 0xC4, f.host["o"][2], f.host["m"][2])
    c = dnp3.crc(h)
    f.send(f.raw("m", "X", h + bytes([c[0] ^ 0xFF, c[1]]) + bytes(6), "badhdr"))
    closing(f)


def chunk_crc(cap):
    """badchunk: a read's frame with its chunk CRC's first octet inverted."""
    f = udp_m(cap)
    opening(f)
    (u,) = f.request("X", dnp3.READ, "g60v1", P_OBJ, state="absent", why="damaged: its chunk CRC fails")
    at = len(u.data) - 2
    u.data, u.label = u.data[:at] + bytes([u.data[at] ^ 0xFF]) + u.data[at + 1:], "badchunk"
    f.send([u])
    closing(f)


def longer(cap):
    """A datagram longer than its frame: W's frame, then 5 octets with no 05."""
    f = udp_m(cap)
    opening(f)
    w = f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(0))
    f.put(w + f.raw("m", "T", no05(f"{cap.name}:tail", 5), "garbage(5)"))
    f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(0)))
    closing(f)


def two_frames(cap):
    """Two frames in one datagram: W and Q, then both responses, then a poll."""
    f = udp_m(cap)
    opening(f)
    w = f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(0))
    sw = f.last
    q = f.request("Q", dnp3.READ, "g60v2,g60v3,g60v4", Q_OBJ)
    f.put(w + q)
    f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(0), seq=sw))
    f.send(f.reply("R(Q)"))
    f.send(f.request("P2", dnp3.READ, "g60v1", P_OBJ))
    f.send(f.reply("R(P2)"))


def len_255(cap):
    """A read of 83 class objects in two frames: the first of the largest
    link length, 255 (target 292 octets), the second its last 2 octets."""
    f = udp_m(cap)
    opening(f)
    objs = b"".join(G60[1 + i % 4] for i in range(83))
    f.send(f.request("X", dnp3.READ, "g60v1,g60v2,g60v3,g60v4", objs, sizes=[249, 2]))
    f.send(f.reply("R(X)"))
    closing(f)


def nofir(cap):
    """A frame with FIN set and FIR clear, and 6 octets of object data (resync's nofir)."""
    f = udp_m(cap)
    opening(f)
    t = FIN | f.tseq["m"]
    f.tseq["m"] = (f.tseq["m"] + 1) & 0x3F
    data = link(0xC4, f.host["o"][2], f.host["m"][2], bytes([t]) + b"\x3c\x02\x06\x3c\x03\x06")
    f.send(f.raw("m", "X", data, "nofir", "1"))
    closing(f)


def nofin_fir(cap):
    """A fragment without FIN (frame 1 of a two-frame read, the control octet
    alone), then a new FIR: Q whole."""
    f = udp_m(cap)
    opening(f)
    us = f.request("X", dnp3.READ, "g60v1", P_OBJ, sizes=[1, len(P_OBJ) + 1], state="absent",
                   why="partial: only its first frame is sent")
    f.send(us[:1])
    closing(f)


def limit(cap):
    """A read beyond DNP3::max_application_layer_fragment_size: resync's
    overlimit, 102,649 application octets in 413 frames, one per datagram."""
    f = udp_m(cap)
    opening(f)
    body = b"\x01" + b"\x3c\x01\x06" * 34214 + b"\x3c\x02\x00\x00\x00"
    seq = f.app
    f.app = (f.app + 1) & 0x0F
    apdu = bytes([0xC0 | seq]) + body
    f.send(f.message("m", "X", dnp3.READ, "g60v1,g60v2", apdu, sizes=[249] * 411 + [61, 249], state="absent",
                     why="over the limit"))
    f.last = seq
    closing(f)


def dir_both(cap):
    """DIR set from both ends: every frame of O1's has DIR set."""
    f = udp_m(cap)
    f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ))
    f.send(f.reply("R(P)", dirbit=True))
    f.send(f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(0)))
    f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(0), dirbit=True))
    closing_dir(f, True)


def dir_change(cap):
    """DIR changing within one flow: O1's DIR clear, then set, then clear."""
    f = udp_m(cap)
    f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ))
    f.send(f.reply("R(P)"))
    f.send(f.request("W", dnp3.DIRECT_OPERATE, "g12v1", dnp3.crob(0)))
    f.send(f.reply("R(W)", objects="g12v1", body=dnp3.crob(0), dirbit=True))
    closing(f)


def closing_dir(f, dirbit):
    f.send(f.request("Q", dnp3.READ, "g60v2,g60v3,g60v4", Q_OBJ))
    f.send(f.reply("R(Q)", dirbit=dirbit))


def short(side, code, extra, why):
    """A master's message of 2 or 3 application octets, on the originator's
    side (a flow the master starts, after P R) or the responder's (a flow
    the relay starts, after R0)."""
    def build(cap):
        if side == "orig":
            f = udp_m(cap)
            f.send(f.request("P", dnp3.READ, "g60v1", P_OBJ))
            f.send(f.reply("R(P)", con=(code == dnp3.CONFIRM)))
            seq = f.last
        else:
            f = udp_relay(cap, con=(code == dnp3.CONFIRM))
            seq = 0
        if code == dnp3.CONFIRM:
            f.send(f.message("m", "X", code, "-", bytes([0xC0 | seq, code])))
        else:
            f.send(f.request("X", code, "-", extra, state="seen" if why == "-" else "absent", why=why))
        closing(f)
    return build


def tcp_open(cap):
    return Flow(cap, "tcp", M1, cap.tcp_port, O1, 20000)


def tcp_code_side(end, apdu_of, code, objects, dirbit, why):
    """On a TCP connection the master opens: P R, then X from end, then Q R, then the FIN exchange."""
    def build(cap):
        f = tcp_open(cap)
        opening(f)
        f.send(f.message(end, "X", code, objects, apdu_of(f), dirbit=dirbit, state="absent" if why != "-" else "seen",
                         why=why))
        closing(f)
        f.close()
    return build


def eof(kind, fin):
    """The TCP inputs that leave a header held when the connection ends
    (design section 4.3): P R, then X from M1, then M1's TCP FIN, or no
    FIN segment at all, so that the capture ends with the header held."""
    def build(cap):
        f = tcp_open(cap)
        opening(f)
        if kind == "firopen":
            us = f.request("X", dnp3.READ, "g60v1", P_OBJ, sizes=[1, len(P_OBJ) + 1], state="absent",
                           why="partial: only its first frame is sent")
            f.send(us[:1])
        elif kind == "badchunk":
            (u,) = f.request("X", dnp3.READ, "g60v1", P_OBJ, state="absent", why="damaged: its chunk CRC fails")
            at = len(u.data) - 2
            u.data, u.label = u.data[:at] + bytes([u.data[at] ^ 0xFF]) + u.data[at + 1:], "badchunk"
            f.send([u])
        else:
            t = FIR | f.tseq["m"]
            f.tseq["m"] = (f.tseq["m"] + 1) & 0x3F
            f.send(f.raw("m", "X", header_only(4, 0xC4, f.host["o"][2], f.host["m"][2]) + bytes([t]),
                         "len(4)+FIR"))
        if fin:
            f.close()
    return build


BADOBJ = b"\x00\x00\x3c"   # IIN 0, then one object octet: an object header cut short (D3's M1 on #718)


def badobj_first(l4):
    """X first on the 5-tuple (D3's M1; D1's 6907928324): M5's or M1's 129
    of 5 application octets, IIN then one object octet, then P R and Q R,
    whole and named, so a stop is told apart from nothing more to parse
    (condition 3 there). Over UDP, M5 and O1 on 20000: dpd_dnp3_server_udp
    attaches DNP3_UDP at X, and the PIA replays it (design 2.3). Over TCP,
    M1 opens a connection to O2 on 20001, both ports outside
    likely_server_ports, so no port attaches DNP3_TCP; dpd_dnp3_server does
    at R(P), the responder's first frame, and PIA_TCP replays X (design
    4.1), the path on which a TCP stop is recorded without (B')."""
    def build(cap):
        f = udp_m(cap) if l4 == "udp" else Flow(cap, "tcp", M1, cap.tcp_port, O2, 20001)
        f.send(f.message("m", "X", dnp3.RESPONSE, "-", bytes([0xC0 | f.app, dnp3.RESPONSE]) + BADOBJ,
                         state="absent", why="a response with 1 object octet: its object header cut short"))
        opening(f)
        closing(f)
        f.close()
    return build


def resp_apdu(n, objects=b""):
    """129 from the master's side: its first n application octets (2, 3 or
    4, IIN 0), or 4 and objects."""
    def apdu(f):
        a = bytes([0xC0 | f.last, dnp3.RESPONSE]) + b"\x00\x00"
        return a + objects if objects else a[:n]
    return apdu


def req_apdu(code, body=b""):
    return lambda f: bytes([0xC0 | f.last, code]) + body


MALFORMED = [
    ("dnp3-mal-udp-octets-1", octets(1)),
    ("dnp3-mal-udp-octets-2", octets(2)),
    ("dnp3-mal-udp-octets-3", octets(3)),
    ("dnp3-mal-udp-len-0", len_k(0)),
    ("dnp3-mal-udp-len-1", len_k(1)),
    ("dnp3-mal-udp-len-2", len_k(2)),
    ("dnp3-mal-udp-len-3", len_k(3)),
    ("dnp3-mal-udp-len-4-nofir", len_k(4, label="len(4)")),
    ("dnp3-mal-udp-len-4-firfin", len_4_transport(FIR | FIN, "len(4)+FIR+FIN")),
    ("dnp3-mal-udp-len-4-fir", len_4_transport(FIR, "len(4)+FIR")),
    ("dnp3-mal-udp-len-5-trail", len_5_trail),
    ("dnp3-mal-udp-len-6", len_6),
    ("dnp3-mal-udp-app-1-orig", app_octets("m", b"", "-", "1 application octet")),
    ("dnp3-mal-udp-app-1-resp", app_octets("o", b"", "-", "1 application octet")),
]
for _c in (129, 130, 131):
    for _n in (2, 3):
        for _side, _end in (("orig", "m"), ("resp", "o")):
            MALFORMED.append((f"dnp3-mal-udp-fc{_c}-{_n}-{_side}",
                              app_octets(_end, bytes([_c]) + b"\x00" * (_n - 2), _c,
                                         f"{_n} application octets, short of the 4-octet response header")))
MALFORMED += [
    ("dnp3-mal-udp-hdr-crc", hdr_crc),
    ("dnp3-mal-udp-chunk-crc", chunk_crc),
    ("dnp3-mal-udp-longer", longer),
    ("dnp3-mal-udp-two-frames", two_frames),
    ("dnp3-mal-udp-len-255", len_255),
    ("dnp3-mal-udp-nofir", nofir),
    ("dnp3-mal-udp-nofin-fir", nofin_fir),
    ("dnp3-mal-udp-limit", limit),
    ("dnp3-mal-udp-dir-both", dir_both),
    ("dnp3-mal-udp-dir-change", dir_change),
]
for _side in ("orig", "resp"):
    MALFORMED += [
        (f"dnp3-mal-udp-short-0-{_side}", short(_side, dnp3.CONFIRM, b"", "-")),
        (f"dnp3-mal-udp-short-13-{_side}", short(_side, COLD_RESTART, b"", "-")),
        (f"dnp3-mal-udp-short-13x-{_side}", short(_side, COLD_RESTART, b"\x00", "a trailing octet after an empty arm")),
        (f"dnp3-mal-udp-short-1x-{_side}", short(_side, dnp3.READ, b"\x3c", "1 object octet: throw")),
    ]
for _d, _dn in ((True, "set"), (False, "clear")):
    for _n, _obj, _nm in ((2, b"", "2"), (3, b"", "3"), (4, b"", "4"), (4, dnp3.crob(0), "4obj")):
        MALFORMED.append((f"dnp3-mal-tcp-fc129-{_nm}-dir{_dn}",
                          tcp_code_side("m", resp_apdu(_n, _obj), dnp3.RESPONSE, "g12v1" if _obj else "-", _d,
                                        "-" if _n >= 4 else f"{_n} application octets, short of the 4-octet "
                                                             "response header")))
    MALFORMED += [
        (f"dnp3-mal-tcp-fc0-resp-dir{_dn}", tcp_code_side("o", req_apdu(dnp3.CONFIRM), dnp3.CONFIRM, "-", _d, "-")),
        (f"dnp3-mal-tcp-fc13-resp-dir{_dn}", tcp_code_side("o", req_apdu(COLD_RESTART), COLD_RESTART, "-", _d, "-")),
        (f"dnp3-mal-tcp-fc2-resp-dir{_dn}", tcp_code_side("o", req_apdu(dnp3.WRITE, dnp3.iin_clear_restart()),
                                                         dnp3.WRITE, "g80v1", _d, "-")),
    ]
MALFORMED += [
    ("dnp3-mal-tcp-eof-firopen-fin", eof("firopen", True)),
    ("dnp3-mal-tcp-eof-firopen-open", eof("firopen", False)),
    ("dnp3-mal-tcp-eof-badchunk-fin", eof("badchunk", True)),
    ("dnp3-mal-tcp-eof-len4-fin", eof("len4", True)),
]
# Rule (A)'s edges (D3's M3 on #718, which D1's 6907176282 item 3 takes): a
# 129, 130 and 131 of exactly 4 octets, IIN 0, from each side. Appended, so
# that no earlier capture's clock or port moves.
for _c in (129, 130, 131):
    for _side, _end in (("orig", "m"), ("resp", "o")):
        MALFORMED.append((f"dnp3-mal-udp-fc{_c}-4-{_side}",
                          app_octets(_end, bytes([_c]) + b"\x00\x00", _c, "-", state="seen")))
MALFORMED += [
    ("dnp3-mal-udp-fc129-badobj-first", badobj_first("udp")),
    ("dnp3-mal-tcp-fc129-badobj-first", badobj_first("tcp")),
]


# --- the rows a case is judged on --------------------------------------------

E_COLUMNS = ["capture", "condition", "l4", "src", "sport", "dst", "dport", "code", "objects", "sa", "show", "frames",
             "protocol", "direction"]
NOT_REQUESTS = {dnp3.CONFIRM, dnp3.RESPONSE, dnp3.UNSOL_RESPONSE, dnp3.AUTH_RESPONSE}


def case_rows(cap):
    """A case's rows in engine-pass-conditions.tsv's columns, from how it was
    built, as engine_conditions.py derives them from a label: a protocol row
    per flow (its src the first sender; direction none over UDP, client-server
    with a handshake, midstream without), a service row at the outstation's
    end, and a function and an objects row per request of the master's that
    the builder labels seen, with its response's packet."""
    rows, numbers = [], {}
    order = {id(fr): n for n, fr in enumerate(frames_of(cap), 1)}
    seq = [(u, order[id(fr)]) for units, fr in cap.sent for u in units]
    for u, n in seq:
        numbers.setdefault(u.name, n)
    for f in cap.flows:
        first, other = f.first, ("o" if f.first == "m" else "m")
        direction = "none" if f.l4 == "udp" else ("client-server" if f.handshake else "midstream")
        rows.append([cap.name, "protocol", f.l4, f.host[first][1], str(f.port[first]), f.host[other][1],
                     str(f.port[other]), "", "", "", "", "", "dnp3", direction])
        rows.append([cap.name, "service", f.l4, "", "", f.host["o"][1], str(f.port["o"]), "", "", "", "",
                     str(min(n for u, n in seq if u.flow is f)), "dnp3", ""])
        done = set()
        for u, n in seq:
            m = u.msg
            if u.flow is not f or m is None or u.end != "m" or m.state != "seen" or id(m) in done:
                continue
            if m.code in NOT_REQUESTS:
                continue
            done.add(id(m))
            last = max(k for v, k in seq if v.msg is m)
            reply = numbers.get(f"R({m.name})")
            frames = f"{last},{reply}" if reply else str(last)
            objects = "" if m.objects == "-" else m.objects
            for cond in ("function", "objects") if objects else ("function",):
                rows.append([cap.name, cond, f.l4, f.host["m"][1], str(f.port["m"]), f.host["o"][1],
                             str(f.port["o"]), str(m.code), objects, "none", "", frames, "dnp3", direction])
        if cap.name == "dnp3-tcp-master-short":
            # The control for attachment and replay (design section 4.1, D6's
            # N-A): a link row from the originator, stamped with the time of
            # the master's first frame, which only the PIA's replay can write.
            rows.append([cap.name, "link", f.l4, f.host[first][1], str(f.port[first]), f.host[other][1],
                         str(f.port[other]), "", "", "",
                         f"a link row with is_orig true stamped with packet {numbers['C']}'s time",
                         f"{numbers['R1']},{numbers['C']}", "dnp3", direction])
    return rows


def build_cell(cap):
    """hr23-malformed.tsv's build cell: the data packets in order, | between
    packets and + between units in one packet; a run of packets that each
    hold the next frame of one message, as X/1 to X/413, is written X/1..X/413."""
    out = []
    for units, _ in cap.sent:
        name = "+".join(u.name for u in units)
        base, _, k = name.rpartition("/")
        prev = out[-1] if out else ""
        pbase, _, pk = prev.split("..")[-1].rpartition("/")
        if base and k.isdigit() and pbase == base and pk.isdigit() and int(k) == int(pk) + 1:
            first = prev.split("..")[0]
            out[-1] = f"{first}..{name}"
        else:
            out.append(name)
    return " | ".join(out)


# --- labels -----------------------------------------------------------------

def captures():
    """Every capture as a Capture, cases first, then the malformed inputs."""
    out, tcp_port = [], FIRST_TCP_PORT
    for index, (name, build) in enumerate(CASES + MALFORMED):
        cap = Capture(name, index, "case" if index < len(CASES) else "malformed")
        cap.tcp_port = None
        if "-tcp-" in name:
            cap.tcp_port, tcp_port = tcp_port, tcp_port + 1
        build(cap)
        out.append(cap)
    return out


def frames_of(cap):
    for f in cap.flows:
        ns = [fr.ns for fr in f.conv.frames]
        assert ns == sorted(ns), cap.name
    return sorted((fr for f in cap.flows for fr in f.conv.frames), key=lambda fr: fr.ns)


COLUMNS = ["capture", "flow", "end", "role", "dir", "side", "unit", "label", "packets", "octets", "message", "code",
           "objects", "app", "state", "why"]


def label_rows(cap):
    numbers = {id(fr): n for n, fr in enumerate(frames_of(cap), 1)}
    rows = []
    for units, fr in cap.sent:
        for u in units:
            m = u.msg
            rows.append([cap.name, u.flow.name, u.end, "master" if u.end == "m" else "outstation", u.dir,
                         u.flow.side[u.end], u.name, u.label, str(numbers[id(fr)]), str(len(u.data)),
                         m.name if m else "-", str(m.code) if m else "-", m.objects if m else "-",
                         str(m.app) if m else "-", m.state if m else "-", m.why if m else "-"])
    return rows


def header(cap):
    return [
        f"# GT-PCAP labels for {cap.name} (D6, brief P4-4-HR2325S, deliverable 1): HR-23's "
        + ("stage-2 case" if cap.kind == "case" else "malformed set")
        + ". The builder's, from how the capture was made; tshark's reading is reported beside them by "
          "hr23_tshark.py, never used as a label.",
        "# one row per link-layer unit, in the order sent. flow: the 5-tuple, its first sender first. end: m, the "
        "master's end, or o, the outstation's. role: whose the unit is, from the builder, whatever its DIR bit says "
        "(design section 4, opening). dir: the DIR bit as built, - for octets that are no frame.",
        "# side: the side Zeek gives that end, orig or resp (design section 1 items 1 and 2, with C0's "
        "likely_server_ports from run 43373373987). label: valid, or the damage the unit's octets carry.",
        "# packets: the 1-based packet that holds the unit. message, code, objects, app: the APDU the unit carries "
        "and its application octets. state: seen when the message is whole, valid and built to parse; absent "
        "otherwise, and why. The expectation under each configuration is the pin's (hr23-cases.tsv, "
        "hr23-malformed.tsv), not the label.",
        "\t".join(COLUMNS),
    ]


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    sums = []
    for cap in captures():
        rows = label_rows(cap)
        path = os.path.join(outdir, cap.name + ".pcap")
        pcapfile.write(path, frames_of(cap))
        with open(path, "rb") as f:
            sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {cap.name}.pcap")
        with open(os.path.join(outdir, cap.name + ".tsv"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(header(cap) + ["\t".join(r) for r in rows]) + "\n")
    with open(os.path.join(outdir, "hr23.sha256"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sums) + "\n")
    print(f"hr23_cases: {len(sums)} captures")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
