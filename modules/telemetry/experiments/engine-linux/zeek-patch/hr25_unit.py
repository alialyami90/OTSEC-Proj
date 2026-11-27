"""HR-25 option A, parts HR25-B1 and HR25-B2: D4's unit tests of the patch
and of its script part, on synthetic frames (brief P4-4-HR25 deliverable 3;
D4-124; brief HR25-B2).

These are D4's own inputs, named `d4u-hr25-*`. They are not GT-PCAP cases
and not D6's `dnp3-resync-*` cases, which D6 pins and which no part of this
file reads; no counted measurement reads these. Each input is written here
from D6's byte helpers (tests/integration/gt_pcap/dnp3.py, synth.py,
pcapfile.py), used as they are. Addresses are from TEST-NET-1 (RFC 5737).

Every test is run under C2A (`zeek-hr25-c2a`, the (i)+A build, with
probe.zeek and the script part zeek-patch/resync.zeek) and under the mutant
controls (`zeek-hr25-m-<name>`): C2A with one control patch of
zeek-patch/controls/hr25-*.patch each, or C2A's image with the script part
changed by one control patch of zeek-patch/controls/script-*.patch. A row
passes when C2A meets its expectation and every control the row names, each
of which breaks one rule of docs/phase4/D4-hr25-design.md sections 2.1 to
2.3, 2.7, 2.8 and 3.1, does not (the control is killed). A configuration
that did not run, or whose Zeek exited non-zero, fails the row: a crash is
never read as a kill. C2 (`zeek-hr25-c2`, the (i) build) is run beside each
row and printed as `ran` or `exit N` only, never judged (D1's ruling on
D4-131 item 5.1).

What a build did is read from four logs, as causes, counts and weird names
only (D1's ruling on D4-131 item 5.1): otsec_probe.log's `fc` rows (each
DNP3 application header, as (is_orig, function code), in order, with its
`resync_cause`) and its `resync` rows (each end's `why`, the delivery it
was written at, and its `counts`); weird.log's `dnp3_` names; and the count
of DNP3 violations in otsec_viol.log (viol.zeek). An expectation names the
whole `fc` list; the counts that are not zero, read from each end's last
resync row, every other count being zero; the resync rows in order; the
weird names with their number of rows; the fc rows that carry a cause; and
the violations. A capture of many flows (the host cap) is judged on its
rows' number by `why`, its overflow rows and its weirds.

Evidence class: the expectations are `desk`, from the design's rules. A
result, once a run that D1 rules reads these, is `simulated` (CI-Linux).

Usage: python -I hr25_unit.py write OUT
       python -I hr25_unit.py check OUT
       python -I hr25_unit.py script-controls   the script controls' names
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import dnp3  # noqa: E402
import pcapfile  # noqa: E402
import synth  # noqa: E402

C2A, C2 = "zeek-hr25-c2a", "zeek-hr25-c2"
# DNP3::max_application_layer_fragment_size, Zeek 9.0.1's default (100 *
# 1024, init-bare.zeek); neither the probe nor resync-unit.zeek redefines it.
LIMIT = 100 * 1024
# The closed set of causes, in the order of dnp3_resync's `counts` (design
# 2.8). test_hr25_unit.py checks it against the patch's own list.
CAUSES = ["magic", "header_crc", "link_length", "chunk_crc", "embedded_header", "first_chunk_missing",
          "fir_restart", "transport_seq", "fragment_limit", "app_parse", "gap", "truncated", "budget",
          "invariant"]

MASTER = synth.Host("02:00:00:00:00:0e", "192.0.2.14", 20000)
OUTSTATION = synth.Host("02:00:00:00:00:14", "192.0.2.20", 20000)
CLIENT_PORT = 40002
M_LINK, O_LINK = 1, 10
M, O = True, False

# Link control octets (DIR 80h, PRM 40h, FCB 20h, FCV 10h, function in the
# low four bits).
U_M = 0xC4   # master, primary, unconfirmed user data (function 4)
U_O = 0x44   # outstation, primary, unconfirmed user data
RST_M = 0xC0  # master, primary, Reset Link States (function 0), link-only
TEST_M = 0xD2  # master, primary, Test Link States (function 2, FCV set), link-only
ACK_O = 0x00  # outstation, secondary, ACK (function 0), link-only


def conf_m(fcb):
    """Master, primary, confirmed user data (function 3) with FCV set."""
    return 0xD3 | (0x20 if fcb else 0)


def tp(fir, fin, n):
    return (0x80 if fin else 0) | (0x40 if fir else 0) | (n & 0x3F)


def badhdr():
    """Ten octets whose magic passes and whose header CRC fails."""
    return b"\x05\x64\x0a\xc4\x0a\x00\x01\x00\x00\x00"


def garbage(n):
    """n octets of 11h, which hold no 05 64."""
    return bytes([0x11]) * n


def frame(from_m, ctrl, user, dest=None):
    """One link frame: the header with its CRC, then user data in 16-octet
    chunks, each with its CRC. `user` may be empty (a link-only frame)."""
    if dest is None:
        dest = O_LINK if from_m else M_LINK
    src = M_LINK if from_m else O_LINK
    hdr = b"\x05\x64" + bytes([5 + len(user), ctrl]) + dest.to_bytes(2, "little") + src.to_bytes(2, "little")
    out = hdr + dnp3.crc(hdr)
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + dnp3.crc(blk)
    return out


def seg(from_m, fir, fin, n, app, ctrl=None):
    """A frame holding one transport segment: the transport octet, then `app`."""
    if ctrl is None:
        ctrl = U_M if from_m else U_O
    return frame(from_m, ctrl, bytes([tp(fir, fin, n)]) + app)


def whole(from_m, n, apdu, ctrl=None):
    return seg(from_m, True, True, n, apdu, ctrl)


def link_only(from_m, ctrl):
    return frame(from_m, ctrl, b"")


def badchunk(from_m, n=7):
    """A whole one-frame read (or response) whose header passes and whose
    first chunk CRC fails."""
    b = bytearray(whole(from_m, n, Q if from_m else R(0)))
    b[10 + 1] ^= 0xFF
    return bytes(b)


def carrier():
    """A frame whose header passes and whose second chunk CRC fails, holding
    W's whole frame as its user data: an embedded header."""
    c = bytearray(frame(M, U_M, whole(M, 1, W)))
    c[10 + 16] ^= 0xFF
    return bytes(c)


# The messages. P and Q are reads (code 1), R(k) a response (129), W the
# master's direct operate (code 5, g12v1), which the tests split.
P = dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1))
Q = dnp3.request(3, dnp3.READ, dnp3.all_objects(60, 2))
W = dnp3.request(1, dnp3.DIRECT_OPERATE, dnp3.crob(0))
W1, W2, W3 = W[:1], W[1:8], W[8:]


def R(k):
    return dnp3.response(k)


# The one fragment these inputs make throw: a response of five application
# octets, IIN 0000h and one object octet, 3Ch, too short for its object
# header (D6's `badobj`, HR-23 design 4.7). Its fc row's place against the
# throw is the generated code's, not read, so an expectation allows both.
BADOBJ = dnp3.response(0, objects=b"\x3c")


class Either:
    """An fc list that may be any of the lists given."""

    def __init__(self, *alts):
        self.alts = [list(a) for a in alts]

    def __contains__(self, fc):
        return list(fc) in self.alts


# The fc rows of a flow P R | W R | Q R, and without W.
ALL = [(M, 1), (O, 129), (M, 5), (O, 129), (M, 1), (O, 129)]
NO_W = [(M, 1), (O, 129), (M, 1), (O, 129)]
NO_W_R = [(M, 1), (O, 129), (O, 129), (M, 1), (O, 129)]


class Flow:
    """One UDP 5-tuple, or one TCP connection after a full handshake, which
    the master opens, so the master is Zeek's originator. `send` puts its
    frames in one datagram or one segment, at the next tick of the clock or
    `at` seconds after the clock's start. `sent` keeps each delivery as
    (from the master, octets, time in ns)."""

    START = synth.Clock().ns

    def __init__(self, tcp=False, clock=None, port=None):
        self.clock = clock or synth.Clock()
        if tcp:
            a = synth.Host(MASTER.mac, MASTER.ip, CLIENT_PORT)
            self.conv = synth.TCPConv(a, OUTSTATION, self.clock)
            self.conv.handshake()
        else:
            m = MASTER if port is None else synth.Host(MASTER.mac, MASTER.ip, port)
            self.conv = synth.UDPConv(m, OUTSTATION, self.clock)
        self.sent = []

    def send(self, from_m, *frames, at=None):
        data = b"".join(frames)
        gap = None if at is None else self.START + round(at * 1e9) - self.clock.ns
        assert gap is None or gap > 0, "times must increase"
        fr = self.conv.send(from_m, data, gap_ns=gap)
        self.sent.append((from_m, data, fr[0].ns))
        return self

    def start(self, p_n=0):
        """P R, each end's first fragment."""
        return self.send(M, whole(M, p_n, P)).send(O, whole(O, 0, R(0)))

    def finish(self, q_n, with_r1=True):
        """R(1), the device's answer to W when it ran it, then Q R(2)."""
        if with_r1:
            self.send(O, whole(O, 1, R(1)))
        return self.send(M, whole(M, q_n, Q)).send(O, whole(O, 2, R(2)))


class Hosts:
    """Many UDP flows on one clock, in one capture: the host cap's inputs."""

    def __init__(self, n):
        self.clock = synth.Clock()
        self.flows = [Flow(clock=self.clock, port=40000 + i) for i in range(n)]

    @property
    def frames(self):
        return sorted((x for f in self.flows for x in f.conv.frames), key=lambda x: x.ns)


def reset(f):
    """Reset Link States from the master, and the outstation's ACK."""
    return f.send(M, link_only(M, RST_M)).send(O, link_only(O, ACK_O))


def ack(f):
    return f.send(O, link_only(O, ACK_O))


def changed(b):
    """b with its last octet inverted."""
    return b[:-1] + bytes([b[-1] ^ 0xFF])


def confirmed_w(f, w2_fin=False):
    """W1c and W2c, confirmed (FCB 1, then 0), each acknowledged. With
    w2_fin, W2c ends W (W1 and W2 + W3 as its two segments)."""
    f.send(M, seg(M, True, False, 1, W1, conf_m(1)))
    ack(f)
    f.send(M, seg(M, False, w2_fin, 2, W2 + W3 if w2_fin else W2, conf_m(0)))
    return f


def cases():
    """Each test's flow, by name."""
    out = {}

    # The wrap: W numbered 62, 63 and 0 (design 3.2 item 4).
    f = Flow().start(p_n=60)
    f.send(M, seg(M, True, False, 62, W1)).send(M, seg(M, False, False, 63, W2)).send(M, seg(M, False, True, 0, W3))
    out["d4u-hr25-wrap"] = f.finish(1)

    # F1 (design 3.2 item 1): I, a valid middle segment numbered neither
    # W1's + 1 nor W1's, between W's two frames; no response to W. Over UDP
    # and over TCP from the master's own stream (item 3).
    for name, tcp in (("d4u-hr25-f1", False), ("d4u-hr25-f1-tcp", True)):
        f = Flow(tcp).start()
        f.send(M, seg(M, True, False, 1, W1)).send(M, seg(M, False, False, 5, b"\x22"))
        f.send(M, seg(M, False, True, 2, W2 + W3))
        out[name] = f.finish(3, with_r1=False)

    # The in-sequence twin (item 2): I numbered W1's + 1, and W2 repeats it.
    f = Flow().start()
    f.send(M, seg(M, True, False, 1, W1)).send(M, seg(M, False, False, 2, b"\x22"))
    f.send(M, seg(M, False, True, 2, W2 + W3))
    out["d4u-hr25-in-sequence"] = f.finish(3, with_r1=False)

    # A link-layer retry of a middle segment, discarded (3.3,
    # link-retry-middle narrowed).
    f = reset(Flow().start())
    confirmed_w(f)
    ack(f)
    f.send(M, seg(M, False, False, 2, W2, conf_m(0)))
    ack(f)
    f.send(M, seg(M, False, True, 3, W3, conf_m(1)))
    ack(f)
    out["d4u-hr25-retry-middle"] = f.finish(4)

    # D3's C1 and its twins (item 9, 9a to 9c): D after W2c, a link-layer
    # retry by its control octet, whose segment differs from W2c's. The
    # device drops D at its link layer and runs W (R(1) follows).
    for name, d in (("d4u-hr25-retry-fin", seg(M, False, True, 2, W2, conf_m(0))),
                    ("d4u-hr25-retry-octet", seg(M, False, False, 2, changed(W2), conf_m(0))),
                    ("d4u-hr25-retry-shorter", seg(M, False, False, 2, W2[:-1], conf_m(0))),
                    ("d4u-hr25-retry-longer", seg(M, False, False, 2, W2 + b"\x00", conf_m(0)))):
        f = reset(Flow().start())
        confirmed_w(f)
        ack(f)
        f.send(M, d)
        ack(f)
        f.send(M, seg(M, False, True, 3, W3, conf_m(1)))
        ack(f)
        out[name] = f.finish(4)

    # Only a link-layer retry is discarded (item 18): an unconfirmed repeat
    # (18a), the FCB toggled (18b), and a repeat after Reset Link States
    # (18c). The device drops its fragment, so no R(1).
    f = Flow().start()
    f.send(M, seg(M, True, False, 1, W1)).send(M, seg(M, False, False, 2, W2)).send(M, seg(M, False, False, 2, W2))
    f.send(M, seg(M, False, True, 3, W3))
    out["d4u-hr25-unconfirmed-repeat"] = f.finish(4, with_r1=False)
    f = reset(Flow().start())
    confirmed_w(f)
    ack(f)
    f.send(M, seg(M, False, False, 2, W2, conf_m(1)))
    ack(f)
    f.send(M, seg(M, False, True, 3, W3, conf_m(0)))
    ack(f)
    out["d4u-hr25-fcb-toggled"] = f.finish(4, with_r1=False)
    f = reset(Flow().start())
    confirmed_w(f)
    ack(f)
    reset(f)
    f.send(M, seg(M, False, False, 2, W2, conf_m(0)))
    ack(f)
    f.send(M, seg(M, False, True, 3, W3, conf_m(1)))
    ack(f)
    out["d4u-hr25-repeat-after-reset"] = f.finish(4, with_r1=False)

    # link-retry-last (item 10): W2c ends W and is retried twice; 10a, a
    # frame without FIR between W2c and one retry; 10b, a retry with one
    # application octet changed.
    f = reset(Flow().start())
    confirmed_w(f, w2_fin=True)
    for _ in range(2):
        f.send(M, seg(M, False, True, 2, W2 + W3, conf_m(0)))
        ack(f)
    out["d4u-hr25-retry-last"] = f.finish(3)
    f = reset(Flow().start())
    confirmed_w(f, w2_fin=True)
    f.send(M, seg(M, False, False, 40, b"\x22"))
    f.send(M, seg(M, False, True, 2, W2 + W3, conf_m(0)))
    ack(f)
    out["d4u-hr25-retry-last-after-drop"] = f.finish(3)
    f = reset(Flow().start())
    confirmed_w(f, w2_fin=True)
    f.send(M, seg(M, False, True, 2, changed(W2 + W3), conf_m(0)))
    ack(f)
    out["d4u-hr25-retry-last-divergent"] = f.finish(3)

    # A full frame (250 octets of user data), accepted and copied: code 34,
    # whose request arm takes the rest of the data (`unknown`).
    full = dnp3.request(1, 34, bytes((i * 7 + 3) & 0xFF for i in range(247)))
    f = Flow().start()
    f.send(M, whole(M, 1, full))
    out["d4u-hr25-full-frame"] = f.finish(2)

    # A FIR whose number does not follow (item 11).
    f = Flow().start()
    f.send(M, whole(M, 9, W))
    out["d4u-hr25-fir-any-number"] = f.finish(10)

    # Per-end state (D3's C2, item 7): Ro1 opens a fragment on the
    # outstation's end, numbered other than W1, and Xo fails there.
    for name, tcp in (("d4u-hr25-per-end", False), ("d4u-hr25-per-end-tcp", True)):
        f = Flow(tcp).start()
        f.send(M, seg(M, True, False, 1, W1))
        f.send(O, seg(O, True, False, 20, R(1)[:2]))
        f.send(O, seg(O, False, False, 30, b"\x00"))
        f.send(M, seg(M, False, True, 2, W2 + W3))
        out[name] = f.finish(3)

    # A link-only frame inside a fragment leaves the state (item 14's rule;
    # link-only-mid-fragment): Test Link States between W's frames.
    for name, tcp in (("d4u-hr25-link-only-mid", False), ("d4u-hr25-link-only-mid-tcp", True)):
        f = Flow(tcp).start()
        f.send(M, seg(M, True, False, 1, W1)).send(M, link_only(M, TEST_M))
        f.send(M, seg(M, False, True, 2, W2 + W3))
        out[name] = f.finish(3)

    # A failed header inside a fragment leaves the state (design 3.1, its
    # second half): garbage between W's frames, over UDP and TCP.
    for name, tcp in (("d4u-hr25-failed-header-mid", False), ("d4u-hr25-failed-header-mid-tcp", True)):
        f = Flow(tcp).start()
        f.send(M, seg(M, True, False, 1, W1)).send(M, bytes([0x11]) * 16)
        f.send(M, seg(M, False, True, 2, W2 + W3))
        out[name] = f.finish(3)

    # A failed header consumes 1 octet (design 2.1; T9's first case): a
    # false 05 64, then W's frame 2 octets later, in one datagram.
    f = Flow().start()
    f.send(M, b"\x05\x64" + whole(M, 1, W))
    out["d4u-hr25-false-magic"] = f.finish(2)
    # The same with W at an odd offset (3), so a scan that consumes 2
    # octets steps over it (D6's B2 residual on #789).
    f = Flow().start()
    f.send(M, b"\x05\x64\x00" + whole(M, 1, W))
    out["d4u-hr25-false-magic-odd"] = f.finish(2)

    # A link-only frame goes on with the rest of the delivery (design 2.1,
    # R4): Test Link States, then W, in one datagram.
    f = Flow().start()
    f.send(M, link_only(M, TEST_M), whole(M, 1, W))
    out["d4u-hr25-link-only-then-w"] = f.finish(2)

    # Skip by length (design 2.2, R1): a frame whose chunk CRC fails, then
    # W, in one datagram; the octets after the failed frame are parsed.
    bad = bytearray(whole(M, 7, Q))
    bad[10 + 1] ^= 0xFF
    f = Flow().start()
    f.send(M, bytes(bad) + whole(M, 1, W))
    out["d4u-hr25-chunk-crc-then-w"] = f.finish(2)

    # The fragment-size limit (design 2.2, in application octets): a
    # fragment of exactly the limit passes, and one octet over is dropped.
    # Code 34, whose request arm takes the rest of the data, in segments of
    # 249 application octets, one frame per datagram.
    for name, extra in (("d4u-hr25-limit-equal", 0), ("d4u-hr25-limit-over", 1)):
        apdu = dnp3.request(1, 34, bytes((i * 7 + 3) & 0xFF for i in range(LIMIT + extra - 2)))
        parts = [apdu[i:i + 249] for i in range(0, len(apdu), 249)]
        f = Flow().start()
        for k, part in enumerate(parts):
            f.send(M, seg(M, k == 0, k == len(parts) - 1, (1 + k) % 64, part))
        out[name] = f.finish((1 + len(parts)) % 64, with_r1=not extra)

    # One test per cause that B1 reaches with a datagram (no control): a
    # failure, then W whole.
    f = Flow().start()
    f.send(M, bytes([0x11]) * 16).send(M, whole(M, 1, W))
    out["d4u-hr25-magic"] = f.finish(2)
    f = Flow().start()
    f.send(M, b"\x05\x64\x0a\xc4\x0a\x00\x01\x00\x00\x00" + whole(M, 1, W))
    out["d4u-hr25-header-crc"] = f.finish(2)
    # D2's C1: a header of length 4 whose CRC passes; consuming 1 octet
    # finds W at offset 8 only if its CRC octets are 05 64, which a builder
    # cannot choose without a search, so this test takes any passing CRC
    # and W follows the 10 octets: it shows the cause, not the offset.
    hdr = b"\x05\x64\x04\xc4\x0a\x00\x01\x00"
    f = Flow().start()
    f.send(M, hdr + dnp3.crc(hdr) + whole(M, 1, W))
    out["d4u-hr25-link-length"] = f.finish(2)
    # D2's C2: a frame whose header passes and whose chunk CRC fails, with
    # W's whole frame as its user data; W is flagged, never parsed.
    inner = whole(M, 1, W)
    carrier = bytearray(frame(M, U_M, inner))
    carrier[10 + 16] ^= 0xFF
    f = Flow().start()
    f.send(M, bytes(carrier))
    out["d4u-hr25-chunk-crc-embedded"] = f.finish(2, with_r1=False)
    # A frame cut by its datagram's end, then W.
    f = Flow().start()
    f.send(M, whole(M, 1, W)[:15]).send(M, whole(M, 1, W))
    out["d4u-hr25-truncated"] = f.finish(2)
    # A FIR while W1 is in progress: fir_restart, and the new W parsed.
    f = Flow().start()
    f.send(M, seg(M, True, False, 1, W1)).send(M, whole(M, 2, W))
    out["d4u-hr25-fir-restart"] = f.finish(3)
    # A frame without FIR and no fragment in progress, then W.
    f = Flow().start()
    f.send(M, seg(M, False, True, 7, b"\x22")).send(M, whole(M, 1, W))
    out["d4u-hr25-first-chunk-missing"] = f.finish(2)
    # TCP: W's frame split inside its header across two segments, and a
    # second W split inside its data: held, nothing counted.
    f = Flow(True).start()
    wf = whole(M, 1, W)
    f.send(M, wf[:4]).send(M, wf[4:])
    f.send(O, whole(O, 1, R(1)))
    f.send(M, wf[:17]).send(M, wf[17:])
    out["d4u-hr25-tcp-split"] = f.finish(2, with_r1=False)
    out.update(cases_b2())
    return out


def session(f, p_n=0):
    """P R | W R | Q R, each whole, after whatever f holds."""
    f.start(p_n)
    f.send(M, whole(M, (p_n + 1) % 64, W))
    return f.finish((p_n + 2) % 64)


def cases_b2():
    """HR25-B2's inputs: confirmation, the budget, the rows, the mark and the
    host cap (design 2.7, 2.8)."""
    out = {}

    # Confirmation at the first fragment that parses whole (design 2.7):
    # before it a failure is counted only, and raises no weird. A frame
    # whose header passes and whose chunk fails; a fragment's first frame,
    # then a frame out of sequence.
    f = Flow().send(M, badchunk(M))
    out["d4u-hr25-unconfirmed-chunk"] = session(f, 2)
    f = Flow().send(M, seg(M, True, False, 1, W1)).send(M, seg(M, False, False, 5, b"\x22"))
    out["d4u-hr25-unconfirmed-multi"] = session(f, 2)
    # A fragment that throws confirms nothing; its flow writes its end row
    # on app_parse, one of the six counts. The master sends Reset Link
    # States first, so that it is the originator.
    f = Flow().send(M, link_only(M, RST_M)).send(O, whole(O, 0, BADOBJ))
    out["d4u-hr25-throw-alone"] = f
    # A flow that never confirms writes an end row only on the six counts:
    # garbage (magic) writes none; a frame out of sequence writes one.
    out["d4u-hr25-unconfirmed-garbage"] = Flow().send(M, garbage(16))
    f = Flow().send(M, seg(M, True, False, 1, W1)).send(M, seg(M, False, False, 5, b"\x22"))
    out["d4u-hr25-unconfirmed-seq-only"] = f

    # The budget's bound F (val-F = 8), per connection: F - 1, F and F + 1
    # failed headers, one datagram each, then the session.
    for name, k in (("d4u-hr25-budget-f-minus-1", 7), ("d4u-hr25-budget-f", 8), ("d4u-hr25-budget-f-plus-1", 9)):
        f = Flow()
        for _ in range(k):
            f.send(M, badhdr())
        out[name] = session(f)
    # The two ends add up: four failed headers from each, alternating.
    f = Flow()
    for i in range(8):
        f.send(i % 2 == 0, badhdr())
    out["d4u-hr25-budget-split"] = session(f)
    # O (val-O = 2048), over TCP: O - 1, O and O + 1 octets of garbage in two
    # segments, one scan run, then the session.
    for name, k in (("d4u-hr25-budget-o-minus-1", 2047), ("d4u-hr25-budget-o", 2048), ("d4u-hr25-budget-o-plus-1", 2049)):
        f = Flow(True).send(M, garbage(1024)).send(M, garbage(k - 1024))
        out[name] = session(f)
    # An embedded header counts two, and the budget runs out mid-delivery:
    # four carriers and P in one datagram.
    f = Flow().send(M, *([carrier()] * 4), whole(M, 0, P))
    f.send(O, whole(O, 0, R(0))).send(M, whole(M, 1, W))
    out["d4u-hr25-budget-embedded"] = f.finish(2)
    # skip set by the analyzer, not left to dpd.zeek's 10 KiB: 11,000 octets
    # of link-only frames first.
    f = Flow()
    for _ in range(11):
        f.send(M, *([link_only(M, TEST_M)] * 100))
    for _ in range(8):
        f.send(M, badhdr())
    out["d4u-hr25-budget-over-10k"] = session(f)
    # A run of first_chunk_missing counts one and no octets: nine full
    # frames without FIR (2,628 octets).
    f = Flow()
    for k in range(9):
        f.send(M, seg(M, False, k == 8, 1 + k, bytes(249)))
    out["d4u-hr25-budget-fcm-run"] = session(f, 20)
    # Another cause ends the run: a frame without FIR and garbage, four
    # times, count eight.
    f = Flow()
    for k in range(4):
        f.send(M, seg(M, False, False, 10 + k, b"\x22")).send(M, garbage(16))
    out["d4u-hr25-budget-fcm-broken"] = session(f, 20)
    # transport_seq counts one, and only its own frame's octets: a fragment
    # of nine full frames, then a frame out of sequence; then three pairs of
    # a FIR frame (its transport octet alone) and a frame out of sequence.
    f = Flow()
    for k in range(9):
        f.send(M, seg(M, k == 0, False, 1 + k, bytes(249)))
    f.send(M, seg(M, False, False, 20, b"\x22"))
    for k in range(3):
        f.send(M, seg(M, True, False, 30 + k, b"")).send(M, seg(M, False, False, 40 + k, b"\x22"))
    out["d4u-hr25-budget-tseq"] = session(f, 50)
    # A link-layer retry discarded counts against neither: W in three
    # confirmed frames, its middle one retried eight times.
    f = reset(Flow())
    f.send(M, seg(M, True, False, 1, W1, conf_m(1)))
    ack(f)
    for _ in range(9):
        f.send(M, seg(M, False, False, 2, W2, conf_m(0)))
        ack(f)
    f.send(M, seg(M, False, True, 3, W3, conf_m(1)))
    ack(f)
    out["d4u-hr25-budget-retry"] = f.finish(4)

    # The first row at confirmation, on both ends (design 2.8).
    f = Flow().send(M, garbage(16)).send(O, garbage(16))
    out["d4u-hr25-first-both-ends"] = session(f)
    # The interval rows (DNP3::resync_report_interval, val-interval = 60 s),
    # anchored at the first row: a failure at 10 s and at 40 s; a read at
    # 69.999999 s, and one at 70 s, the interval's edge; none changed at 130 s;
    # a failure at 140 s; a delivery at 190 s.
    f = Flow().send(M, whole(M, 0, P), at=1).send(O, whole(O, 0, R(0)), at=1.01)
    f.send(M, badchunk(M), at=10).send(M, badchunk(M), at=40)
    f.send(M, whole(M, 1, P), at=69.999999)
    for k, t in ((2, 70), (3, 130)):
        f.send(M, whole(M, k, P), at=t).send(O, whole(O, k, R(k)), at=t + 0.01)
    f.send(M, badchunk(M), at=140)
    out["d4u-hr25-interval"] = f.send(M, whole(M, 4, P), at=190).send(O, whole(O, 4, R(4)), at=190.01)

    # The cause on the next fc row of its end (design 2.8): a chunk failure
    # on m, then two reads; a chunk failure on o, then a read; garbage on m,
    # then a read.
    f = Flow().start()
    f.send(M, badchunk(M)).send(M, whole(M, 1, P)).send(O, whole(O, 1, R(1)))
    f.send(M, whole(M, 2, P)).send(O, whole(O, 2, R(2)))
    f.send(O, badchunk(O)).send(M, whole(M, 3, P)).send(O, whole(O, 3, R(3)))
    out["d4u-hr25-mark"] = f.send(M, garbage(16)).send(M, whole(M, 4, P)).send(O, whole(O, 4, R(4)))

    # The host cap (val-K = 100): K, and K + 1, flows each confirmed, then
    # one chunk failure; one delivery at 85 s, past the first interval.
    for name, n in (("d4u-hr25-cap-k", 100), ("d4u-hr25-cap-k-plus-1", 101)):
        h = Hosts(n)
        for i, f in enumerate(h.flows):
            f.send(M, whole(M, 0, P), at=1 + 0.05 * i).send(O, whole(O, 0, R(0)), at=1.01 + 0.05 * i)
        for i, f in enumerate(h.flows):
            f.send(M, badchunk(M), at=10 + 0.05 * i)
        h.flows[0].send(M, link_only(M, TEST_M), at=85)
        out[name] = h
    return out


# Expectations: (case, rule, fc rows, non-zero counts as {(end, cause): n},
# controls). An end is "m" or "o".
EXPECT = [
    ("d4u-hr25-wrap", "append at tseq + 1, mod 64; off by one", ALL, {},
     ["no-mod64", "append-at-tseq", "append-at-tseq2"]),
    ("d4u-hr25-f1", "drop on any other number (F1 counted)", NO_W,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["no-seq-check"]),
    ("d4u-hr25-f1-tcp", "drop on any other number, TCP, the master's own stream", NO_W,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["no-seq-check"]),
    ("d4u-hr25-in-sequence", "every divergence counted: the repeat after an in-sequence I", NO_W,
     {("m", "transport_seq"): 1}, ["append-repeat"]),
    ("d4u-hr25-retry-middle", "a link-layer retry discarded", ALL, {}, ["count-every-repeat"]),
    ("d4u-hr25-retry-fin", "the whole segment compared: FIN differs", NO_W_R,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["cmp-number", "cmp-app-only"]),
    ("d4u-hr25-retry-octet", "the whole segment compared: one application octet differs", NO_W_R,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["cmp-number", "cmp-transport"]),
    ("d4u-hr25-retry-shorter", "the whole segment compared: one octet fewer", NO_W_R,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["cmp-number", "cmp-shorter"]),
    ("d4u-hr25-retry-longer", "the whole segment compared: one octet more", NO_W_R,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["cmp-number", "cmp-shorter"]),
    ("d4u-hr25-unconfirmed-repeat", "only a link-layer retry discarded: unconfirmed", NO_W,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["any-repeat"]),
    ("d4u-hr25-fcb-toggled", "only a link-layer retry discarded: FCB toggled", NO_W,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["ignore-fcb"]),
    ("d4u-hr25-repeat-after-reset", "only a link-layer retry discarded: after Reset Link States", NO_W,
     {("m", "transport_seq"): 1, ("m", "first_chunk_missing"): 1}, ["reset-keeps-fcb"]),
    ("d4u-hr25-retry-last", "identical retries after FIN discarded", ALL, {}, ["no-window", "window-once"]),
    ("d4u-hr25-retry-last-after-drop", "a drop ends the window", ALL,
     {("m", "first_chunk_missing"): 2}, ["drop-keeps-window"]),
    ("d4u-hr25-retry-last-divergent", "the whole segment compared, after FIN", ALL,
     {("m", "first_chunk_missing"): 1}, ["cmp-number", "cmp-transport"]),
    ("d4u-hr25-full-frame", "the 250-octet bound on last_seg (sizeof)",
     [(M, 1), (O, 129), (M, 34), (O, 129), (M, 1), (O, 129)], {}, ["seg-lt-250", "seg-249"]),
    ("d4u-hr25-fir-any-number", "a FIR frame accepts any number", ALL, {}, ["fir-checked"]),
    ("d4u-hr25-per-end", "per-end state", ALL, {("o", "transport_seq"): 1}, ["shared-tseq"]),
    ("d4u-hr25-per-end-tcp", "per-end state, TCP", ALL, {("o", "transport_seq"): 1}, ["shared-tseq"]),
    ("d4u-hr25-link-only-mid", "a link-only frame leaves the state; a length of 5 passes", ALL, {},
     ["linkonly-clears", "link-length-lt6"]),
    ("d4u-hr25-link-only-mid-tcp", "a link-only frame leaves the state, TCP", ALL, {},
     ["linkonly-clears", "link-length-lt6"]),
    ("d4u-hr25-failed-header-mid", "a failed header leaves the state", ALL, {("m", "magic"): 1}, ["scan-clears"]),
    ("d4u-hr25-failed-header-mid-tcp", "a failed header leaves the state, TCP", ALL, {("m", "magic"): 1},
     ["scan-clears"]),
    ("d4u-hr25-false-magic", "a failed header consumes 1 octet", ALL, {("m", "header_crc"): 1}, ["header-skip-10"]),
    ("d4u-hr25-false-magic-odd", "a failed header consumes 1 octet: W at an odd offset", ALL,
     {("m", "header_crc"): 1}, ["header-skip-2"]),
    ("d4u-hr25-link-only-then-w", "a link-only frame goes on with the rest of the delivery (R4)", ALL, {},
     ["linkonly-ends-delivery"]),
    ("d4u-hr25-chunk-crc-then-w", "skip by length: the octets after a failed frame are parsed (R1)", ALL,
     {("m", "chunk_crc"): 1}, ["chunk-crc-ends-delivery"]),
    ("d4u-hr25-limit-equal", "the fragment limit: a sum equal to it passes",
     [(M, 1), (O, 129), (M, 34), (O, 129), (M, 1), (O, 129)], {}, ["limit-ge"]),
    ("d4u-hr25-limit-over", "the fragment limit: one octet over is dropped", NO_W, {("m", "fragment_limit"): 1},
     ["limit-plus-one"]),
    ("d4u-hr25-magic", "cause magic, then W", ALL, {("m", "magic"): 1}, []),
    ("d4u-hr25-header-crc", "cause header_crc, the rest of the datagram scanned", ALL, {("m", "header_crc"): 1}, []),
    ("d4u-hr25-link-length", "cause link_length", ALL, {("m", "link_length"): 1}, []),
    ("d4u-hr25-chunk-crc-embedded", "cause chunk_crc, and the header inside the frame flagged", NO_W,
     {("m", "chunk_crc"): 1, ("m", "embedded_header"): 1}, []),
    ("d4u-hr25-truncated", "cause truncated", ALL, {("m", "truncated"): 1}, []),
    ("d4u-hr25-fir-restart", "cause fir_restart", ALL, {("m", "fir_restart"): 1}, []),
    ("d4u-hr25-first-chunk-missing", "cause first_chunk_missing", ALL, {("m", "first_chunk_missing"): 1}, []),
    ("d4u-hr25-tcp-split", "a frame split across segments is held", [(M, 1), (O, 129), (M, 5), (O, 129), (M, 5),
                                                                      (M, 1), (O, 129)], {}, []),
    # HR25-B2 (design 2.7 and 2.8).
    ("d4u-hr25-unconfirmed-chunk", "confirmed at a whole fragment; before it a failure raises no weird", ALL,
     {("m", "chunk_crc"): 1}, ["confirm-at-header", "weirds-before-confirm"]),
    ("d4u-hr25-unconfirmed-multi", "confirmed at a whole fragment, not at its first frame", ALL,
     {("m", "transport_seq"): 1}, ["confirm-at-fir"]),
    ("d4u-hr25-throw-alone", "a fragment that throws confirms nothing; its end row on app_parse",
     Either([], [(O, 129)]), {("o", "app_parse"): 1}, ["confirm-before-eof"]),
    ("d4u-hr25-unconfirmed-garbage", "a flow never confirmed: no end row on magic", [], {}, ["end-any-count"]),
    ("d4u-hr25-unconfirmed-seq-only", "a flow never confirmed: its end row on transport_seq", [],
     {("m", "transport_seq"): 1}, ["end-five"]),
    ("d4u-hr25-budget-f-minus-1", "the budget: F - 1 failures", ALL, {("m", "header_crc"): 7}, ["budget-f-7"]),
    ("d4u-hr25-budget-f", "the budget: F failures; its weird, row, one violation and skip", [],
     {("m", "header_crc"): 8, ("m", "budget"): 1}, ["budget-f-gt", "budget-no-violation", "budget-weird-gated"]),
    ("d4u-hr25-budget-f-plus-1", "the budget: F + 1 failures, reaching ends it", [],
     {("m", "header_crc"): 8, ("m", "budget"): 1}, ["budget-f-gt"]),
    ("d4u-hr25-budget-split", "the budget is per connection: the two ends add up", [],
     {("o", "header_crc"): 4, ("o", "budget"): 1}, ["budget-orig-only"]),
    ("d4u-hr25-budget-o-minus-1", "the budget: O - 1 octets", ALL, {("m", "magic"): 1}, ["budget-o-2047"]),
    ("d4u-hr25-budget-o", "the budget: O octets, the failed header's octet counted", [],
     {("m", "magic"): 1, ("m", "budget"): 1}, ["budget-o-gt", "scan-first-octet-free"]),
    ("d4u-hr25-budget-o-plus-1", "the budget: O + 1 octets, checked after each", [],
     {("m", "magic"): 1, ("m", "budget"): 1}, ["budget-o-gt"]),
    ("d4u-hr25-budget-embedded", "an embedded header counts two; out in the middle of a delivery", [],
     {("m", "chunk_crc"): 4, ("m", "embedded_header"): 4, ("m", "budget"): 1},
     ["embedded-free", "budget-at-delivery-end"]),
    ("d4u-hr25-budget-over-10k", "skip set by the analyzer, above dpd.zeek's 10 KiB", [],
     {("m", "header_crc"): 8, ("m", "budget"): 1}, ["budget-no-skip"]),
    ("d4u-hr25-budget-fcm-run", "a run of first_chunk_missing counts one and no octets", ALL,
     {("m", "first_chunk_missing"): 9}, ["fcm-each-charged", "fcm-octets-charged"]),
    ("d4u-hr25-budget-fcm-broken", "another cause ends a run of first_chunk_missing", [],
     {("m", "first_chunk_missing"): 4, ("m", "magic"): 4, ("m", "budget"): 1}, ["fcm-run-unbroken"]),
    ("d4u-hr25-budget-tseq", "transport_seq counts one, and only its own frame's octets", ALL,
     {("m", "transport_seq"): 4}, ["tseq-charges-fragment", "tseq-charges-two"]),
    ("d4u-hr25-budget-retry", "a discarded link-layer retry counts against neither", [(M, 5), (O, 129), (M, 1), (O, 129)],
     {}, ["retry-charged"]),
    ("d4u-hr25-first-both-ends", "the first rows at confirmation, on both ends", ALL,
     {("m", "magic"): 1, ("o", "magic"): 1}, ["no-first-at-confirm"]),
    ("d4u-hr25-interval", "interval rows: at the edge, once per interval, only on a change",
     [(M, 1), (O, 129), (M, 1), (M, 1), (O, 129), (M, 1), (O, 129), (M, 1), (O, 129)], {("m", "chunk_crc"): 3},
     ["interval-strict", "interval-twice", "interval-any-delivery",
      "interval-no-change-check"]),
    ("d4u-hr25-mark", "the cause on the next fc row of its end, once", [(M, 1), (O, 129)] * 5,
     {("m", "chunk_crc"): 1, ("m", "magic"): 1, ("o", "chunk_crc"): 1},
     ["mark-drop-only", "script-mark-kept", "script-mark-one-field"]),
    ("d4u-hr25-cap-k", "the host cap: K rows in an interval, no overflow row", None, None, ["script-cap-lt"]),
    ("d4u-hr25-cap-k-plus-1", "the host cap: K + 1, one overflow row, every row counted but it; sampling", None, None,
     ["script-cap-gt", "script-overflow-counted", "script-end-free", "script-no-sampling"]),
]
# A frame from the master is TCP's client and UDP's first sender: the
# originator. The fc rows of d4u-hr25-tcp-split: P R, W R(1), W, Q R(2).




def more(rows, weirds=None, marks=(), viol=0, scanned=None):
    return dict(rows=list(rows), weirds=dict(weirds or {}), marks=list(marks), viol=viol, scanned=dict(scanned or {}))


# The rest of each expectation (HR25-B2): each resync row as (end, why, the
# index of the delivery it was written at, or "end"), in order; the dnp3_
# weird names with their rows in weird.log; the fc rows that carry a cause,
# as (index among the fc rows, cause); the DNP3 violations; and, where
# named, each end's scanned octets in its last row. A host-cap input names
# its rows' number by why, its overflow rows' values in order, and its
# weirds.
MORE = {
    "d4u-hr25-wrap": more([]),
    "d4u-hr25-f1": more([('m', 'first', 3), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(2, 'first_chunk_missing')]),
    "d4u-hr25-f1-tcp": more([('m', 'first', 3), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(2, 'first_chunk_missing')]),
    "d4u-hr25-in-sequence": more([('m', 'first', 4), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1}, marks=[(2, 'transport_seq')]),
    "d4u-hr25-retry-middle": more([]),
    "d4u-hr25-retry-fin": more([('m', 'first', 8), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(3, 'first_chunk_missing')]),
    "d4u-hr25-retry-octet": more([('m', 'first', 8), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(3, 'first_chunk_missing')]),
    "d4u-hr25-retry-shorter": more([('m', 'first', 8), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(3, 'first_chunk_missing')]),
    "d4u-hr25-retry-longer": more([('m', 'first', 8), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(3, 'first_chunk_missing')]),
    "d4u-hr25-unconfirmed-repeat": more([('m', 'first', 4), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(2, 'first_chunk_missing')]),
    "d4u-hr25-fcb-toggled": more([('m', 'first', 8), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(2, 'first_chunk_missing')]),
    "d4u-hr25-repeat-after-reset": more([('m', 'first', 10), ('m', 'end', 'end')], weirds={'dnp3_transport_sequence': 1, 'dnp3_first_application_layer_chunk_missing': 1}, marks=[(2, 'first_chunk_missing')]),
    "d4u-hr25-retry-last": more([]),
    "d4u-hr25-retry-last-after-drop": more([('m', 'first', 7), ('m', 'end', 'end')], weirds={'dnp3_first_application_layer_chunk_missing': 1}, marks=[(4, 'first_chunk_missing')]),
    "d4u-hr25-retry-last-divergent": more([('m', 'first', 7), ('m', 'end', 'end')], weirds={'dnp3_first_application_layer_chunk_missing': 1}, marks=[(4, 'first_chunk_missing')]),
    "d4u-hr25-full-frame": more([]),
    "d4u-hr25-fir-any-number": more([]),
    "d4u-hr25-per-end": more([('o', 'first', 4), ('o', 'end', 'end')], weirds={'dnp3_transport_sequence': 1}, marks=[(3, 'transport_seq')]),
    "d4u-hr25-per-end-tcp": more([('o', 'first', 4), ('o', 'end', 'end')], weirds={'dnp3_transport_sequence': 1}, marks=[(3, 'transport_seq')]),
    "d4u-hr25-link-only-mid": more([]),
    "d4u-hr25-link-only-mid-tcp": more([]),
    "d4u-hr25-failed-header-mid": more([('m', 'first', 3), ('m', 'end', 'end')], weirds={'dnp3_header_lacks_magic': 1}, marks=[(4, 'magic')]),
    "d4u-hr25-failed-header-mid-tcp": more([('m', 'first', 3), ('m', 'end', 'end')], weirds={'dnp3_header_lacks_magic': 1}, marks=[(4, 'magic')]),
    "d4u-hr25-false-magic": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_corrupt_header_checksum': 1}, marks=[(2, 'header_crc')]),
    "d4u-hr25-false-magic-odd": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_corrupt_header_checksum': 1}, marks=[(2, 'header_crc')]),
    "d4u-hr25-link-only-then-w": more([]),
    "d4u-hr25-chunk-crc-then-w": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_corrupt_app_chunk_checksum': 1}, marks=[(2, 'chunk_crc')]),
    "d4u-hr25-limit-equal": more([]),
    "d4u-hr25-limit-over": more([('m', 'first', 413), ('m', 'end', 'end')], weirds={'dnp3_max_application_layer_fragment_size_exceeded': 1}, marks=[(2, 'fragment_limit')]),
    "d4u-hr25-magic": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_header_lacks_magic': 1}, marks=[(2, 'magic')]),
    "d4u-hr25-header-crc": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_corrupt_header_checksum': 1}, marks=[(2, 'header_crc')]),
    "d4u-hr25-link-length": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_invalid_link_length': 1}, marks=[(2, 'link_length')]),
    "d4u-hr25-chunk-crc-embedded": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_corrupt_app_chunk_checksum': 1, 'dnp3_embedded_header': 1}, marks=[(2, 'chunk_crc')]),
    "d4u-hr25-truncated": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_truncated_frame': 1}, marks=[(2, 'truncated')]),
    "d4u-hr25-fir-restart": more([('m', 'first', 3), ('m', 'end', 'end')], weirds={'dnp3_fragment_restarted': 1}, marks=[(2, 'fir_restart')]),
    "d4u-hr25-first-chunk-missing": more([('m', 'first', 2), ('m', 'end', 'end')], weirds={'dnp3_first_application_layer_chunk_missing': 1}, marks=[(2, 'first_chunk_missing')]),
    "d4u-hr25-tcp-split": more([]),
    "d4u-hr25-unconfirmed-chunk": more([('m', 'first', 1), ('m', 'end', 'end')], marks=[(0, 'chunk_crc')]),
    "d4u-hr25-unconfirmed-multi": more([('m', 'first', 2), ('m', 'end', 'end')], marks=[(0, 'transport_seq')]),
    "d4u-hr25-throw-alone": more([('o', 'end', 'end')]),
    "d4u-hr25-unconfirmed-garbage": more([]),
    "d4u-hr25-unconfirmed-seq-only": more([('m', 'end', 'end')]),
    "d4u-hr25-budget-f-minus-1": more([('m', 'first', 7), ('m', 'end', 'end')], marks=[(0, 'header_crc')]),
    "d4u-hr25-budget-f": more([('m', 'budget', 7)], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1),
    "d4u-hr25-budget-f-plus-1": more([('m', 'budget', 7)], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1),
    "d4u-hr25-budget-split": more([('o', 'budget', 7)], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1),
    "d4u-hr25-budget-o-minus-1": more([('m', 'first', 2), ('m', 'end', 'end')], marks=[(0, 'magic')], scanned={'m': 2047}),
    "d4u-hr25-budget-o": more([('m', 'budget', 2)], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1, scanned={'m': 2048}),
    "d4u-hr25-budget-o-plus-1": more([('m', 'budget', 2)], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1, scanned={'m': 2048}),
    "d4u-hr25-budget-embedded": more([('m', 'budget', 0), ('m', 'end', 'end')], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1),
    "d4u-hr25-budget-over-10k": more([('m', 'budget', 18)], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1),
    "d4u-hr25-budget-fcm-run": more([('m', 'first', 9), ('m', 'end', 'end')], marks=[(0, 'first_chunk_missing')]),
    "d4u-hr25-budget-fcm-broken": more([('m', 'budget', 7), ('m', 'end', 'end')], weirds={'dnp3_resync_budget_exhausted': 1}, viol=1),
    "d4u-hr25-budget-tseq": more([('m', 'first', 16), ('m', 'end', 'end')], marks=[(0, 'transport_seq')]),
    "d4u-hr25-budget-retry": more([]),
    "d4u-hr25-first-both-ends": more([('m', 'first', 2), ('o', 'first', 2), ('m', 'end', 'end'), ('o', 'end', 'end')], marks=[(0, 'magic'), (1, 'magic')]),
    "d4u-hr25-interval": more([('m', 'first', 2), ('m', 'interval', 5), ('m', 'interval', 10), ('m', 'end', 'end')], weirds={'dnp3_corrupt_app_chunk_checksum': 1}, marks=[(2, 'chunk_crc'), (7, 'chunk_crc')]),
    "d4u-hr25-mark": more([('m', 'first', 2), ('o', 'first', 7), ('m', 'end', 'end'), ('o', 'end', 'end')], weirds={'dnp3_corrupt_app_chunk_checksum': 1, 'dnp3_header_lacks_magic': 1}, marks=[(2, 'chunk_crc'), (7, 'chunk_crc'), (8, 'magic')]),
    "d4u-hr25-cap-k": dict(host=({'first': 100, 'end': 100}, [], {'dnp3_corrupt_app_chunk_checksum': 25})),
    "d4u-hr25-cap-k-plus-1": dict(host=({'first': 100, 'end': 100}, [1, 1], {'dnp3_corrupt_app_chunk_checksum': 25})),
}


def controls():
    """Every control a row names, in the order of first use."""
    out = []
    for row in EXPECT:
        for m in row[4]:
            if m not in out:
                out.append(m)
    return out


def patch_controls():
    """The controls that are A's patch with one control patch (an image
    each); the others change the script part."""
    return [m for m in controls() if not m.startswith("script-")]


def script_controls():
    return [m for m in controls() if m.startswith("script-")]


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, f in cases().items():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), f.frames if isinstance(f, Hosts) else f.conv.frames)


def rows(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.startswith("{")]


def us(t):
    return round(t * 1e6)


def reading(d, f):
    """(exit code, what the configuration did) on one input, or (exit
    code, None) when it left no probe log. Only causes, counts, weird names
    and the count of violations are read (D1's ruling on D4-131 item 5.1)."""
    p = os.path.join(d, "exit-code")
    code = open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None
    probe = rows(os.path.join(d, "otsec_probe.log"))
    if probe is None:
        return code, None
    weirds = {}
    for r in rows(os.path.join(d, "weird.log")) or []:
        if r.get("name", "").startswith("dnp3_"):
            weirds[r["name"]] = weirds.get(r["name"], 0) + 1
    resync = [r for r in probe if r.get("kind") == "resync"]
    if isinstance(f, Hosts):
        by_why, overflow = {}, []
        for r in resync:
            if r["why"] == "overflow":
                overflow.append(r["overflow"])
            else:
                by_why[r["why"]] = by_why.get(r["why"], 0) + 1
        return code, (by_why, overflow, weirds)
    fcrows = [r for r in probe if r.get("kind") == "fc"]
    fc = [(r["is_orig"], r["fc"]) for r in fcrows]
    marks = [(i, r["resync_cause"]) for i, r in enumerate(fcrows) if r.get("resync_cause")]
    at = {ns // 1000: i for i, (_, _, ns) in enumerate(f.sent)}
    out, counts, scanned = [], {}, {}
    for r in resync:
        end = "m" if r["is_orig"] else "o"
        out.append((end, r["why"], "end" if r["why"] == "end" else at.get(us(r["ts"]), "?")))
        counts = {k: v for k, v in counts.items() if k[0] != end}
        counts.update({(end, c): n for c, n in zip(CAUSES, r["counts"]) if n})
        scanned[end] = r["scanned_octets"]
    viol = sum(1 for r in rows(os.path.join(d, "otsec_viol.log")) or [] if "DNP3" in r.get("analyzer", ""))
    return code, (fc, counts, out, weirds, marks, viol, scanned)


def meets(row, got):
    """Whether a reading meets a row's expectation."""
    case, _, want_fc, want_counts, _ = row
    m = MORE[case]
    if "host" in m:
        return tuple(got) == m["host"]
    fc, counts, out, weirds, marks, viol, scanned = got
    fc_ok = fc in want_fc if isinstance(want_fc, Either) else list(fc) == list(want_fc)
    return (fc_ok and counts == want_counts and out == m["rows"] and weirds == m["weirds"]
            and marks == m["marks"] and viol == m["viol"]
            and all(scanned.get(e) == n for e, n in m["scanned"].items()))


def state(d, row, f):
    """`not run`, `exit N`, `met` or `not met`."""
    code, got = reading(d, f)
    if code is None or got is None:
        return "not run"
    if code != "0":
        return f"exit {code}"
    return "met" if meets(row, got) else "not met"


def ran(d):
    """C2's column: whether it ran, and its exit code, never more (D1's
    ruling on D4-131 item 5.1)."""
    p = os.path.join(d, "exit-code")
    if not os.path.exists(p):
        return "not run"
    code = open(p, encoding="utf-8").read().strip()
    return "ran" if code == "0" else f"exit {code}"


def verdict(c2a, ctl):
    """pass when C2A meets the row and every control is killed (`not met`)."""
    if c2a != "met":
        return f"FAIL (C2A {c2a})"
    bad = [f"{m} {s}" for m, s in ctl if s != "not met"]
    return "FAIL (" + "; ".join(bad) + ")" if bad else "pass"


def check(out):
    rc = 0
    flows = cases()
    print("| input | rule | C2A | controls (each must be killed: not met) | C2 | result |")
    print("| --- | --- | --- | --- | --- | --- |")
    for row in EXPECT:
        case, rule, ctl_names = row[0], row[1], row[4]
        base = os.path.join(out, case)
        f = flows[case]
        c2a = state(os.path.join(base, C2A), row, f)
        ctl = [(m, state(os.path.join(base, "zeek-hr25-m-" + m), row, f)) for m in ctl_names]
        v = verdict(c2a, ctl)
        if v != "pass":
            rc = 1
        cs = "; ".join(f"{m}: {s}" for m, s in ctl) or "none"
        print(f"| {case} | {rule} | {c2a} | {cs} | {ran(os.path.join(base, C2))} | {v} |")
    return rc


if __name__ == "__main__":
    if sys.argv[1:] == ["script-controls"]:
        print(" ".join(script_controls()))
    elif len(sys.argv) != 3 or sys.argv[1] not in ("write", "check"):
        sys.exit(__doc__)
    elif sys.argv[1] == "write":
        write(sys.argv[2])
    else:
        sys.exit(check(sys.argv[2]))
