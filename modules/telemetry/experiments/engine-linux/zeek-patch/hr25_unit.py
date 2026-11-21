"""HR-25 option A, part HR25-B1: D4's unit tests of the patch, on synthetic
frames (brief P4-4-HR25 deliverable 3; D4-124).

These are D4's own inputs, named `d4u-hr25-*`. They are not GT-PCAP cases
and not D6's `dnp3-resync-*` cases, which D6 pins and which no part of this
file reads; no counted measurement reads these. Each input is written here
from D6's byte helpers (tests/integration/gt_pcap/dnp3.py, synth.py,
pcapfile.py), used as they are. Addresses are from TEST-NET-1 (RFC 5737).

Every test is run under C2A (`zeek-hr25-c2a`, the (i)+A build) and under
the mutant controls of zeek-patch/controls/hr25-*.patch (`zeek-hr25-m-<name>`,
C2A with one control patch each). A row passes when C2A meets its
expectation and every control the row names, each of which breaks one rule
of docs/phase4/D4-hr25-design.md sections 2.1, 2.2 and 3.1, does not (the
control is killed). A configuration that did not run, or whose Zeek exited non-zero,
fails the row: a crash is never read as a kill. C2 (`zeek-hr25-c2`, the (i)
build) is quoted beside each row, never judged.

What a build did is read from two logs: the probe log's `fc` rows (each
DNP3 application header, as (is_orig, function code), in order), and
otsec_resync_unit.log (resync-unit.zeek), one row per dnp3_resync event,
whose `counts` are in the closed set's order. An expectation names the
whole `fc` list, and the counts that are not zero; every other count must
be zero on both ends.

Evidence class: the expectations are `desk`, from the design's rules. A
result, once a run that D1 rules reads these, is `simulated` (CI-Linux).

Usage: python -I hr25_unit.py write OUT
       python -I hr25_unit.py check OUT
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


# The messages. P and Q are reads (code 1), R(k) a response (129), W the
# master's direct operate (code 5, g12v1), which the tests split.
P = dnp3.request(0, dnp3.READ, dnp3.all_objects(60, 1))
Q = dnp3.request(3, dnp3.READ, dnp3.all_objects(60, 2))
W = dnp3.request(1, dnp3.DIRECT_OPERATE, dnp3.crob(0))
W1, W2, W3 = W[:1], W[1:8], W[8:]


def R(k):
    return dnp3.response(k)


# The fc rows of a flow P R | W R | Q R, and without W.
ALL = [(M, 1), (O, 129), (M, 5), (O, 129), (M, 1), (O, 129)]
NO_W = [(M, 1), (O, 129), (M, 1), (O, 129)]
NO_W_R = [(M, 1), (O, 129), (O, 129), (M, 1), (O, 129)]


class Flow:
    """One UDP 5-tuple, or one TCP connection after a full handshake, which
    the master opens, so the master is Zeek's originator. `send` puts its
    frames in one datagram or one segment."""

    def __init__(self, tcp=False):
        self.clock = synth.Clock()
        if tcp:
            a = synth.Host(MASTER.mac, MASTER.ip, CLIENT_PORT)
            self.conv = synth.TCPConv(a, OUTSTATION, self.clock)
            self.conv.handshake()
        else:
            self.conv = synth.UDPConv(MASTER, OUTSTATION, self.clock)
        self.sent = []

    def send(self, from_m, *frames):
        data = b"".join(frames)
        self.conv.send(from_m, data)
        self.sent.append((from_m, data))
        return self

    def start(self, p_n=0):
        """P R, each end's first fragment."""
        return self.send(M, whole(M, p_n, P)).send(O, whole(O, 0, R(0)))

    def finish(self, q_n, with_r1=True):
        """R(1), the device's answer to W when it ran it, then Q R(2)."""
        if with_r1:
            self.send(O, whole(O, 1, R(1)))
        return self.send(M, whole(M, q_n, Q)).send(O, whole(O, 2, R(2)))


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
    f.send(M, b"d" + whole(M, 1, W))
    out["d4u-hr25-false-magic"] = f.finish(2)

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
]
# A frame from the master is TCP's client and UDP's first sender: the
# originator. The fc rows of d4u-hr25-tcp-split: P R, W R(1), W, Q R(2).


def controls():
    """Every control a row names, in the order of first use."""
    out = []
    for row in EXPECT:
        for m in row[4]:
            if m not in out:
                out.append(m)
    return out


def write(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, f in cases().items():
        pcapfile.write(os.path.join(outdir, name + ".pcap"), f.conv.frames)


def rows(path):
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return [json.loads(x) for x in fh if x.startswith("{")]


def reading(d):
    """(exit code, fc rows, counts) of one configuration on one input, or
    (exit code, None, None) when it left no probe log. counts maps (end,
    cause) to n, for the counts that are not zero."""
    p = os.path.join(d, "exit-code")
    code = open(p, encoding="utf-8").read().strip() if os.path.exists(p) else None
    probe = rows(os.path.join(d, "otsec_probe.log"))
    if probe is None:
        return code, None, None
    fc = [(r["is_orig"], r["fc"]) for r in probe if r.get("kind") == "fc"]
    counts = {}
    for r in rows(os.path.join(d, "otsec_resync_unit.log")) or []:
        if r.get("why") != "end":
            continue
        end = "m" if r["is_orig"] else "o"
        for cause, n in zip(CAUSES, r["counts"]):
            if n:
                counts[(end, cause)] = n
    return code, fc, counts


def state(d, want_fc, want_counts):
    """`not run`, `exit N`, `met` or `not met`."""
    code, fc, counts = reading(d)
    if code is None or fc is None:
        return "not run"
    if code != "0":
        return f"exit {code}"
    return "met" if fc == want_fc and counts == want_counts else "not met"


def verdict(c2a, ctl):
    """pass when C2A meets the row and every control is killed (`not met`)."""
    if c2a != "met":
        return f"FAIL (C2A {c2a})"
    bad = [f"{m} {s}" for m, s in ctl if s != "not met"]
    return "FAIL (" + "; ".join(bad) + ")" if bad else "pass"


def check(out):
    rc = 0
    print("| input | rule | C2A | controls (each must be killed: not met) | C2, quoted | result |")
    print("| --- | --- | --- | --- | --- | --- |")
    for case, rule, want_fc, want_counts, ctl_names in EXPECT:
        base = os.path.join(out, case)
        c2a = state(os.path.join(base, C2A), want_fc, want_counts)
        ctl = [(m, state(os.path.join(base, "zeek-hr25-m-" + m), want_fc, want_counts)) for m in ctl_names]
        c2 = state(os.path.join(base, C2), want_fc, {})
        v = verdict(c2a, ctl)
        if v != "pass":
            rc = 1
        cs = "; ".join(f"{m}: {s}" for m, s in ctl) or "none"
        print(f"| {case} | {rule} | {c2a} | {cs} | {c2} (fc rows only) | {v} |")
    return rc


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("write", "check"):
        sys.exit(__doc__)
    if sys.argv[1] == "write":
        write(sys.argv[2])
    else:
        sys.exit(check(sys.argv[2]))
