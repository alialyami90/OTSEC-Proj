"""The dnp3-resync-* builder against its pinned rows (D6, brief P4-4-HR25, deliverable 3).

resync_cases.py writes every case and twin of resync-cases.tsv. This test
checks what it writes against the rows that pin it, from the bytes on the
wire: the captures and labels are the committed ones, every case and twin is
there, the wire is valid, the solved headers and S5 input (7)'s frame are
the rows' octets, every failure is made as builder-failures says, the
application and transport sequences and the endpoints are builder-msgs',
builder-limit's and builder-join's arithmetic holds, the twins differ from
their case only as judge-twins says, and the timed cases keep their times.
The expected bytes are made here from dnp3.py, not taken from the builder's
helpers. Each check has a named control: a mutant of the built bytes or of
the builder that the check must fail. Stdlib only and no tshark, so it runs
in CI's python job; resync_tshark.py is tshark's half.
"""

import hashlib
import os
import re
import struct

import pytest

import dnp3
import pcapfile
import resync_cases as rc
import synth

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "fixtures", "network", "gt-pcap",
                        "resync")
ROWS = {r["case"]: r for r in rc.CASES}
COND = rc.CONDITIONS
_CAPS = []


def caps():
    if not _CAPS:
        _CAPS.append({cap.name: (case, cap) for case, cap in rc.captures()})
    return _CAPS[0]


def cap(name):
    return caps()[name][1]


# --- reading the wire ------------------------------------------------------

def parse(fr):
    """(src ip, dst ip, proto, sport, dport, seq, ack, flags, payload) of an Ethernet IPv4 frame."""
    d = fr.data
    assert d[12:14] == b"\x08\x00"
    ihl = (d[14] & 0x0F) * 4
    total = struct.unpack("!H", d[16:18])[0]
    t = 14 + ihl
    proto = d[23]
    sport, dport = struct.unpack("!HH", d[t:t + 4])
    if proto == synth.UDP:
        return d[26:30], d[30:34], proto, sport, dport, None, None, None, d[t + 8:14 + total]
    seq, ack = struct.unpack("!II", d[t + 4:t + 12])
    off = (d[t + 12] >> 4) * 4
    return d[26:30], d[30:34], proto, sport, dport, seq, ack, d[t + 13], d[t + off:14 + total]


def ones_complement_ok(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def delivered(c, unit):
    """Each (payload, offset) where a piece of the named unit sits, in order."""
    out = []
    for d in c.deliveries:
        off = 0
        for u, a, b in d.pieces:
            if u.name == unit and not d.lost:
                out.append((parse(d.frame)[-1], off, u, a, b))
            off += b - a
    return out


def units(c, pred=lambda u: True):
    seen, out = set(), []
    for d in c.deliveries:
        for u, _, _ in d.pieces:
            if id(u) not in seen and pred(u):
                seen.add(id(u))
                out.append(u)
    return out


# --- the expected bytes, from dnp3.py --------------------------------------

M_LINK = {"udp": 5, "tcp": 1}


def frame_from(end, l4, user, ctrl=None):
    dest, src = (10, M_LINK[l4]) if end == "m" else (M_LINK[l4], 10)
    if ctrl is None:
        return dnp3.link(dest, src, end == "m", user)
    return rc.link_frame(ctrl, dest, src, user)


def app_of(frame):
    """A frame's user data without its CRCs."""
    out, i = b"", 10
    while i < len(frame):
        n = min(16, len(frame) - i - 2)
        out += frame[i:i + n]
        i += n + 2
    return out


def crcs_ok(frame):
    """(header CRC good, [each chunk CRC good])."""
    out, i = [], 10
    while i < len(frame):
        n = min(16, len(frame) - i - 2)
        out.append(dnp3.crc(frame[i:i + n]) == frame[i + n:i + n + 2])
        i += n + 2
    return dnp3.crc(frame[:8]) == frame[8:10], out


P_OBJ = dnp3.all_objects(60, 1)
Q_OBJ = dnp3.all_objects(60, 2) + dnp3.all_objects(60, 3) + dnp3.all_objects(60, 4)


# --- inventory -------------------------------------------------------------

IRREGULAR = {
    "dnp3-resync-udp-weird-burst", "dnp3-resync-tcp-r2-midstream", "dnp3-resync-tcp-r2-midstream-both",
    "dnp3-resync-udp-join-response", "dnp3-resync-tcp-join-response", "dnp3-resync-udp-budget-split-ends-minus-1",
    "dnp3-resync-udp-budget-split-ends", "dnp3-resync-udp-budget-over-10k", "dnp3-resync-tcp-gap-header",
    "dnp3-resync-tcp-gap-data", "dnp3-resync-tcp-gap-middle-frame", "dnp3-resync-tcp-gap-non-dnp3",
    "dnp3-resync-udp-report-interval", "dnp3-resync-udp-report-cap", "dnp3-resync-udp-report-mark-state",
}


def test_every_case_and_twin_is_built_and_nothing_else():
    want = set()
    for r in rc.CASES:
        want.add(r["case"])
        if r["twins"] != "-":
            want |= {f"{r['case']}--{t}" for t in r["twins"].split(",")}
    want.add("dnp3-resync-udp-report-mark-state--control")
    assert set(caps()) == want and len(want) == 112 + 189 + 1
    # The prose cells are exactly these, and every other cell is read token by token.
    assert set(rc.IRREGULAR) == IRREGULAR
    for r in rc.CASES:
        if r["case"] not in IRREGULAR:
            rc.parse(r["build"])


def test_the_committed_hashes_and_labels_are_the_builders(tmp_path):
    rc.main(str(tmp_path))
    with open(os.path.join(FIXTURES, "resync.sha256"), encoding="utf-8") as f:
        pinned = f.read()
    with open(tmp_path / "resync.sha256", encoding="utf-8") as f:
        assert f.read() == pinned
    for line in pinned.splitlines():
        digest, name = line.split("  ")
        with open(tmp_path / name, "rb") as f:
            assert hashlib.sha256(f.read()).hexdigest() == digest, name
    committed = sorted(n for n in os.listdir(FIXTURES) if n.endswith(".tsv"))
    assert committed == sorted(r["case"] + ".tsv" for r in rc.CASES)
    for name in committed:
        with open(os.path.join(FIXTURES, name), "rb") as a, open(tmp_path / name, "rb") as b:
            assert a.read().replace(b"\r\n", b"\n") == b.read(), name


# --- the wire --------------------------------------------------------------

def check_wire(c):
    """Valid IPv4, UDP and TCP; TEST-NET ends; builder-msgs' ports; each
    packet's payload is the pieces sent in it."""
    row = ROWS[c.case]
    m_ip = bytes([192, 0, 2, 14 if row["l4"] == "udp" else 10])
    o_ip = bytes([192, 0, 2, 20])
    numbers = {id(fr): n for n, fr in enumerate(c.frames(), 1)}
    for fr in c.frames():
        src, dst, proto, sport, dport, *_, payload = parse(fr)
        ihl = (fr.data[14] & 0x0F) * 4
        assert ones_complement_ok(fr.data[14:14 + ihl]), c.name
        total = struct.unpack("!H", fr.data[16:18])[0]
        seg = fr.data[14 + ihl:14 + total]
        assert ones_complement_ok(fr.data[26:34] + struct.pack("!BBH", 0, proto, len(seg)) + seg), c.name
        assert {src, dst} == {m_ip, o_ip} and len(fr.data) >= 60, c.name
        mport, oport = (sport, dport) if src == m_ip else (dport, sport)
        assert oport == 20000, c.name
        if row["l4"] == "udp":
            assert proto == synth.UDP
            assert mport == 20000 or c.case in ("dnp3-resync-udp-report-cap", "dnp3-resync-udp-report-mark-state")
        else:
            assert proto == synth.TCP and mport == c.tcp_port
    for d in c.deliveries:
        if not d.lost:
            assert parse(d.frame)[-1] == b"".join(u.data[a:b] for u, a, b in d.pieces), (c.name, numbers[id(d.frame)])
    tcp_ports = [cap(r["case"]).tcp_port for r in rc.CASES if r["l4"] == "tcp"]
    assert tcp_ports == list(range(41100, 41100 + len(tcp_ports)))


def test_the_wire_is_valid_and_builder_msgs_endpoints():
    for name in caps():
        check_wire(cap(name))


def check_tcp_stream(c):
    """The handshake first and the FIN exchange last unless the cell says
    otherwise; each side's sequence continues, except across a labelled
    hole, whose octets only the peer's ACK past it accounts for, so that ACK
    must come before that side's next segment."""
    frames = c.frames()
    flags = [parse(fr)[7] for fr in frames]
    if "no handshake" not in ROWS[c.case]["build"]:
        assert flags[:3] == [synth.SYN, synth.SYN | synth.ACK, synth.ACK], c.name
    assert flags[-3:] == [synth.FIN | synth.ACK] * 2 + [synth.ACK], c.name
    holes = {id(d.frame): sum(b - a for _, a, b in d.pieces) for d in c.deliveries if d.lost}
    nxt = {}
    for fr in frames:
        src, dst, _, _, _, seq, ack, fl, payload = parse(fr)
        if src in nxt and not fl & synth.SYN:
            assert seq == nxt[src], c.name
        if id(fr) in holes:
            nxt[dst] += holes[id(fr)]   # the ACK past the hole acknowledges octets never captured
            assert ack == nxt[dst], c.name
        elif fl & synth.ACK and dst in nxt:
            assert ack == nxt[dst], c.name
        nxt[src] = seq + len(payload) + (1 if fl & (synth.SYN | synth.FIN) else 0)


def test_tcp_streams_open_close_and_hold_only_the_labelled_holes():
    for name in caps():
        if cap(name).l4 == "tcp":
            check_tcp_stream(cap(name))


# --- builder-c1-*, builder-falsemagic, builder-s5-7 ------------------------

def check_solved_headers(c):
    """The datagram or segment that holds X:crcmagic(k) starts with the
    row's 8 octets, and W's frame follows at its octet 8."""
    k = re.search(r"crcmagic\((\d)\)", ROWS[c.case]["build"]).group(1)
    ((payload, off, u, _, _),) = delivered(c, "X")
    assert off == 0 and payload[:8] == bytes.fromhex(COND[f"builder-c1-{c.l4}-{k}"]["value"]), c.name
    if c.twin == "nowrite":
        assert payload == u.data, c.name   # the case without W: the header alone
        return
    w = payload[8:]
    assert len(w) == 35 and crcs_ok(w) == (True, [True, True]) and app_of(w)[2] == dnp3.DIRECT_OPERATE, c.name
    assert payload[8:10] == dnp3.crc(payload[:8]), c.name


CRC_MAGIC = [r["case"] for r in rc.CASES if "crcmagic" in r["build"]]


def test_the_solved_headers_are_the_rows_and_w_is_at_octet_8():
    assert len(CRC_MAGIC) == 10
    for case in CRC_MAGIC:
        check_solved_headers(cap(case))


def test_the_false_magic_is_05_64_before_ws_frame():
    c = cap("dnp3-resync-tcp-false-magic-straddle")
    ((p1, _, _, _, _),) = delivered(c, "X")
    (w1, w2) = delivered(c, "W")
    assert p1[:2] == b"\x05\x64" and p1[2:] == w1[2].data[:9] and w2[0] == w1[2].data[9:]
    w = w1[2].data
    assert dnp3.crc(p1[:8]) != p1[8:10] and p1[8:10] == w[6:8] == b"\x01\x00"   # its CRC octets are W's SRC


def test_s5_input_7s_frame_is_the_rows():
    tail = bytes.fromhex(COND["builder-s5-7"]["value"])
    for l4 in ("udp", "tcp"):
        f = rc.s5_7_frame(l4)
        hdr = b"\x05\x64" + bytes([255, 0xC4, 10, 0, M_LINK[l4], 0])
        assert f == hdr + dnp3.crc(hdr) + b"\x05\x64" * 136 + tail and len(f) == 292
        assert f[282:] == tail and crcs_ok(f)[0] and not any(crcs_ok(f)[1])


# --- builder-failures ------------------------------------------------------

def badchunk(frame):
    """builder-failures: the frame with its (first) chunk CRC's first octet
    inverted. Every frame damaged so here holds one chunk."""
    at = len(frame) - 2
    assert 10 < at <= 10 + 16
    return frame[:at] + bytes([frame[at] ^ 0xFF]) + frame[at + 1:]


def tseq_app(frame):
    """(transport octet, application control octet or None) of a frame."""
    a = app_of(frame)
    return a[0], (a[1] if len(a) > 1 else None)


def check_failure(c, u):
    """One failure unit against builder-failures, from its own bytes."""
    l4, end, data, spec = c.l4, u.end, u.data, u.fail
    m = end == "m"
    dest, src = (10, M_LINK[l4]) if m else (M_LINK[l4], 10)
    ctrl = 0xC4 if m else 0x44
    hdr = lambda n: b"\x05\x64" + struct.pack("<BBHH", n, ctrl, dest, src)
    g = re.fullmatch(r"(garbage|zeros|len)\((\d+)\)", spec)
    if g and g.group(1) == "garbage":
        assert len(data) == int(g.group(2)) and 0x05 not in data
    elif g and g.group(1) == "zeros":
        assert data == bytes(int(g.group(2)))
    elif g and g.group(1) == "len":
        h = hdr(int(g.group(2)))
        assert data == h + dnp3.crc(h) + bytes(6)
    elif spec.startswith("crcmagic"):
        check_solved_headers(c)
    elif spec == "badhdr":
        h = hdr(0x0B if m else 0x0A)
        assert len(data) == 16 and data[:8] == h and data[8:10] != dnp3.crc(h) and data[10:] == bytes(6)
        assert data[8] == dnp3.crc(h)[0] ^ 0xFF and data[9] == dnp3.crc(h)[1]
    elif spec == "falsemagic":
        assert data == b"\x05\x64"
    elif spec == "holds":
        h = hdr(53)
        assert data[:8] == h and data[8:10] != dnp3.crc(h) and data[10:] == bytes(3)
        ((payload, off, _, _, _),) = delivered(c, u.name)
        assert off == 0 and (c.twin == "nowrite" or rc.candidate(payload, 13))   # W at offset 13
    elif spec in ("badchunk", "P", "throw", "cut", "open+badchunk", "firopen", "nofir"):
        frames = [x.data for x in units(c, lambda x: x.msg is u.msg and x.kind == "frame")] if spec in (
            "open+badchunk", "firopen") else [data]
        t, s = tseq_app(frames[0])
        seqn = t & 0x3F
        if spec == "nofir":
            body = rc.NOFIR_DATA if m else dnp3.response(c_last_request_seq(c, u))
            assert data == frame_from(end, l4, bytes([0x80 | seqn]) + body)
            return
        s &= 0x0F
        assert m or s == c_last_request_seq(c, u)
        if spec in ("badchunk", "P", "open+badchunk", "firopen"):
            apdu = dnp3.request(s, dnp3.READ, P_OBJ) if m else dnp3.response(s)
        elif spec == "throw":
            apdu = bytes([0xC0 | s, 0x01, 0x3C]) if m else bytes([0xC0 | s, 0x81, 0x00])
        else:
            apdu = dnp3.request(s, dnp3.READ, Q_OBJ) if m else dnp3.response(s)
        if spec in ("open+badchunk", "firopen"):
            f1 = frame_from(end, l4, bytes([0x40 | seqn]) + apdu[:1])
            f2 = frame_from(end, l4, bytes([0x80 | ((seqn + 1) & 0x3F)]) + apdu[1:])
            if spec == "firopen":
                assert frames == [f1]
            else:
                assert frames == [f1, badchunk(f2)]
            return
        whole = frame_from(end, l4, bytes([0xC0 | seqn]) + apdu)
        want = {"badchunk": badchunk(whole), "cut": whole[:14]}.get(spec, whole)
        assert data == want and (spec != "cut" or len(whole) == (24 if m else 17))
    elif spec == "overlimit":
        msg_units = units(c, lambda x: x.msg is u.msg)
        if u is not msg_units[0]:
            return
        apps = [app_of(x.data) for x in msg_units]
        assert all(crcs_ok(x.data) == (True, [True] * len(crcs_ok(x.data)[1])) for x in msg_units)
        assert [len(a) - 1 for a in apps] == [249] * 411 + [61, 249]
        body = b"".join(a[1:] for a in apps)
        s = body[0] & 0x0F
        want = (bytes([0xC0 | s, 0x01]) + b"\x3c\x01\x06" * 34214 + b"\x3c\x02\x00\x00\x00" if m
                else dnp3.response(s, objects=b"\x3c\x01\x06" * 34215))
        assert body == want and len(body) == 102649
    elif spec == "embed(W5)":
        w5 = data[20:55]
        s = app_of(w5)[1] & 0x0F
        t = app_of(w5)[0] & 0x3F
        want_w5 = frame_from(end, l4, bytes([0xC0 | t]) + (
            dnp3.request(s, dnp3.DIRECT_OPERATE, dnp3.crob(5)) if m else dnp3.response(s, objects=dnp3.crob(5))))
        w5 = data[20:20 + len(want_w5)]
        assert w5 == want_w5 and len(data) == 64 and data[:8] == hdr(53) and crcs_ok(data)[0]
        assert not crcs_ok(data)[1][0]
        assert data[10:20] == bytes(10) and data[20 + len(w5):] == bytes(64 - 20 - len(w5))
    elif spec == "embedtail(W5)":
        if u.label == "after":
            return
        after = next(x for x in units(c) if x.msg is u.msg and x.label == "after")
        w5 = data[60:] + after.data
        t, s = app_of(w5)[0] & 0x3F, app_of(w5)[1] & 0x0F
        assert w5 == frame_from(end, l4, bytes([0xC0 | t]) + (
            dnp3.request(s, dnp3.DIRECT_OPERATE, dnp3.crob(5)) if m else dnp3.response(s, objects=dnp3.crob(5))))
        assert len(data) == 64 and data[:8] == hdr(53) and crcs_ok(data) == (True, [True, True, False])
        assert data[10:26] == bytes(16) and data[28:44] == bytes(16) and data[46:60] == bytes(14)
    elif re.fullmatch(r"tail\((\d+)\)", spec):
        assert len(data) == int(spec[5:-1])
    else:
        raise AssertionError(f"no check for {spec!r}")


def c_last_request_seq(c, u):
    """The sequence of the request sent last before u (judge-twins: from o, a
    failure answers in the most recent request's sequence)."""
    seq = 0
    for d in c.deliveries:
        for x, _, _ in d.pieces:
            if x is u:
                return seq
            if x.msg is not None and x.msg.end == "m" and x.msg.code != dnp3.RESPONSE:
                seq = x.msg.seq
    raise AssertionError("not sent")


def test_every_failure_is_made_as_builder_failures_says():
    n = 0
    for name in caps():
        c = cap(name)
        for u in units(c, lambda x: x.fail != "-"):
            check_failure(c, u)
            n += 1
    assert n > 2000


def test_the_midstream_tails_are_the_ends_of_real_frames():
    c = cap("dnp3-resync-tcp-r2-midstream")
    (u,) = units(c, lambda x: x.fail == "tail(7)")
    assert u.data == frame_from("m", "tcp", bytes([0xC0 | 63]) + dnp3.request(15, dnp3.READ, P_OBJ))[-7:]
    c = cap("dnp3-resync-tcp-r2-midstream-both")
    q = dnp3.request(15, dnp3.READ, Q_OBJ)
    r = dnp3.response(14)
    qa, qb = frame_from("m", "tcp", bytes([0x40 | 62]) + q[:1]), frame_from("m", "tcp", bytes([0x80 | 63]) + q[1:])
    ra, rb = frame_from("o", "tcp", bytes([0x40 | 62]) + r[:1]), frame_from("o", "tcp", bytes([0x80 | 63]) + r[1:])
    payloads = [parse(fr)[-1] for fr in c.frames() if parse(fr)[-1]]
    assert payloads[:2] == [ra[-7:] + rb, qa[-9:] + qb]


# --- builder-msgs ----------------------------------------------------------

def check_sequences(c):
    """Requests carry 0, 1, 2 and on, mod 16, in the order built; a response
    echoes its request; each end's transport sequence counts per frame from
    0, mod 64, a message's frames taking consecutive numbers when it is built
    at its first frame (so in W1 | I | W2 the master's W2 follows W1, and the
    inserted I comes after both), and a retry repeating its frame."""
    tseq, app, counted = {"m": 63, "o": 63}, 15, set()
    for u in units(c, lambda x: x.kind == "frame"):
        if u.msg is not None and id(u.msg) in counted:
            continue
        # A message's frames as built (an embedded W5's too), else the unit's own.
        frames = u.msg.frames if u.msg is not None else [u.data]
        if u.msg is not None:
            counted.add(id(u.msg))
        for f in frames:
            t = app_of(f)[0]
            assert t & 0x3F == (tseq[u.end] + 1) & 0x3F, (c.name, u.name)
            tseq[u.end] = t & 0x3F
        f = frames[0]
        if u.end == "m" and app_of(f)[0] & 0x40 and len(app_of(f)) > 1:
            s = app_of(f)[1] & 0x0F
            assert s == (app + 1) & 0x0F, (c.name, u.name, s, app)
            app = s
    latest = {}
    for u in units(c, lambda x: x.msg is not None):
        apdu = b"".join(app_of(f)[1:] for f in u.msg.frames)
        if u.end == "m":
            latest[u.msg.name] = latest[u.name] = apdu[0] & 0x0F
        elif u.msg.name.startswith("R(") and u is u.msg.units[0]:
            assert apdu[1] == dnp3.RESPONSE and apdu[0] & 0x0F == latest[u.msg.name[2:-1]], (c.name, u.name)


NUMBERED_BEFORE = {"dnp3-resync-tcp-r2-midstream-both", "dnp3-resync-udp-join-response",
                   "dnp3-resync-tcp-join-response", "dnp3-resync-udp-report-cap", "dnp3-resync-udp-report-mark-state"}


def test_application_and_transport_sequences_follow_builder_msgs():
    for name, (case, c) in caps().items():
        if case not in NUMBERED_BEFORE:
            check_sequences(c)


def test_r_echoes_a_direct_operate_and_r_to_a_throw_carries_iin_0004():
    c = cap("dnp3-resync-udp-chunk-crc")
    (rw,) = units(c, lambda x: x.name == "R(W)")
    a = app_of(rw.data)
    assert a[1:] == dnp3.response(a[1] & 0x0F, objects=dnp3.crob(0))
    (ri,) = units(cap("dnp3-resync-udp-insert-fir-restart-throws"), lambda x: x.name == "R(I)")
    assert app_of(ri.data)[3:5] == b"\x00\x04"
    (ri,) = units(cap("dnp3-resync-udp-insert-fir-restart-confirms"), lambda x: x.name == "R(I)")
    assert app_of(ri.data)[3:5] == b"\x00\x00"


def test_w1_and_w2_split_ws_fragment_as_builder_msgs_says():
    check_w1_w2(cap("dnp3-resync-udp-insert-truncated"))


def check_w1_w2(c):
    (w1,), (w2,) = units(c, lambda x: x.name == "W1"), units(c, lambda x: x.name == "W2")
    assert (len(w1.data), len(w2.data)) == (14, 34)
    assert app_of(w1.data)[1:] + app_of(w2.data)[1:] == dnp3.request(0, dnp3.DIRECT_OPERATE, dnp3.crob(0))
    assert app_of(w1.data)[0] & 0xC0 == 0x40 and app_of(w2.data)[0] & 0xC0 == 0x80


def test_confirmed_user_data_follows_rst_with_fcb_1_and_a_retry_repeats_it():
    c = cap("dnp3-resync-udp-link-retry-first")
    ctrl = [u.data[3] for u in units(c, lambda x: x.name in ("Rst", "A", "W1c", "retry", "W2c"))]
    assert ctrl == [0xC0, 0x00, 0xF3, 0xF3, 0x00, 0xD3, 0x00]   # Rst, A, W1c FCB 1, its retry, A, W2c FCB 0, A
    retry = units(c, lambda x: x.name == "retry")[0]
    assert retry.data == units(c, lambda x: x.name == "W1c")[0].data
    c = cap("dnp3-resync-udp-link-retry-middle")
    assert [u.data[3] for u in units(c, lambda x: x.name in ("W1c", "W2c", "retry", "W3c"))] == [0xF3, 0xD3, 0xD3, 0xF3]


def test_link_only_frames_are_the_functions_builder_msgs_names():
    want = {"L": 0xC9, "Lo": 0x49, "Lm": 0x8B, "Ls": 0x0B, "Rst": 0xC0, "A": 0x00}
    n = 0
    for name in caps():
        for u in units(cap(name), lambda x: x.kind == "link"):
            base = re.sub(r"\d+$", "", u.name)
            assert len(u.data) == 10 and u.data[2] == 5 and u.data[3] == want[base] and crcs_ok(u.data)[0]
            n += 1
    assert n > 1100


def test_link_frame_is_dnp3_link_with_another_control_octet():
    for user in (b"", b"\xc0\xc0\x01\x3c\x01\x06", bytes(range(40))):
        for master, ctrl in ((True, 0xC4), (False, 0x44)):
            assert rc.link_frame(ctrl, 10, 5, user) == dnp3.link(10, 5, master, user)


# --- builder-limit and builder-join ----------------------------------------

def test_the_fragment_limit_cases_hold_the_rows_octets():
    lim = int(COND["val-limit"]["value"])
    for case, name, total in (("dnp3-resync-udp-fragment-limit-at", "B400", lim),
                              ("dnp3-resync-udp-fragment-limit-over", "B401", lim + 1)):
        us = units(cap(case), lambda x: x.msg is not None and x.msg.name == name)
        apps = [app_of(u.data) for u in us]
        body = b"".join(a[1:] for a in apps)
        assert len(body) == total and [len(a) - 1 for a in apps[:-1]] == [249] * 411
        assert len(apps[-1]) - 1 == total - 411 * 249
        assert body[1:2] == b"\x01" and body[2:5] == b"\x3c\x01\x06"
        assert body.endswith(b"\x3c\x02\x00\x00\x00") == (name == "B400")
        assert [a[0] & 0x3F for a in apps] == [(apps[0][0] + k) & 0x3F for k in range(len(apps))]


def test_the_joined_response_is_builder_joins():
    objects = bytes([1, 2, 0x01]) + struct.pack("<HH", 0, 2036) + b"\x01" * 2037
    apdu = dnp3.response(15, objects=objects)
    assert len(apdu) == 2048
    for case in ("dnp3-resync-udp-join-response", "dnp3-resync-tcp-join-response"):
        us = units(cap(case), lambda x: x.name.startswith("Rbig/"))
        assert [len(u.data) for u in us] == [292] * 7 + [75] and sum(len(u.data) for u in us) == 2119
        assert [app_of(u.data)[0] & 0x3F for u in us] == list(range(1, 9))
        assert all(not app_of(u.data)[0] & 0x40 for u in us) and app_of(us[-1].data)[0] & 0x80
        assert b"".join(app_of(u.data)[1:] for u in us) == apdu[249:]
        first = [parse(fr)[-1] for fr in cap(case).frames() if parse(fr)[-1]][0]
        assert first == us[0].data and parse(cap(case).frames()[0])[-1] == us[0].data   # the capture starts there


# --- the twins (judge-twins) -----------------------------------------------

FAIL_NAMES = re.compile(r"(X|I|R\(I\)|L|Lo|Lm|Ls)([0-9/\[].*)?")


def shape(c, pred=lambda u: True):
    return [(u.name, u.end, u.data) for u in units(c, pred)]


def check_twins(case, get=None):
    """get(name) gives a capture; by default the built ones."""
    cap = get or globals()["cap"]
    twins = ROWS[case]["twins"].split(",")
    base = cap(case)
    if "nofail" in twins:
        nf = cap(f"{case}--nofail")
        assert not [d for d in nf.deliveries if d.lost], case
        if case.startswith("dnp3-resync-tcp-gap-"):
            # The failure is the hole alone: the same units, none lost.
            assert [(n, e) for n, e, _ in shape(nf)] == [(n, e) for n, e, _ in shape(base)], case
        else:
            assert not units(nf, lambda u: u.fail != "-"), case
            keep = [(n, e) for n, e, _ in shape(base, lambda u: not FAIL_NAMES.fullmatch(u.name))]
            assert [(n, e) for n, e, _ in shape(nf)] == keep, case
    if "nowrite" in twins:
        nw = cap(f"{case}--nowrite")
        assert not units(nw, lambda u: u.msg is not None and u.msg.code == dnp3.DIRECT_OPERATE
                         and u.msg.name != "W5"), case
        drop = re.compile(r"W([0-9]c?|\[.*\])?|R\(W\)|W[12]")
        assert [(n, e) for n, e, _ in shape(nw)] == [(n, e) for n, e, _ in shape(
            base, lambda u: not drop.fullmatch(u.name))], case
    if "otherend" in twins:
        oe = cap(f"{case}--otherend")
        xb = shape(base, lambda u: FAIL_NAMES.fullmatch(u.name) and u.name not in ("R(I)",))
        xo = shape(oe, lambda u: FAIL_NAMES.fullmatch(u.name) and u.name not in ("R(I)",))
        assert [{"m": "o", "o": "m"}[e] for _, e, _ in xb] == [e for _, e, _ in xo], case
        rest = lambda c: [(n, e) for n, e, _ in shape(c, lambda u: not FAIL_NAMES.fullmatch(u.name))
                          if not n.startswith("R(")]
        assert rest(oe)[:len(rest(base))] == rest(base) or case.startswith("dnp3-resync-tcp-gap-"), case


def test_each_twin_differs_from_its_case_only_as_judge_twins_says():
    for r in rc.CASES:
        if r["twins"] != "-":
            check_twins(r["case"])


def test_the_gap_twins_move_the_hole_to_rs_frame():
    for case in ("dnp3-resync-tcp-gap-header", "dnp3-resync-tcp-gap-data", "dnp3-resync-tcp-gap-middle-frame"):
        base, oe = cap(case), cap(f"{case}--otherend")
        assert [d.end for d in base.deliveries if d.lost] == ["m"] and [d.end for d in oe.deliveries if d.lost] == ["o"]
        (lost,) = [d for d in oe.deliveries if d.lost]
        assert all(u.msg.name == "R(G)" for u, _, _ in lost.pieces)
        (blost,) = [d for d in base.deliveries if d.lost]
        if case != "dnp3-resync-tcp-gap-middle-frame":
            assert [(a, b) for _, a, b in lost.pieces] == [(a, b) for _, a, b in blost.pieces]


# --- the times -------------------------------------------------------------

def t(c, unit):
    """The time of the packet that holds the named unit's first piece."""
    return next(d.frame.ns for d in c.deliveries if not d.lost and any(x.name == unit for x, _, _ in d.pieces))


def test_the_timed_cases_keep_their_times():
    s = 1_000_000_000
    c = cap("dnp3-resync-udp-weird-burst")
    x1, x2000 = t(c, "X1"), t(c, "X2000")
    assert x2000 - x1 == 50 * s and t(c, "W") - x1 == 52 * s and t(c, "Q") - x1 == 54 * s
    c = cap("dnp3-resync-udp-r2-idle")
    xs = sorted(d.frame.ns for d in c.deliveries)
    assert max(b - a for a, b in zip(xs, xs[1:])) >= 90 * s
    c = cap("dnp3-resync-tcp-keepalive")
    assert t(c, "Lo") - t(c, "R(P)") >= 130 * s
    c = cap("dnp3-resync-udp-report-interval")
    assert [(t(c, u) - c.t0) / s for u in ("X1", "X2", "X3", "X4")] == [10, 40, 100, 160]
    polls = sorted(d.frame.ns for d in c.deliveries if d.pieces[0][0].name.startswith("P"))
    assert [(p - c.t0) / s for p in polls] == [5 + 20 * k for k in range(11)]
    c = cap("dnp3-resync-udp-report-cap")
    t0 = c.t0 + 30 * s
    xs = sorted((d.flow.port, d.frame.ns - t0) for d in c.deliveries if d.pieces[0][0].fail == "badchunk")
    assert xs == [(40000 + i, i * s // 10) for i in range(101)] + [
        (40000 + i, 60 * s + s // 2 + (i - 101) * s // 10) for i in range(101, 201)]
    budget = sorted(d.frame.ns - t0 for d in c.deliveries if d.flow.port == 41000)
    assert len(budget) == 8 and budget[0] == 20 * s
    assert c.frames()[-1].ns - t0 == 125 * s
    for port in range(40000, 40201):
        polls = sorted(d.frame.ns for d in c.deliveries if d.flow.port == port and d.end == "m"
                       and d.pieces[0][0].name.startswith("P"))
        assert polls[0] < t0 and [b - a for a, b in zip(polls, polls[1:])] == [30 * s] * 5


# --- the controls: named mutants that each check must fail -----------------

def fresh(name):
    """The capture rebuilt on its own, for a control to change."""
    case, _, twin = name.partition("--")
    r = ROWS[case]
    tcp = [x["case"] for x in rc.CASES if x["l4"] == "tcp"]
    port = rc.FIRST_TCP_PORT + tcp.index(case) if case in tcp else None
    c = rc.Capture(case, twin or None, r["l4"], rc.CASES.index(r), port)
    if case in rc.IRREGULAR:
        rc.IRREGULAR[case](c)
    else:
        rc.interpret(c, r["build"])
    return c


def payload_start(fr):
    ihl = (fr.data[14] & 0x0F) * 4
    t = 14 + ihl
    return t + (8 if fr.data[23] == synth.UDP else (fr.data[t + 12] >> 4) * 4)


def mutate(c, unit, change):
    """Change one unit's octets, and the packet that carries them, keeping their length."""
    u = next(x for x in units(c) if x.name == unit)
    new = change(u.data)
    assert len(new) == len(u.data)
    for d in c.deliveries:
        off = 0
        for x, a, b in d.pieces:
            if x is u and not d.lost:
                s = payload_start(d.frame) + off
                d.frame.data = d.frame.data[:s] + new[a:b] + d.frame.data[s + b - a:]
            off += b - a
    u.data = new
    return c, u


def flip(i):
    return lambda b: b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]


# Each control sets up its mutant and returns the check, which must fail on it.
# The setup runs outside pytest.raises, so an error there is never a kill.

def control_solved_header_octet(mp):
    """crcmagic(2) with one octet of DEST changed: no longer the row's."""
    c, _ = mutate(fresh("dnp3-resync-udp-crc-magic-2"), "X", flip(5))
    return lambda: check_solved_headers(c)


def control_s5_7_tail(mp):
    """The builder's S5 input (7) frame with its last two octets swapped."""
    orig = rc.pinned
    mp.setattr(rc, "pinned", lambda rid: orig(rid)[:8] + orig(rid)[:7:-1] if rid == "builder-s5-7" else orig(rid))
    return test_s5_input_7s_frame_is_the_rows


def control_badchunk_second_octet(mp):
    """badchunk with its chunk CRC's second octet inverted, not its first."""
    c, u = mutate(fresh("dnp3-resync-udp-chunk-crc"), "X", lambda b: b[:-2] + bytes([b[-2] ^ 0xFF, b[-1] ^ 0xFF]))
    return lambda: check_failure(c, u)


def control_badhdr_crc_ok(mp):
    """badhdr whose header CRC passes."""
    c, u = mutate(fresh("dnp3-resync-udp-header-crc"), "X", lambda b: b[:8] + dnp3.crc(b[:8]) + b[10:])
    return lambda: check_failure(c, u)


def control_garbage_holds_05(mp):
    """garbage(16) that holds a 05 octet."""
    c, u = mutate(fresh("dnp3-resync-udp-magic"), "X", lambda b: b"\x05" + b[1:])
    return lambda: check_failure(c, u)


def control_embed_w5_shifted(mp):
    """embed(W5) with W5 one octet after octet 20."""
    c, u = mutate(fresh("dnp3-resync-udp-embedded-frame"), "X", lambda b: b[:20] + b"\x00" + b[20:63])
    return lambda: check_failure(c, u)


def control_embedtail_third_crc_valid(mp):
    """embedtail(W5) whose third chunk CRC passes."""
    c, u = mutate(fresh("dnp3-resync-tcp-embedded-tail"), "X", lambda b: b[:62] + dnp3.crc(b[46:62]))
    return lambda: check_failure(c, u)


def control_overlimit_split(mp):
    """overlimit split as 412 frames of 249 and the rest, not as builder-limit says."""
    orig = rc.sizes
    mp.setattr(rc, "sizes", lambda n, how: [249] * 412 + [n - 249 * 412] if how == "overlimit" else orig(n, how))
    c = fresh("dnp3-resync-udp-fragment-limit")
    u = next(x for x in units(c) if x.name == "X/1")
    return lambda: check_failure(c, u)


def control_tseq_skip(mp):
    """o's transport sequence skipping one number before each of its messages."""
    orig = rc.Flow._frames

    def skipping(self, end, apdu, how="one", take=None, confirmed=False):
        if end == "o":
            self.tseq[end] = (self.tseq[end] + 1) & 0x3F
        return orig(self, end, apdu, how, take, confirmed)
    mp.setattr(rc.Flow, "_frames", skipping)
    c = fresh("dnp3-resync-udp-magic")
    return lambda: check_sequences(c)


def control_app_seq_from_1(mp):
    """Requests numbered from 1, not 0."""
    orig = rc.Flow.request

    def from_one(self, *a, **k):
        self.app = self.app or 1
        return orig(self, *a, **k)
    mp.setattr(rc.Flow, "request", from_one)
    c = fresh("dnp3-resync-udp-magic")
    return lambda: check_sequences(c)


def control_nowrite_keeps_w(mp):
    """A nowrite twin that keeps W and its response."""
    mp.setattr(rc, "w_family", lambda name: False)
    nw = fresh("dnp3-resync-udp-magic--nowrite")
    return lambda: check_twins("dnp3-resync-udp-magic", lambda n: nw if n.endswith("--nowrite") else cap(n))


def control_otherend_from_m(mp):
    """An otherend twin whose failure is from m, as the case's is."""
    oe = fresh("dnp3-resync-udp-magic")
    return lambda: check_twins("dnp3-resync-udp-magic", lambda n: oe if n.endswith("--otherend") else cap(n))


def control_nofail_keeps_x(mp):
    """A nofail twin that keeps the failure."""
    nf = fresh("dnp3-resync-udp-chunk-crc")
    return lambda: check_twins("dnp3-resync-udp-chunk-crc", lambda n: nf if n.endswith("--nofail") else cap(n))


def control_report_cap_end(mp):
    """report-cap's last packet 1 ms after T0 + 125 s."""
    last = cap("dnp3-resync-udp-report-cap").frames()[-1]
    mp.setattr(last, "ns", last.ns + 1_000_000)
    return test_the_timed_cases_keep_their_times


def control_weird_burst_span(mp):
    """weird-burst's X2000 at X1 + 49.999 s."""
    fr = next(d.frame for d in cap("dnp3-resync-udp-weird-burst").deliveries if d.pieces[0][0].name == "X2000")
    mp.setattr(fr, "ns", fr.ns - 1_000_000)
    return test_the_timed_cases_keep_their_times


def control_gap_not_acked(mp):
    """A TCP hole the peer never ACKs past: the ACK left out of the capture."""
    c = fresh("dnp3-resync-tcp-gap-header")
    c.flows[0].conv.frames.remove(next(d.frame for d in c.deliveries if d.lost))
    return lambda: check_tcp_stream(c)


def control_w1_two_octets(mp):
    """W1 holding two application octets, not W's control octet alone."""
    orig = rc.sizes
    mp.setattr(rc, "sizes", lambda n, how: [2, n - 2] if how == "two" else orig(n, how))
    c = fresh("dnp3-resync-udp-insert-truncated")
    return lambda: check_w1_w2(c)


CONTROLS = {name[len("control_"):].replace("_", "-"): f for name, f in globals().items() if name.startswith("control_")}


def test_the_controls_pass_unmutated():
    """Each check passes on the built captures, so a control's failure is its mutant's."""
    check_solved_headers(cap("dnp3-resync-udp-crc-magic-2"))
    for name, unit in (("dnp3-resync-udp-chunk-crc", "X"), ("dnp3-resync-udp-header-crc", "X"),
                       ("dnp3-resync-udp-magic", "X"), ("dnp3-resync-udp-embedded-frame", "X"),
                       ("dnp3-resync-tcp-embedded-tail", "X"), ("dnp3-resync-udp-fragment-limit", "X/1")):
        c = fresh(name)
        check_failure(c, next(x for x in units(c) if x.name == unit))
    check_sequences(fresh("dnp3-resync-udp-magic"))
    check_twins("dnp3-resync-udp-magic", lambda n: fresh(n))
    check_twins("dnp3-resync-udp-chunk-crc", lambda n: fresh(n))
    check_tcp_stream(fresh("dnp3-resync-tcp-gap-header"))
    check_w1_w2(fresh("dnp3-resync-udp-insert-truncated"))


@pytest.mark.parametrize("control", sorted(CONTROLS))
def test_each_check_fails_its_named_control(control, monkeypatch):
    check = CONTROLS[control](monkeypatch)
    with pytest.raises(AssertionError):
        check()


def test_the_candidate_check_fails_an_unnamed_candidate():
    """Control for the builder's own check (builder-failures, last sentence):
    a garbage unit that holds a whole header is refused."""
    c = rc.Capture("dnp3-resync-udp-magic", None, "udp", 0, None)
    rc.interpret(c, ROWS["dnp3-resync-udp-magic"]["build"])
    (u,) = [x for x in units(c) if x.name == "X"]
    h = b"\x05\x64\x05\xc4\x0a\x00\x05\x00"
    u.data = h + dnp3.crc(h) + u.data[10:]
    with pytest.raises(AssertionError, match="not named"):
        rc.check_candidates(c)
