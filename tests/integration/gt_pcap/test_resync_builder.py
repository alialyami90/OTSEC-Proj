"""The dnp3-resync-* builder against its pinned rows (D6, brief P4-4-HR25, deliverable 3).

resync_cases.py writes every case and twin of resync-cases.tsv. This test
checks what it writes against the rows that pin it, from the bytes on the
wire: the captures and labels are the committed ones, every case and twin is
there, the wire is valid, the solved headers and S5 input (7)'s frame are
the rows' octets, every failure is made as builder-failures says, the
application and transport sequences and the endpoints are builder-msgs',
builder-limit's and builder-join's arithmetic holds, the twins differ from
their case only as judge-twins says, the timed cases keep their times, and
the committed list of tshark's expected differences names a cause for each.
The expected bytes are made here from dnp3.py, not taken from the builder's
helpers. Each check has a named control: a mutant of the built bytes or of
the builder that the check must fail. Stdlib only and no tshark, so it runs
in CI's python job; resync_tshark.py is tshark's half.
"""

import collections
import hashlib
import os
import re
import struct

import pytest

import dnp3
import pcapfile
import resync_cases as rc
import resync_tshark as rt
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
    assert set(caps()) == want and len(want) == 166 + 189 + 1
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
    committed = sorted(n for n in os.listdir(FIXTURES) if n.endswith(".tsv") and n != "tshark-beside.tsv")
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
        check_seq_failure(c, u)


# --- builder-seq (P4-4-HR2325S deliverable 3) --------------------------------

def check_seq_failure(c, u):
    """One unit of builder-seq against that row, from its own bytes and dnp3.py."""
    l4, end, data, spec = c.l4, u.end, u.data, u.fail
    m = end == "m"
    dest, src = (10, M_LINK[l4]) if m else (M_LINK[l4], 10)
    g = re.fullmatch(r"(seg|sub)\((\d+)((?:,\w+=\w+)*)\)", spec)
    if g:
        n, opts = int(g.group(2)), dict(kv.split("=") for kv in g.group(3).split(",")[1:])
        user = bytes([n, 0x22])
        to = int(opts.get("dest", dest))
        if "ctl" in opts:
            base, k, _ = rc.FRAME_TOKENS[opts["ctl"]]
            want = rc.link_frame(u.pieces[0][0].flow.msgs[base].frames[k][3], to, src, user)
        else:
            want = dnp3.link(to, src, m, user)
        assert data == want, (c.name, spec)
        return
    g = re.fullmatch(r"firopen\((\d+)\)", spec)
    if g:
        # firopen as builder-failures says (an empty response's frame 1 from o), numbered n.
        s = c_last_request_seq(c, u)
        assert not m and data == frame_from(end, l4, bytes([0x40 | int(g.group(1))]) + dnp3.response(s)[:1])
        return
    g = SET_BY_CELL.fullmatch(spec)
    if g and g.group("copy"):
        f = source(u)
        ctrl, user = f[3], app_of(f)
        to, frm = struct.unpack("<HH", f[4:8])
        how = g.group("copy")
        if how == "fin":
            assert not user[0] & 0x80
            user = bytes([user[0] | 0x80]) + user[1:]
        elif how == "octet":
            user = user[:1] + bytes([user[1] ^ 0xFF]) + user[2:]
        elif how == "fewer":
            user = user[:-1]
        elif how == "more":
            user += b"\x00"
        elif how == "fcb":
            ctrl ^= 0x20
        elif how == "read":
            user, to = user[:1] + b"\x01\x3c\x01\x06", 11
        assert data == rc.link_frame(ctrl, to, frm, user), (c.name, spec)
        # The control octet a copy of W1c to W3c keeps: confirmed user data, PRM and FCV set (builder-msgs).
        assert (ctrl & 0x5F == 0x53) == g.group("of").endswith("c") and (how == "same" or data != f), (c.name, spec)
        return
    if spec == "badobj":
        s = c_last_request_seq(c, u) if not m else app_of(data)[1] & 0x0F
        assert data == frame_from(end, l4, bytes([0xC0 | (app_of(data)[0] & 0x3F)]) + dnp3.response(s) + b"\x3c")
        assert len(app_of(data)) - 1 == 5
        return
    g = re.fullmatch(r"(fc|fc2)\((\d+),(\d+)\)", spec)
    if g:
        mine = units(c, lambda x: x.msg is u.msg)
        if u is not mine[0]:
            return
        frames = [x.data for x in mine]
        code, n = int(g.group(2)), int(g.group(3))
        apps = [app_of(f) for f in frames]
        body = b"".join(a[1:] for a in apps)
        s = c_last_request_seq(c, u) if not m else body[0] & 0x0F
        assert body == bytes([0xC0 | s, code]) + bytes(n - 2), (c.name, spec)
        assert [len(a) - 1 for a in apps] == ([2, n - 2] if g.group(1) == "fc2" else [n]), (c.name, spec)
        assert [a[0] & 0xC0 for a in apps] == ([0x40, 0x80] if g.group(1) == "fc2" else [0xC0]), (c.name, spec)
        return
    if spec == "lostmiddle":
        frames = u.msg.frames
        assert not m and len(frames) == 3 and u.data in (frames[0], frames[2])
        s = c_last_request_seq(c, u)
        assert b"".join(app_of(f)[1:] for f in frames) == dnp3.response(s)
        assert [len(app_of(f)) - 1 for f in frames] == [1, 2, 1]
        t = app_of(frames[0])[0] & 0x3F
        assert [app_of(f)[0] for f in frames] == [0x40 | t, (t + 1) & 0x3F, 0x80 | ((t + 2) & 0x3F)]
        # Frame 2 is not in the capture.
        assert not any(x.data == frames[1] for x in units(c)), c.name
        return
    if spec == "embedhead":
        assert len(data) == 64 and data[:3] == b"\x05\x64\x35" and data[3:5] == b"\x05\x64"
        assert crcs_ok(data) == (True, [False, True, True]), c.name
        assert rc.candidate(data, 3) and [i for i in range(1, 64) if rc.candidate(data, i)] == [3], c.name
        assert data[13:26] == bytes(13) and data[28:44] == bytes(16) and data[46:62] == bytes(16)
        return
    if spec == "embedlast(W5)":
        if u.label == "after":
            return
        after = next(x for x in units(c) if x.msg is u.msg and x.label == "after")
        w5 = data[63:] + after.data
        t, s = app_of(w5)[0] & 0x3F, app_of(w5)[1] & 0x0F
        assert m and w5 == frame_from(end, l4, bytes([0xC0 | t]) + dnp3.request(s, dnp3.DIRECT_OPERATE, dnp3.crob(5)))
        h = b"\x05\x64" + struct.pack("<BBHH", 53, 0xC4, dest, src)
        assert len(data) == 64 and data[:8] == h and crcs_ok(data) == (True, [True, True, False])
        assert data[10:26] == bytes(16) and data[28:44] == bytes(16) and data[46:62] == bytes(16)
        assert [i for i in range(1, 64) if rc.candidate(data + after.data, i)] == [63], c.name
        return
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
        set_by = SET_BY_CELL.fullmatch(u.fail)
        if set_by and set_by.group("copy"):
            # builder-seq: a copy repeats its source frame's number, and the end's count goes on unchanged.
            counted.add(id(u.msg))
            assert app_of(u.data)[0] & 0x3F == app_of(source(u))[0] & 0x3F, (c.name, u.name)
            continue
        if set_by and set_by.group("n") is not None:
            # builder-seq: the number the cell gives; seg and sub leave the end's count, firopen restarts it.
            counted.add(id(u.msg))
            assert app_of(u.data)[0] & 0x3F == int(set_by.group("n")), (c.name, u.name)
            if set_by.group("kind") == "firopen":
                tseq[u.end] = int(set_by.group("n"))
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
# builder-seq: a cell that sets m's next number with "m numbered from n" (check_numbered_from).
NUMBERED_FROM = {r["case"] for r in rc.CASES if "numbered from" in r["build"]}
SET_BY_CELL = re.compile(r"(?P<kind>seg|sub|firopen)\((?P<n>\d+)(?:,[^)]*)?\)"
                         r"|(?P<copy>fin|octet|fewer|more|same|fcb|read)\((?P<of>\w+)\)")


def source(u):
    """The frame a builder-seq copy names (fin(W2c) names W's frame 2), as its flow built it."""
    tok = SET_BY_CELL.fullmatch(u.fail).group("of")
    base, k, _ = rc.FRAME_TOKENS[tok]
    return u.pieces[0][0].flow.msgs[base].frames[k]


def test_application_and_transport_sequences_follow_builder_msgs():
    for name, (case, c) in caps().items():
        if case not in NUMBERED_BEFORE | NUMBERED_FROM:
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
        # The twin keeps the failure, so a TCP hole is the case's, at the same offsets (D2's B1 on #714).
        holes = lambda c: [(d.end, [(u.name, a, b) for u, a, b in d.pieces]) for d in c.deliveries if d.lost]
        assert holes(nw) == holes(base), case
    if "otherend" in twins:
        oe = cap(f"{case}--otherend")
        xb = shape(base, lambda u: FAIL_NAMES.fullmatch(u.name) and u.name not in ("R(I)",))
        xo = shape(oe, lambda u: FAIL_NAMES.fullmatch(u.name) and u.name not in ("R(I)",))
        # Every failure unit is built from o's side: one from m moves to o,
        # and one already o's (the keep-alive's Lo) stays itself, so no
        # failure unit is left on W's end (D2's B2 and D4's B1 on #714).
        assert len(xb) == len(xo) and all(e == "o" for _, e, _ in xo), case
        assert all(ub == uo for ub, uo in zip(xb, xo) if ub[1] == "o"), case
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


# --- tshark's expected differences (D4's N1 on #714) -------------------------

EXPECTED = os.path.join(FIXTURES, "tshark-beside.tsv")


def listed(rows):
    """The committed rows as resync_tshark.py writes its list: without the cause."""
    return ["\t".join(r[:-1]) for r in rows]


def check_tshark_list(produced, rows):
    assert rt.compare(produced, rows) == []


def test_the_expected_tshark_list_names_one_of_its_causes_for_each_row():
    rows = rt.expected_rows(EXPECTED)
    check_tshark_list(listed(rows), rows)
    assert rows[0] == rt.COLUMNS + ["cause"]
    assert collections.Counter(r[-1] for r in rows[1:]) == {"no-resync": 22, "throw-code": 24, "no-limit": 9,
                                                            "insert-rebuild": 8, "seq-rebuild": 9, "retry-last": 2,
                                                            "merged": 1, "no-wrap": 1}


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


def control_nowrite_without_the_hole(mp):
    """gap-header's nowrite twin built with no segment lost (D2's B1 on #714)."""
    caps()   # the built captures first, so the patch reaches only the mutant
    orig = rc.Flow.send
    mp.setattr(rc.Flow, "send", lambda self, pieces, lost=False, at=None: orig(self, pieces, False, at))
    nw = fresh("dnp3-resync-tcp-gap-header--nowrite")
    return lambda: check_twins("dnp3-resync-tcp-gap-header", lambda n: nw if n.endswith("--nowrite") else cap(n))


def control_keepalive_otherend_l_from_m(mp):
    """The keep-alive's otherend twin with the master's L for O1's Lo (D2's B2 and D4's B1 on #714)."""
    caps()
    mp.setitem(rc.OTHER_END_LINK, "Lo", "L")
    oe = fresh("dnp3-resync-tcp-keepalive--otherend")
    return lambda: check_twins("dnp3-resync-tcp-keepalive", lambda n: oe if n.endswith("--otherend") else cap(n))


def control_tshark_difference_not_listed(mp):
    """tshark reads a difference that the committed list does not hold."""
    rows = rt.expected_rows(EXPECTED)
    extra = "\t".join(["dnp3-resync-udp-magic", "W", "m", "3", "5", "-", "the builder labels it seen"])
    return lambda: check_tshark_list(listed(rows) + [extra], rows)


def control_tshark_listed_not_read(mp):
    """tshark no longer reads a difference that the committed list holds."""
    rows = rt.expected_rows(EXPECTED)
    return lambda: check_tshark_list(listed(rows)[:-1], rows)


def control_tshark_cause_not_named(mp):
    """A committed row whose cause is none of the four."""
    rows = rt.expected_rows(EXPECTED)
    produced = listed(rows)
    rows[1][-1] = "unknown"
    return lambda: check_tshark_list(produced, rows)


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


# --- the audit of the pinned rows (design 3.3), and deliverable 3's cells ----
#
# Design 3.3's audit was a scratch reading, so this one is the one that counts
# (P4-4-HR2325S deliverable 3). It applies design 2.3's transport rule to every
# whole frame with valid CRCs, per flow and end, in the order sent. A link-only
# frame and a failed header leave the state (2.1, 2.3); a frame whose header
# passes and that then fails or is cut short, a frame cut by a datagram's end, a
# lost TCP segment, a throw at FIN and the fragment limit drop it (2.2 to 2.6).
# It models the rule, not A's code, and runs no engine.

PINNED = {r["case"] for r in rc.CASES[:112]}
NEW = [r for r in rc.CASES[112:]]
LIMIT = int(COND["val-limit"]["value"])
DROPPED = re.compile(r"badchunk|cut|embed")


class End:
    """One end's state under design 2.3."""

    def __init__(self):
        self.clear()

    def clear(self):
        self.frag, self.tseq, self.last, self.after_fin, self.fcb, self.octets = False, None, None, False, None, 0


def confirmed(ctrl):
    """A primary frame of confirmed user data with FCV set (link function 3)."""
    return ctrl & 0x5F == 0x53


def rule(st, u):
    """Design 2.3 for one whole frame with valid CRCs; its verdict."""
    ctrl, user = u.data[3], app_of(u.data)
    t, n = user[0], user[0] & 0x3F
    if t & 0x40:
        verdict = "fir_restart" if st.frag else "accept"
        st.octets = 0
    elif st.frag and n == (st.tseq + 1) & 0x3F:
        verdict = "accept"
    elif (st.frag or st.after_fin) and confirmed(ctrl) and st.fcb == (ctrl >> 5) & 1 and n == st.tseq \
            and user == st.last:
        return "discard"   # a link-layer retry, the whole segment identical: no state changes
    elif st.frag:
        st.clear()
        return "transport_seq"
    else:
        st.clear()
        return "first_chunk_missing"
    st.tseq, st.last, st.after_fin, st.frag = n, user, bool(t & 0x80), not t & 0x80
    st.fcb = (ctrl >> 5) & 1 if confirmed(ctrl) else None
    st.octets += len(user) - 1
    if st.octets > LIMIT:
        st.clear()
        return "fragment_limit"
    if t & 0x80 and u.msg is not None and u.msg.why == "throws":
        st.clear()
        return "app_parse"
    return verdict


def audit(c):
    """Every verdict other than accept, as (flow port, end, unit, verdict), in the order sent."""
    out, state = [], collections.defaultdict(End)
    for d in c.deliveries:
        st = state[(d.flow.port, d.end)]
        if d.lost:
            st.clear()   # gap (2.5)
            continue
        for u, a, b in d.pieces:
            if any(p[0].lost for p in u.pieces):
                continue   # octets after a hole are scanned: nothing of the unit is a frame
            if c.l4 == "udp" and len({id(p[0]) for p in u.pieces}) > 1:
                if a == 0 and u.kind in ("frame", "retry"):
                    st.clear()   # truncated at the first datagram's end (2.4); the rest is scanned
                continue
            if b < len(u.data):
                continue   # the rest follows in a later segment
            if u.kind == "link":
                st.fcb = None if u.data[3] & 0x40 else st.fcb   # a primary link-only frame clears fcb
            elif u.kind in ("frame", "retry") and u.label == "valid":
                v = rule(st, u)
                if v != "accept":
                    out.append((d.flow.port, d.end, u.name, v))
            elif DROPPED.match(u.label) or (u.label.startswith("zeros") and c.l4 == "udp"):
                st.clear()   # chunk_crc or truncated
    return out


def check_pinned_audit(get):
    found = [(name, v) for name, (case, c) in get().items() if case in PINNED for v in audit(c)
             if v[3] in ("transport_seq", "discard")]
    assert found == [("dnp3-resync-udp-link-retry-middle", (20000, "m", "retry", "discard"))], found


def test_the_audit_of_the_pinned_rows():
    """Design 3.3: of the 112 pinned cases, their twins and control, the rule changes only
    dnp3-resync-udp-link-retry-middle, whose retry it discards; no other frame meets the drop rule or
    either discard."""
    check_pinned_audit(caps)


def cell_counts(a):
    return {(m.group(1), m.group(2)): int(m.group(3)) for m in re.finditer(r"cnt\.([mo])\.([a-z_]+)=(\d+)", a)}


def check_new_cells(rows):
    """Each deliverable 3 cell's transport_seq and first_chunk_missing, per end, are what the rule gives
    on the case's capture (0 where the cell names none, a report cell's included)."""
    for r in rows:
        got = collections.Counter((e, v) for _, e, _, v in audit(cap(r["case"])))
        want = cell_counts(r["a"])
        for e in "mo":
            for cause in ("transport_seq", "first_chunk_missing"):
                assert got[(e, cause)] == want.get((e, cause), 0), (r["case"], e, cause)


def test_the_new_cells_count_what_the_rule_gives():
    check_new_cells(NEW)
    assert sum(cell_counts(r["a"]).get(("m", "transport_seq"), 0) + cell_counts(r["a"]).get(("o", "transport_seq"), 0)
               for r in NEW) == 17


def check_numbered_from(c):
    """m numbered from n: m's next frame after the marker carries n, and W's frames step on, mod 64."""
    build = ROWS[c.case]["build"]
    n = int(re.search(r"m numbered from (\d+)", build).group(1))
    ms = [u for u in units(c, lambda x: x.end == "m" and x.kind == "frame")]
    first = ms[0] if build.startswith("m numbered") else next(u for u in ms if u.msg.name == "W")
    assert app_of(first.data)[0] & 0x3F == n, c.name
    if c.case == "dnp3-resync-udp-seq-wrap":
        assert [app_of(u.data)[0] & 0x3F for u in ms if u.msg.name == "W"] == [62, 63, 0]


def test_the_cells_that_number_m_do_so():
    assert NUMBERED_FROM == {"dnp3-resync-udp-seq-wrap", "dnp3-resync-udp-fir-any-number"}
    for case in NUMBERED_FROM:
        check_numbered_from(cap(case))


def check_three_w(c):
    """W1, W2 and W3 in one cell: W in three frames of unconfirmed user data, split as W1c to W3c are."""
    ws = units(c, lambda x: x.name in ("W1", "W2", "W3"))
    assert [len(u.data) for u in ws] == [14, 23, 22] and all(u.data[3] == 0xC4 for u in ws), c.name
    assert b"".join(app_of(u.data)[1:] for u in ws) == dnp3.request(app_of(ws[0].data)[1] & 0x0F, dnp3.DIRECT_OPERATE,
                                                                     dnp3.crob(0))


def test_three_frame_w_is_split_as_w1c_to_w3c():
    for case in ("dnp3-resync-udp-seq-wrap", "dnp3-resync-udp-substitution-missed", "dnp3-resync-udp-repeat-unconfirmed"):
        c = cap(case)
        if case == "dnp3-resync-udp-substitution-missed":
            # W2 is left out of the capture: its frame as built.
            w = c.flows[0].msgs["W"]
            assert [len(f) for f in w.frames] == [14, 23, 22] and w.frames[1] not in [u.data for u in units(c)]
        else:
            check_three_w(c)


def check_labels(c):
    """builder-seq's labels: a retry after a primary link-only frame is no retry, and fc is labelled by rule (A)."""
    state = {u.msg.name: rc.message_state(u.msg, c)[0] for u in units(c) if u.msg is not None}
    want = {"dnp3-resync-udp-repeat-after-reset": ("W", "absent"), "dnp3-resync-udp-link-retry-middle": ("W", "seen"),
            "dnp3-resync-udp-edge-fc32-4-resp": ("Xo", "absent"), "dnp3-resync-udp-edge-fc32-2-resp": ("Xo", "seen"),
            "dnp3-resync-udp-edge-fc100-2-resp": ("Xo", "seen"), "dnp3-resync-udp-edge-fc129-4-orig": ("X", "seen")}
    name, st = want[c.case]
    assert state[name] == st, (c.case, state[name])


LABELLED = ["dnp3-resync-udp-repeat-after-reset", "dnp3-resync-udp-link-retry-middle",
            "dnp3-resync-udp-edge-fc32-4-resp", "dnp3-resync-udp-edge-fc32-2-resp",
            "dnp3-resync-udp-edge-fc100-2-resp", "dnp3-resync-udp-edge-fc129-4-orig"]


def test_builder_seq_labels():
    for case in LABELLED:
        check_labels(cap(case))


def seq_unit(case, name):
    c = fresh(case)
    return c, next(x for x in units(c) if x.name == name)


def control_audit_skips_a_number(mp):
    """A builder that numbers a multi-frame message's frame 2 one past its frame 1's next number."""
    caps()
    orig = rc.Flow._frames

    def skipping(self, end, apdu, how="one", take=None, confirmed=False):
        out = orig(self, end, apdu, how, take, confirmed)
        if len(out) > 1 and not confirmed:
            user = rc.user_data(out[1])
            out[1] = rc.link_frame(out[1][3], out[1][4] | out[1][5] << 8, out[1][6] | out[1][7] << 8,
                                   bytes([(user[0] & 0xC0) | ((user[0] + 1) & 0x3F)]) + user[1:])
        return out
    mp.setattr(rc.Flow, "_frames", skipping)
    c = fresh("dnp3-resync-udp-link-only-mid-fragment")
    return lambda: check_pinned_audit(lambda: dict(caps(), **{c.name: (c.case, c)}))


def control_audit_retry_toggles_fcb(mp):
    """link-retry-middle's retry with its FCB toggled: no longer a link-layer retry."""
    c, u = mutate(fresh("dnp3-resync-udp-link-retry-middle"), "retry", lambda b: b)
    u.data = rc.link_frame(u.data[3] ^ 0x20, 10, 5, rc.user_data(u.data))
    return lambda: check_pinned_audit(lambda: dict(caps(), **{c.name: (c.case, c)}))


def control_new_cell_counts_nothing(mp):
    """Item 1's cell with transport_seq dropped, as if the rule did not run."""
    r = dict(ROWS["dnp3-resync-udp-insert-valid-middle"])
    r["a"] = r["a"].replace("cnt.m.transport_seq=1", "cnt.m.transport_seq=0")
    return lambda: check_new_cells([r])


def control_seg_octet(mp):
    """seg's application octet 23h, not 22h."""
    c, u = mutate(fresh("dnp3-resync-udp-insert-valid-middle"), "I", lambda b: b[:11] + b"\x23" + b[12:])
    return lambda: check_seq_failure(c, u)


def control_seg_ctl_unconfirmed(mp):
    """seg(2,ctl=W1c) with the unconfirmed control octet."""
    c, u = mutate(fresh("dnp3-resync-udp-fcb-repeat-middle"), "I", lambda b: b[:3] + b"\xc4" + b[4:])
    return lambda: check_seq_failure(c, u)


def control_firopen_number(mp):
    """firopen(5) numbered 6."""
    c, u = seq_unit("dnp3-resync-udp-per-end-seq", "Ro/1")
    u.data = frame_from("o", "udp", bytes([0x40 | 6]) + app_of(u.data)[1:])
    return lambda: check_seq_failure(c, u)


def control_copy_octet_last(mp):
    """octet(W2c) inverting the last application octet, not the first."""
    c, u = seq_unit("dnp3-resync-udp-retry-compare-octet", "D")
    user = rc.user_data(source(u))
    u.data = rc.link_frame(u.data[3], 10, 5, user[:-1] + bytes([user[-1] ^ 0xFF]))
    return lambda: check_seq_failure(c, u)


def control_copy_fewer_first(mp):
    """fewer(W2c) without the first application octet, not the last."""
    c, u = seq_unit("dnp3-resync-udp-retry-compare-shorter", "D")
    user = rc.user_data(source(u))
    u.data = rc.link_frame(u.data[3], 10, 5, user[:1] + user[2:])
    return lambda: check_seq_failure(c, u)


def control_copy_more_first(mp):
    """more(W2c) with 00h before the application octets, not after."""
    c, u = seq_unit("dnp3-resync-udp-retry-compare-longer", "D")
    user = rc.user_data(source(u))
    u.data = rc.link_frame(u.data[3], 10, 5, user[:1] + b"\x00" + user[1:])
    return lambda: check_seq_failure(c, u)


def control_copy_fin_clear(mp):
    """fin(W2c) with FIN left clear: W2c itself."""
    c, u = seq_unit("dnp3-resync-udp-retry-compare-fin", "D")
    u.data = source(u)
    return lambda: check_seq_failure(c, u)


def control_copy_fcb_kept(mp):
    """fcb(W2c) with the FCB not toggled."""
    c, u = seq_unit("dnp3-resync-udp-repeat-fcb-toggled", "W2c'")
    u.data = source(u)
    return lambda: check_seq_failure(c, u)


def control_read_to_o1(mp):
    """read(W2c) addressed to O1's link 10, not 11."""
    c, u = seq_unit("dnp3-resync-udp-retry-compare-after-fin", "s")
    u.data = rc.link_frame(u.data[3], 10, 5, rc.user_data(u.data))
    return lambda: check_seq_failure(c, u)


def control_badobj_four_octets(mp):
    """badobj without its object octet: a whole 4-octet response."""
    c, u = seq_unit("dnp3-resync-udp-other-end-app-parse-open", "Xo")
    u.data = frame_from("o", "udp", rc.user_data(u.data)[:-1])
    return lambda: check_seq_failure(c, u)


def control_fc2_split_one_three(mp):
    """fc2(129,4) split 1 + 3, not 2 + 2."""
    orig = rc.sizes
    mp.setattr(rc, "sizes", lambda n, how: [1, n - 1] if how == "fc2" else orig(n, how))
    c, u = seq_unit("dnp3-resync-udp-edge-fc129-split-orig", "X/1")
    return lambda: check_seq_failure(c, u)


def control_lostmiddle_sent(mp):
    """lostmiddle with its frame 2 on the wire."""
    c, u = seq_unit("dnp3-resync-udp-middle-lost", "Ro/1")
    c.flows[0].send([rc.Unit("Ro/2", "o", u.msg.frames[1], msg=u.msg)])
    return lambda: check_seq_failure(c, u)


def control_embedhead_chunk_valid(mp):
    """embedhead whose first chunk CRC passes."""
    c, u = seq_unit("dnp3-resync-udp-embedded-offset-3", "Xo")
    u.data = u.data[:26] + dnp3.crc(u.data[10:26]) + u.data[28:]
    return lambda: check_seq_failure(c, u)


def control_embedlast_not_last(mp):
    """embedlast whose last octet is 00h, so W5 does not start there."""
    c, u = seq_unit("dnp3-resync-udp-embedded-last-octet", "X")
    u.data = u.data[:63] + b"\x00"
    return lambda: check_seq_failure(c, u)


def control_three_w_two_octets(mp):
    """W1 of a three-frame W holding two application octets."""
    orig = rc.sizes
    mp.setattr(rc, "sizes", lambda n, how: [2, 9, n - 11] if how == "three" else orig(n, how))
    c = fresh("dnp3-resync-udp-seq-wrap")
    return lambda: check_three_w(c)


def control_numbered_from_ignored(mp):
    """A builder that ignores m numbered from n."""
    orig = rc.parse
    mp.setattr(rc, "parse", lambda build: [p for p in orig(build) if p[0] != "number"])
    c = fresh("dnp3-resync-udp-seq-wrap")
    return lambda: check_numbered_from(c)


def control_reset_reads_secondary(mp):
    """18c with its second Reset Link States read as a secondary frame: the retry after it then reads as one."""
    c = fresh("dnp3-resync-udp-repeat-after-reset")
    rsts = units(c, lambda x: x.name == "Rst")
    rsts[1].data = rsts[1].data[:3] + bytes([rsts[1].data[3] & ~0x40 & 0xFF]) + rsts[1].data[4:]
    return lambda: check_labels(c)


def control_fc_label_without_32(mp):
    """fc's label rule with 32 left out of the object arms."""
    mp.setattr(rc, "OBJECT_ARM", rc.OBJECT_ARM - {32})
    c = fresh("dnp3-resync-udp-edge-fc32-4-resp")
    return lambda: check_labels(c)


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
    check_twins("dnp3-resync-tcp-gap-header", lambda n: fresh(n))
    check_twins("dnp3-resync-tcp-keepalive", lambda n: fresh(n))
    check_tcp_stream(fresh("dnp3-resync-tcp-gap-header"))
    check_w1_w2(fresh("dnp3-resync-udp-insert-truncated"))
    rows = rt.expected_rows(EXPECTED)
    check_tshark_list(listed(rows), rows)
    check_pinned_audit(caps)
    check_new_cells(NEW)
    for case, name in (("insert-valid-middle", "I"), ("fcb-repeat-middle", "I"), ("per-end-seq", "Ro/1"),
                       ("retry-compare-fin", "D"), ("retry-compare-octet", "D"), ("retry-compare-shorter", "D"),
                       ("retry-compare-longer", "D"), ("repeat-fcb-toggled", "W2c'"), ("retry-compare-after-fin", "s"),
                       ("other-end-app-parse-open", "Xo"), ("edge-fc129-split-orig", "X/1"), ("middle-lost", "Ro/1"),
                       ("embedded-offset-3", "Xo"), ("embedded-last-octet", "X")):
        check_seq_failure(*seq_unit(f"dnp3-resync-udp-{case}", name))
    check_three_w(fresh("dnp3-resync-udp-seq-wrap"))
    check_numbered_from(fresh("dnp3-resync-udp-seq-wrap"))
    for case in LABELLED:
        check_labels(fresh(case))


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
