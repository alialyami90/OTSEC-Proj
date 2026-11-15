"""HR-23's stage-2 builder and the false-positive set's, against their pins (D6, brief P4-4-HR2325S, deliverable 1).

hr23_cases.py writes HR-23's stage-2 cases and malformed set, and fp_set.py
the false-positive set built once for HR-23 and HR-25. This test checks what
they write from the bytes on the wire: the captures and labels are the
committed ones; the wire is valid and on TEST-NET; every frame is whole and
valid, or carries exactly the damage its label names; each label's DIR bit,
side and message are the bytes'; the cases are built as the design's section
4.2 says (the relay's first datagram, the short messages, the port
arrangements, the mid-stream join, the forged DIR); each malformed input is
what its name says; the false-positive set meets its floors, its classes'
rules and the redraw rule; and the committed tshark lists and the sort name a
cause or a side for each row. The expected bytes come from dnp3.py, not from
the builders' helpers. Each check has a named control: a mutant the check
must fail. Stdlib only and no tshark, so it runs in CI's python job;
hr23_tshark.py is tshark's half.
"""

import collections
import hashlib
import os
import struct

import pytest

import dnp3
import dnp3_cases
import fp_set as fs
import hr23_cases as hc
import hr23_tshark as ht
import pcapfile
import resync_tshark as rt
import synth

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "fixtures", "network", "gt-pcap")
HR23, FP = os.path.join(FIX, "hr23"), os.path.join(FIX, "fp")
_CACHE = {}


def caps():
    if "hr23" not in _CACHE:
        _CACHE["hr23"] = {c.name: c for c in hc.captures()}
    return _CACHE["hr23"]


def fps():
    if "fp" not in _CACHE:
        _CACHE["fp"] = {b.name: b for b in fs.built()}
    return _CACHE["fp"]


# --- reading the wire ------------------------------------------------------

def parse(data):
    """(src ip, dst ip, proto, sport, dport, seq, ack, flags, payload) of an Ethernet IPv4 frame."""
    assert data[12:14] == b"\x08\x00"
    ihl = (data[14] & 0x0F) * 4
    total = struct.unpack("!H", data[16:18])[0]
    t = 14 + ihl
    proto = data[23]
    sport, dport = struct.unpack("!HH", data[t:t + 4])
    if proto == synth.UDP:
        return data[26:30], data[30:34], proto, sport, dport, None, None, None, data[t + 8:14 + total]
    seq, ack = struct.unpack("!II", data[t + 4:t + 12])
    off = (data[t + 12] >> 4) * 4
    return data[26:30], data[30:34], proto, sport, dport, seq, ack, data[t + 13], data[t + off:14 + total]


def ones_complement_ok(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def ip(s):
    return bytes(int(x) for x in s.split("."))


TEST_NET = ip("192.0.2.0")[:3]
LLMNR = ip("224.0.0.252")


def check_wire(frames):
    """Valid IPv4, UDP and TCP checksums; TEST-NET-1 ends (LLMNR's group as a
    destination); locally administered source MACs."""
    for fr in frames:
        d = fr.data
        ihl = (d[14] & 0x0F) * 4
        assert ones_complement_ok(d[14:14 + ihl])
        total = struct.unpack("!H", d[16:18])[0]
        seg = d[14 + ihl:14 + total]
        assert ones_complement_ok(d[26:34] + struct.pack("!BBH", 0, d[23], len(seg)) + seg)
        src, dst = d[26:30], d[30:34]
        assert src[:3] == TEST_NET and (dst[:3] == TEST_NET or dst == LLMNR)
        assert d[6] & 0x02 and not d[6] & 0x01 and len(d) >= 60


def check_hr23_wire(cap):
    check_wire(hc.frames_of(cap))
    for units, fr in cap.sent:
        assert parse(fr.data)[-1] == b"".join(u.data for u in units), cap.name


# --- frames, from dnp3.py ---------------------------------------------------

def frame_ok(b):
    """(header CRC passes, [each chunk CRC passes], link length, the user data)."""
    out, user, i = [], b"", 10
    while i < len(b):
        n = min(16, len(b) - i - 2)
        out.append(dnp3.crc(b[i:i + n]) == b[i + n:i + n + 2])
        user += b[i:i + n]
        i += n + 2
    return dnp3.crc(b[:8]) == b[8:10], out, b[2], user


def frame_len(length):
    n = length - 5
    return 10 + n + 2 * (-(-n // 16))


def check_hr23_units(cap):
    """Every valid unit is a whole frame whose CRCs pass, whose length is its
    octets', whose DIR is its label's, and whose link addresses are its
    ends'; its application octets carry the label's code."""
    for units, _ in cap.sent:
        for u in units:
            if u.label != "valid":
                continue
            hdr_ok, chunks, length, user = frame_ok(u.data)
            assert hdr_ok and all(chunks) and len(u.data) == frame_len(length), (cap.name, u.name)
            ctrl, dest, src = u.data[3], *struct.unpack("<HH", u.data[4:8])
            assert str(ctrl >> 7) == u.dir, (cap.name, u.name)
            me, peer = u.flow.host[u.end][2], u.flow.host["o" if u.end == "m" else "m"][2]
            assert (dest, src) == (peer, me), (cap.name, u.name)
            m = u.msg
            if m is not None and user[0] & 0x40 and len(user) >= 3 and m.code != "-":
                assert user[2] == m.code, (cap.name, u.name)


def check_hr23_sides(cap):
    """The label's side for each end is the one hr23_tshark.zeek_sides gives
    from the flow's first packet: a second reading of the design's rule."""
    for f in cap.flows:
        src, dst, proto, sport, dport, _, _, flags, _ = parse(f.conv.frames[0].data)
        dotted = lambda b: ".".join(str(x) for x in b)
        fl = ("1" if flags and flags & synth.SYN else "0", "1" if flags and flags & synth.ACK else "0")
        orig, _, _ = ht.zeek_sides(f.l4, (dotted(src), str(sport), dotted(dst), str(dport)), fl)
        end = next(e for e in ("m", "o") if (f.host[e][1], str(f.port[e])) == orig)
        assert f.side[end] == "orig", (cap.name, f.name)


def units_of(cap, end=None):
    return [u for units, _ in cap.sent for u in units if end is None or u.end == end]


def app(u):
    return frame_ok(u.data)[3][1:]


def check_relay_first(cap):
    """The relay's first datagram is its solicited 129, CON clear, answering
    a missed request (design 4.2), and nothing of the master's before the
    write or the restart is shorter than 4 application octets."""
    first = units_of(cap)[0]
    assert first.end == "o" and app(first)[1] == dnp3.RESPONSE and not app(first)[0] & 0x20, cap.name
    for u in units_of(cap, "m"):
        if u.msg.code in (dnp3.WRITE, hc.COLD_RESTART):
            break
        assert len(app(u)) >= 4, (cap.name, u.name)


def check_master_short(cap):
    """0, 13 and 24 are each 2 application octets and each followed by a
    master request of 4 or more; the confirm follows a response with CON set."""
    seq = units_of(cap)
    for i, u in enumerate(seq):
        if u.end == "m" and u.msg.code in (dnp3.CONFIRM, hc.COLD_RESTART, hc.RECORD_CURRENT_TIME):
            assert len(app(u)) == 2, u.name
            nxt = next(v for v in seq[i + 1:] if v.end == "m")
            assert len(app(nxt)) >= 4, u.name
        if u.end == "m" and u.msg.code == dnp3.CONFIRM:
            assert app(seq[i - 1])[0] & 0x20, u.name


def check_tcp_master_short(cap):
    """No SYN or SYN-ACK; the outstation's frames before the master's first
    within the PIA's 1,024 octets and 100 packets; the master's first frame
    at a time no packet of the outstation's has; one response with CON set;
    each short message followed by a write with objects."""
    (f,) = cap.flows
    assert not any(parse(fr.data)[7] & synth.SYN for fr in f.conv.frames)
    order = [(units, fr) for units, fr in cap.sent]
    k = next(i for i, (units, _) in enumerate(order) if units[0].end == "m")
    before = [units for units, _ in order[:k]]
    assert sum(len(u.data) for us in before for u in us) <= 1024 and len(before) <= 100
    first_m = order[k][1].ns
    o_times = {fr.ns for units, fr in order if units[0].end == "o"}
    assert first_m not in o_times
    assert sum(1 for u in units_of(cap, "o") if app(u)[0] & 0x20) == 1
    check_master_short_tcp(cap)


def check_master_short_tcp(cap):
    seq = units_of(cap, "m")
    for i, u in enumerate(seq):
        if u.msg.code in (dnp3.CONFIRM, hc.COLD_RESTART, hc.RECORD_CURRENT_TIME):
            assert len(app(u)) == 2 and seq[i + 1].msg.code == dnp3.WRITE and seq[i + 1].msg.objects != "-"


def check_dir_spoof(cap):
    """Exactly one master frame has DIR clear: the direct operate with g12v1."""
    clear = [u for u in units_of(cap, "m") if u.dir == "0"]
    assert len(clear) == 1 and clear[0].msg.code == dnp3.DIRECT_OPERATE and app(clear[0])[2:5] == b"\x0c\x01\x28"
    assert all(u.dir == "1" for u in units_of(cap, "m") if u is not clear[0])
    assert all(u.dir == "0" for u in units_of(cap, "o"))


def check_ports(c):
    """Design 4.1's port arrangement: a relay-started UDP case puts both ends
    in likely_server_ports or both outside, except swap-control (relay in,
    master out) and relay-off-set (relay out, master in); the TCP case puts
    both ends outside."""
    want = {"dnp3-udp-swap-control": (True, False), "dnp3-udp-relay-off-set": (False, True)}
    (f,) = c.flows
    s = hc.LIKELY[f.l4]
    got = (f.port["o"] in s, f.port["m"] in s)
    if c.name in want:
        assert got == want[c.name], c.name
    elif f.l4 == "tcp":
        assert got == (False, False), c.name
    else:
        assert got[0] == got[1], c.name


RELAY_STARTED = ("dnp3-udp-relay-write", "dnp3-udp-relay-restart", "dnp3-udp-swap-control",
                 "dnp3-udp-relay-off-set", "dnp3-udp-relay-both-off-set", "dnp3-tcp-master-short")


def payloads(cap):
    return [(units[0].end, b"".join(u.data for u in units)) for units, _ in cap.sent]


def check_swap_pair(a, b):
    """swap-control is relay-write with the master's port moved, and nothing else."""
    assert payloads(a) == payloads(b)
    assert (a.flows[0].port["m"], b.flows[0].port["m"]) == (20000, 41019)


def unsolicited_apdus():
    case = next(c for c in dnp3_cases.cases() if c[0] == "dnp3-udp-unsolicited")
    return [mask(frame_ok(parse(fr.data)[-1])[3][1:]) for fr in case[1]]


def mask(a):
    """An APDU with its g2v2 object's event time zeroed (each capture has its
    own clock): control, code, IIN, then 02 02 17 01, the index, the flags,
    and the time at octets 10 to 15."""
    return a[:10] + bytes(6) + a[16:] if a[1:2] == bytes([dnp3.UNSOL_RESPONSE]) else a


def check_arrangement(cap):
    """The two arrangement cases carry dnp3-udp-unsolicited's APDUs (design 1 item 2)."""
    assert [mask(app(u)) for u in units_of(cap)] == unsolicited_apdus(), cap.name


def test_the_hr23_captures_are_valid_and_built_as_the_design_says():
    c = caps()
    for cap in c.values():
        check_hr23_wire(cap)
        check_hr23_units(cap)
        check_hr23_sides(cap)
    for name in RELAY_STARTED[:3]:
        check_relay_first(c[name])
    check_master_short(c["dnp3-udp-master-short"])
    check_tcp_master_short(c["dnp3-tcp-master-short"])
    check_dir_spoof(c["dnp3-udp-dir-spoof"])
    check_dir_spoof(c["dnp3-tcp-dir-spoof"])
    for name in RELAY_STARTED:
        check_ports(c[name])
    check_swap_pair(c["dnp3-udp-relay-write"], c["dnp3-udp-swap-control"])
    check_arrangement(c["dnp3-udp-relay-off-set"])
    check_arrangement(c["dnp3-udp-relay-both-off-set"])


# --- the malformed set -------------------------------------------------------

def unit(cap, name):
    return next(u for u in units_of(cap) if u.name == name)


def check_malformed(cap):
    """Each input is what its name says, from its bytes (hr23-conditions.tsv, mal-checks)."""
    n = cap.name[len("dnp3-mal-"):]
    if n.startswith("udp-octets-"):
        k = int(n[-1])
        x = unit(cap, "X").data
        assert x == b"\x05\x64\x0b"[:k]
        if k >= 2:
            # With Q's first octets, the 11-octet header stage assembles a header whose CRC fails.
            h = (x + unit(cap, "Q").data)[:10]
            assert h[:2] == b"\x05\x64" and dnp3.crc(h[:8]) != h[8:10]
    elif n in ("udp-len-0", "udp-len-1", "udp-len-2", "udp-len-3", "udp-len-4-nofir"):
        x = unit(cap, "X").data
        k = int(n[8])
        assert x[2] == k and dnp3.crc(x[:8]) == x[8:10] and x[10:] == bytes(6)
    elif n.startswith("udp-len-4-fir"):
        x = unit(cap, "X").data
        assert len(x) == 11 and x[2] == 4 and dnp3.crc(x[:8]) == x[8:10]
        assert x[10] & 0xC0 == (0xC0 if n.endswith("firfin") else 0x40)
    elif n == "udp-len-5-trail":
        units = next(us for us, _ in cap.sent if us[0].name == "L")
        assert [u.name for u in units] == ["L", "W"] and units[0].data[2] == 5 and len(units[0].data) == 10
    elif n == "udp-len-6":
        x = unit(cap, "X").data
        assert x[2] == 6 and frame_ok(x)[3][0] & 0xC0 == 0xC0 and len(frame_ok(x)[3]) == 1
    elif n.startswith("udp-app-1-"):
        assert len(app(unit(cap, "X"))) == 1 and unit(cap, "X").end == ("m" if n.endswith("orig") else "o")
    elif n.startswith(("udp-fc", "tcp-fc")):
        parts = n.split("-")
        code = int(parts[1][2:])
        x = app(unit(cap, "X"))
        assert x[1] == code
        if parts[2].isdigit():
            assert len(x) == int(parts[2])
        if n.startswith("tcp-"):
            assert unit(cap, "X").dir == ("1" if n.endswith("dirset") else "0")
            assert unit(cap, "X").end == ("o" if "resp" in n else "m")
        else:
            assert unit(cap, "X").end == ("m" if n.endswith("orig") else "o")
    elif n == "udp-hdr-crc":
        x = unit(cap, "X").data
        assert dnp3.crc(x[:8]) != x[8:10] and x[8] ^ 0xFF == dnp3.crc(x[:8])[0]
    elif n in ("udp-chunk-crc", "tcp-eof-badchunk-fin"):
        hdr_ok, chunks, _, _ = frame_ok(unit(cap, "X").data)
        assert hdr_ok and chunks == [False]
    elif n == "udp-longer":
        units = next(us for us, _ in cap.sent if us[0].name == "W")
        assert [u.name for u in units] == ["W", "T"] and len(units[1].data) == 5 and 5 not in units[1].data
    elif n == "udp-two-frames":
        assert [u.name for u in next(us for us, _ in cap.sent if us[0].name == "W")] == ["W", "Q"]
    elif n == "udp-len-255":
        x1 = unit(cap, "X/1").data
        assert x1[2] == 255 and len(x1) == 292
    elif n == "udp-nofir":
        assert frame_ok(unit(cap, "X").data)[3][0] & 0xC0 == 0x80
    elif n in ("udp-nofin-fir", "tcp-eof-firopen-fin", "tcp-eof-firopen-open"):
        assert frame_ok(unit(cap, "X/1").data)[3][0] & 0xC0 == 0x40 and len(app(unit(cap, "X/1"))) == 1
    elif n == "udp-limit":
        xs = [u for u in units_of(cap) if u.name.startswith("X/")]
        total = sum(len(frame_ok(u.data)[3]) - 1 for u in xs)
        assert len(xs) == 413 and total == 102_649 > 102_400
    elif n.startswith("udp-dir-"):
        dirs = [u.dir for u in units_of(cap, "o")]
        assert dirs == (["1", "1", "1"] if n.endswith("both") else ["0", "1", "0"])
    elif n.startswith("udp-short-"):
        code, side = n.split("-")[2], n.split("-")[3]
        want = {"0": b"\x00", "13": b"\x0d", "13x": b"\x0d\x00", "1x": b"\x01\x3c"}[code]
        assert app(unit(cap, "X"))[1:] == want
        assert unit(cap, "X").flow.side["m"] == side
    elif n == "tcp-eof-len4-fin":
        x = unit(cap, "X").data
        assert x[2] == 4 and len(x) == 11 and x[10] & 0xC0 == 0x40
    else:
        raise AssertionError(f"no check for {cap.name}")
    if n.startswith("tcp-eof-"):
        fins = sum(1 for fr in cap.flows[0].conv.frames if parse(fr.data)[7] & synth.FIN)
        assert fins == (0 if n.endswith("open") else 2)


def test_every_malformed_input_is_what_its_name_says():
    for name, _ in hc.MALFORMED:
        check_malformed(caps()[name])


# --- the false-positive set --------------------------------------------------

def datagrams(b):
    """{item: [payload, ...]} of a UDP class, from the wire."""
    out = collections.defaultdict(list)
    for fr in b.frames:
        src, dst, _, sport, dport, *_, payload = parse(fr.data)
        out[(sport, dport)].append(payload)
    return list(out.values())


def streams(b):
    """{(client port): {'c': [payloads], 's': [payloads]}} of a TCP class, data segments only."""
    out = collections.OrderedDict()
    for fr in b.frames:
        src, dst, _, sport, dport, seq, ack, flags, payload = parse(fr.data)
        key = sport if dport == 20000 else dport
        f = out.setdefault(key, {"c": [], "s": [], "frames": []})
        f["frames"].append((src, seq, ack, flags, payload))
        if payload:
            f["c" if dport == 20000 else "s"].append((seq, payload))
    return out


def passing(buf):
    """An independent reading of the redraw rule: every offset of 05 64 with 8
    more octets whose header CRC passes."""
    return [i for i in range(len(buf) - 9) if buf[i:i + 2] == b"\x05\x64" and dnp3.crc(buf[i:i + 8]) == buf[i + 8:i + 10]]


def check_fp_counts(by):
    n = {name: len(b.items) for name, b in by.items()}
    floors = {"fp-udp-1": 300, "fp-udp-2": 300, "fp-udp-4": 300, "fp-udp-5": 300, "fp-udp-3a": 30,
              "fp-udp-3b-data": 30, "fp-udp-3b-link": 30, "fp-udp-3c": 30, "fp-tcp-6": 100, "fp-tcp-6-hole": 30}
    for name, floor in floors.items():
        assert n[name] >= floor, name
    ones = collections.Counter(len(d[0]) for d in datagrams(by["fp-udp-1"]))
    assert sorted(ones) == list(range(2, 11)) and min(ones.values()) >= 33
    protos = collections.Counter(it.facts for it in by["fp-udp-4"].items)
    assert len(protos) == 4 and min(protos.values()) >= 75
    codes = collections.Counter(it.code for it in by["fp-udp-3b-data"].items)
    assert all(codes[str(c)] >= 2 for c in fs.EMPTY_ARM)
    assert sum(v for k, v in codes.items() if int(k) not in fs.EMPTY_ARM) >= 16


def check_fp_redraw(b):
    """No datagram, end's stream or run between holes holds a passing header
    at an offset its class does not name."""
    if b.l4 == "udp":
        for it, ds in zip(b.items, datagrams(b)):
            for d, named in zip(ds, it.named):
                assert set(passing(d)) <= set(named), (b.name, it.k)
    else:
        for it in b.items:
            for end in ("c", "s"):
                segs = it.streams[end]
                assert not passing(b"".join(x for x, _ in segs)), (b.name, it.k)
                for run in fs.runs_of(segs):
                    assert not passing(run), (b.name, it.k)


def check_fp_classes(by):
    """Each class's rule, from the bytes (design 4.3; arm-3bdata)."""
    for d in datagrams(by["fp-udp-1"]):
        assert len(d) == 1 and d[0][:2] == b"\x05\x64" and 2 <= len(d[0]) <= 10
    lens = []
    for d in datagrams(by["fp-udp-2"]):
        assert len(d) == 1 and d[0][:2] == b"\x05\x64" and dnp3.crc(d[0][:8]) != d[0][8:10]
        lens.append(len(d[0]))
    assert min(lens) == 11 and max(lens) == 1472
    for d in datagrams(by["fp-udp-3a"]):
        hdr_ok, chunks, length, user = frame_ok(d[0])
        assert len(d) == 1 and hdr_ok and not any(chunks) and len(d[0]) == frame_len(length)
        assert user[0] & 0xC0 == 0xC0
    for it, d in zip(by["fp-udp-3b-data"].items, datagrams(by["fp-udp-3b-data"])):
        hdr_ok, chunks, length, user = frame_ok(d[0])
        assert len(d) == 2 and hdr_ok and all(chunks) and user[0] & 0xC0 == 0xC0 and user[1] & 0xC0 == 0xC0
        code, n = user[2], len(user) - 1
        assert str(code) == it.code
        assert (code in fs.EMPTY_ARM and n == 2) or ((34 <= code <= 128 or 132 <= code <= 255) and n >= 2)
        assert len(d[1]) >= 11 and d[1][:2] != b"\x05\x64"
    for d in datagrams(by["fp-udp-3b-link"]):
        assert len(d) == 3 and len(d[0]) == 10 and d[0][2] == 5 and dnp3.crc(d[0][:8]) == d[0][8:10]
        assert d[1][:2] != b"\x05\x64" and len(d[2]) >= 11 and d[2][:2] != b"\x05\x64"
    for it, d in zip(by["fp-udp-3c"].items, datagrams(by["fp-udp-3c"])):
        hdr_ok, chunks, _, user = frame_ok(d[0])
        assert len(d) == 1 and hdr_ok and all(chunks) and len(user) == 4 and user[2] in fs.OBJECT_ARM
        assert str(user[2]) == it.code
    for d in datagrams(by["fp-udp-4"]) + datagrams(by["fp-udp-5"]):
        assert len(d) == 1 and d[0][:2] == b"\x05\x64" and dnp3.crc(d[0][:8]) != d[0][8:10]
    for it, d in zip(by["fp-udp-4"].items, datagrams(by["fp-udp-4"])):
        if "radius" in it.facts:
            assert d[0][:4] == b"\x05\x64\x00\x14" and len(d[0]) == 20 and it.sport == 1813
        else:
            assert struct.unpack(">HHHHHH", d[0][:12])[2:] == (1, 0, 0, 0)


def check_fp_tcp(b):
    """Handshake first and FIN exchange last; a hole flow has exactly one
    data segment missing on its labelled end, and the peer's ACK past it;
    reaches is O exactly when the delivered octets reach O, never within the
    margin of it."""
    for it, (port, f) in zip(b.items, streams(b).items()):
        facts = dict(kv.split("=", 1) for kv in it.facts.split(";"))
        delivered = sum(len(p) for e in ("c", "s") for _, p in f[e])
        assert int(facts["delivered"]) == delivered, it.k
        assert abs(delivered - fs.O_BUDGET) >= fs.O_MARGIN and facts["reaches"] == (
            "O" if delivered >= fs.O_BUDGET else "none"), it.k
        holes = []
        for e, isn in (("c", 1001), ("s", 51001)):
            want = isn
            for seq, p in f[e]:
                if seq != want:
                    holes.append((e, seq - want, seq))
                want = seq + len(p)
        if b.name.endswith("hole"):
            assert len(holes) == 1 and facts["hole"] == f"{holes[0][0]}:{holes[0][1]}", it.k
            e, _, after = holes[0]
            peer = ip(fs.SERVER_IP) if e == "c" else ip(fs.CLIENT_IP)
            assert any(x[0] == peer and x[2] >= after for x in f["frames"]), it.k
        else:
            assert not holes and facts["hole"] == "-", it.k
        flags = [x[3] for x in f["frames"]]
        assert flags[:3] == [synth.SYN, synth.SYN | synth.ACK, synth.ACK] and flags[-3] & synth.FIN, it.k


def check_fp_tuples(b):
    tuples = [(it.sport, it.dport) for it in b.items]
    assert len(set(tuples)) == len(tuples), b.name


def test_the_false_positive_set_meets_its_floors_and_its_rules():
    by = fps()
    check_fp_counts(by)
    check_fp_classes(by)
    for b in by.values():
        check_wire(b.frames)
        check_fp_redraw(b)
        check_fp_tuples(b)
    check_fp_tcp(by["fp-tcp-6"])
    check_fp_tcp(by["fp-tcp-6-hole"])


# --- the committed files -----------------------------------------------------

def test_the_committed_hashes_and_labels_are_the_builders(tmp_path):
    for main, d, sha in ((hc.main, HR23, "hr23.sha256"), (fs.main, FP, "fp.sha256")):
        out = tmp_path / os.path.basename(d)
        main(str(out))
        with open(os.path.join(d, sha), encoding="utf-8") as f:
            pinned = f.read()
        assert (out / sha).read_text(encoding="utf-8") == pinned
        for line in pinned.splitlines():
            digest, name = line.split("  ")
            assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest, name
        labels = sorted(n for n in os.listdir(d) if n.endswith(".tsv") and not n.startswith(("tshark-", "sides")))
        assert labels == sorted(n for n in os.listdir(out) if n.endswith(".tsv"))
        for name in labels:
            with open(os.path.join(d, name), "rb") as f:
                assert f.read().replace(b"\r\n", b"\n") == (out / name).read_bytes(), name


def check_tshark_list(path, mode):
    rows = rt.expected_rows(path)
    produced = ["\t".join(r[:-1]) for r in rows]
    assert rows[0][-1] == "cause"
    assert [x for x in rt.compare(produced, rows) if not x.startswith("a cause not in")] == []
    assert all(r[-1] in ht.CAUSES[mode] for r in rows[1:]), [r for r in rows[1:] if r[-1] not in ht.CAUSES[mode]]


def check_sides(rows):
    """The sort's rows: each how is one the rule gives, and on GT-PCAP's own
    DNP3 captures the flows that disagree are exactly those the design names
    (design 4.7): dnp3-udp-temp-port's responses' flow and
    dnp3-udp-unsolicited's, besides the HR-23 cases that start with the relay."""
    assert rows[0] == ht.SIDE_COLUMNS
    gt = {name for name in (fr for fr in os.listdir(os.path.join(FIX, "dnp3")) if fr.endswith(".tsv"))}
    gt = {n[:-4] for n in gt}
    for r in rows[1:]:
        assert r[4] in ("syn", "syn-ack", "first", "first,swapped"), r
        assert (int(r[6]) == 0) == (r[7] == "-"), r
    dis = sorted((r[0], r[2]) for r in rows[1:] if int(r[6]) > 0 and r[0] in gt)
    assert dis == [("dnp3-udp-temp-port", "192.0.2.20:20000"), ("dnp3-udp-unsolicited", "192.0.2.20:20000")], dis
    hr = sorted(r[0] for r in rows[1:] if int(r[6]) > 0 and r[0] in caps())
    assert hr == sorted(set(RELAY_STARTED) - {"dnp3-udp-swap-control"}), hr


def test_the_tshark_lists_and_the_sort_name_a_cause_or_a_side_for_each_row():
    check_tshark_list(os.path.join(HR23, "tshark-beside-labels.tsv"), "labels")
    check_tshark_list(os.path.join(FP, "tshark-beside-fp.tsv"), "fp")
    check_sides(rt.expected_rows(os.path.join(HR23, "sides.tsv")))


# --- the controls: named mutants that each check must fail -------------------

def fresh(name):
    """One capture rebuilt on its own, for a control to change."""
    build = dict(hc.CASES + hc.MALFORMED)[name]
    names = [n for n, _ in hc.CASES + hc.MALFORMED]
    cap = hc.Capture(name, names.index(name), "case" if name in dict(hc.CASES) else "malformed")
    cap.tcp_port = caps()[name].tcp_port
    build(cap)
    return cap


def mutate(cap, name, change):
    """Change one unit's octets, and the packet that carries them, keeping their length."""
    for units, fr in cap.sent:
        off = 0
        for u in units:
            if u.name == name:
                new = change(u.data)
                assert len(new) == len(u.data)
                d = fr.data
                ihl = (d[14] & 0x0F) * 4
                t = 14 + ihl
                start = t + (8 if d[23] == synth.UDP else (d[t + 12] >> 4) * 4) + off
                fr.data = d[:start] + new + d[start + len(new):]
                u.data = new
                return cap
            off += len(u.data)
    raise KeyError(name)


def flip(i):
    return lambda b: b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]


def control_payload_octet_without_checksum(mp):
    c = mutate(fresh("dnp3-udp-relay-write"), "W34", flip(12))
    return lambda: check_wire(hc.frames_of(c))


def control_chunk_crc_octet(mp):
    """A valid unit whose chunk CRC fails, its UDP checksum not checked here."""
    c = mutate(fresh("dnp3-udp-relay-write"), "W34", lambda b: b[:-1] + bytes([b[-1] ^ 0xFF]))
    return lambda: check_hr23_units(c)


def control_dir_bit_not_the_label(mp):
    c = fresh("dnp3-udp-dir-spoof")
    u = unit(c, "W")
    u.dir = "1"
    return lambda: check_hr23_units(c)


def control_side_from_the_first_sender(mp):
    """swap-control labelled with the first sender as orig, as if Zeek never swapped."""
    mp.setattr(hc, "zeek_orig", lambda *a: "first")
    c = fresh("dnp3-udp-swap-control")
    return lambda: check_hr23_sides(c)


def control_relay_first_with_con(mp):
    mp.setattr(hc, "relay_first", lambda f, con=False: f.send(f.reply("R0", seq=0, con=True)))
    c = fresh("dnp3-udp-relay-write")
    return lambda: check_relay_first(c)


def control_master_short_confirm_without_con(mp):
    """R(P), which the confirm follows, with CON clear: its application control octet is at 11."""
    c = fresh("dnp3-udp-master-short")
    mutate(c, "R(P)", lambda b: b[:11] + bytes([b[11] & 0xDF]) + b[12:])
    return lambda: check_master_short(c)


def control_tcp_master_short_with_handshake(mp):
    orig = hc.Flow.__init__

    def with_handshake(self, *a, **k):
        k["handshake"] = True
        orig(self, *a, **k)
    mp.setattr(hc.Flow, "__init__", with_handshake)
    c = fresh("dnp3-tcp-master-short")
    return lambda: check_tcp_master_short(c)


def control_dir_spoof_all_set(mp):
    c = fresh("dnp3-udp-dir-spoof")
    unit(c, "W").dir = "1"
    return lambda: check_dir_spoof(c)


def control_relay_write_on_swap_ports(mp):
    """relay-write built with the master outside the set: Zeek would swap it."""
    c = hc.Capture("dnp3-udp-relay-write", 0, "case")
    c.tcp_port = None
    hc.relay_write(41019)(c)
    return lambda: check_ports(c)


def control_swap_pair_octet(mp):
    b = mutate(fresh("dnp3-udp-swap-control"), "W34", flip(12))
    return lambda: check_swap_pair(caps()["dnp3-udp-relay-write"], b)


def control_arrangement_drops_a_message(mp):
    c = fresh("dnp3-udp-relay-off-set")
    c.sent = c.sent[:-1]
    return lambda: check_arrangement(c)


def control_octets_2_header_passes(mp):
    """octets-2 whose X, with Q's first octets, would pass the header CRC."""
    c = fresh("dnp3-mal-udp-octets-2")
    q = unit(c, "Q").data
    h = b"\x05\x64" + q[:6]
    unit(c, "Q").data = q[:6] + dnp3.crc(h) + q[8:]
    return lambda: check_malformed(c)


def control_len_2_says_3(mp):
    c = fresh("dnp3-mal-udp-len-2")
    mutate(c, "X", lambda b: b[:2] + b"\x03" + b[3:])
    return lambda: check_malformed(c)


def control_fc129_2_with_3_octets(mp):
    mp.setattr(hc, "MALFORMED", [(n, hc.app_octets("m", b"\x81\x00", 129, "-") if n == "dnp3-mal-udp-fc129-2-orig"
                                  else b) for n, b in hc.MALFORMED])
    c = fresh("dnp3-mal-udp-fc129-2-orig")
    return lambda: check_malformed(c)


def control_eof_open_with_fin(mp):
    mp.setattr(hc, "MALFORMED", [(n, hc.eof("firopen", True) if n == "dnp3-mal-tcp-eof-firopen-open" else b)
                                 for n, b in hc.MALFORMED])
    c = fresh("dnp3-mal-tcp-eof-firopen-open")
    return lambda: check_malformed(c)


def control_limit_at_the_limit(mp):
    c = fresh("dnp3-mal-udp-limit")
    c.sent = [s for s in c.sent if s[0][0].name != "X/413"]
    return lambda: check_malformed(c)


def control_fp_floor_short(mp):
    by = dict(fps())
    b = by["fp-udp-3a"]
    short = fs.Built(b.name, b.cls, b.l4, 2)
    short.items = b.items[:29]
    by["fp-udp-3a"] = short
    return lambda: check_fp_counts(by)


def control_fp_planted_header(mp):
    """A class (5) item that holds a passing header at offset 20."""
    b = fps()["fp-udp-5"]
    mb = fs.Built(b.name, b.cls, b.l4, 7)
    it = b.items[0]
    d = it.datagrams[0]
    h = b"\x05\x64\x0b\xc4\x0a\x00\x05\x00"
    planted = fs.Item(it.cls, it.k, it.sport, it.dport)
    planted.datagrams, planted.named = [d[:20] + h + dnp3.crc(h) + d[30:]], [()]
    mb.items = [planted]
    mb.frames = fs.build_udp(mb, planted, mb.t0)
    return lambda: check_fp_redraw(mb)


def control_fp_3c_two_object_octets(mp):
    orig = fs.class3c

    def two(k, D, d):
        it = orig(k, D, d)
        f = it.datagrams[0]
        user = frame_ok(f)[3] + b"\x00"
        hdr = b"\x05\x64" + struct.pack("<BBHH", 5 + len(user), f[3], *struct.unpack("<HH", f[4:8]))
        it.datagrams = [hdr + dnp3.crc(hdr) + user + dnp3.crc(user)]
        return it
    mp.setattr(fs, "class3c", two)
    mp.setattr(fs, "CLASSES", [(n, c, two if g is orig else g, k, l) for n, c, g, k, l in fs.CLASSES])
    by = {b.name: b for b in fs.built()}
    return lambda: check_fp_classes(by)


def copy_class(name):
    """A class's items and frames, copied so a control can change them."""
    b = fps()[name]
    mb = fs.Built(b.name, b.cls, b.l4, 8)
    mb.frames = list(b.frames)
    for it in b.items:
        new = fs.Item(it.cls, it.k, it.sport, it.dport)
        new.streams, new.facts, new.datagrams, new.named = it.streams, it.facts, it.datagrams, it.named
        mb.items.append(new)
    return mb


def control_fp_reaches_flipped(mp):
    """One flow labelled as reaching O when it does not, or the other way."""
    mb = copy_class("fp-tcp-6")
    f = mb.items[0].facts
    mb.items[0].facts = f.replace("reaches=none", "reaches=O") if "reaches=none" in f else f.replace("reaches=O",
                                                                                                    "reaches=none")
    return lambda: check_fp_tcp(mb)


def control_fp_hole_unacked(mp):
    """The first hole flow with no acknowledgement past the hole: every
    packet of the peer's that acknowledges past it acknowledges one octet
    short of its end instead (checksums are not this check's)."""
    mb = copy_class("fp-tcp-6-hole")
    it = mb.items[0]
    segs = it.streams["c"]   # flow 0's hole is on the client's end, its second segment
    assert segs[1][1] and not segs[0][1]
    after = 1001 + len(segs[0][0]) + len(segs[1][0])
    peer = ip(fs.SERVER_IP)
    out = []
    for fr in mb.frames:
        src, _, _, _, dport, _, ack, _, _ = parse(fr.data)
        if src == peer and dport == it.sport and ack >= after:
            t = 14 + (fr.data[14] & 0x0F) * 4
            fr = pcapfile.Frame(fr.ns, fr.data[:t + 8] + struct.pack("!I", after - 1) + fr.data[t + 12:])
        out.append(fr)
    mb.frames = out
    return lambda: check_fp_tcp(mb)


def control_fp_duplicate_tuple(mp):
    b = fps()["fp-udp-1"]
    mb = fs.Built(b.name, b.cls, b.l4, 0)
    mb.items = b.items + b.items[:1]
    return lambda: check_fp_tuples(mb)


def control_tshark_cause_not_named(mp):
    path = os.path.join(HR23, "tshark-beside-labels.tsv")
    rows = rt.expected_rows(path)
    rows[1][-1] = "unknown"
    mp.setattr(rt, "expected_rows", lambda p: rows)
    return lambda: check_tshark_list(path, "labels")


def control_sides_disagree_dropped(mp):
    rows = rt.expected_rows(os.path.join(HR23, "sides.tsv"))
    for r in rows[1:]:
        if r[0] == "dnp3-udp-temp-port" and r[6] != "0":
            r[6], r[7] = "0", "-"
    return lambda: check_sides(rows)


CONTROLS = {name[len("control_"):].replace("_", "-"): f for name, f in globals().items() if name.startswith("control_")}


def test_the_controls_pass_unmutated():
    """Each check passes on a fresh build, so a control's failure is its mutant's."""
    check_wire(hc.frames_of(fresh("dnp3-udp-relay-write")))
    check_hr23_units(fresh("dnp3-udp-dir-spoof"))
    check_hr23_sides(fresh("dnp3-udp-swap-control"))
    check_relay_first(fresh("dnp3-udp-relay-write"))
    check_master_short(fresh("dnp3-udp-master-short"))
    check_tcp_master_short(fresh("dnp3-tcp-master-short"))
    check_dir_spoof(fresh("dnp3-udp-dir-spoof"))
    check_ports(fresh("dnp3-udp-relay-write"))
    check_swap_pair(caps()["dnp3-udp-relay-write"], fresh("dnp3-udp-swap-control"))
    check_arrangement(fresh("dnp3-udp-relay-off-set"))
    for name in ("dnp3-mal-udp-octets-2", "dnp3-mal-udp-len-2", "dnp3-mal-udp-fc129-2-orig",
                 "dnp3-mal-tcp-eof-firopen-open", "dnp3-mal-udp-limit"):
        check_malformed(fresh(name))


@pytest.mark.parametrize("control", sorted(CONTROLS))
def test_each_check_fails_its_named_control(control, monkeypatch):
    check = CONTROLS[control](monkeypatch)
    with pytest.raises(AssertionError):
        check()
