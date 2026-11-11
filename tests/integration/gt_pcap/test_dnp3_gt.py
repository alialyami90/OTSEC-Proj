"""Self-tests of GT-PCAP's DNP3 sources (D6). Stdlib only and no tshark, so
they run in the pytest job. Tshark's half, which reads every frame's
checksums and CRCs and writes the labels, runs in a6-gt-pcap.yml's dnp3 job
(gtlabel.py)."""

import struct

import dnp3
import dnp3_cases
import synth


def ones_complement_ok(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s == 0xFFFF


def crc_bitwise(b):
    """The DNP3 CRC computed bit by bit from the polynomial 0x3D65, not from
    dnp3.py's table."""
    c = 0
    for x in b:
        for i in range(8):
            bit = ((x >> i) & 1) ^ (c & 1)
            c >>= 1
            if bit:
                c ^= 0xA6BC  # 0x3D65 reflected
    return struct.pack("<H", ~c & 0xFFFF)


def all_frames():
    out = [f for _, frames, _ in dnp3_cases.cases() for f in frames]
    return out + dnp3_cases.series(7, dnp3_cases.SERIES["dnp3-train"][1], 120)


def test_generation_is_deterministic():
    a = [(f.ns, f.data) for f in all_frames()]
    b = [(f.ns, f.data) for f in all_frames()]
    assert a == b


def test_ipv4_and_tcp_checksums():
    for f in all_frames():
        d = f.data
        assert d[12:14] == b"\x08\x00"
        ihl = (d[14] & 0x0F) * 4
        ip = d[14:14 + ihl]
        assert ones_complement_ok(ip)
        total = struct.unpack("!H", ip[2:4])[0]
        seg = d[14 + ihl:14 + total]
        pseudo = ip[12:20] + struct.pack("!BBH", 0, ip[9], len(seg))
        assert ones_complement_ok(pseudo + seg)


def l4_payload(d):
    """(IP protocol, source port, destination port, payload) of an untagged
    Ethernet IPv4 frame carrying TCP or UDP."""
    ihl = (d[14] & 0x0F) * 4
    total = struct.unpack("!H", d[16:18])[0]
    off = 14 + ihl
    sport, dport = struct.unpack("!HH", d[off:off + 4])
    hdr = 8 if d[23] == synth.UDP else (d[off + 12] >> 4) * 4
    return d[23], sport, dport, d[off + hdr:14 + total]


def test_dnp3_link_crcs_match_a_bitwise_crc():
    for f in all_frames():
        payload = l4_payload(f.data)[3]
        if not payload:
            continue
        assert payload[:2] == b"\x05\x64"
        assert crc_bitwise(payload[:8]) == payload[8:10]
        body, i = payload[10:], 0
        while i < len(body):
            blk = body[i:i + 16] if len(body) - i > 18 else body[i:-2]
            assert crc_bitwise(blk) == body[i + len(blk):i + len(blk) + 2]
            i += len(blk) + 2


def test_frames_are_ethernet_minimum_and_test_net():
    for f in all_frames():
        assert len(f.data) >= 60
        assert f.data[26:29] == bytes([192, 0, 2]) and f.data[30:33] == bytes([192, 0, 2])


def test_cases_name_known_rules_and_contexts():
    rules = {"unknown-pair", "new-service", "new-function", "unauthorized-write", "own-session-outside-record",
             "node-address-spoofed", "own-session-unseen", "unresolved-address", "sa-failed"}
    for name, frames, rows in dnp3_cases.cases():
        assert rows, name
        for r in rows:
            assert set(r["rules"]) <= rules, (name, r["rules"])
            assert r["context"] in ("acknowledged", "before-acknowledgement")
            assert all(1 <= n <= len(frames) for n in r["frames"])
            assert r["sa"] in ("", "none", "challenged", "aggressive", "failed")
            assert ("sa_error_from" in r) == (r["sa"] == "failed")


def test_the_removed_response_is_gone():
    cases = {n: (f, r) for n, f, r in dnp3_cases.cases()}
    full, rows = cases["dnp3-unauthorized-operate"]
    cut, _ = cases["dnp3-unauthorized-operate-no-response"]
    resp = rows[0]["frames"][1]
    assert len(cut) == len(full) - 2
    assert full[resp - 1].data not in {f.data for f in cut}


def test_group_120_headers_as_s23_names_them():
    # group, variation and qualifier only; the bodies are filler (module note).
    assert dnp3.g120v1_challenge()[:3] == bytes([120, 1, 0x5B])
    assert dnp3.g120v2_reply()[:3] == bytes([120, 2, 0x5B])
    assert dnp3.g120v3_aggressive()[:3] == bytes([120, 3, 0x07])
    assert dnp3.g120v7_error()[:3] == bytes([120, 7, 0x5B])
    assert dnp3.g120v9_hmac()[:3] == bytes([120, 9, 0x5B])


def test_tcp_sequence_numbers_follow_the_payload():
    clock = synth.Clock()
    c = synth.TCPConv(synth.Host("02:00:00:00:00:01", "192.0.2.1", 40000),
                      synth.Host("02:00:00:00:00:02", "192.0.2.2", 20000), clock)
    c.handshake()
    c.send(True, b"abc")
    seqs = [struct.unpack("!II", f.data[38:46]) for f in c.frames]
    assert seqs[3][0] == 1001 and seqs[4][1] == 1004  # data at isn+1; the ACK covers 3 octets


def test_no_case_has_a_hole_in_either_sequence_space():
    """Over every case, the derived ones included: each side's sequence
    number continues from where it left off and from the other side's last
    acknowledgement, so a removed response reads as never sent, not as a
    capture gap (D1 on #548)."""
    for name, frames, _ in dnp3_cases.cases():
        if dnp3_cases.DECODE.get(name, {}).get("l4") == "udp":
            continue
        nxt, last_ack = {}, {}
        for i, f in enumerate(frames, 1):
            src, dst, seq, ack, flags, n, _ = synth.tcp_fields(f.data)
            where = (name, i)
            if flags & synth.SYN:
                assert src not in nxt, where
            else:
                assert seq == nxt[src], (where, seq, nxt[src])
                assert last_ack.get(dst, seq) == seq, (where, "seq", seq, "the peer last acked", last_ack[dst])
            if flags & synth.ACK:
                assert ack == nxt[dst], (where, "ack", ack, "the peer's next", nxt[dst])
                last_ack[src] = ack
            nxt[src] = seq + n + (1 if flags & (synth.SYN | synth.FIN) else 0)


def test_remove_segments_renumbers_and_keeps_checksums():
    cases = {n: (f, r) for n, f, r in dnp3_cases.cases()}
    full, rows = cases["dnp3-unauthorized-operate"]
    cut, _ = cases["dnp3-unauthorized-operate-no-response"]
    resp = rows[0]["frames"][1]
    removed = synth.tcp_fields(full[resp - 1].data)[5]
    assert removed == 37
    for before, after in zip(full[resp + 1:], cut[resp - 1:]):
        src, dst, seq, ack, flags, n, _ = synth.tcp_fields(before.data)
        s2, d2, seq2, ack2, flags2, n2, _ = synth.tcp_fields(after.data)
        out = src[3] == 20  # the outstation, 192.0.2.20
        assert (s2, d2, flags2, n2) == (src, dst, flags, n)
        assert seq2 == seq - (removed if out else 0) and ack2 == ack - (0 if out else removed)


def test_the_moved_port_case_never_uses_port_20000():
    """A decoder that looks for DNP3 only on its registered port has nothing
    to find here: O2 answers on its moved port, and no end is on 20000."""
    cases = {n: f for n, f, _ in dnp3_cases.cases()}
    o2 = dnp3_cases.NET["outstations"]["O2"]
    assert o2["port"] == dnp3_cases.DECODE["dnp3-moved-port"]["port"] != 20000
    # A port a relay accepts (DNPNUM, 1 to 65534), and none of its fixed ones.
    assert 1 <= o2["port"] <= 65534 and o2["port"] not in (20, 21, 23, 102, 502)
    carried = 0
    for f in cases["dnp3-moved-port"]:
        proto, sport, dport, payload = l4_payload(f.data)
        assert proto == synth.TCP and 20000 not in (sport, dport) and o2["port"] in (sport, dport)
        carried += payload[:2] == b"\x05\x64"
    assert carried == 4  # the poll, the operate and their two responses


def test_the_udp_case_is_one_link_frame_per_datagram():
    cases = {n: f for n, f, _ in dnp3_cases.cases()}
    frames = cases["dnp3-udp"]
    assert len(frames) == 4  # no handshake, no bare acknowledgement, no close
    for f in frames:
        proto, sport, dport, payload = l4_payload(f.data)
        # DNPUDPn at its default: the relay answers to UDP 20000.
        assert (proto, sport, dport) == (synth.UDP, 20000, 20000)
        assert payload[:2] == b"\x05\x64" and payload.count(b"\x05\x64") == 1
        assert len(payload) == 10 + (payload[2] - 5) + 2 * -(-(payload[2] - 5) // 16)  # header, user data, CRCs


def test_the_baseline_series_never_holds_the_two_new_services():
    """Both captures are new-service samples only if the R6.2 series never
    shows O2, O1 over UDP, or M5."""
    net = dnp3_cases.NET
    for f in dnp3_cases.series(7, dnp3_cases.SERIES["dnp3-train"][1], 120):
        proto, sport, dport, _ = l4_payload(f.data)
        assert proto == synth.TCP and net["outstation"]["port"] in (sport, dport)
        ends = {f.data[26:30], f.data[30:34]}
        assert synth.ip4(net["outstations"]["O2"]["ip"]) not in ends
        assert synth.ip4(net["masters"]["M5"]["ip"]) not in ends


def test_the_labeller_is_told_the_port_and_transport_from_the_settings():
    import gtlabel
    assert gtlabel.options_for(gtlabel.TCP_20000) == []
    assert gtlabel.fields_for("tcp") is gtlabel.FIELDS
    assert gtlabel.options_for(dnp3_cases.DECODE["dnp3-moved-port"]) == ["-d", "tcp.port==20001,dnp3"]
    assert gtlabel.options_for(dnp3_cases.DECODE["dnp3-udp"]) == []
    udp = gtlabel.fields_for("udp")
    assert "udp.srcport" in udp and "udp.dstport" in udp and not [f for f in udp if f.startswith("tcp.")]
    # Every capture named under DECODE is a case, so each gets its label.
    assert set(dnp3_cases.DECODE) <= {n for n, _, _ in dnp3_cases.cases()}
