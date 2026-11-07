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


def test_dnp3_link_crcs_match_a_bitwise_crc():
    for f in all_frames():
        d = f.data
        ihl = (d[14] & 0x0F) * 4
        total = struct.unpack("!H", d[16:18])[0]
        tcp_off = 14 + ihl
        payload = d[tcp_off + (d[tcp_off + 12] >> 4) * 4:14 + total]
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
