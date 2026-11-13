"""Self-tests of movedport.py (D6). Stdlib only and no tshark, so they run in
the pytest job. Tshark's half, which labels the derived capture and checks
it against its source, runs in a6-gt-pcap.yml's modbus-moved-port job."""

import random
import struct

import pytest

import movedport
import pcapfile
import synth

CLIENT = synth.Host("02:00:00:00:00:31", "192.0.2.31", 2074)
SERVER = synth.Host("02:00:00:00:00:38", "192.0.2.38", 502)
READ = bytes.fromhex("000100000006010300000002")  # one ADU: unit 1, function 3


def tcp_ok(d):
    """The TCP checksum of an untagged IPv4 frame verifies."""
    return tcp_sum(d) == 0xFFFF


def tcp_sum(d):
    """The folded sum over an untagged IPv4 frame's TCP pseudo-header and
    segment, checksum included: 0xFFFF where the checksum verifies."""
    ihl = (d[14] & 0x0F) * 4
    total = struct.unpack("!H", d[16:18])[0]
    seg = d[14 + ihl:14 + total]
    b = d[26:34] + struct.pack("!BBH", 0, 6, len(seg)) + seg
    b += b"\0" * (len(b) % 2)
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def pseudo_sum(d):
    """The folded sum of an untagged IPv4 frame's TCP pseudo-header, which a
    sender with checksum offload leaves in the field for its card to finish."""
    ihl = (d[14] & 0x0F) * 4
    s = sum(struct.unpack("!6H", d[26:34] + struct.pack("!HH", 6, struct.unpack("!H", d[16:18])[0] - ihl)))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def reading(d):
    """tshark 4.2's reading of an untagged IPv4 frame's TCP checksum
    (Wireshark v4.2.2, epan/dissectors/packet-tcp.c lines 8369 to 8411)."""
    c = struct.unpack("!H", d[50:52])[0]
    if tcp_ok(d):
        return "bad: 0xffff" if c == 0xFFFF else "good"
    return "good: partial" if c == pseudo_sum(d) else "bad"


def conversation(vlan=None):
    c = synth.TCPConv(CLIENT, SERVER, synth.Clock(), vlan=vlan)
    c.handshake()
    c.send(True, READ)
    c.send(False, READ[:8] + b"\x04\x00\x01\x00\x02")
    c.close()
    return c.frames


def test_only_the_port_and_the_checksum_change_and_the_checksum_still_verifies():
    src = conversation()
    out = movedport.derive(src)
    assert len(out) == len(src) and [f.ns for f in out] == [f.ns for f in src]
    for a, b in zip(src, out):
        assert tcp_ok(a.data) and tcp_ok(b.data)
        sp, dp = struct.unpack("!HH", a.data[34:38])
        want = bytearray(a.data)
        struct.pack_into("!HH", want, 34, *(movedport.NEW if p == 502 else p for p in (sp, dp)))
        want[50:52] = b.data[50:52]  # the checksum, shown right by tcp_ok above
        assert b.data == bytes(want)
        assert 502 not in struct.unpack("!HH", b.data[34:38])


def test_a_checksum_that_was_wrong_in_the_source_stays_wrong():
    f = conversation()[3]
    bad = f.data[:50] + bytes([f.data[50] ^ 0x55]) + f.data[51:]
    assert not tcp_ok(bad) and tcp_sum(movedport.move(bad)) == tcp_sum(bad)  # by the same error


def test_a_partial_checksum_is_kept_because_it_holds_no_port():
    # icsnpp-modbus-example on #643: every segment carries the pseudo-header's
    # sum, which tshark reads as good. Adjusted by the port, it read bad.
    for f in conversation():
        d = f.data[:50] + struct.pack("!H", pseudo_sum(f.data)) + f.data[52:]
        m = movedport.move(d)
        assert reading(d) == reading(m) == "good: partial" and m[50:52] == d[50:52]


def test_a_bad_checksum_is_kept_where_its_adjustment_would_read_as_partial():
    # zeek-modbus-big frame 10931 on #643: bad in the source, and adjusted by
    # the port it landed on the pseudo-header's sum, which tshark reads as good.
    f = conversation()[3].data
    d = f[:50] + struct.pack("!H", movedport.adjust(pseudo_sum(f), movedport.NEW, 502)) + f[52:]
    m = movedport.move(d)
    assert reading(d) == reading(m) == "bad" and m[50:52] == d[50:52]


def test_a_checksum_of_0xffff_that_verifies_is_refused():
    # tshark reads it as bad (RFC 1624's negative zero); no moved checksum
    # both verifies and reads bad, so its reading can't be kept. The frame's
    # Ethernet padding is not in the segment, so it is not in the sum.
    f = conversation()[3].data[:50] + b"\xff\xff" + conversation()[3].data[52:-2]
    d = next(f + struct.pack("!H", w) for w in range(65536) if tcp_ok(f + struct.pack("!H", w))) + b"\x5a" * 6
    assert reading(d) == "bad: 0xffff"
    with pytest.raises(ValueError):
        movedport.move(d)


def test_adjust_equals_a_full_recomputation():
    rnd = random.Random(1)
    for _ in range(2000):
        words = [rnd.randrange(65536) for _ in range(6)]
        full = lambda w: ~movedport._fold(sum(w)) & 0xFFFF  # noqa: E731
        new = rnd.randrange(65536)
        moved = [new] + words[1:]
        # Ones-complement sums have two zeros, so compare what a receiver checks.
        got = movedport.adjust(full(words), words[0], new)
        assert movedport._fold(sum(moved) + got) == 0xFFFF and movedport._fold(sum(moved) + full(moved)) == 0xFFFF


def test_what_is_not_tcp_on_the_old_port_is_copied_unchanged():
    other = synth.TCPConv(CLIENT, synth.Host(SERVER.mac, SERVER.ip, 20000), synth.Clock())
    other.handshake()
    udp = synth.UDPConv(CLIENT, SERVER, synth.Clock()).send(True, READ)
    arp = pcapfile.Frame(1, bytes(12) + b"\x08\x06" + bytes(46))
    for f in other.frames + udp + [arp]:
        assert movedport.move(f.data) is f.data


def test_a_tagged_frame_is_moved_too():
    for a, b in zip(conversation(vlan=10), movedport.derive(conversation(vlan=10))):
        assert a.data[:38] == b.data[:38] and a.data != b.data
        assert movedport.NEW in struct.unpack("!HH", b.data[38:42])


def test_refusals():
    with pytest.raises(ValueError):  # the new port is already in the capture
        movedport.move(conversation()[0].data, 502, 2074)
    d = bytearray(conversation()[3].data)
    struct.pack_into("!H", d, 20, 0x0010)  # a later fragment
    with pytest.raises(ValueError):
        movedport.move(bytes(d))
    struct.pack_into("!HH", d, 34, 7, 9)  # and one whose bytes there name neither port
    with pytest.raises(ValueError):
        movedport.move(bytes(d))
    with pytest.raises(ValueError):  # cut inside the TCP header
        movedport.move(conversation()[0].data[:40])
