"""Self-test of GT-PCAP's PRP rewriter (D6). Stdlib only, on hand-made
frames, so it runs in the pytest job with no capture and no tshark. The
tshark half, which checks that an independent PRP dissector reads the same
trailers, runs in .github/workflows/a6-gt-pcap.yml (prp_check.py)."""

import struct

import pytest

import pcapfile
import prp

MAC_1 = bytes.fromhex("020000000001")
MAC_2 = bytes.fromhex("020000000002")
DST = bytes.fromhex("020000000099")


def eth(src, payload, vlan=None):
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return DST + src + tag + b"\x08\x00" + payload


def trailer(data):
    seq, lan_size, suffix = struct.unpack("!HHH", data[-6:])
    return seq, lan_size >> 12, lan_size & 0x0FFF, suffix


def frames():
    return [
        pcapfile.Frame(1_000_000_000, eth(MAC_1, b"\x45" + b"\x00" * 45)),
        pcapfile.Frame(1_000_500_000, eth(MAC_2, b"\x45" + b"\x00" * 99)),
        pcapfile.Frame(1_001_000_000, eth(MAC_1, b"\x45" + b"\x00" * 45, vlan=7)),
    ]


def test_each_frame_twice_same_seq_lan_a_then_b():
    src = frames()
    ab, a = prp.derive(src)
    assert len(ab) == 2 * len(src) and len(a) == len(src)
    for i, orig in enumerate(src):
        ca, cb = ab[2 * i], ab[2 * i + 1]
        assert ca.data[:-6] == orig.data and cb.data[:-6] == orig.data
        sa, la, za, xa = trailer(ca.data)
        sb, lb, zb, xb = trailer(cb.data)
        assert (la, lb) == (prp.LAN_A, prp.LAN_B)
        assert sa == sb and za == zb and xa == xb == 0x88FB
        assert ca.ns == orig.ns and cb.ns == orig.ns + prp.SKEW_NS
        assert a[i].data == ca.data and a[i].ns == ca.ns


def test_lsdu_size_counts_after_the_ethertype_with_the_rct():
    ab, _ = prp.derive(frames())
    assert trailer(ab[0].data)[2] == len(ab[0].data) - 14
    assert trailer(ab[2].data)[2] == len(ab[2].data) - 14
    assert trailer(ab[4].data)[2] == len(ab[4].data) - 18


def test_sequence_counts_per_source_mac_and_wraps():
    ab, _ = prp.derive(frames())
    assert [trailer(ab[i].data)[0] for i in (0, 2, 4)] == [prp.SEQ_START, prp.SEQ_START, prp.SEQ_START + 1]
    many = [pcapfile.Frame(i, eth(MAC_1, b"\x45" + b"\x00" * 45)) for i in range(0x10000 - prp.SEQ_START + 1)]
    _, a = prp.derive(many)
    assert trailer(a[-2].data)[0] == 0xFFFF and trailer(a[-1].data)[0] == 0


def test_oversized_lsdu_is_refused():
    with pytest.raises(ValueError):
        prp.derive([pcapfile.Frame(0, eth(MAC_1, b"\x00" * 0x0FFF))])


def test_round_trip_is_byte_identical(tmp_path):
    ab, a = prp.derive(frames())
    p = tmp_path / "x.pcap"
    pcapfile.write(p, ab)
    back = pcapfile.read(p)
    assert [(f.ns, f.data) for f in back] == [(f.ns, f.data) for f in ab]
    pcapfile.write(tmp_path / "y.pcap", ab)
    assert p.read_bytes() == (tmp_path / "y.pcap").read_bytes()


def test_truncated_and_non_ethernet_records_are_refused(tmp_path):
    p = tmp_path / "t.pcap"
    hdr = struct.pack("<4sHHiIII", b"\xd4\xc3\xb2\xa1", 2, 4, 0, 0, 96, 1)
    p.write_bytes(hdr + struct.pack("<IIII", 0, 0, 60, 80) + b"\x00" * 60)
    with pytest.raises(ValueError, match="truncated"):
        pcapfile.read(p)
    q = tmp_path / "l.pcap"
    q.write_bytes(struct.pack("<4sHHiIII", b"\xd4\xc3\xb2\xa1", 2, 4, 0, 0, 96, 105))
    with pytest.raises(ValueError, match="link type"):
        pcapfile.read(q)
