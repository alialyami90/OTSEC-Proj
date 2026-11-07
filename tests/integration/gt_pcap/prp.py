"""GT-PCAP's PRP derived captures (D6, plan section 2C; ADR-0009's PRP row).

From one Ethernet capture this writes two:

- `<stem>-prp-ab.pcap`: every frame twice, as a PRP doubly attached node
  sends it. Each copy carries an IEC 62439-3 (PRP-1) Redundancy Control
  Trailer with the same sequence number: LAN A's copy first, then LAN B's
  copy SKEW_NS later.
- `<stem>-prp-a.pcap`: only the LAN A copies, the single-LAN reference.

The RCT is six octets appended after the frame as captured (any padding
stays before it, as PRP-1 places the trailer last):

    SeqNr (16) | LanId (4) | LSDUsize (12) | PRP suffix 0x88FB (16)

LanId is 0xA or 0xB. LSDUsize counts the octets after the EtherType (after
the 802.1Q tag's inner EtherType when the frame is tagged), the RCT
included. The sequence number counts per source MAC from SEQ_START and
wraps at 16 bits.

ADR-0009's pass condition for an engine run on these: each flow and
service is recorded once, with counts equal to those from `-prp-a`.

Usage: python prp.py INPUT.pcap OUTDIR
"""

import os
import struct
import sys

import pcapfile

SUFFIX = 0x88FB
LAN_A, LAN_B = 0xA, 0xB
SEQ_START = 0x1000
SKEW_NS = 10_000
_VLAN_TPIDS = (0x8100, 0x88A8)
_MAX_LSDU = 0x0FFF


def header_len(data):
    """Octets up to and including the EtherType: 14, or 18 with one VLAN tag."""
    if len(data) < 14:
        raise ValueError(f"frame of {len(data)} octets has no Ethernet header")
    if struct.unpack("!H", data[12:14])[0] in _VLAN_TPIDS:
        if len(data) < 18:
            raise ValueError("tagged frame cut short")
        return 18
    return 14


def rct(seq, lan, data):
    """The six-octet trailer for frame `data` (the frame without its RCT)."""
    lsdu = len(data) - header_len(data) + 6
    if lsdu > _MAX_LSDU:
        raise ValueError(f"LSDU of {lsdu} octets does not fit PRP's 12-bit size")
    return struct.pack("!HHH", seq & 0xFFFF, (lan << 12) | lsdu, SUFFIX)


def derive(frames):
    """Return (ab, a): the doubled frames and the LAN A copies only."""
    seqs, ab, a = {}, [], []
    for fr in frames:
        src = fr.data[6:12]
        seq = seqs.get(src, SEQ_START)
        seqs[src] = (seq + 1) & 0xFFFF
        copy_a = pcapfile.Frame(fr.ns, fr.data + rct(seq, LAN_A, fr.data))
        copy_b = pcapfile.Frame(fr.ns + SKEW_NS, fr.data + rct(seq, LAN_B, fr.data))
        ab += [copy_a, copy_b]
        a.append(copy_a)
    return ab, a


def main(src, outdir):
    stem = os.path.splitext(os.path.basename(src))[0]
    ab, a = derive(pcapfile.read(src))
    os.makedirs(outdir, exist_ok=True)
    pcapfile.write(os.path.join(outdir, f"{stem}-prp-ab.pcap"), ab)
    pcapfile.write(os.path.join(outdir, f"{stem}-prp-a.pcap"), a)
    print(f"prp: {stem}: {len(a)} frames, {len(ab)} with both copies")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
