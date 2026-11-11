"""GT-PCAP's derived capture of Modbus/TCP on a moved port (D6; D1 on #623).

GT-PCAP has no Modbus/TCP writer yet, so this case is derived from a public
capture, as the PRP pairs are (plan section 2C). From one Ethernet capture
this writes `<stem>-moved-port.pcap`, in which every TCP segment to or from
port OLD is to or from port NEW instead, and nothing else differs:

- only the two port octets change, and the TCP checksum is adjusted by the
  same difference (RFC 1624), so a checksum that was right stays right and
  one that was wrong in the source stays wrong in the same way;
- frame order, timestamps, addresses, sequence numbers and payload are the
  source's;
- a frame that is not IPv4 TCP, or uses neither port, is copied unchanged.

A segment that already uses NEW, a non-first IPv4 fragment, and a frame too
short to hold its TCP header are refused: the result would not be the
source's conversation on another port.

A relay's Modbus/TCP port is a setting (`MODNUM1`, 502 by default; D2's
note `docs/phase4/D2-sel-network-services.md`), so a server off 502 is a
documented configuration. The label of the result is tshark's reading of it
with the moved port decoded as Modbus/TCP (modbus_label.py).

Usage: python movedport.py INPUT.pcap OUTDIR [OLD NEW]   (default 502 15020)
"""

import os
import struct
import sys

import pcapfile

# NEW is a port a relay accepts for MODNUM1 (1 to 65534, S22) and none of
# its fixed ports (plan section 2B).
OLD, NEW = 502, 15020


def _fold(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def adjust(checksum, old, new):
    """RFC 1624, equation 3: the checksum after one 16-bit field changes
    from `old` to `new`."""
    return ~_fold((~checksum & 0xFFFF) + (~old & 0xFFFF) + new) & 0xFFFF


def move(data, old=OLD, new=NEW):
    """The frame with its TCP port `old` rewritten to `new`, or the frame
    itself if it is not an IPv4 TCP segment on `old`."""
    off = 14
    if len(data) >= 18 and data[12:14] == b"\x81\x00":
        off = 18
    if len(data) < off + 20 or data[off - 2:off] != b"\x08\x00" or data[off + 9] != 6:
        return data
    t = off + (data[off] & 0x0F) * 4
    frag = struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF
    if len(data) < t + 20:
        raise ValueError("a TCP segment cut short of its header")
    sport, dport = struct.unpack("!HH", data[t:t + 4])
    if new in (sport, dport):
        raise ValueError(f"the capture already uses port {new}")
    if old not in (sport, dport):
        return data
    if frag:
        raise ValueError("a fragment of a TCP segment: its ports are not in it")
    out = bytearray(data)
    csum = struct.unpack("!H", data[t + 16:t + 18])[0]
    for at, port in ((t, sport), (t + 2, dport)):
        if port == old:
            struct.pack_into("!H", out, at, new)
            csum = adjust(csum, old, new)
    struct.pack_into("!H", out, t + 16, csum)
    return bytes(out)


def derive(frames, old=OLD, new=NEW):
    return [pcapfile.Frame(f.ns, move(f.data, old, new)) for f in frames]


def main(src, outdir, old=OLD, new=NEW):
    stem = os.path.splitext(os.path.basename(src))[0]
    frames = pcapfile.read(src)
    out = derive(frames, int(old), int(new))
    os.makedirs(outdir, exist_ok=True)
    pcapfile.write(os.path.join(outdir, f"{stem}-moved-port.pcap"), out)
    moved = sum(1 for a, b in zip(frames, out) if a.data != b.data)
    print(f"movedport: {stem}: {moved} of {len(frames)} frames moved from port {old} to {new}")
    return 0 if moved else 1


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:5]))
