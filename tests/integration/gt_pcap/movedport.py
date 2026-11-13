"""GT-PCAP's derived capture of Modbus/TCP on a moved port (D6; D1 on #623).

GT-PCAP has no Modbus/TCP writer yet, so this case is derived from a public
capture, as the PRP pairs are (plan section 2C). From one Ethernet capture
this writes `<stem>-moved-port.pcap`, in which every TCP segment to or from
port OLD is to or from port NEW instead, and nothing else differs:

- only the two port octets and the TCP checksum change, and tshark's reading
  of the checksum is the source's (`reading`). The checksum is adjusted by
  the ports' difference (RFC 1624), so one that was right stays right and
  one that was wrong stays wrong by the same error. Where that would change
  tshark's reading, the source's checksum is kept: a partial one, the
  pseudo-header's sum that a sender with checksum offload leaves for its
  card to finish, holds no port; and a wrong one whose adjustment lands on
  that sum would read as partial. A segment for which neither keeps the
  reading is refused;
- frame order, timestamps, addresses, sequence numbers and payload are the
  source's;
- a frame that is not IPv4 TCP, or uses neither port, is copied unchanged.

A segment that already uses NEW, any later fragment of an IPv4 TCP segment
(whichever port its first fragment used), and a frame too short to hold its
TCP header are refused: the result would not be the source's conversation
on another port.

A SEL-751's Modbus/TCP port is a setting (`MODNUM1`, 1 to 65534, 502 by
default; S22 Table 4.104, p. 4.250), so a server off 502 is a documented
configuration. The source is a public capture of unknown origin, not a
relay's traffic. The label of the result is tshark's reading of it with the
moved port decoded as Modbus/TCP (modbus_label.py).

Usage: python movedport.py INPUT.pcap OUTDIR [OLD NEW]   (default 502 15020)
"""

import os
import struct
import sys

import pcapfile

# NEW is a port a SEL-751 accepts for MODNUM1 (1 to 65534; S22 Table 4.104,
# p. 4.250): none of its fixed ports, and no other port setting's value
# (p. 4.251; Table 4.105, p. 4.252; D2 on #623).
OLD, NEW = 502, 15020


def _fold(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def adjust(checksum, old, new):
    """RFC 1624, equation 3: the checksum after one 16-bit field changes
    from `old` to `new`."""
    return ~_fold((~checksum & 0xFFFF) + (~old & 0xFFFF) + new) & 0xFFFF


def _sum(b):
    b += b"\0" * (len(b) % 2)
    return _fold(sum(struct.unpack(f"!{len(b) // 2}H", b)))


def reading(data, off, t):
    """tshark 4.2's reading of the TCP checksum of the IPv4 packet at `off`,
    whose TCP header is at `t` (Wireshark v4.2.2, epan/dissectors/
    packet-tcp.c lines 8369 to 8411): a checksum that verifies is good,
    except 0xFFFF (RFC 1624's negative zero), which it reads as bad; one that
    does not verify is good if it equals the pseudo-header's sum (partial,
    from checksum offload), else bad."""
    end = off + struct.unpack("!H", data[off + 2:off + 4])[0]
    pseudo = _sum(data[off + 12:off + 20] + struct.pack("!HH", 6, end - t))
    csum = struct.unpack("!H", data[t + 16:t + 18])[0]
    if _fold(pseudo + _sum(data[t:end])) == 0xFFFF:
        return "bad: 0xffff" if csum == 0xFFFF else "good"
    return "good: partial" if csum == pseudo else "bad"


def move(data, old=OLD, new=NEW):
    """The frame with its TCP port `old` rewritten to `new`, or the frame
    itself if it is not an IPv4 TCP segment on `old`."""
    off = 14
    if len(data) >= 18 and data[12:14] == b"\x81\x00":
        off = 18
    if len(data) < off + 20 or data[off - 2:off] != b"\x08\x00" or data[off + 9] != 6:
        return data
    t = off + (data[off] & 0x0F) * 4
    if struct.unpack("!H", data[off + 6:off + 8])[0] & 0x1FFF:
        # Its ports are in the first fragment, so which port it belongs to
        # can't be read from it: refused, whatever its bytes look like.
        raise ValueError("a later fragment of a TCP segment: its ports are not in it")
    if len(data) < t + 20:
        raise ValueError("a TCP segment cut short of its header")
    sport, dport = struct.unpack("!HH", data[t:t + 4])
    if new in (sport, dport):
        raise ValueError(f"the capture already uses port {new}")
    if old not in (sport, dport):
        return data
    out = bytearray(data)
    kept = data[t + 16:t + 18]
    csum = struct.unpack("!H", kept)[0]
    for at, port in ((t, sport), (t + 2, dport)):
        if port == old:
            struct.pack_into("!H", out, at, new)
            csum = adjust(csum, old, new)
    was = reading(data, off, t)
    for c in (struct.pack("!H", csum), kept):
        out[t + 16:t + 18] = c
        if reading(out, off, t) == was:
            return bytes(out)
    raise ValueError(f"no TCP checksum on port {new} keeps tshark's reading of it ({was})")


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
