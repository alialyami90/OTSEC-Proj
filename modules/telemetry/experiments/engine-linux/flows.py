"""P4-4-E2 (D4): the TCP and UDP flows in each capture, read by this stdlib
reader and never by an engine, so the Modbus signature's corpus is labelled
from the capture and not from the engine under test (D6's `label-flow`).

A flow is a pair of ends (address, port) on one transport, in either
direction. For each flow it prints, per end:

- packets sent, and payload octets sent, taken from the IP and transport
  headers (IPv4 total length or IPv6 payload length, less the headers), so
  a capture cut short by its snap length still counts what was sent;
- `syn`: the end that sent a SYN without ACK (TCP), the client by RFC 9293;
- `first`: the end that sent the flow's first frame, and `first_payload`,
  the end that sent its first payload;
- `head`: the first 8 octets that end sent, in hex. For TCP they are read
  from the reassembled stream: from the sequence number after the end's
  SYN, or, with no SYN, from the first payload segment the end sent, with
  segments placed by sequence number (D2's N1 on #642). For UDP they are
  the first datagram's. `head` is for the near-miss test only; the labels
  carry no payload byte (`label-flow`), and this output is not uploaded.

Reads classic pcap (either byte order, micro- or nanosecond) and pcapng
(section, interface, enhanced, simple and obsolete packet blocks). Link
types: Ethernet (1, with 802.1Q and 802.1ad tags), Linux cooked (113 and
276), BSD loopback (0, either byte order), raw IP (12, 14, 101, 228, 229).
IPv4 fragments after the first, IPv6 with an extension header before the
transport, other link types and other transports are counted as skipped.

Usage: python -I flows.py CAPTURE...   (TSV on stdout; one `#` line per
capture with its frame and skipped counts)
"""

import ipaddress
import os
import struct
import sys

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
HEAD = 8
COLUMNS = ["capture", "l4", "a", "ap", "b", "bp", "packets_a", "packets_b", "octets_a", "octets_b", "syn", "first",
           "first_payload", "head_a", "head_b"]


def records(raw):
    """(link type, frame bytes) for each record of a pcap or pcapng file."""
    if raw[:4] in PCAP_MAGIC:
        o = PCAP_MAGIC[raw[:4]]
        lt = struct.unpack(o + "I", raw[20:24])[0] & 0xFFFF
        off = 24
        while off + 16 <= len(raw):
            incl = struct.unpack(o + "I", raw[off + 8:off + 12])[0]
            yield lt, raw[off + 16:off + 16 + incl]
            off += 16 + incl
        return
    if raw[:4] != b"\x0a\x0d\x0d\x0a":
        raise ValueError("neither pcap nor pcapng")
    off, o, links = 0, "<", []
    while off + 12 <= len(raw):
        if raw[off:off + 4] == b"\x0a\x0d\x0d\x0a":
            o = "<" if raw[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        btype, blen = struct.unpack(o + "II", raw[off:off + 8])
        if blen < 12:
            raise ValueError(f"pcapng block of length {blen} at {off}")
        body = raw[off + 8:off + blen - 4]
        if btype == 1:
            links.append(struct.unpack(o + "H", body[:2])[0])
        elif btype == 6:
            iface, _, _, cap = struct.unpack(o + "IIII", body[:16])
            yield links[iface], body[20:20 + cap]
        elif btype == 3:
            orig = struct.unpack(o + "I", body[:4])[0]
            yield links[0], body[4:4 + min(orig, len(body) - 4)]
        elif btype == 2:
            iface = struct.unpack(o + "H", body[:2])[0]
            cap = struct.unpack(o + "I", body[12:16])[0]
            yield links[iface], body[20:20 + cap]
        off += blen


def network(lt, f):
    """(IP version, IP packet) from a frame, or None."""
    if lt == 1:
        off, et = 14, f[12:14]
        while et in (b"\x81\x00", b"\x88\xa8") and len(f) >= off + 4:
            et, off = f[off + 2:off + 4], off + 4
        return {b"\x08\x00": (4, f[off:]), b"\x86\xdd": (6, f[off:])}.get(et)
    if lt == 113:
        return {b"\x08\x00": (4, f[16:]), b"\x86\xdd": (6, f[16:])}.get(f[14:16])
    if lt == 276:
        return {b"\x08\x00": (4, f[20:]), b"\x86\xdd": (6, f[20:])}.get(f[0:2])
    if lt == 0 and len(f) >= 4:
        fam = {struct.unpack("<I", f[:4])[0], struct.unpack(">I", f[:4])[0]}
        return (4, f[4:]) if 2 in fam else (6, f[4:]) if fam & {24, 28, 30} else None
    if lt in (12, 14, 101, 228, 229) and f:
        v = f[0] >> 4
        return (v, f) if v in (4, 6) else None
    return None


def segment(v, p):
    """(l4, (src, sport), (dst, dport), payload octets sent, payload bytes
    captured, TCP flags, TCP sequence number) of a TCP or UDP packet, or None."""
    if v == 4 and len(p) >= 20 and p[9] in (6, 17) and not struct.unpack("!H", p[6:8])[0] & 0x1FFF:
        ihl, total = (p[0] & 0x0F) * 4, struct.unpack("!H", p[2:4])[0] or len(p)
        a, b, proto, t = str(ipaddress.IPv4Address(p[12:16])), str(ipaddress.IPv4Address(p[16:20])), p[9], p[ihl:]
        size = total - ihl
        t = t[:max(0, size)]
    elif v == 6 and len(p) >= 40 and p[6] in (6, 17):
        a, b, proto, t = str(ipaddress.IPv6Address(p[8:24])), str(ipaddress.IPv6Address(p[24:40])), p[6], p[40:]
        size = struct.unpack("!H", p[4:6])[0]
        t = t[:size]
    else:
        return None
    if proto == 17:
        if len(t) < 8:
            return None
        sport, dport = struct.unpack("!HH", t[:4])
        return "udp", (a, str(sport)), (b, str(dport)), max(0, size - 8), t[8:], 0, 0
    if len(t) < 14:
        return None
    sport, dport, seq = struct.unpack("!HHI", t[:8])
    hl = (t[12] >> 4) * 4
    return "tcp", (a, str(sport)), (b, str(dport)), max(0, size - hl), t[hl:], t[13], seq


class End:
    def __init__(self):
        self.packets = self.octets = 0
        self.isn = None  # sequence number after this end's SYN
        self.segs = []  # (seq, captured payload) of payload segments, until HEAD octets are placed

    def head(self, l4):
        if not self.segs:
            return ""
        if l4 == "udp":
            return self.segs[0][1][:HEAD].hex()
        start = self.isn if self.isn is not None else self.segs[0][0]

        def rel(seq):  # signed distance from start, modulo 2**32
            d = (seq - start) & 0xFFFFFFFF
            return d - (1 << 32) if d >= 1 << 31 else d

        buf = bytearray()
        for seq, data in sorted(self.segs, key=lambda s: rel(s[0])):
            off = rel(seq)
            if off < 0:
                data, off = data[-off:], 0
            if off > len(buf):
                break  # a gap: the octets after it are not the stream's next ones
            buf[off:off + len(data)] = data
            if len(buf) >= HEAD:
                break
        return bytes(buf[:HEAD]).hex()


def flows(path):
    out, order, frames, skipped = {}, [], 0, 0
    with open(path, "rb") as fh:
        raw = fh.read()
    for lt, f in records(raw):
        frames += 1
        n = network(lt, f)
        seg = segment(*n) if n else None
        if seg is None:
            skipped += 1
            continue
        l4, src, dst, size, data, flags, seq = seg
        key = (l4,) + tuple(sorted([src, dst]))
        if key not in out:
            out[key] = {"ends": {src: End(), dst: End()}, "syn": None, "first": src, "first_payload": None}
            order.append(key)
        fl = out[key]
        e = fl["ends"][src]
        e.packets += 1
        e.octets += size
        if l4 == "tcp" and flags & 0x02:
            e.isn = (seq + 1) & 0xFFFFFFFF
            if not flags & 0x10 and fl["syn"] is None:
                fl["syn"] = src
        if size:
            fl["first_payload"] = fl["first_payload"] or src
            if data and (l4 == "tcp" or not e.segs) and len(e.segs) < 64:
                e.segs.append((seq, bytes(data)))
    return out, frames, skipped


def main(paths):
    print("\t".join(COLUMNS))
    for path in paths:
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            fl, frames, skipped = flows(path)
        except (ValueError, IndexError, struct.error) as e:
            print(f"# {name}: not read ({e})")
            continue
        tcp = sum(1 for k in fl if k[0] == "tcp")
        print(f"# {name}: {frames} frames, {skipped} not read as TCP or UDP, {tcp} TCP flows, {len(fl) - tcp} UDP flows")
        for key in sorted(fl):
            l4, x, y = key
            f = fl[key]
            side = {x: "a", y: "b", None: "-"}
            ex, ey = f["ends"][x], f["ends"][y]
            print("\t".join([name, l4, x[0], x[1], y[0], y[1], str(ex.packets), str(ey.packets), str(ex.octets),
                             str(ey.octets), side[f["syn"]], side[f["first"]], side[f["first_payload"]],
                             ex.head(l4), ey.head(l4)]))


if __name__ == "__main__":
    main(sys.argv[1:])
