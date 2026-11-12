"""P4-4-E2 (D4): the TCP flows in each capture, read by this stdlib reader
and never by an engine, so the Modbus signature's corpus counts flows the
way its labels do and not the way the engine under test does.

A flow is a pair of TCP ends (address, port), in either direction. For each
flow it prints the TCP payload octets each end sent, taken from the IP and
TCP headers (IPv4 total length or IPv6 payload length, less the headers),
so a capture cut short by its snap length still counts what was sent.

Reads classic pcap (either byte order, micro- or nanosecond) and pcapng
(section, interface, enhanced, simple and obsolete packet blocks). Link
types: Ethernet (1, with 802.1Q and 802.1ad tags), Linux cooked (113 and
276), BSD loopback (0, either byte order), raw IP (12, 14, 101, 228, 229).
IPv4 fragments after the first, IPv6 with an extension header before TCP,
other link types and other transports are counted as skipped, not read.

Usage: python -I flows.py CAPTURE...   (TSV on stdout; one `#` line per
capture with its frame and skipped counts)
"""

import ipaddress
import os
import struct
import sys

PCAP_MAGIC = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


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


def tcp(v, p):
    """((src, sport), (dst, dport), payload octets) of a TCP segment, or None."""
    if v == 4 and len(p) >= 20 and p[9] == 6 and not struct.unpack("!H", p[6:8])[0] & 0x1FFF:
        ihl, total = (p[0] & 0x0F) * 4, struct.unpack("!H", p[2:4])[0] or len(p)
        a, b, t = str(ipaddress.IPv4Address(p[12:16])), str(ipaddress.IPv4Address(p[16:20])), p[ihl:]
        size = total - ihl
    elif v == 6 and len(p) >= 40 and p[6] == 6:
        a, b, t = str(ipaddress.IPv6Address(p[8:24])), str(ipaddress.IPv6Address(p[24:40])), p[40:]
        size = struct.unpack("!H", p[4:6])[0]
    else:
        return None
    if len(t) < 14:
        return None
    sport, dport = struct.unpack("!HH", t[:4])
    return (a, str(sport)), (b, str(dport)), max(0, size - (t[12] >> 4) * 4)


def flows(path):
    out, frames, skipped = {}, 0, 0
    with open(path, "rb") as fh:
        raw = fh.read()
    for lt, f in records(raw):
        frames += 1
        n = network(lt, f)
        seg = tcp(*n) if n else None
        if seg is None:
            skipped += 1
            continue
        src, dst, size = seg
        key = tuple(sorted([src, dst]))
        sent = out.setdefault(key, {key[0]: 0, key[1]: 0})
        sent[src] += size
    return out, frames, skipped


def main(paths):
    print("capture\ta\tap\tb\tbp\toctets_a\toctets_b")
    for path in paths:
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            fl, frames, skipped = flows(path)
        except (ValueError, IndexError, struct.error) as e:
            print(f"# {name}: not read ({e})")
            continue
        print(f"# {name}: {frames} frames, {skipped} not read as TCP, {len(fl)} TCP flows")
        for (x, y), sent in sorted(fl.items()):
            print(f"{name}\t{x[0]}\t{x[1]}\t{y[0]}\t{y[1]}\t{sent[x]}\t{sent[y]}")


if __name__ == "__main__":
    main(sys.argv[1:])
