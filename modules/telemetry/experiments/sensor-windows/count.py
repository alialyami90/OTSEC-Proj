"""Count what E-D4-01 needs, with no third-party module (run with python -I).

  count.py pcapng FILE      -> packets in a pcapng file (enhanced and simple blocks)
  count.py eve FILE         -> app-layer events per protocol in a Suricata eve.json
  count.py port FILE PORT   -> frames in a pcapng file, the link types seen, and
                               the TCP frames to or from PORT (IPv4 and IPv6,
                               Ethernet with 802.1Q tags, raw IP, or null/loopback)
"""
import collections
import json
import struct
import sys


def _tcp_ports(linktype, frame):
    """The (sport, dport) of a TCP frame, or None."""
    off = 0
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return None
        et, off = struct.unpack_from(">H", frame, 12)[0], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:
            et, off = struct.unpack_from(">H", frame, off + 2)[0], off + 4
        ver = {0x0800: 4, 0x86DD: 6}.get(et)
    elif linktype == 0:  # null/loopback: 4-byte address family
        off = 4
        ver = frame[off] >> 4 if len(frame) > off else None
    elif linktype in (101, 228, 229):  # raw IP
        ver = frame[0] >> 4 if frame else None
    else:
        return None
    if ver == 4 and len(frame) >= off + 20 and frame[off + 9] == 6:
        off += (frame[off] & 0x0F) * 4
    elif ver == 6 and len(frame) >= off + 40 and frame[off + 6] == 6:
        off += 40
    else:
        return None
    if len(frame) < off + 4:
        return None
    return struct.unpack_from(">HH", frame, off)


def pcapng_port(path, port):
    with open(path, "rb") as f:
        data = f.read()
    frames, hits, off, endian = 0, 0, 0, "<"
    links, seen = [], collections.Counter()
    while off + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            raise SystemExit(f"malformed block at offset {off}")
        if btype == 0x00000001:  # interface description
            links.append(struct.unpack_from(endian + "H", data, off + 8)[0])
        elif btype in (0x00000006, 0x00000003):
            if btype == 6:
                iface = struct.unpack_from(endian + "I", data, off + 8)[0]
                caplen = struct.unpack_from(endian + "I", data, off + 20)[0]
                frame = data[off + 28:off + 28 + caplen]
            else:
                iface, frame = 0, data[off + 12:off + blen - 4]
            lt = links[iface] if iface < len(links) else -1
            frames += 1
            seen[lt] += 1
            ports = _tcp_ports(lt, frame)
            if ports and port in ports:
                hits += 1
        off += blen
    return {"frames": frames, "linktypes": dict(sorted(seen.items())), "tcp_port_frames": hits}


def pcapng_packets(path):
    with open(path, "rb") as f:
        data = f.read()
    n, off, endian = 0, 0, "<"
    while off + 12 <= len(data):
        btype = struct.unpack_from(endian + "I", data, off)[0]
        if btype == 0x0A0D0D0A:  # section header: read its byte-order magic
            endian = "<" if data[off + 8:off + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        blen = struct.unpack_from(endian + "I", data, off + 4)[0]
        if blen < 12 or off + blen > len(data):
            raise SystemExit(f"malformed block at offset {off}")
        if btype in (0x00000006, 0x00000003):  # enhanced, simple packet block
            n += 1
        off += blen
    return n


def eve_protocols(path):
    seen = collections.Counter()
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                seen["(unparsed line)"] += 1
                continue
            if ev.get("event_type") in ("dnp3", "modbus"):
                seen[ev["event_type"]] += 1
            elif ev.get("event_type") == "flow":
                seen["flow:" + str(ev.get("app_proto", "none"))] += 1
            elif ev.get("event_type") == "stats":  # the last one is the total
                seen["stats:decoder.pkts"] = ev.get("stats", {}).get("decoder", {}).get("pkts", 0)
    return dict(sorted(seen.items()))


if __name__ == "__main__":
    kind, path = sys.argv[1], sys.argv[2]
    if kind == "pcapng":
        print(pcapng_packets(path))
    elif kind == "eve":
        print(json.dumps(eve_protocols(path), sort_keys=True))
    elif kind == "port":
        print(json.dumps(pcapng_port(path, int(sys.argv[3])), sort_keys=True))
    else:
        raise SystemExit("usage: count.py pcapng|eve FILE, or count.py port FILE PORT")
