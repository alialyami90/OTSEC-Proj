"""Count what E-D4-01 needs, with no third-party module (run with python -I).

  count.py pcapng FILE      -> packets in a pcapng file (enhanced and simple blocks)
  count.py eve FILE         -> app-layer events per protocol in a Suricata eve.json
"""
import collections
import json
import struct
import sys


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
    return dict(sorted(seen.items()))


if __name__ == "__main__":
    kind, path = sys.argv[1], sys.argv[2]
    if kind == "pcapng":
        print(pcapng_packets(path))
    elif kind == "eve":
        print(json.dumps(eve_protocols(path), sort_keys=True))
    else:
        raise SystemExit("usage: count.py pcapng|eve FILE")
