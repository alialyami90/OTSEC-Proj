"""Classic pcap reading and writing for GT-PCAP's derived captures (D6).

Stdlib only, and shared with no product code (GT-PCAP's labels must not
come from the product). Only what the derived captures need: the classic
format, microsecond or nanosecond timestamps, either byte order, and
Ethernet (link type 1). A truncated record (captured length below the
original length) is refused, because a derived frame built from it would
not be the frame that was on the wire.
"""

import struct

ETHERNET = 1
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class Frame:
    """One record: its time in integer nanoseconds and its link-layer bytes."""

    __slots__ = ("ns", "data")

    def __init__(self, ns, data):
        self.ns = ns
        self.data = bytes(data)


def read(path):
    """Return the Ethernet frames of a classic pcap file, in file order."""
    with open(path, "rb") as f:
        raw = f.read()
    if len(raw) < 24 or raw[:4] not in _MAGIC:
        raise ValueError(f"{path}: not a classic pcap file")
    order, per_s = _MAGIC[raw[:4]]
    linktype = struct.unpack(order + "I", raw[20:24])[0]
    if linktype != ETHERNET:
        raise ValueError(f"{path}: link type {linktype}, want Ethernet (1)")
    frames, off = [], 24
    while off < len(raw):
        if off + 16 > len(raw):
            raise ValueError(f"{path}: record header cut short at byte {off}")
        sec, frac, incl, orig = struct.unpack(order + "IIII", raw[off:off + 16])
        off += 16
        if incl != orig:
            raise ValueError(f"{path}: record {len(frames) + 1} is truncated ({incl} of {orig} bytes)")
        if off + incl > len(raw):
            raise ValueError(f"{path}: record {len(frames) + 1} cut short")
        ns = sec * 1_000_000_000 + frac * (1_000_000_000 // per_s)
        frames.append(Frame(ns, raw[off:off + incl]))
        off += incl
    return frames


def write(path, frames):
    """Write frames as a little-endian, nanosecond classic pcap file."""
    out = [struct.pack("<4sHHiIII", b"\x4d\x3c\xb2\xa1", 2, 4, 0, 0, 262144, ETHERNET)]
    for fr in frames:
        sec, ns = divmod(fr.ns, 1_000_000_000)
        out.append(struct.pack("<IIII", sec, ns, len(fr.data), len(fr.data)))
        out.append(fr.data)
    with open(path, "wb") as f:
        f.write(b"".join(out))
