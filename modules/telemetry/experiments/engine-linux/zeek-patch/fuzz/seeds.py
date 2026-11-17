"""HR-23's sanitizer fuzz run: the seed conversion (brief P4-4-HR23-FUZZ;
docs/phase4/D4-hr23-design.md, section 4.6, "The seeds"). Pinned by its
SHA-256 in fuzz.env, and its output by the corpus hash there.

It turns captures into FuzzBuffer inputs, the format of Zeek 9.0.1's
src/fuzzers/FuzzBuffer.h: each chunk is PKT_MAGIC ("\\x01PKT"), one flag
octet whose low bit is is_orig, then the chunk's octets up to the next
PKT_MAGIC. An input holds at most MAX_CHUNK_COUNT (64) chunks, since
FuzzBuffer::Valid drops a longer one whole.

- `dnp3_tcp` and `dnp3_udp` (the generic targets, which take the analyzer's
  octets): every capture's TCP or UDP payloads, one chunk each, in capture
  order, from the capture's first 5-tuple. A chunk's is_orig is set when the
  first packet's sender sent it. The fuzzer has no role swap (section 4.6),
  so Zeek's own choice of originator is not modelled. Zeek's dnp3_tcp
  corpus (5 inputs, 4,847 octets) is added to both, unchanged.
- `packet` (DLT_RAW): every UDP capture's IPv4 packets of its first
  5-tuple, Ethernet header and any padding removed, one chunk each, so that
  each flow's first datagram reaches the PIA's replay.

An input is cut to its first chunks that fit both 64 chunks and --max-len
octets; the count of cut inputs is reported. A capture whose octets hold
PKT_MAGIC is refused, since it would cut a chunk in two.

Writes OUT/<target>/<name>.pkt and OUT/manifest.sha256 ("sha256  target/name"
lines, sorted), whose own SHA-256 is the corpus hash. Prints counts only.
Stdlib only; reads the captures with GT-PCAP's pcapfile.py.

Usage: python -I seeds.py --max-len N --zeek-corpus ZIP OUT CAPDIR...
"""
import argparse
import hashlib
import os
import struct
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "..", "..", "tests", "integration", "gt_pcap"))
import pcapfile  # noqa: E402

MAGIC = b"\x01PKT"
MAX_CHUNKS = 64
TARGETS = ("dnp3_tcp", "dnp3_udp", "packet")


def packets(path):
    """Each IPv4 TCP or UDP packet of a capture as (5-tuple key, sender,
    proto, IP packet octets, L4 payload)."""
    out = []
    for fr in pcapfile.read(path):
        d = fr.data
        off, etype = 14, struct.unpack("!H", d[12:14])[0]
        if etype == 0x8100:
            off, etype = 18, struct.unpack("!H", d[16:18])[0]
        if etype != 0x0800:
            continue
        ip = d[off:]
        if len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 0x0F) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        ip = ip[:total]
        proto = ip[9]
        if proto == 6:
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            payload = ip[ihl + (ip[ihl + 12] >> 4) * 4:]
        elif proto == 17:
            sport, dport = struct.unpack("!HH", ip[ihl:ihl + 4])
            payload = ip[ihl + 8:]
        else:
            continue
        a, b = (ip[12:16], sport), (ip[16:20], dport)
        out.append(((proto,) + tuple(sorted((a, b))), a, proto, bytes(ip), bytes(payload)))
    return out


def fuzzbuffer(chunks, max_len):
    """The FuzzBuffer input of (is_orig, octets) chunks, cut to fit; and
    whether it was cut."""
    out = b""
    n = 0
    for is_orig, data in chunks:
        if MAGIC in data:
            raise ValueError("a chunk holds PKT_MAGIC")
        piece = MAGIC + bytes([1 if is_orig else 0]) + data
        if n == MAX_CHUNKS or len(out) + len(piece) > max_len:
            return out, True
        out += piece
        n += 1
    return out, False


def convert(path, max_len):
    """{target: (input, cut)} for one capture; a target the capture does not
    feed is absent."""
    pk = packets(path)
    if not pk:
        return {}
    key, first = pk[0][0], pk[0][1]
    flow = [p for p in pk if p[0] == key]
    gen = [(p[1] == first, p[4]) for p in flow if p[4]]
    out = {}
    if gen:
        for t in ("dnp3_tcp", "dnp3_udp"):
            out[t] = fuzzbuffer(gen, max_len)
    if key[0] == 17:
        out["packet"] = fuzzbuffer([(True, p[3]) for p in flow], max_len)
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-len", type=int, required=True)
    ap.add_argument("--zeek-corpus", required=True)
    ap.add_argument("out")
    ap.add_argument("capdirs", nargs="+")
    a = ap.parse_args(argv)
    seeds = {t: {} for t in TARGETS}
    cut = 0
    caps = 0
    for cd in a.capdirs:
        for name in sorted(os.listdir(cd)):
            if not name.endswith(".pcap"):
                continue
            caps += 1
            stem = name[:-5]
            for t, (data, was_cut) in convert(os.path.join(cd, name), a.max_len).items():
                if stem in seeds[t]:
                    raise ValueError(f"two captures named {stem}")
                seeds[t][stem] = data
                cut += was_cut
    with zipfile.ZipFile(a.zeek_corpus) as z:
        for zn in sorted(z.namelist()):
            data = z.read(zn)
            if len(data) > a.max_len:
                raise ValueError(f"Zeek's seed {zn} is longer than --max-len")
            for t in ("dnp3_tcp", "dnp3_udp"):
                seeds[t]["zeek-" + os.path.splitext(os.path.basename(zn))[0]] = data
    lines = []
    for t in TARGETS:
        os.makedirs(os.path.join(a.out, t), exist_ok=True)
        for stem, data in seeds[t].items():
            with open(os.path.join(a.out, t, stem + ".pkt"), "wb") as fh:
                fh.write(data)
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {t}/{stem}.pkt\n")
    with open(os.path.join(a.out, "manifest.sha256"), "w", encoding="ascii", newline="\n") as fh:
        fh.writelines(sorted(lines, key=lambda x: x.split("  ", 1)[1]))
    print(f"seeds.py: {caps} captures; seeds: " + ", ".join(f"{t} {len(seeds[t])}" for t in TARGETS)
          + f"; {cut} cut to 64 chunks or --max-len")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
