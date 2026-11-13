"""P4-4-E2 (D4): the synthesized captures of the Modbus signature's corpus.

Written frame by frame with D6's GT-PCAP writer (tests/integration/gt_pcap/
synth.py and pcapfile.py, read and not changed), so the bytes are the same
on every run and only their SHA-256s are pinned (corpus.tsv). Addresses are
from 192.0.2.0/24 (TEST-NET-1). Nothing here sends a packet. Each capture
is reported apart from the public ones (D6's `fp-near`, `report-counts`).

- synth-rtu-reads.pcap: Modbus RTU framing carried in raw TCP, as a port
  server or a tunnelled serial link carries it (D2's B2 on #642): four
  connections to 192.0.2.40:4001, each two reads with codes 1, 2, 3 and 4
  at address 0 and a quantity of 2, each answered by the RTU reply. Every
  request is a near miss (`fp-near`: octets 2 and 3 zero, octets 4 and 5
  equal to 2), and they are reads, as D1 ruled on #642 (6839544318). The
  RTU framing (address, code, fields, CRC-16 with polynomial A001h from
  FFFFh, low octet first) is `inference`: reference/ holds no Modbus
  specification. Labelled `not-modbus` by `label-not-modbus`.
- synth-modbus-server-first.pcap: one Modbus/TCP connection to
  192.0.2.60:15020 with no handshake, whose first frame is the server's
  reply to a request the capture does not hold (D4's N2 on #642), then
  three reads with code 3 and their replies. A `held-other` member listed
  as `(roles not recoverable off 502)`.
- synth-modbus-sel-codes.pcap: five Modbus/TCP connections to
  192.0.2.80:15020, each opened with one of SEL's own codes of
  fc-classes/1 (60h, 61h, 62h, 7Dh, 7Eh) and answered with exception code
  01h (D6's `review-text` (b) and (e)). The request's body after the code
  is two zero octets: SEL's layouts (S22 Tables E.2 and E.30) are not read
  here, so the request shows the code and not the function.

Usage: python synth_corpus.py OUTDIR
"""

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..",
                                "tests", "integration", "gt_pcap"))
import pcapfile  # noqa: E402
import synth  # noqa: E402


def crc16(b):
    c = 0xFFFF
    for x in b:
        c ^= x
        for _ in range(8):
            c = (c >> 1) ^ 0xA001 if c & 1 else c >> 1
    return struct.pack("<H", c)


def rtu(b):
    return b + crc16(b)


def mbap(tid, unit, pdu):
    return struct.pack("!HHHB", tid, 0, len(pdu) + 1, unit) + pdu


def rtu_reads():
    clock, frames = synth.Clock(), []
    server = synth.Host("02:00:00:00:00:40", "192.0.2.40", 4001)
    for k, code in enumerate((1, 2, 3, 4)):
        c = synth.TCPConv(synth.Host("02:00:00:00:00:30", "192.0.2.30", 49200 + k), server, clock,
                          isn_c=1000 + k * 100000, isn_s=5000 + k * 100000, ident=1 + k * 16)
        c.handshake()
        data = b"\x01" if code <= 2 else b"\x00\x00\x00\x00"
        for _ in range(2):
            c.send(True, rtu(bytes([1, code, 0, 0, 0, 2])))
            c.send(False, rtu(bytes([1, code, len(data)]) + data))
        c.close()
        frames += c.frames
    return frames


def server_first():
    clock = synth.Clock()
    c = synth.TCPConv(synth.Host("02:00:00:00:00:50", "192.0.2.50", 49300),
                      synth.Host("02:00:00:00:00:60", "192.0.2.60", 15020), clock)
    c.send(False, mbap(0x0010, 1, bytes([3, 4, 0, 0, 0, 0])))
    for tid in (0x0011, 0x0012, 0x0013):
        c.send(True, mbap(tid, 1, bytes([3, 0, 0, 0, 2])))
        c.send(False, mbap(tid, 1, bytes([3, 4, 0, 0, 0, 0])))
    return c.frames


def sel_codes():
    clock, frames = synth.Clock(), []
    server = synth.Host("02:00:00:00:00:80", "192.0.2.80", 15020)
    for k, code in enumerate((0x60, 0x61, 0x62, 0x7D, 0x7E)):
        c = synth.TCPConv(synth.Host("02:00:00:00:00:70", "192.0.2.70", 49400 + k), server, clock,
                          isn_c=2000 + k * 100000, isn_s=7000 + k * 100000, ident=1 + k * 16)
        c.handshake()
        c.send(True, mbap(k + 1, 1, bytes([code, 0, 0])))
        c.send(False, mbap(k + 1, 1, bytes([code + 0x80, 1])))
        c.close()
        frames += c.frames
    return frames


def main(outdir):
    os.makedirs(outdir, exist_ok=True)
    for name, fn in (("synth-rtu-reads", rtu_reads), ("synth-modbus-server-first", server_first),
                     ("synth-modbus-sel-codes", sel_codes)):
        pcapfile.write(os.path.join(outdir, name + ".pcap"), fn())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
