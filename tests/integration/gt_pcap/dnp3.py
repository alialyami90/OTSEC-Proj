"""DNP3 link, transport and application bytes for GT-PCAP's sources (D6).

Written by D6 in stdlib Python, not taken from a library the product might
link, so a shared bug can't make product and truth agree (plan section 2B).
What a frame means is what tshark's dissector reads from it, and that is the
label; these helpers only put the bytes on the wire.

Secure Authentication (group 120): the project holds neither IEEE 1815's SA
clause nor IEC 62351-5, and no public SA capture (D2 on #542). So every g120
object here is synthetic at header level: its group, variation and qualifier
are as S23 Table 2.30 names them, and its body is filler of a plausible
length. Tshark may read the body as malformed; the labels key only on the
object headers it reads (dnp3.al.obj), never on the contents.
"""

import struct

# Function codes used here (S23 Table 2.30). CONFIRM, 0, is the master's
# Application Confirm of an unsolicited response (S22 p. D.7 names the
# message; its code is what tshark reads, IEEE 1815 not being held).
CONFIRM, READ, WRITE, SELECT, OPERATE, DIRECT_OPERATE = 0, 1, 2, 3, 4, 5
ENABLE_UNSOL, DISABLE_UNSOL, ASSIGN_CLASS = 20, 21, 22
AUTH_REQ, AUTH_REQ_NO_ACK = 32, 33
RESPONSE, UNSOL_RESPONSE, AUTH_RESPONSE = 129, 130, 131

_CRC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0xA6BC if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


def crc(b):
    """DNP3 link-layer CRC: polynomial 0x3D65, reflected, complemented."""
    c = 0
    for x in b:
        c = (c >> 8) ^ _CRC_TABLE[(c ^ x) & 0xFF]
    return struct.pack("<H", ~c & 0xFFFF)


def link(dest, src, from_master, user):
    """One link-layer frame of unconfirmed user data carrying `user`.

    DIR is set from the master, PRM is set (primary), function 4 (unconfirmed
    user data). User data goes in 16-octet blocks, each with its CRC.
    """
    if len(user) > 250:
        raise ValueError("a link frame holds at most 250 octets of user data")
    ctrl = (0x80 if from_master else 0) | 0x40 | 0x04
    hdr = b"\x05\x64" + struct.pack("<BBHH", 5 + len(user), ctrl, dest, src)
    out = hdr + crc(hdr)
    for i in range(0, len(user), 16):
        blk = user[i:i + 16]
        out += blk + crc(blk)
    return out


def tpdu(seq, apdu):
    """One transport segment holding the whole APDU (FIR and FIN set)."""
    if len(apdu) > 249:
        raise ValueError("this writer sends single-segment APDUs only")
    return bytes([0xC0 | (seq & 0x3F)]) + apdu


def request(app_seq, fc, objects=b""):
    """A request APDU: FIR, FIN, no CON, no UNS, and its sequence number."""
    return bytes([0xC0 | (app_seq & 0x0F), fc]) + objects


def response(app_seq, fc=RESPONSE, iin=0, objects=b""):
    return bytes([0xC0 | (app_seq & 0x0F), fc]) + struct.pack(">H", iin) + objects


def unsolicited(app_seq, iin=0, objects=b""):
    """An unsolicited response APDU: function 130 with FIR, FIN, CON and UNS
    set, so the master must confirm it (S22 p. D.7)."""
    return bytes([0xF0 | (app_seq & 0x0F), UNSOL_RESPONSE]) + struct.pack(">H", iin) + objects


def confirm(app_seq):
    """The master's Application Confirm of an unsolicited response: function
    0 with FIR, FIN and UNS set, in the response's sequence number."""
    return bytes([0xD0 | (app_seq & 0x0F), CONFIRM])


# Object headers (S23 §2.x; qualifier codes as tshark reads them).

def all_objects(g, v):
    """Qualifier 0x06: all objects of the group and variation."""
    return bytes([g, v, 0x06])


def count8(g, v, data, count=1):
    """Qualifier 0x07: an 8-bit count, then the objects."""
    return bytes([g, v, 0x07, count]) + data


def start_stop8(g, v, start, stop, data):
    """Qualifier 0x00: 8-bit start and stop indices, then the objects."""
    return bytes([g, v, 0x00, start, stop]) + data


def crob(index, code=0x03, count=1, on_ms=1000, off_ms=0):
    """g12v1 with qualifier 0x28 (16-bit count, 16-bit index prefix): one
    control relay output block. code 0x03 is LATCH_ON."""
    return bytes([12, 1, 0x28]) + struct.pack("<HH", 1, index) + struct.pack("<BBIIB", code, count, on_ms, off_ms, 0)


def time_sync(ms):
    """g50v1, qualifier 0x07 count 1: the absolute time, 48-bit milliseconds."""
    return count8(50, 1, struct.pack("<Q", ms)[:6])


def binary_event(index, ms, flags=0x81):
    """g2v2, a binary input change with time, qualifier 0x17 (an 8-bit
    count of 1, an 8-bit index): flags (0x81, online and state 1), then
    48-bit milliseconds. In 129 and 130 with qualifiers 17h and 28h (S22
    Table D.9, p. D.15)."""
    return bytes([2, 2, 0x17, 1, index, flags]) + struct.pack("<Q", ms)[:6]


def deadband16(index, value):
    """g34v1, a 16-bit analog input reporting deadband, qualifier 0x00 (8-bit
    start and stop indices). Written with function 2 (S22 Table D.9,
    p. D.17)."""
    return start_stop8(34, 1, index, index, struct.pack("<H", value))


def iin_clear_restart():
    """g80v1 index 7 written to 0: the master clears IIN1.7 (device restart)."""
    return start_stop8(80, 1, 7, 7, b"\x00")


def free_format(g, v, body):
    """Qualifier 0x5B: an 8-bit count of 1, a 16-bit object size, the object.
    Used for the group 120 objects, whose bodies here are filler."""
    return bytes([g, v, 0x5B, 1]) + struct.pack("<H", len(body)) + body


# Group 120 objects, synthetic at header level (see the module note). The
# filler is fixed, so the bytes are the same on every run.

def g120v1_challenge():
    return free_format(120, 1, b"\x01\x00\x00\x00" + b"\x01\x00" + b"\x04" + b"\x01" + b"\xAA" * 4)


def g120v2_reply():
    return free_format(120, 2, b"\x01\x00\x00\x00" + b"\x01\x00" + b"\xBB" * 16)


def g120v3_aggressive():
    return count8(120, 3, b"\x02\x00\x00\x00" + b"\x01\x00")


def g120v7_error():
    return free_format(120, 7, b"\x01\x00\x00\x00" + b"\x01\x00" + b"\x01\x00" + b"\x01" + b"\x00" * 6)


def g120v9_hmac():
    return free_format(120, 9, b"\xCC" * 16)
