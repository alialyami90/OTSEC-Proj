"""Deterministic Ethernet, IPv4, TCP and UDP frames for GT-PCAP's sources (D6).

Stdlib only, and shared with no product code (plan section 1). GT-PCAP's
DNP3, Modbus/TCP and HTTP cases are synthesized frame by frame, not recorded
through a kernel: the derived cases (a removed response, a reused sequence
number, a lost segment, one byte per frame) need control of every frame, and
a fixed writer gives the same bytes on every run, so only their hashes are
committed. Tshark's reading of these frames is the label, and the self-tests
check that tshark reads every checksum as correct.

Addresses come from 192.0.2.0/24 (TEST-NET-1) and MACs are locally
administered (02:...). Nothing here sends a packet.
"""

import struct

import pcapfile

ETH_IPV4 = 0x0800
ETH_VLAN = 0x8100
TCP, UDP = 6, 17
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def mac(s):
    return bytes(int(x, 16) for x in s.split(":"))


def ip4(s):
    return bytes(int(x) for x in s.split("."))


def checksum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def eth(dst, src, ethertype, payload, vlan=None):
    """An Ethernet II frame with no FCS, padded to 60 octets as a NIC sends it."""
    hdr = mac(dst) + mac(src)
    if vlan is not None:
        hdr += struct.pack("!HH", ETH_VLAN, vlan & 0x0FFF)
    frame = hdr + struct.pack("!H", ethertype) + payload
    return frame + b"\0" * max(0, 60 - len(frame))


def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0x4000, 64, proto, 0,
                      ip4(src), ip4(dst))
    return hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:] + payload


def tcp(src, dst, sport, dport, seq, ack, flags, payload=b"", window=8192):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, window, 0, 0)
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, TCP, len(hdr) + len(payload))
    c = checksum(pseudo + hdr + payload)
    return hdr[:16] + struct.pack("!H", c) + hdr[18:] + payload


def udp(src, dst, sport, dport, payload):
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, UDP, len(hdr) + len(payload))
    c = checksum(pseudo + hdr + payload) or 0xFFFF
    return hdr[:6] + struct.pack("!H", c) + payload


class Host:
    """One end: its MAC, IPv4 address and port."""

    def __init__(self, mac_s, ip_s, port):
        self.mac, self.ip, self.port = mac_s, ip_s, port


class Clock:
    """Integer nanoseconds from a fixed start, advanced by each frame."""

    def __init__(self, start_ns=1_762_545_600_000_000_000, step_ns=1_000_000):
        self.ns, self.step = start_ns, step_ns

    def tick(self, gap_ns=None):
        self.ns += self.step if gap_ns is None else gap_ns
        return self.ns


class TCPConv:
    """One TCP connection between a client and a server, frame by frame.

    Every method returns the frames it adds, in order, each also appended to
    self.frames. Sequence numbers start from fixed values, so the bytes are
    the same on every run. `vlan` tags every frame of the connection.
    """

    def __init__(self, client, server, clock, isn_c=1000, isn_s=5000, vlan=None, ident=1):
        self.c, self.s, self.clock, self.vlan = client, server, clock, vlan
        self.seq = {True: isn_c, False: isn_s}  # True: the client's next seq
        self.ident = {True: ident, False: ident + 0x4000}
        self.frames = []

    def _frame(self, from_client, flags, payload=b"", seq=None, gap_ns=None):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        s = self.seq[from_client] if seq is None else seq
        ack = self.seq[not from_client] if flags & ACK else 0
        seg = tcp(a.ip, b.ip, a.port, b.port, s, ack, flags, payload)
        pkt = ipv4(a.ip, b.ip, TCP, seg, self.ident[from_client])
        self.ident[from_client] += 1
        fr = pcapfile.Frame(self.clock.tick(gap_ns), eth(b.mac, a.mac, ETH_IPV4, pkt, self.vlan))
        self.frames.append(fr)
        return fr

    def handshake(self):
        out = [self._frame(True, SYN)]
        self.seq[True] += 1
        out.append(self._frame(False, SYN | ACK))
        self.seq[False] += 1
        out.append(self._frame(True, ACK))
        return out

    def send(self, from_client, data, acked=True, gap_ns=None):
        """One data segment, and the peer's bare ACK unless acked is False."""
        out = [self._frame(from_client, PSH | ACK, data, gap_ns=gap_ns)]
        self.seq[from_client] += len(data)
        if acked:
            out.append(self._frame(not from_client, ACK))
        return out

    def close(self):
        out = [self._frame(True, FIN | ACK)]
        self.seq[True] += 1
        out.append(self._frame(False, FIN | ACK))
        self.seq[False] += 1
        out.append(self._frame(True, ACK))
        return out


class UDPConv:
    """One UDP conversation between a client and a server."""

    def __init__(self, client, server, clock, vlan=None, ident=1):
        self.c, self.s, self.clock, self.vlan = client, server, clock, vlan
        self.ident = ident
        self.frames = []

    def send(self, from_client, data, gap_ns=None):
        a, b = (self.c, self.s) if from_client else (self.s, self.c)
        pkt = ipv4(a.ip, b.ip, UDP, udp(a.ip, b.ip, a.port, b.port, data), self.ident)
        self.ident += 1
        fr = pcapfile.Frame(self.clock.tick(gap_ns), eth(b.mac, a.mac, ETH_IPV4, pkt, self.vlan))
        self.frames.append(fr)
        return [fr]
