"""Packet capture for V-M8's paired runs (C6, P4-3-C6; D4-49 Q12, D4-50).

The paired runs execute in a network namespace of their own (unshare -n),
so every packet any process of the run sends is on one of two interfaces:

  - lo, where the simulator, the RELP receiver and the node's peers are;
  - d0, a TUN device that holds the namespace's default route, so a packet
    to any other address is routed there and read by this module instead
    of failing with "network unreachable" before it is sent.

setup() brings lo up and makes d0; Capture records what is sent on both.
Both need root, which the namespace's creator has. Nothing here sends a
packet. Evidence class: simulated.
"""

import fcntl
import os
import socket
import struct
import subprocess
import threading

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
TUN = "d0"


def interfaces():
    """This network namespace's interfaces (sysfs may show the host's)."""
    return sorted(name for _, name in socket.if_nameindex())


def setup():
    """lo up, and d0 holding the default route. Returns d0's file
    descriptor, which Capture reads; d0 lives while it is open."""
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", TUN.encode(), IFF_TUN | IFF_NO_PI))
    for argv in (["ip", "addr", "add", "10.99.0.1/24", "dev", TUN], ["ip", "link", "set", TUN, "up"],
                 ["ip", "route", "add", "default", "dev", TUN]):
        subprocess.run(argv, check=True)
    return fd


def parse_ip(b):
    """(version, proto, src, sport, dst, dport, tcp_flags) of one IP
    packet, or None for anything else."""
    if not b:
        return None
    v = b[0] >> 4
    if v == 4 and len(b) >= 20:
        ihl, proto = (b[0] & 0x0F) * 4, b[9]
        src, dst, rest = socket.inet_ntop(socket.AF_INET, b[12:16]), socket.inet_ntop(socket.AF_INET, b[16:20]), b[ihl:]
    elif v == 6 and len(b) >= 40:
        proto, src, dst, rest = b[6], socket.inet_ntop(socket.AF_INET6, b[8:24]), socket.inet_ntop(socket.AF_INET6, b[24:40]), b[40:]
    else:
        return None
    sport = dport = flags = 0
    if proto in (6, 17) and len(rest) >= 4:
        sport, dport = struct.unpack("!HH", rest[:4])
        if proto == 6 and len(rest) >= 14:
            flags = rest[13]
    return v, proto, src, sport, dst, dport, flags


class Capture:
    """Every packet sent on lo (one copy each: the outgoing one) and every
    packet routed to d0, until stop()."""

    def __init__(self, tun_fd):
        self.lo = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.lo.bind(("lo", 0))
        self.lo.settimeout(0.2)
        self.tun_fd = tun_fd
        self.packets, self.external = [], []
        self._stop = threading.Event()
        self._threads = [threading.Thread(target=self._read_lo, daemon=True), threading.Thread(target=self._read_tun, daemon=True)]
        for t in self._threads:
            t.start()

    def _read_lo(self):
        while not self._stop.is_set():
            try:
                frame, addr = self.lo.recvfrom(65535)
            except socket.timeout:
                continue
            if addr[2] != PACKET_OUTGOING:
                continue
            p = parse_ip(frame[14:])  # lo frames carry a 14-byte Ethernet header
            self.packets.append(p if p else ("other", len(frame)))

    def _read_tun(self):
        os.set_blocking(self.tun_fd, False)
        while not self._stop.is_set():
            try:
                b = os.read(self.tun_fd, 65535)
            except BlockingIOError:
                self._stop.wait(0.05)
                continue
            p = parse_ip(b)
            self.external.append(p if p else ("other", len(b)))

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(5)
        self.lo.close()
        return self.packets, self.external


def connections(packets):
    """The TCP connections and UDP flows in packets, each as
    {proto, server: (addr, port), client: (addr, port), packets: n}, in the
    order they began. A TCP connection's server is the end its first SYN
    was sent to; a UDP flow's is the destination of its first datagram."""
    out, index = [], {}
    for p in packets:
        if p[0] == "other":
            out.append({"proto": "other", "server": None, "client": None, "packets": 1})
            continue
        v, proto, src, sport, dst, dport, flags = p
        key = (proto, frozenset([(src, sport), (dst, dport)]))
        c = index.get(key)
        if c is None:
            # A TCP packet with SYN and no ACK opens a connection; any other
            # first packet is a connection already open (or a UDP flow),
            # whose server is taken to be its destination.
            c = index[key] = {"proto": {6: "tcp", 17: "udp"}.get(proto, str(proto)), "server": (dst, dport), "client": (src, sport), "packets": 0}
            out.append(c)
        c["packets"] += 1
    return out
