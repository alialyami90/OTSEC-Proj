"""Packet capture for V-M8's paired runs (C6, P4-3-C6; D4-49 Q12, D4-50).

The paired runs execute in a network namespace of their own (unshare -n),
so every packet any process of the run sends is on one of two interfaces:

  - lo, where the simulator, the RELP receiver and the node's peers are;
  - d0, a TUN device that holds the namespace's default route, so a packet
    to any other address is routed there and read by this module instead
    of failing with "network unreachable" before it is sent.

d0 holds the IPv4 default route and, where the kernel has IPv6, the IPv6
default route too (C3 on #470), so an attempt to reach any address of
either family becomes a packet on d0 rather than an error before any
packet exists. Where the kernel has no IPv6, no process can open an IPv6
socket at all, and probe() records that.

setup() brings lo up and makes d0; Capture records what is sent on both;
probe() checks that a datagram to an outside address of each family is
read from d0. All three need root, which the namespace's creator has. The
only packets this module sends are probe()'s, into d0, which only this
module reads. Evidence class: simulated.
"""

import fcntl
import os
import socket
import struct
import subprocess
import threading
import time

ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000
TUN = "d0"


def interfaces():
    """This network namespace's interfaces (sysfs may show the host's)."""
    return sorted(name for _, name in socket.if_nameindex())


def ipv6():
    """Whether this kernel lets a process open an IPv6 socket."""
    try:
        socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
        return True
    except OSError:
        return False


def setup():
    """lo up, and d0 holding the default route of each family. Returns d0's
    file descriptor, which Capture reads; d0 lives while it is open."""
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    fd = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", TUN.encode(), IFF_TUN | IFF_NO_PI))
    steps = [["ip", "addr", "add", "10.99.0.1/24", "dev", TUN]]
    if ipv6():
        # No link-local address and no router solicitation, so the kernel
        # itself sends as little as it can on d0; probe() drains the rest.
        for name, value in (("addr_gen_mode", "1"), ("accept_ra", "0"), ("router_solicitations", "0")):
            with open(f"/proc/sys/net/ipv6/conf/{TUN}/{name}", "w") as f:
                f.write(value)
        steps.append(["ip", "-6", "addr", "add", "fd99::1/64", "dev", TUN, "nodad"])
    steps.append(["ip", "link", "set", TUN, "up"])
    steps.append(["ip", "route", "add", "default", "dev", TUN])
    if ipv6():
        steps.append(["ip", "-6", "route", "add", "default", "dev", TUN])
    for argv in steps:
        subprocess.run(argv, check=True)
    return fd


PROBES = {4: ("192.0.2.1", 9), 6: ("2001:db8::1", 9)}  # documentation addresses


def probe(tun_fd, settle=3.0):
    """Send one UDP datagram to an outside address of each family the
    kernel has, and read d0 for settle seconds. Returns {"seen": {family:
    bool}, "ipv6": bool, "other": [packets on d0 that were not a probe]}.
    The kernel's own packets at d0's start (IPv6 multicast reports) are
    read here, so a run's capture does not hold them."""
    fams = [4, 6] if ipv6() else [4]
    c = Capture(tun_fd)
    for v in fams:
        with socket.socket(socket.AF_INET if v == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.sendto(b"otsec-vm8-probe", PROBES[v])
    time.sleep(settle)
    _, ext = c.stop()
    seen = {v: any(p[0] == v and (p[4], p[5]) == PROBES[v] for p in ext if p[0] != "other") for v in fams}
    other = [p for p in ext if p[0] == "other" or (p[4], p[5]) not in PROBES.values()]
    return {"seen": seen, "ipv6": ipv6(), "other": other}


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
