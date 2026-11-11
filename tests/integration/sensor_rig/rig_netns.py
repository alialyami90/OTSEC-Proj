"""The veth rig for the sensor's tests (D6, P4-4-R1; GT-PCAP plan sections 5 and 6).

Two network namespaces and one veth pair, made for a test and removed after
it. `tap0` is the rig's end and `mon0` is the sensor's monitoring interface,
each in a namespace of its own, so nothing here touches the runner's real
NIC, and no host daemon sees either end. Every frame comes from a file or
from this module. Nothing captures a real network and nothing scans.

    rig namespace                      sensor namespace
    replayer -> tap0 ================= mon0 -> the sensor (or a stand-in)
    capture  <- tap0  (every frame mon0 transmits arrives here)

C-11 asks for zero frames sourced from the monitoring interface. A packet
socket on `tap0` receives each frame with its packet type: a frame the rig
itself sent on `tap0` is PACKET_OUTGOING, and anything else arrived from
`mon0`. So "sourced from mon0" is read from the kernel, not inferred from a
list of what the replay sent.

Linux and root only. Stdlib only. Used by no product code.
"""

import contextlib
import errno
import hashlib
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_QDISC_BYPASS = 20
PACKET_OUTGOING = 4
TAP, MON = "tap0", "mon0"
MON_TEST_ADDR = "192.0.2.99/24"  # TEST-NET-1; only the misconfigured control gets an address


def why_not():
    """Why the rig can't run here, or '' if it can."""
    if not sys.platform.startswith("linux"):
        return "the rig needs Linux network namespaces"
    if os.geteuid() != 0:
        return "the rig needs root, to make namespaces and open packet sockets"
    if not shutil.which("ip") or not hasattr(os, "setns"):
        return "the rig needs iproute2's ip and os.setns (Python 3.12)"
    return ""


def sh(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"{' '.join(args)}: exit {p.returncode}: {p.stderr.strip()}")
    return p.stdout


class Unavailable(RuntimeError):
    """The runner's kernel lacks what a measurement needs, such as a module
    for a queueing discipline or a device type. The result is then unknown
    on that runner. It is never a pass."""


def need(*args):
    """Run a command that may fail only because the kernel lacks a module.
    That failure is Unavailable; any other failure is an error."""
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        msg = f"{' '.join(args)}: exit {p.returncode}: {p.stderr.strip()}"
        missing = ("unknown", "not found", "not supported", "no such file", "failed to load")
        raise (Unavailable if any(m in p.stderr.lower() for m in missing) else RuntimeError)(msg)
    return p.stdout


@contextlib.contextmanager
def in_ns(name):
    """Run the body with this thread in the named network namespace. A
    socket opened inside stays in that namespace after the body ends."""
    here = os.open("/proc/thread-self/ns/net", os.O_RDONLY)
    there = os.open(f"/run/netns/{name}", os.O_RDONLY)
    try:
        os.setns(there, os.CLONE_NEWNET)
        yield
    finally:
        os.setns(here, os.CLONE_NEWNET)
        os.close(here)
        os.close(there)


def sysctl(ns, key, value):
    with in_ns(ns), open("/proc/sys/" + key.replace(".", "/"), "w") as f:
        f.write(str(value))


def packet_socket(ns, ifname, bypass=False):
    """A raw packet socket on the interface, opened in the namespace. With
    bypass, its sends skip the queueing layer (PACKET_QDISC_BYPASS), and so
    whatever is attached there."""
    with in_ns(ns):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((ifname, 0))
    if bypass:
        s.setsockopt(SOL_PACKET, PACKET_QDISC_BYPASS, 1)
    return s


class Capture:
    """Everything a packet socket on one interface sees, from start() to
    stop(): (monotonic ns at receipt, wall ns at receipt, packet type,
    frame bytes)."""

    def __init__(self, ns, ifname):
        self.sock = packet_socket(ns, ifname)
        self.sock.settimeout(0.05)
        self.frames, self._stop, self.error = [], threading.Event(), None
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                # A socket bound while its interface was down reports that
                # once, and receives from the moment the interface is up.
                if e.errno == errno.ENETDOWN:
                    continue
                self.error = e  # raised by stop(): a dead capture must not read as zero frames
                return
            self.frames.append((time.monotonic_ns(), time.time_ns(), addr[2], data))

    def start(self):
        self._thread.start()
        return self

    def stop(self, settle_s=0.3):
        time.sleep(settle_s)  # let the last frames cross the pair
        self._stop.set()
        self._thread.join()
        self.sock.close()
        if self.error:
            raise self.error
        return self

    def arrived(self):
        """Frames that came in from the peer: not the ones this end sent."""
        return [f for f in self.frames if f[2] != PACKET_OUTGOING]

    def sent(self):
        return [f for f in self.frames if f[2] == PACKET_OUTGOING]


class Rig:
    """The two namespaces and the pair. `misconfigured` is C-11's negative
    control: the monitoring interface with IPv6 on, an IPv4 address and ARP,
    which must be seen to transmit. Otherwise `mon0` is set as a sensor's
    installer must set it: no IPv4 address, IPv6 off, ARP off, promiscuous.

    Both ends are made down. Open the capture, then call up(), so the frames
    an interface sends as it comes up are in the capture.
    """

    def __init__(self, misconfigured=False):
        tag = f"{os.getpid()}-{time.monotonic_ns() % 100000}"
        self.rig_ns, self.sensor_ns, self.misconfigured = f"otsec-rig-{tag}", f"otsec-sen-{tag}", misconfigured

    def __enter__(self):
        sh("ip", "netns", "add", self.rig_ns)
        sh("ip", "netns", "add", self.sensor_ns)
        # Set before the pair exists, so each end starts with the setting.
        for ns, off in ((self.rig_ns, 1), (self.sensor_ns, 0 if self.misconfigured else 1)):
            for scope in ("all", "default"):
                sysctl(ns, f"net.ipv6.conf.{scope}.disable_ipv6", off)
        sh("ip", "-n", self.rig_ns, "link", "add", TAP, "type", "veth", "peer", "name", MON, "netns", self.sensor_ns)
        sh("ip", "-n", self.rig_ns, "link", "set", TAP, "arp", "off", "promisc", "on")
        if self.misconfigured:
            sysctl(self.sensor_ns, f"net.ipv4.conf.{MON}.arp_notify", 1)
            sh("ip", "-n", self.sensor_ns, "addr", "add", MON_TEST_ADDR, "dev", MON)
        else:
            sh("ip", "-n", self.sensor_ns, "link", "set", MON, "arp", "off", "promisc", "on")
        return self

    def up(self):
        sh("ip", "-n", self.rig_ns, "link", "set", TAP, "up")
        sh("ip", "-n", self.sensor_ns, "link", "set", MON, "up")
        deadline = time.monotonic() + 5
        while "LOWER_UP" not in sh("ip", "-n", self.sensor_ns, "link", "show", MON):
            if time.monotonic() > deadline:
                raise RuntimeError("mon0 never came up")
            time.sleep(0.02)

    def __exit__(self, *exc):
        for ns in (self.rig_ns, self.sensor_ns):
            subprocess.run(["ip", "netns", "del", ns], capture_output=True)

    def tc_egress_drop(self):
        """A clsact queueing discipline on mon0 with one egress filter that
        drops everything: the `tc` form of a host rule against sending. It
        sits in the queueing layer's egress hook, a different point from
        nftables' netdev egress hook, so it is measured on its own."""
        need("tc", "-n", self.sensor_ns, "qdisc", "add", "dev", MON, "clsact")
        need("tc", "-n", self.sensor_ns, "filter", "add", "dev", MON, "egress", "matchall", "action", "drop")

    def enslave_to_bridge(self, name="br0"):
        """Make mon0 a port of a bridge that has what mon0 itself lacks:
        IPv6, ARP and an IPv4 address. Nothing is changed on mon0 but its
        master. Call after up()."""
        ns = self.sensor_ns
        need("ip", "-n", ns, "link", "add", name, "type", "bridge")
        sysctl(ns, f"net.ipv6.conf.{name}.disable_ipv6", 0)
        sh("ip", "-n", ns, "addr", "add", MON_TEST_ADDR, "dev", name)
        sh("ip", "-n", ns, "link", "set", MON, "master", name)
        sh("ip", "-n", ns, "link", "set", name, "up")

    def stack_vlan(self, name="monv10", vid="10"):
        """Stack a VLAN device on mon0 that has what mon0 itself lacks:
        IPv6, ARP and an IPv4 address. Nothing is changed on mon0. Call
        after up(): an upper device comes up only on a lower one that is."""
        ns = self.sensor_ns
        need("ip", "-n", ns, "link", "add", "link", MON, "name", name, "type", "vlan", "id", vid)
        sysctl(ns, f"net.ipv6.conf.{name}.disable_ipv6", 0)
        sh("ip", "-n", ns, "addr", "add", MON_TEST_ADDR, "dev", name)
        sh("ip", "-n", ns, "link", "set", name, "arp", "on", "up")

    def mon0_own_settings(self):
        """mon0's own settings, the ones C-11's quiet arrangement sets: no
        IPv4 address, IPv6 off, ARP off. A master or an upper device leaves
        all three as they were."""
        ns = self.sensor_ns
        with in_ns(ns), open(f"/proc/sys/net/ipv6/conf/{MON}/disable_ipv6") as f:
            ipv6_off = f.read().strip() == "1"
        return {"ipv4_address": bool(sh("ip", "-n", ns, "-o", "-4", "addr", "show", "dev", MON).strip()),
                "ipv6_off": ipv6_off, "arp_off": "NOARP" in sh("ip", "-n", ns, "link", "show", MON)}

    def qdisc_drop_all(self):
        """A queue on mon0 that holds nothing, so the queueing layer drops
        every frame handed to it. It is the control for the bypass sender:
        a send that still leaves has skipped that layer."""
        sh("tc", "-n", self.sensor_ns, "qdisc", "replace", "dev", MON, "root", "pfifo", "limit", "0")

    def nft_egress_drop(self):
        """A netdev egress chain on mon0 that drops everything, as a host
        rule against sending would be written. Needs the nft binary."""
        rules = (f'table netdev c11 {{\n  chain out {{\n    type filter hook egress device "{MON}" priority 0; '
                 'policy drop;\n  }\n}\n')
        p = subprocess.run(["ip", "netns", "exec", self.sensor_ns, "nft", "-f", "-"], input=rules,
                           capture_output=True, text=True)
        if p.returncode:
            raise RuntimeError(f"nft: exit {p.returncode}: {p.stderr.strip()}")


def marker_frame(tag):
    """A frame no protocol stack sends: a local experimental EtherType
    (0x88B5) from a locally administered MAC, carrying the tag."""
    body = b"otsec-rig:" + tag.encode()
    return bytes.fromhex("ffffffffffff" "020000000c11") + struct.pack("!H", 0x88B5) + body.ljust(46, b"\0")


def dhcp_discover(ns, ifname):
    """What a DHCP client left on the interface would send: one DISCOVER,
    through the host's own UDP stack. The negative control's stand-in for
    a client, since the runner need not have one installed."""
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s192s4s", 1, 1, 6, 0, 0x0C110C11, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4,
                      b"\0" * 4, bytes.fromhex("020000000c11"), b"", bytes([99, 130, 83, 99])) + bytes([53, 1, 1, 255])
    with in_ns(ns):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode())
        s.bind(("0.0.0.0", 68))
        s.sendto(pkt, ("255.255.255.255", 67))


def reach_neighbour(ns, addr="192.0.2.1"):
    """What any host with an address does: try to reach a neighbour, so
    the stack asks for it with ARP. One datagram to the discard port."""
    with in_ns(ns):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with s:
        s.sendto(b"otsec-rig", (addr, 9))


def classify(frame):
    """A name for a frame the monitoring interface sent, for the report."""
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == 0x0806:
        return "arp"
    if ethertype == 0x86DD:
        return {135: "ipv6-neighbour-solicitation", 133: "ipv6-router-solicitation",
                143: "ipv6-mld-report"}.get(_icmp6_type(frame), "ipv6")
    if ethertype == 0x0800 and frame[23] == 17 and struct.unpack("!HH", frame[34:38]) == (68, 67):
        return "dhcp"
    return f"ethertype-0x{ethertype:04x}"


def _icmp6_type(frame):
    nxt, off = frame[20], 54
    if nxt == 0 and len(frame) > off + 8:  # hop-by-hop options, as MLD carries
        nxt, off = frame[off], off + 8 + frame[off + 1] * 8
    return frame[off] if nxt == 58 and len(frame) > off else -1


def c11(rig, frames, start_sensor=None, stop_sensor=None, replay=None, settle_s=1.0):
    """One C-11 run (plan section 6): capture on tap0, bring both ends up,
    start the sensor, replay `frames` onto tap0, stop the sensor, and only
    then stop the capture. Returns what mon0 sent and what the replay sent.
    The verdict is the caller's: C-11 passes only on zero frames from mon0.
    """
    cap = Capture(rig.rig_ns, TAP).start()
    rig.up()
    handle = start_sensor() if start_sensor else None
    time.sleep(settle_s)  # what an interface sends on coming up, and a sensor on starting
    out = packet_socket(rig.rig_ns, TAP)
    log = replay(out, frames) if replay else [out.send(f.data) for f in frames]
    out.close()
    if stop_sensor:
        stop_sensor(handle)
    time.sleep(settle_s)
    cap.stop()
    return {"from_mon0": [f[3] for f in cap.arrived()], "replayed": [f[3] for f in cap.sent()], "log": log,
            "kinds": sorted({classify(f[3]) for f in cap.arrived()})}


def sha(data):
    return hashlib.sha256(data).hexdigest()
