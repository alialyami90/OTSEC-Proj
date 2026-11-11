"""A stand-in for the sensor, for the rig's self-tests only (D6, P4-4-R1).

It is not a sensor and decodes nothing. It opens a packet socket on the
monitoring interface, as a capture process must, and then behaves in one of
the ways the rig has to tell apart:

  drop   gives up every capability after the socket is open (no new
         privileges, then an unprivileged user), and goes on receiving;
  keep   stays root, capabilities and all: the control the check must flag.

With a fourth argument, `pre-bypass`, it sets PACKET_QDISC_BYPASS on the
socket before it drops anything.

After "ready" on stdout it counts the frames it receives and obeys one
command a line on stdin, answering each with one line, so the rig can
measure what such a process can still do with the socket it already holds
(D3 on #626):

  send TAG   send the rig's marker frame for TAG on the open socket;
             answers "accepted", or the errno's name if the kernel refuses
  bypass     set PACKET_QDISC_BYPASS on the open socket; answers the same

When stdin closes it prints "frames <n>" and "reopen <ok|denied>": whether
it could still open a second packet socket, which a process without
CAP_NET_RAW cannot.

Usage (root): python standin_sensor.py NAMESPACE INTERFACE drop|keep [pre-bypass]
"""

import ctypes
import errno
import os
import select
import socket
import sys

import rig_netns

PR_SET_NO_NEW_PRIVS = 38
NOBODY = 65534


def attempt(call):
    try:
        call()
        return "accepted"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))


def main(ns, ifname, mode, pre=""):
    fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    os.setns(fd, os.CLONE_NEWNET)
    os.close(fd)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(rig_netns.ETH_P_ALL))
    s.bind((ifname, 0))

    def bypass():
        s.setsockopt(rig_netns.SOL_PACKET, rig_netns.PACKET_QDISC_BYPASS, 1)

    if pre == "pre-bypass":
        bypass()
    if mode == "drop":
        if ctypes.CDLL(None, use_errno=True).prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0):
            raise OSError(ctypes.get_errno(), "prctl(PR_SET_NO_NEW_PRIVS)")
        os.setgroups([])
        os.setgid(NOBODY)
        os.setuid(NOBODY)  # leaving uid 0 clears the permitted and effective sets
    print("ready", flush=True)
    n = 0
    while True:
        r, _, _ = select.select([s, sys.stdin], [], [])
        if s in r:
            _, addr = s.recvfrom(65535)
            n += addr[2] != rig_netns.PACKET_OUTGOING  # its own sends come back to it; they are not received frames
        if sys.stdin in r:
            line = sys.stdin.readline().split()
            if not line:
                break
            if line[0] == "send":
                print(attempt(lambda: s.send(rig_netns.marker_frame(line[1]))), flush=True)
            elif line[0] == "bypass":
                print(attempt(bypass), flush=True)
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(rig_netns.ETH_P_ALL)).close()
        again = "ok"
    except PermissionError:
        again = "denied"
    print(f"frames {n}\nreopen {again}", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:5])
