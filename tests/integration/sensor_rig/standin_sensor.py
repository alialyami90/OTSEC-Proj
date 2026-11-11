"""A stand-in for the sensor, for the rig's self-tests only (D6, P4-4-R1).

It is not a sensor and decodes nothing. It opens a packet socket on the
monitoring interface, as a capture process must, and then behaves in one of
the ways the rig has to tell apart:

  drop   gives up every capability after the socket is open (no new
         privileges, then an unprivileged user), and goes on receiving;
  keep   stays root, capabilities and all: the control the check must flag.

After "ready" on stdout it counts frames until stdin closes, then prints
"frames <n>" and "reopen <ok|denied>": whether it could still open a second
packet socket, which a process without CAP_NET_RAW cannot.

Usage (root): python standin_sensor.py NAMESPACE INTERFACE drop|keep
"""

import ctypes
import os
import select
import socket
import sys

PR_SET_NO_NEW_PRIVS = 38
NOBODY = 65534


def main(ns, ifname, mode):
    fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    os.setns(fd, os.CLONE_NEWNET)
    os.close(fd)
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((ifname, 0))
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
            s.recv(65535)
            n += 1
        if sys.stdin in r and not sys.stdin.readline():
            break
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)).close()
        again = "ok"
    except PermissionError:
        again = "denied"
    print(f"frames {n}\nreopen {again}", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:4])
