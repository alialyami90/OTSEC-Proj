#!/usr/bin/env python3
"""Connect to host:port, optionally send one line, print the reply or the failure.

Usage: probe.py <host> <port> [line]
Prints one of: REPLY <text> | NOREPLY (connection closed without data) |
CONNFAIL <error> | TIMEOUT. Exit status is always 0; the caller interprets output.
"""
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
line = sys.argv[3] if len(sys.argv) > 3 else None
try:
    with socket.create_connection((host, port), timeout=5) as s:
        s.settimeout(5)
        if line is not None:
            s.sendall((line + "\n").encode())
        data = s.recv(4096)
        print("REPLY " + data.decode().strip() if data else "NOREPLY")
except socket.timeout:
    print("TIMEOUT")
except OSError as exc:
    print("CONNFAIL %s" % exc)
