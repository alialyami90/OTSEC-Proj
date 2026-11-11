"""Replay one recorded TCP session's payloads over loopback (run with python -I).

  replay.py FILE PORT   -> JSON: segments and bytes sent each way

FILE is a classic pcap (Ethernet) of one TCP session in which one side uses
PORT. Both ends run in this process, on 127.0.0.1 only: a listener on PORT
plays the side that used PORT, a client plays the other, and each payload is
sent in capture order and read in full by the other end before the next. It
reproduces the payload bytes, not the original headers, timing or addresses.
Nothing leaves the host; this is traffic for pktmon to see (E-D4-01, part 2).
"""
import json
import socket
import struct
import sys


def payloads(path, port):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}.get(magic)
    if endian is None or struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise SystemExit("not a classic Ethernet pcap")
    out, seen, off = [], set(), 24
    while off + 16 <= len(data):
        caplen = struct.unpack_from(endian + "I", data, off + 8)[0]
        fr, off = data[off + 16:off + 16 + caplen], off + 16 + caplen
        if len(fr) < 34 or fr[12:14] != b"\x08\x00" or fr[23] != 6:
            continue
        ip = 14
        tcp = ip + (fr[ip] & 0x0F) * 4
        total = struct.unpack_from(">H", fr, ip + 2)[0]
        sport, dport, seq = struct.unpack_from(">HHI", fr, tcp)
        body = fr[tcp + (fr[tcp + 12] >> 4) * 4:ip + total]
        from_port_side = sport == port
        if not body or (sport != port and dport != port):
            continue
        if (from_port_side, seq) in seen:  # a retransmission
            continue
        seen.add((from_port_side, seq))
        out.append((from_port_side, body))
    return out


def recv_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SystemExit("peer closed early")
        buf += chunk
    return buf


def main():
    path, port = sys.argv[1], int(sys.argv[2])
    segs = payloads(path, port)
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.bind(("127.0.0.1", port))
    lst.listen(1)
    cli = socket.create_connection(("127.0.0.1", port), timeout=10)
    srv, _ = lst.accept()
    srv.settimeout(10)
    sent = {"from_port_side": [0, 0], "to_port_side": [0, 0]}
    for from_port_side, body in segs:
        a, b = (srv, cli) if from_port_side else (cli, srv)
        a.sendall(body)
        if recv_exactly(b, len(body)) != body:
            raise SystemExit("payload changed in transit")
        k = "from_port_side" if from_port_side else "to_port_side"
        sent[k][0] += 1
        sent[k][1] += len(body)
    for s in (cli, srv, lst):
        s.close()
    print(json.dumps({"port": port, "segments_and_bytes": sent}, sort_keys=True))


if __name__ == "__main__":
    main()
