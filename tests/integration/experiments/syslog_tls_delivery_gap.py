"""Phase 0 experiment E-01: does a successful TLS syslog write imply delivery?

Question (challenges R4.6, R4.7, V-S6): when a forwarder sends RFC 5425
(syslog over TLS, octet-counted framing) and every write call returns without
error, has the collector received every message?

Method: a local TLS collector reads K frames, then stops reading while the
forwarder writes M more frames (all writes return successfully because they
fit in kernel and TLS buffers), then the collector aborts the connection with
a TCP RST, as a crashed or restarted collector would. We compare what the
forwarder believes it sent with what the collector actually received.

Classification: simulated (loopback, Python ssl module, no real collector).
Requires: Python 3.9+ standard library and the openssl CLI (for a throwaway
self-signed certificate). Writes nothing outside a temporary directory.

Run: python3 -I tests/integration/experiments/syslog_tls_delivery_gap.py
"""

import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading

K_READ = 50      # frames the collector reads before it stalls
M_STALLED = 100  # frames written while the collector is stalled
TRIALS = 5


def frame(seq):
    # RFC 5424 message, RFC 5425 octet-counting frame: "MSG-LEN SP SYSLOG-MSG".
    msg = (
        f"<134>1 2026-10-23T00:00:00.000000Z lab-node otsec - SER - "
        f"seq={seq:06d}"
    ).encode()
    return str(len(msg)).encode() + b" " + msg


FRAME_LEN = len(frame(0))  # constant because seq is zero-padded


def make_cert(tmp):
    cert, key = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
        check=True, capture_output=True,
    )
    return cert, key


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def trial(cert, key):
    srv_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    srv_ctx.load_cert_chain(cert, key)
    cli_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cli_ctx.load_verify_locations(cert)

    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    stalled = threading.Event()
    writes_done = threading.Event()
    result = {}

    def collector():
        raw, _ = listener.accept()
        conn = srv_ctx.wrap_socket(raw, server_side=True)
        data = recv_exact(conn, K_READ * FRAME_LEN)
        result["collector_received"] = len(data) // FRAME_LEN
        stalled.set()
        writes_done.wait(10)
        # Abort as a crashed collector would: RST, unread data discarded.
        # wrap_socket() detached `raw`, so act on the TLS socket's descriptor.
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack("ii", 1, 0))
        conn.close()
        listener.close()

    t = threading.Thread(target=collector)
    t.start()

    sock = cli_ctx.wrap_socket(
        socket.create_connection(("127.0.0.1", port)),
        server_hostname="localhost")
    acknowledged = 0  # writes that returned without raising
    for seq in range(K_READ):
        sock.sendall(frame(seq))
        acknowledged += 1
    stalled.wait(10)
    for seq in range(K_READ, K_READ + M_STALLED):
        sock.sendall(frame(seq))
        acknowledged += 1
    writes_done.set()
    t.join(10)

    # The forwarder keeps writing until the transport finally reports failure.
    first_error_after = None
    for extra in range(1000):
        try:
            sock.sendall(frame(K_READ + M_STALLED + extra))
            acknowledged += 1
        except OSError as exc:
            first_error_after = type(exc).__name__
            break
    sock.close()

    result["forwarder_write_ok"] = acknowledged
    result["lost_silently"] = acknowledged - result["collector_received"]
    result["first_error"] = first_error_after
    return result


def main():
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = make_cert(tmp)
        trials = [trial(cert, key) for _ in range(TRIALS)]
    report = {
        "experiment": "E-01 syslog TLS delivery gap",
        "classification": "simulated",
        "python": sys.version.split()[0],
        "openssl": ssl.OPENSSL_VERSION,
        "frame_bytes": FRAME_LEN,
        "k_read": K_READ,
        "m_written_while_stalled": M_STALLED,
        "trials": trials,
        "claim_disproved": all(r["lost_silently"] > 0 for r in trials),
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
