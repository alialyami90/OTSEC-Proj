"""Send every hostile case over each standard Syslog transport to one stock
rsyslog receiver and record what the receiver parsed. The owner asked that
the forwarder support every standard transport and assume a generic
Syslog-compliant collector, so each (transport, format) pair is checked for
forgery, message splitting, and lossless recovery of the device bytes.

Transports: UDP (RFC 5426) at 2048 and 480 octets, TCP with octet counting
and with LF framing (RFC 6587), TLS (RFC 5425), RELP (plain). Formats: the
RFC 5424 profile, and an RFC 3164-style rendering for legacy collectors.
Ground truth is the receiver's own parse (rsyslog properties).

Usage: python3 -I run_transports.py <work-dir> <results.md>
Throwaway experiment, not product code.
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "relp-ack"))
from encode import legacy_3164_message, lf_frame, octet_frame, profile_message  # noqa: E402
from hostile_cases import CASES  # noqa: E402
from relp_ack_test import AckParser, frame  # noqa: E402
from run_test import recovered, sd_param  # noqa: E402

UDP, TCP, TLS, RELP = 10515, 10514, 10516, 10517

CONF = """
global(workDirectory="{work}" maxMessageSize="64k"
       defaultNetstreamDriverCAFile="{d}/ca.pem"
       defaultNetstreamDriverCertFile="{d}/server.pem"
       defaultNetstreamDriverKeyFile="{d}/server.key")
module(load="imudp")
module(load="imtcp")
module(load="imrelp")
template(name="j" type="list" option.jsonf="on") {{
  property(outname="input" name="inputname" format="jsonf")
  property(outname="host" name="hostname" format="jsonf")
  property(outname="msgid" name="msgid" format="jsonf")
  property(outname="sd" name="structured-data" format="jsonf")
  property(outname="msg" name="msg" format="jsonf")
}}
ruleset(name="r") {{ action(type="omfile" file="{out}" template="j") }}
input(type="imudp" port="{udp}" address="127.0.0.1" ruleset="r")
input(type="imtcp" port="{tcp}" address="127.0.0.1" ruleset="r")
input(type="imtcp" port="{tls}" address="127.0.0.1" ruleset="r"
      streamDriver.name="gtls" streamDriver.mode="1" streamDriver.authMode="anon")
input(type="imrelp" port="{relp}" address="127.0.0.1" ruleset="r")
"""


def make_certs(d):
    """Self-signed CA and a localhost server certificate, for this run only."""
    run = lambda *a: subprocess.run(a, check=True, capture_output=True)  # noqa: E731
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=otsec-exp-ca",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-keyout", f"{d}/ca.key", "-out", f"{d}/ca.pem")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
        "-keyout", f"{d}/server.key", "-out", f"{d}/server.csr")
    with open(f"{d}/ext", "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    run("openssl", "x509", "-req", "-in", f"{d}/server.csr", "-CA", f"{d}/ca.pem", "-CAkey", f"{d}/ca.key",
        "-CAcreateserial", "-days", "1", "-extfile", f"{d}/ext", "-out", f"{d}/server.pem")


def lines(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def wait_new(out, before):
    deadline, seen = time.time() + 3, -1
    while time.time() < deadline:
        n = len(lines(out))
        if n == seen and n > before:
            break
        seen = n
        time.sleep(0.3)
    return lines(out)[before:]


def send_udp(payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(payload, ("127.0.0.1", UDP))


def send_tcp(payload):
    with socket.create_connection(("127.0.0.1", TCP)) as s:
        s.sendall(payload)


def send_tls(payload, cafile):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", TLS)) as raw, ctx.wrap_socket(raw, server_hostname="localhost") as s:
        s.sendall(payload)


def send_relp(msg):
    """Open, one syslog frame, wait for its 200 OK, close. Returns acked."""
    with socket.create_connection(("127.0.0.1", RELP)) as s:
        s.settimeout(2)
        outstanding = {1}
        p = AckParser(outstanding)
        s.sendall(frame(1, "open", b"relp_version=0\nrelp_software=otsec-exp\ncommands=syslog"))
        while 1 not in p.acked:
            p.feed(s.recv(65536))
        outstanding.add(2)
        s.sendall(frame(2, "syslog", msg))
        while 2 not in p.acked:
            p.feed(s.recv(65536))
        outstanding.add(3)
        s.sendall(frame(3, "close", b""))
        return 2 in p.acked and p.violations == 0


# (label, format, max octets, sender)
PAIRS = [
    ("udp", "rfc5424", 2048), ("udp-480", "rfc5424", 480), ("udp", "rfc3164", 1024),
    ("tcp-octet", "rfc5424", 2048), ("tcp-lf", "rfc5424", 2048), ("tcp-lf", "rfc3164", 1024),
    ("tls-octet", "rfc5424", 2048), ("relp", "rfc5424", 2048),
]


def main(work, results):
    os.makedirs(work, exist_ok=True)
    make_certs(work)
    out = os.path.join(work, "received.jsonl")
    conf = os.path.join(work, "rsyslog.conf")
    with open(conf, "w") as f:
        f.write(CONF.format(work=work, d=work, out=out, udp=UDP, tcp=TCP, tls=TLS, relp=RELP))
    if os.path.exists(out):
        os.remove(out)
    proc = subprocess.Popen(["rsyslogd", "-n", "-f", conf, "-i", os.path.join(work, "pid")],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(2)
    rows = []
    try:
        for label, fmt, limit in PAIRS:
            for i, (name, raw) in enumerate(CASES.items()):
                eid = f"0192b7e0-0000-7000-8000-{len(rows):012d}"
                event = {"pri": 134, "received_at": "2026-10-23T15:00:00.123456Z",
                         "collector": "site-a-node1", "msgid": f"C{i:02d}", "event_id": eid,
                         "origin": "device", "asset_id": "asset:sel751:feeder1",
                         "device_ts_native": "02/28/2007 16:34:28", "precision": "1s",
                         "offset": "unknown", "summary": "SER row", "device_bytes": raw}
                msg = (profile_message(event, limit) if fmt == "rfc5424"
                       else legacy_3164_message(event, limit))
                before = len(lines(out))
                acked = "n/a"
                if label.startswith("udp"):
                    send_udp(msg)
                elif label == "tcp-octet":
                    send_tcp(octet_frame(msg))
                elif label == "tcp-lf":
                    send_tcp(lf_frame(msg))
                elif label == "tls-octet":
                    send_tls(octet_frame(msg), os.path.join(work, "ca.pem"))
                else:
                    acked = "yes" if send_relp(msg) else "NO"
                got = wait_new(out, before)
                forged = sum(1 for g in got if g["host"] == "forged-host" or g["msgid"] == "FORGED"
                             or "FORGED" in g["msg"].split("[")[0])
                # Find our own message by event id, wherever the collector put the SD.
                own = [g for g in got if eid in g["sd"] or eid in g["msg"]]
                where = "-"
                lossless = "not received"
                if own:
                    carrier = own[0]["sd"] if eid in own[0]["sd"] else own[0]["msg"]
                    where = "SD" if carrier is own[0]["sd"] else "MSG"
                    rec = recovered(carrier)
                    origin = sd_param(carrier, "origin")
                    lossless = ("reference-only" if rec is None and "dtext_omitted" in carrier
                                else "yes" if rec == raw else "NO")
                    if origin != "device":
                        lossless += f" (origin={origin})"
                rows.append((label, fmt, name, len(msg), len(got), forged, where, lossless, acked))
    finally:
        proc.terminate()
        proc.wait()
    version = subprocess.run(["rsyslogd", "-v"], capture_output=True, text=True).stdout.splitlines()[0]
    with open(results, "w") as f:
        f.write("# Syslog transports: hostile cases over every standard transport\n\n")
        f.write("Generated by `run_transports.py` against " + version.split(" compiled")[0].replace("  ", " ") +
                " (imudp, imtcp, imtcp with gtls, imrelp; one receiver). Do not edit by hand.\n\n")
        f.write("| Transport | Format | Case | Message octets | Messages the receiver parsed | Forged | "
                "SD found in | Device bytes recovered | RELP ack |\n")
        f.write("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
        for r in rows:
            f.write("| " + " | ".join(str(x) for x in r) + " |\n")
        bad = [r for r in rows if r[4] != 1 or r[5] != 0 or not (r[7] in ("yes", "reference-only"))]
        f.write(f"\nRows with other than exactly one parsed message, any forgery, or a lossy recovery: {len(bad)}\n")
    print(open(results).read())


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
