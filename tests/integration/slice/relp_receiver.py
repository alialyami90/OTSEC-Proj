"""Upstream Syslog collector for the slice: a RELP receiver over TLS (A6).

Purpose (P2-A6, D2-3): on Windows, where rsyslog does not run, the slice's
forwarder is tested against this receiver. On Linux the same suite also runs
against rsyslog. It is a verification oracle, not a product component: it
must not share code with the forwarder under test, and it uses the standard
library only.

What it does, per RFC 5424 messages carried in RELP (librelp's
doc/relp.html; the frame grammar is C6 relp.go's, read from the other side):
  - answers "open" with "200 OK" and the offers relp_version=0 and
    commands=syslog;
  - for each "syslog" frame, appends the message to the log, flushes and
    fsyncs it, and only then answers "200 OK" (a durable acknowledgement);
  - answers "close" with an empty "rsp" and closes the connection;
  - closes with "serverclose" on any frame that breaks the grammar, or the
    session rules C6 relp.go writes by: the first frame is "open", and only
    the first; the client offers commands=syslog; TXNRs run from 1 and
    strictly increase; no number has a leading zero; a syslog message is at
    most 65535 octets (C6 MaxMaxOctets). The oracle is stricter than the
    forwarder it tests, never looser.

Peer check (C6 0.2, D2-9): with --permitted-peer NAME the client certificate
must chain to --ca and carry NAME exactly, read the way librelp's
tls.authmode="name" reads it: the SAN dNSNames when the certificate has any,
otherwise the subject CN. No wildcards. A client that fails is closed before
any frame is read and logged as "peer_refused". There is no CA-only mode:
--require-client-cert without --permitted-peer is refused at start, because
that is imrelp's "certvalid", which C6 0.2 does not commission.

Fault injection, counted over the process lifetime, for the failure tests
(V-S6): --close-after N drops the connection when the Nth syslog frame
arrives, before writing or acknowledging it; --reject-after N answers the Nth
with "500"; --serverclose-after N sends "serverclose" instead of answering the
Nth. A frame that is not acknowledged is logged as "unacked" and must be sent
again by the forwarder.

Log records, one JSON object per line:
  ready          host, port (also printed to stdout, so a harness can read the
                 port when --port 0)
  session_open   session, peer, tls (protocol and the client certificate's
                 subject and SAN dNSNames, when one was presented)
  peer_refused   session, names (the names the peer check read), want
  open           session, txnr, offers (the client's open data)
  syslog         session, txnr, b64, text (latin-1), octets: the message as
                 received, written durably before the acknowledgement
  unacked        session, txnr, octets, reason: a frame the receiver chose not
                 to acknowledge
  frame_error    session, error
  session_close  session

Run: python relp_receiver.py --port 0 --log recv.jsonl \\
       --cert server.pem --key server.key --ca ca.pem --require-client-cert \\
       --permitted-peer a6-slice-node
"""

import argparse
import asyncio
import base64
import itertools
import json
import os
import ssl
import time

MAX_DATALEN = 128 * 1024  # librelp's default maximum frame size
MAX_SYSLOG_OCTETS = 65535  # C6 MaxMaxOctets: no forwarder sends more
MAX_TXNR = 999999999


class FrameError(Exception):
    pass


async def read_frame(reader):
    """Read one RELP frame: TXNR SP COMMAND SP DATALEN [SP DATA] LF.
    Returns (txnr, command, data), or None at a clean end of stream."""

    async def token(limit):
        out = b""
        while True:
            c = await reader.read(1)
            if not c:
                if out == b"":
                    return None
                raise FrameError("connection closed inside a frame header")
            if c == b" ":
                return out
            if c == b"\n" and out.isdigit():
                # DATALEN 0 may be followed directly by LF.
                return out + b"\n"
            out += c
            if len(out) > limit:
                raise FrameError("frame header field too long")

    txnr = await token(9)
    if txnr is None:
        return None
    if not txnr.isdigit() or (len(txnr) > 1 and txnr.startswith(b"0")):
        raise FrameError(f"bad TXNR {txnr!r}")
    command = await token(32)
    if command is None or not command.isalpha():
        raise FrameError(f"bad command {command!r}")
    datalen = await token(9)
    if datalen is None:
        raise FrameError("missing DATALEN")
    if datalen.endswith(b"\n"):
        if datalen[:-1] != b"0":
            raise FrameError("DATALEN without data")
        return int(txnr), command.decode(), b""
    if not datalen.isdigit() or (len(datalen) > 1 and datalen.startswith(b"0")):
        raise FrameError(f"bad DATALEN {datalen!r}")
    n = int(datalen)
    if n > MAX_DATALEN:
        raise FrameError(f"DATALEN {n} over {MAX_DATALEN}")
    if n == 0:
        # "0 " then LF is not in the grammar; the LF must follow DATALEN.
        raise FrameError("DATALEN 0 followed by SP")
    data = await reader.readexactly(n)
    trailer = await reader.readexactly(1)
    if trailer != b"\n":
        raise FrameError("frame not terminated by LF")
    return int(txnr), command.decode(), data


def rsp(txnr, status=b"200 OK", data=b""):
    body = status + (b"\n" + data if data else b"")
    return b"%d rsp %d %s\n" % (txnr, len(body), body)


class Receiver:
    def __init__(self, log_path, close_after=None, reject_after=None, serverclose_after=None, permitted_peer=None):
        self.permitted_peer = permitted_peer
        self._log = open(log_path, "a", buffering=1, encoding="utf-8")
        self._ids = itertools.count(1)
        self._frames = 0
        self.close_after, self.reject_after = close_after, reject_after
        self.serverclose_after = serverclose_after

    def write(self, event, durable=False, **fields):
        fields.update(event=event, t=time.time())
        self._log.write(json.dumps(fields, sort_keys=True) + "\n")
        if durable:
            self._log.flush()
            os.fsync(self._log.fileno())

    async def handle(self, reader, writer):
        sid = next(self._ids)
        info = {"peer": str(writer.get_extra_info("peername"))}
        sslobj = writer.get_extra_info("ssl_object")
        cert = None
        if sslobj is not None:
            cert = sslobj.getpeercert()
            info["tls"] = {"version": sslobj.version(),
                           "client_subject": dict(x[0] for x in cert.get("subject", ())) if cert else None,
                           "client_san_dns": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"] if cert else None}
        self.write("session_open", session=sid, **info)
        if self.permitted_peer is not None:
            names = peer_names(cert)
            if self.permitted_peer not in names:
                self.write("peer_refused", durable=True, session=sid, names=names, want=self.permitted_peer)
                writer.close()
                self.write("session_close", durable=True, session=sid)
                return
        opened = False
        last_txnr = 0
        try:
            while True:
                frame = await read_frame(reader)
                if frame is None:
                    break
                txnr, command, data = frame
                if not 1 <= txnr <= MAX_TXNR or txnr <= last_txnr:
                    raise FrameError(f"TXNR {txnr} after {last_txnr}: client TXNRs start at 1 and strictly increase")
                last_txnr = txnr
                if not opened and command != "open":
                    raise FrameError(f"{command} before open")
                if command == "open":
                    if opened:
                        raise FrameError("second open in one session")
                    if not offers_syslog(data):
                        raise FrameError("open does not offer commands=syslog")
                    opened = True
                    self.write("open", session=sid, txnr=txnr, offers=data.decode("latin-1"))
                    writer.write(rsp(txnr, data=b"relp_version=0\nrelp_software=a6-relp-receiver\ncommands=syslog"))
                elif command == "syslog":
                    if len(data) > MAX_SYSLOG_OCTETS:
                        raise FrameError(f"syslog message of {len(data)} octets, over {MAX_SYSLOG_OCTETS}")
                    self._frames += 1
                    n = self._frames
                    if n == self.close_after:
                        self.write("unacked", durable=True, session=sid, txnr=txnr, octets=len(data),
                                   reason="close-after")
                        break
                    if n == self.serverclose_after:
                        self.write("unacked", durable=True, session=sid, txnr=txnr, octets=len(data),
                                   reason="serverclose-after")
                        writer.write(b"0 serverclose 0\n")
                        break
                    if n == self.reject_after:
                        self.write("unacked", durable=True, session=sid, txnr=txnr, octets=len(data),
                                   reason="reject-after")
                        writer.write(rsp(txnr, status=b"500 rejected by test"))
                        await writer.drain()
                        continue
                    self.write("syslog", durable=True, session=sid, txnr=txnr, octets=len(data),
                               b64=base64.b64encode(data).decode(), text=data.decode("latin-1"))
                    writer.write(rsp(txnr))
                elif command == "close":
                    writer.write(b"%d rsp 0\n" % txnr)
                    break
                else:
                    raise FrameError(f"command {command!r} not offered")
                await writer.drain()
        except FrameError as exc:
            self.write("frame_error", durable=True, session=sid, error=str(exc))
            try:
                writer.write(b"0 serverclose 0\n")
            except Exception:
                pass
        except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError) as exc:
            self.write("frame_error", durable=True, session=sid, error=f"{type(exc).__name__}: {exc}")
        finally:
            try:
                await writer.drain()
            except Exception:
                pass
            writer.close()
            self.write("session_close", durable=True, session=sid)


def peer_names(cert):
    """The names librelp's name mode checks: the SAN dNSNames if the
    certificate has any, otherwise the subject CN. None or {} gives []."""
    if not cert:
        return []
    san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    if san:
        return san
    return [v for rdn in cert.get("subject", ()) for k, v in rdn if k == "commonName"]


def offers_syslog(data):
    for line in data.split(b"\n"):
        if line.startswith(b"commands="):
            return b"syslog" in line[len(b"commands="):].split(b",")
    return False


def tls_context(cert, key, ca=None, require_client_cert=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    if ca:
        ctx.load_verify_locations(ca)
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
    return ctx


async def serve(args):
    recv = Receiver(args.log, args.close_after, args.reject_after, args.serverclose_after, args.permitted_peer)
    ctx = None
    if args.cert:
        ctx = tls_context(args.cert, args.key, args.ca, args.require_client_cert)
    server = await asyncio.start_server(recv.handle, args.host, args.port, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    recv.write("ready", durable=True, host=args.host, port=port, tls=ctx is not None)
    print(json.dumps({"event": "ready", "host": args.host, "port": port}), flush=True)
    async with server:
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--log", required=True)
    ap.add_argument("--cert", help="server certificate (PEM); omit for plain RELP")
    ap.add_argument("--key", help="server key (PEM)")
    ap.add_argument("--ca", help="CA that signs client certificates")
    ap.add_argument("--require-client-cert", action="store_true")
    ap.add_argument("--permitted-peer", help="the one client certificate name accepted (SAN dNSName, or CN without SAN)")
    ap.add_argument("--close-after", type=int)
    ap.add_argument("--reject-after", type=int)
    ap.add_argument("--serverclose-after", type=int)
    args = ap.parse_args()
    if bool(args.cert) != bool(args.key):
        ap.error("--cert and --key go together")
    if args.require_client_cert != bool(args.permitted_peer):
        ap.error("--require-client-cert needs --permitted-peer and the reverse: a CA-only check is certvalid (D2-9)")
    if args.permitted_peer and not args.ca:
        ap.error("--permitted-peer needs --ca")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
