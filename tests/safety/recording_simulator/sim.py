"""Recording device simulator: logs every byte a collector sends to a "device".

Purpose (V-S7, V-S10, V-S13): prove what a collector actually sent to a device
without trusting the collector's own transcript. Point the adapter under test
at this simulator instead of a device, then run check.py over the recording.

This is a verification oracle, not a device emulator. It answers every command
with a fixed placeholder and never imitates real device output, so nothing it
produces may be used as device evidence. It must not share code with any
module under test.

Transports:
  ssh   SSH server, password authentication, exec and interactive shell.
  tcp   Raw TCP line service. With --telnet, Telnet IAC negotiation is removed
        from the data stream and recorded separately. Use this for device
        families with no SSH (A2 found none documented for SEL relays).

In-band authentication (--inband-auth-command, --inband-password): devices such
as SEL relays authenticate inside the session (send ACC, answer "Password:").
The line after the auth command is recorded as an auth event (accepted or not,
and its length), never as a command line, and its bytes are never stored.

Profiles: the default responder answers every command with a placeholder.
--profile sel-751-doc answers from SEL-751 instruction manual examples and
documented behaviour (profile_sel751.py); its output is documentation, not
device capture.

Records, one JSON object per line:
  session_open / session_close   session id, peer address
  auth                           username or in-band, accepted; never the secret
  exec                           SSH exec command, raw bytes as base64 and latin-1 text
  line                           each received line: raw bytes, the terminator seen
                                 (CRLF, CR, LF, CRNUL, or none), and before_prompt,
                                 true when the line arrived before the simulator had
                                 answered the previous one and shown a prompt
  telnet                         Telnet IAC sequences, base64 (tcp --telnet only)
  device_effect                  a documented device state change the session caused
                                 (profile only), with its manual citation
  session_refused                connection beyond --max-sessions

Run: python sim.py --transport tcp --telnet --port 2323 --log rec.jsonl \
       --inband-auth-command ACC --inband-password <canary>
"""

import argparse
import asyncio
import base64
import itertools
import json
import time

import asyncssh

PLACEHOLDER = b"\r\n[recording simulator: placeholder output, not device data]"
IAC, SB, SE = 0xFF, 0xFA, 0xF0
WILL_WONT_DO_DONT = range(0xFB, 0xFF)


class Recorder:
    def __init__(self, path):
        self._f = open(path, "a", buffering=1)
        self._ids = itertools.count(1)

    def new_session(self):
        return next(self._ids)

    def write(self, event, **fields):
        fields.update(event=event, t=time.time())
        self._f.write(json.dumps(fields, sort_keys=True) + "\n")

    def close(self):
        self._f.close()


def _raw(data):
    return {"b64": base64.b64encode(data).decode(), "text": data.decode("latin-1")}


def split_lines(buf):
    """Split complete lines off buf. Returns ([(line, terminator)], rest).

    Terminators: CRLF, CR NUL (Telnet), CR, LF. A CR at the very end of buf is
    held back until the next byte shows whether LF or NUL follows.
    """
    lines, start, i = [], 0, 0
    while i < len(buf):
        b = buf[i]
        if b == 0x0D:
            if i + 1 == len(buf):
                break
            nxt = buf[i + 1]
            term = {0x0A: "CRLF", 0x00: "CRNUL"}.get(nxt, "CR")
            lines.append((buf[start:i], term))
            i += 2 if term != "CR" else 1
            start = i
            continue
        if b == 0x0A:
            lines.append((buf[start:i], "LF"))
            start = i + 1
        i += 1
    return lines, buf[start:]


class TelnetFilter:
    """Removes Telnet IAC sequences from a byte stream, keeping state across reads.

    Option negotiation is answered by refusing every option (WILL -> DONT,
    DO -> WONT), the minimal compliant behaviour, so clients fall back to
    plain NVT. Refusals are returned for the caller to send.
    """

    def __init__(self):
        self.state, self.seq = "data", b""

    def feed(self, data):
        """Returns (data bytes, IAC sequences seen, refusal bytes to send)."""
        out, seqs = bytearray(), []
        for b in data:
            if self.state == "data":
                if b == IAC:
                    self.state, self.seq = "iac", bytes([b])
                else:
                    out.append(b)
            elif self.state == "iac":
                if b == IAC:            # escaped 0xFF is data
                    out.append(b)
                    self.state = "data"
                    continue
                self.seq += bytes([b])
                if b in WILL_WONT_DO_DONT:
                    self.state = "opt"
                elif b == SB:
                    self.state = "sb"
                else:
                    seqs.append(self.seq)
                    self.state = "data"
            elif self.state == "opt":
                seqs.append(self.seq + bytes([b]))
                self.state = "data"
            elif self.state == "sb":
                self.seq += bytes([b])
                if b == IAC:
                    self.state = "sb_iac"
            elif self.state == "sb_iac":
                self.seq += bytes([b])
                if b == SE:
                    seqs.append(self.seq)
                    self.state = "data"
                else:
                    self.state = "sb"
        replies = b"".join(
            bytes([IAC, {0xFB: 0xFE, 0xFD: 0xFC}[q[1]], q[2]])
            for q in seqs if len(q) == 3 and q[1] in (0xFB, 0xFD))
        return bytes(out), seqs, replies


class Reply:
    """What a responder answers to one line.

    secret: the line was consumed as a password; the session records an auth
    event instead of the line. effects: device state changes the line caused,
    recorded as device_effect events (each a short text with its citation).
    """

    def __init__(self, out=b"", secret=False, accepted=None, effects=()):
        self.out, self.secret, self.accepted, self.effects = out, secret, accepted, list(effects)


class PlaceholderResponder:
    """Default responder: a fixed placeholder for every command, never device-like."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.awaiting = False

    def greeting(self):
        return self.cfg.prompt

    def handle(self, line):
        if self.awaiting:
            self.awaiting = False
            return Reply(self.cfg.prompt, secret=True,
                         accepted=line == self.cfg.inband_password)
        if self.cfg.inband_auth_command and line == self.cfg.inband_auth_command:
            self.awaiting = True
            return Reply(b"\r\nPassword: ")
        return Reply((PLACEHOLDER if line.strip() else b"") + self.cfg.prompt)

    def on_close(self):
        return []


class Session:
    """Line handling shared by all transports. `write` sends bytes to the client."""

    def __init__(self, recorder, session_id, write, cfg):
        self.rec, self.id, self._write, self.cfg = recorder, session_id, write, cfg
        self.responder = cfg.responder_factory(cfg)
        self.buf = b""
        self.ready = False
        self.queue = asyncio.Queue()
        self.worker = asyncio.create_task(self._work())

    def start(self):
        self._write(self.responder.greeting())
        self.ready = True

    def feed(self, data):
        lines, self.buf = split_lines(self.buf + data)
        for line, term in lines:
            before_prompt = not self.ready
            self.ready = False
            self.queue.put_nowait((line, term, before_prompt))

    def _effects(self, effects):
        for e in effects:
            self.rec.write("device_effect", session=self.id, effect=e)

    async def _work(self):
        while True:
            line, term, before_prompt = await self.queue.get()
            if self.cfg.response_delay:
                await asyncio.sleep(self.cfg.response_delay)
            reply = self.responder.handle(line)
            if reply.secret:
                self.rec.write("auth", session=self.id, inband=True,
                               accepted=reply.accepted, length=len(line),
                               before_prompt=before_prompt)
            else:
                self.rec.write("line", session=self.id, term=term,
                               before_prompt=before_prompt, **_raw(line))
            self._effects(reply.effects)
            self._write(reply.out)
            self.ready = self.queue.empty()
            self.queue.task_done()

    async def close(self):
        await self.queue.join()
        self.worker.cancel()
        if self.buf:
            # A CR held back by split_lines is a complete CR-terminated line.
            line, term = ((self.buf[:-1], "CR") if self.buf.endswith(b"\r")
                          else (self.buf, "none"))
            self.rec.write("line", session=self.id, term=term,
                           before_prompt=not self.ready, **_raw(line))
            self.buf = b""
        self._effects(self.responder.on_close())


class Config:
    def __init__(self, prompt=b"\r\nSIM> ", inband_auth_command=None,
                 inband_password=None, response_delay=0.0, telnet=False,
                 responder_factory=PlaceholderResponder, max_sessions=None):
        self.prompt = prompt
        self.inband_auth_command = inband_auth_command
        self.inband_password = inband_password
        self.response_delay = response_delay
        self.telnet = telnet
        self.responder_factory = responder_factory
        self.max_sessions = max_sessions


# --- SSH transport ------------------------------------------------------------

class _SSHServer(asyncssh.SSHServer):
    def __init__(self, recorder, user, password):
        self._rec, self._user, self._password = recorder, user, password
        self.session = None

    def connection_made(self, conn):
        self.session = self._rec.new_session()
        conn.set_extra_info(sim_session=self.session)
        self._rec.write("session_open", session=self.session,
                        peer=str(conn.get_extra_info("peername")))

    def connection_lost(self, exc):
        self._rec.write("session_close", session=self.session,
                        error=None if exc is None else str(exc))

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        ok = username == self._user and password == self._password
        self._rec.write("auth", session=self.session, inband=False,
                        username=username, accepted=ok)
        return ok


async def _ssh_process(process, recorder, cfg):
    sid = process.get_extra_info("sim_session")
    if process.command is not None:
        recorder.write("exec", session=sid, **_raw(process.command.encode("latin-1")))
        process.stdout.write(PLACEHOLDER + b"\r\n")
        process.exit(0)
        return
    session = Session(recorder, sid, process.stdout.write, cfg)
    session.start()
    try:
        while True:
            data = await process.stdin.read(4096)
            if not data:
                break
            session.feed(data)
    except asyncssh.BreakReceived:
        recorder.write("break", session=sid)
    await session.close()
    process.exit(0)


async def start_ssh(recorder, host, port, user, password, cfg=None, host_key=None):
    """Start the SSH transport. Returns the server; port 0 picks a free port."""
    cfg = cfg or Config()
    key = host_key or asyncssh.generate_private_key("ssh-ed25519")
    return await asyncssh.create_server(
        lambda: _SSHServer(recorder, user, password), host, port,
        server_host_keys=[key],
        process_factory=lambda p: _ssh_process(p, recorder, cfg),
        encoding=None, line_editor=False)


start = start_ssh  # name used by the original self-test


# --- Raw TCP / Telnet transport -----------------------------------------------

async def start_tcp(recorder, host, port, cfg=None):
    """Start the raw TCP (optionally Telnet) transport. Returns an asyncio server."""
    cfg = cfg or Config()
    active = set()

    async def handle(reader, writer):
        sid = recorder.new_session()
        peer = str(writer.get_extra_info("peername"))
        if cfg.max_sessions is not None and len(active) >= cfg.max_sessions:
            recorder.write("session_refused", session=sid, peer=peer,
                           limit=cfg.max_sessions)
            writer.close()
            return
        active.add(sid)
        recorder.write("session_open", session=sid, peer=peer)
        session = Session(recorder, sid, writer.write, cfg)
        telnet = TelnetFilter() if cfg.telnet else None
        session.start()
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                if telnet:
                    data, seqs, replies = telnet.feed(data)
                    for s in seqs:
                        recorder.write("telnet", session=sid,
                                       b64=base64.b64encode(s).decode())
                    if replies:
                        writer.write(replies)
                session.feed(data)
        except ConnectionError as exc:
            recorder.write("transport_error", session=sid, error=str(exc))
        await session.close()
        writer.close()
        active.discard(sid)
        recorder.write("session_close", session=sid, error=None)

    return await asyncio.start_server(handle, host, port)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--transport", choices=("ssh", "tcp"), default="ssh")
    ap.add_argument("--telnet", action="store_true", help="tcp only: strip and log IAC")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--log", required=True)
    ap.add_argument("--user", help="ssh only")
    ap.add_argument("--password", help="ssh only")
    ap.add_argument("--prompt", default="\r\nSIM> ")
    ap.add_argument("--inband-auth-command")
    ap.add_argument("--inband-password")
    ap.add_argument("--profile", choices=("placeholder", "sel-751-doc"), default="placeholder",
                    help="sel-751-doc answers from SEL-751 manual examples (profile_sel751.py)")
    ap.add_argument("--profile-password", help="sel-751-doc: Level 1 password; omit to model passwords disabled")
    ap.add_argument("--profile-fid", help="sel-751-doc: FID in the ID reply, line checksum recomputed")
    ap.add_argument("--profile-stx-etx", action="store_true",
                    help="sel-751-doc: frame messages in STX ... ETX (p. 7.28)")
    ap.add_argument("--profile-ser", choices=("example", "none", "grow", "hang", "malformed", "dst"),
                    default="example",
                    help="sel-751-doc: SER answers Figure 10.16, No Data Available, or Figure 10.16 "
                         "with SYNTHESIZED rows added at each read (needs --profile-ser-state); "
                         "SYNTHESIZED faults: hang stops after four rows, malformed damages one row; "
                         "SYNTHESIZED dst: rows in a fall-back hour under Time Source: External")
    ap.add_argument("--profile-ser-grow", type=int, default=4, help="sel-751-doc grow: rows added per SER read")
    ap.add_argument("--profile-ser-state", help="sel-751-doc grow: file holding the count of added rows")
    ap.add_argument("--profile-inherit", choices=("none", "level", "prompt"), default="none",
                    help="sel-751-doc: what a new connection inherits before TIDLE (see profile_sel751)")
    ap.add_argument("--profile-tidle", type=float, default=900.0, help="sel-751-doc: TIDLE in seconds")
    ap.add_argument("--max-sessions", type=int, help="tcp only: refuse connections beyond this count")
    ap.add_argument("--response-delay", type=float, default=0.0,
                    help="seconds before answering; lines sent meanwhile are before_prompt")
    args = ap.parse_args()
    if args.profile_ser == "grow" and not args.profile_ser_state:
        ap.error("--profile-ser grow needs --profile-ser-state")
    if args.transport == "ssh" and not (args.user and args.password):
        ap.error("--transport ssh needs --user and --password")
    cfg = Config(
        prompt=args.prompt.encode("latin-1"),
        inband_auth_command=(args.inband_auth_command or "").encode("latin-1") or None,
        inband_password=(args.inband_password or "").encode("latin-1") or None,
        response_delay=args.response_delay, telnet=args.telnet,
        max_sessions=args.max_sessions)
    if args.profile == "sel-751-doc":
        import profile_sel751
        relay = None
        if args.profile_inherit != "none":
            relay = profile_sel751.RelayState(inherit=args.profile_inherit, tidle=args.profile_tidle)
        cfg.responder_factory = profile_sel751.factory(
            password=(args.profile_password or "").encode("latin-1") or None,
            fid=args.profile_fid.encode("latin-1") if args.profile_fid else None,
            stx_etx=args.profile_stx_etx, ser=args.profile_ser, relay=relay,
            growth=profile_sel751.SerGrowth(args.profile_ser_state, args.profile_ser_grow)
            if args.profile_ser == "grow" else None)

    async def run():
        rec = Recorder(args.log)
        if args.transport == "ssh":
            server = await start_ssh(rec, args.host, args.port, args.user, args.password, cfg)
        else:
            server = await start_tcp(rec, args.host, args.port, cfg)
        # With --port 0 the OS picks the port; a harness reads it from this
        # first line on stdout.
        if hasattr(server, "get_port"):
            port = server.get_port()
        else:
            port = server.sockets[0].getsockname()[1]
        print(json.dumps({"event": "ready", "host": args.host, "port": port}), flush=True)
        await asyncio.Event().wait()

    asyncio.run(run())


if __name__ == "__main__":
    main()
