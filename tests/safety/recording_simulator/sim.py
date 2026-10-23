"""Recording device simulator: an SSH endpoint that logs every byte it receives.

Purpose (V-S7, V-S10, V-S13): prove what a collector actually sent to a device
without trusting the collector's own transcript. Point the adapter under test
at this simulator instead of a device, then run check.py over the recording.

This is a verification oracle, not a device emulator. It answers every command
with a fixed placeholder and never imitates real device output, so nothing it
produces may be used as device evidence. It must not share code with any
module under test.

Records, one JSON object per line:
  session_open / session_close   session id, peer address
  auth                           username and whether it was accepted (never the password)
  exec                           the exec command, raw bytes as base64 and latin-1 text
  chunk                          every raw read from an interactive shell, as base64
  line                           each shell line, split on CR, LF, or CRLF

Run: python sim.py --port 2222 --log rec.jsonl --user collector --password <canary>
"""

import argparse
import asyncio
import base64
import itertools
import json
import time

import asyncssh

PROMPT = b"\r\nSIM> "
PLACEHOLDER = b"\r\n[recording simulator: placeholder output, not device data]"


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
    """Split complete lines off buf on CR, LF, or CRLF. Returns (lines, rest)."""
    lines = []
    start = i = 0
    while i < len(buf):
        if buf[i] in b"\r\n":
            lines.append(buf[start:i])
            if buf[i:i + 2] == b"\r\n":
                i += 1
            start = i + 1
        i += 1
    return lines, buf[start:]


class _Server(asyncssh.SSHServer):
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
        self._rec.write("auth", session=self.session, username=username, accepted=ok)
        return ok


async def _handle(process, recorder):
    session = process.get_extra_info("sim_session")
    if process.command is not None:
        recorder.write("exec", session=session, **_raw(process.command.encode("latin-1")))
        process.stdout.write(PLACEHOLDER + b"\r\n")
        process.exit(0)
        return
    process.stdout.write(PROMPT)
    buf = b""
    try:
        while True:
            data = await process.stdin.read(4096)
            if not data:
                break
            recorder.write("chunk", session=session, b64=base64.b64encode(data).decode())
            lines, buf = split_lines(buf + data)
            for line in lines:
                recorder.write("line", session=session, **_raw(line))
                process.stdout.write((PLACEHOLDER if line.strip() else b"") + PROMPT)
    except asyncssh.BreakReceived:
        recorder.write("break", session=session)
    if buf:
        recorder.write("line", session=session, unterminated=True, **_raw(buf))
    process.exit(0)


async def start(recorder, host, port, user, password, host_key=None):
    """Start the simulator. Returns the asyncssh server; port 0 picks a free port."""
    key = host_key or asyncssh.generate_private_key("ssh-ed25519")
    return await asyncssh.create_server(
        lambda: _Server(recorder, user, password), host, port,
        server_host_keys=[key],
        process_factory=lambda p: _handle(p, recorder),
        encoding=None, line_editor=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--log", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    async def run():
        await start(Recorder(args.log), args.host, args.port, args.user, args.password)
        await asyncio.Event().wait()

    asyncio.run(run())


if __name__ == "__main__":
    main()
