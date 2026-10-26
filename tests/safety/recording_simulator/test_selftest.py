"""Self-test: the recording simulator and checker catch what they claim to catch.

Uses selftest-register.json, a synthetic register with neutral command names.
It is not a device command register and says nothing about any real device.
Two scenarios: SSH transport, and raw TCP with Telnet negotiation and an
in-band password exchange (the shape of SEL ASCII sessions, with neutral names).

Run from the repository root:
  python -m unittest tests/safety/recording_simulator/test_selftest.py
"""

import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest

import asyncssh

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check  # noqa: E402
import sim  # noqa: E402

USER, PASSWORD = "collector", "canary-7f3e"


async def _shell(conn, payloads):
    proc = await conn.create_process(encoding=None)
    for p in payloads:
        proc.stdin.write(p)
        await asyncio.sleep(0.05)
    proc.stdin.write_eof()
    await proc.wait()


async def _scenario(log_path):
    recorder = sim.Recorder(log_path)
    server = await sim.start(recorder, "127.0.0.1", 0, USER, PASSWORD)
    port = server.sockets[0].getsockname()[1]
    opts = dict(host="127.0.0.1", port=port, username=USER,
                known_hosts=None, client_keys=None)

    # A failed login, as a misconfigured collector would produce.
    try:
        async with asyncssh.connect(password="wrong", **opts):
            pass
    except asyncssh.PermissionDenied:
        pass

    # Two sessions held open at once: peak concurrency must read 2.
    async with asyncssh.connect(password=PASSWORD, **opts) as a, \
            asyncssh.connect(password=PASSWORD, **opts) as b:
        await a.run("SHOW-ID")
        await _shell(b, [
            b"SHOW-EVENTS 10\r\n",
            b"\r\n",                           # bare Enter: allowed
            b"SHOW-EVENTS CLEAR\r\n",          # parameter makes it state-changing
            b"SHOW-ID\nUNLISTED-CMD\r\n",      # embedded newline smuggles a 2nd line
            b"SHOW-EVENTS \x1b[2J\r\n",        # escape sequence in a parameter
            b"SHOW-EV",                        # split across reads ...
            b"ENTS 5\r",                       # ... and CR-only terminator
        ])
    server.close()
    await server.wait_closed()
    recorder.close()


class RecordingSimulatorSelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        log = os.path.join(cls.tmp.name, "rec.jsonl")
        asyncio.run(_scenario(log))
        with open(log) as f:
            cls.events = [json.loads(line) for line in f]
        register = check.load_register(os.path.join(HERE, "selftest-register.json"))
        cls.report = check.check(cls.events, register)
        cls.by_text = {c["text"]: c["verdict"] for c in cls.report["violations"]}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_allowed_commands_are_not_violations(self):
        self.assertNotIn("SHOW-ID", self.by_text)
        self.assertNotIn("SHOW-EVENTS 10", self.by_text)

    def test_line_split_across_reads_is_reassembled(self):
        lines = [e["text"] for e in self.events if e["event"] == "line"]
        self.assertIn("SHOW-EVENTS 5", lines)

    def test_state_changing_parameter_is_caught(self):
        self.assertEqual(self.by_text.get("SHOW-EVENTS CLEAR"), "state-changing")

    def test_smuggled_line_is_caught(self):
        self.assertEqual(self.by_text.get("UNLISTED-CMD"), "unregistered")

    def test_control_bytes_are_caught(self):
        self.assertEqual(self.by_text.get("SHOW-EVENTS \x1b[2J"), "non-printable")

    def test_exactly_the_expected_violations(self):
        self.assertEqual(len(self.report["violations"]), 3)
        self.assertFalse(self.report["pass"])

    def test_failed_auth_and_concurrency_are_reported(self):
        self.assertEqual(sum(self.report["failed_auth_per_session"].values()), 1)
        self.assertEqual(self.report["peak_concurrent_sessions"], 2)

    def test_password_never_recorded(self):
        for ev in self.events:
            self.assertNotIn(PASSWORD, json.dumps(ev))
            self.assertNotIn("wrong", ev.get("text", ""))


INBAND_PASSWORD = b"canary-inband-91c2"
PROMPT = b"SIM> "


async def _tcp_scenario(log_path):
    recorder = sim.Recorder(log_path)
    cfg = sim.Config(inband_auth_command=b"LOGIN", inband_password=INBAND_PASSWORD,
                     response_delay=0.1, telnet=True)
    server = await sim.start_tcp(recorder, "127.0.0.1", 0, cfg)
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    received = bytearray()

    async def until(marker, count=1):
        for _ in range(count):
            received.extend(await asyncio.wait_for(reader.readuntil(marker), 5))

    async def send(data, marker=PROMPT, count=1):
        writer.write(data)
        await until(marker, count)

    await until(PROMPT)
    # WILL TERMINAL-TYPE, DO ECHO: the simulator must refuse both.
    writer.write(bytes([0xFF, 0xFB, 0x18, 0xFF, 0xFD, 0x01]))
    received.extend(await asyncio.wait_for(reader.readexactly(6), 5))
    await send(b"LOGIN\r\n", b"Password: ")
    await send(b"wrongpw\r\n")                      # failed in-band auth
    await send(b"LOGIN\r\x00", b"Password: ")       # Telnet CR NUL terminator
    await send(INBAND_PASSWORD + b"\r\n")
    await send(b"SHOW-EVENTS\r\n")                   # allowed
    await send(b"\xa5\xe0SHOW-EVENTS\r\n")           # binary prefix on the ASCII port
    await send(b"SHOW-ID\r\nSHOW-EVENTS 3\r\n", count=2)  # pipelined, no wait
    await send(b"SHOW-ID\xff\xff\r\n")               # IAC IAC is a literal 0xFF
    writer.close()
    await writer.wait_closed()
    await asyncio.sleep(0.3)
    server.close()
    await server.wait_closed()
    recorder.close()
    return bytes(received)


class TelnetInbandSelfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        log = os.path.join(cls.tmp.name, "rec.jsonl")
        cls.received = asyncio.run(_tcp_scenario(log))
        with open(log) as f:
            cls.raw_log = f.read()
        cls.events = [json.loads(line) for line in cls.raw_log.splitlines()]
        register = check.load_register(os.path.join(HERE, "selftest-register.json"))
        cls.report = check.check(cls.events, register)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def verdicts(self):
        return sorted((v["text"], v["verdict"]) for v in self.report["violations"])

    def test_telnet_options_refused_and_logged(self):
        self.assertIn(bytes([0xFF, 0xFE, 0x18, 0xFF, 0xFC, 0x01]), self.received)
        self.assertEqual(self.report["telnet_sequences"], 2)

    def test_inband_password_is_auth_event_not_line(self):
        auths = [e for e in self.events if e["event"] == "auth"]
        self.assertEqual([a["accepted"] for a in auths], [False, True])
        self.assertEqual(self.report["failed_auth_per_session"], {1: 1})

    def test_passwords_never_recorded(self):
        self.assertNotIn(INBAND_PASSWORD.decode(), self.raw_log)
        self.assertNotIn("wrongpw", self.raw_log)

    def test_sent_bytes_are_recorded_in_order(self):
        # Everything the client read is the start of what the log says the
        # simulator sent (the client stops reading at its last marker).
        sent = b"".join(base64.b64decode(e["b64"]) for e in self.events if e["event"] == "sent")
        self.assertTrue(self.received)
        self.assertEqual(sent[:len(self.received)], self.received)
        self.assertIn(bytes([0xFF, 0xFE, 0x18, 0xFF, 0xFC, 0x01]), sent)

    def test_cr_nul_terminator_recognised(self):
        terms = {e["text"]: e["term"] for e in self.events if e["event"] == "line"}
        self.assertEqual(terms.get("LOGIN"), "CRNUL")  # last LOGIN line wins

    def test_expected_violations_only(self):
        self.assertEqual(self.verdicts(), sorted([
            ("", "auth-retry"),          # the second LOGIN after wrongpw
            ("SHOW-EVENTS 3", "before-prompt"),
            ("SHOW-ID\xff", "non-printable"),
            ("\xa5\xe0SHOW-EVENTS", "non-printable"),
        ]))


if __name__ == "__main__":
    unittest.main()
