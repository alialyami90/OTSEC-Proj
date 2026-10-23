"""Self-test: the recording simulator and checker catch what they claim to catch.

Uses selftest-register.json, a synthetic register with neutral command names.
It is not a device command register and says nothing about any real device.

Run from the repository root:
  python -m unittest tests/safety/recording_simulator/test_selftest.py
"""

import asyncio
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
        self.assertEqual(self.by_text.get("SHOW-EVENTS \x1b[2J"), "control-bytes")

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


if __name__ == "__main__":
    unittest.main()
