"""Tests of SEL-751 session state the collector must not depend on: the password
re-prompt (p. 7.33) and the state a Telnet session leaves when it closes without
QUIT (p. 7.16). For C7-A6 change 2 (T-10, T-11) and A2's C7 review.

Whether a new connection inherits that state is not documented, so the profile
models it as a switch (RelayState). These tests show what each setting does to a
collector; they say nothing about which one a real relay follows (H-12).
Results are `simulated`.

Run from the repository root:
  python -m unittest tests/safety/recording_simulator/test_sel751_session_state.py
"""

import asyncio
import json
import os
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check  # noqa: E402
import profile_sel751  # noqa: E402
import sim  # noqa: E402

PASSWORD = b"canary-acc-5d1e"
REGISTER = check.load_register(os.path.join(HERE, "sel751-collector-register.json"))
LOGIN = [(b"ACC\r\n", b"Password: ?"), (PASSWORD + b"\r\n", b"=>")]


async def drive(connections, relay, pause=0.0):
    """connections: one list of (bytes, marker) steps per connection, run one
    after another against one relay. Returns events, each connection's
    greeting, everything received, and the check report."""
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "rec.jsonl")
        rec = sim.Recorder(log)
        cfg = sim.Config(telnet=True, responder_factory=profile_sel751.factory(
            password=PASSWORD, relay=relay))
        server = await sim.start_tcp(rec, "127.0.0.1", 0, cfg)
        port = server.sockets[0].getsockname()[1]
        greetings, received = [], bytearray()
        for i, steps in enumerate(connections):
            if i and pause:
                await asyncio.sleep(pause)
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            await asyncio.sleep(0.1)
            greetings.append(await asyncio.wait_for(reader.read(64), 5))
            for data, marker in steps:
                writer.write(data)
                if marker:
                    received.extend(await asyncio.wait_for(reader.readuntil(marker), 5))
            writer.close()
            await asyncio.sleep(0.2)
        server.close()
        await server.wait_closed()
        rec.close()
        with open(log) as f:
            raw = f.read()
    events = [json.loads(line) for line in raw.splitlines()]
    return events, greetings, bytes(received), check.check(events, REGISTER)


def run(connections, relay=None, pause=0.0):
    return asyncio.run(drive(connections, relay, pause))


def effects(events, session=None):
    return [e["effect"] for e in events if e["event"] == "device_effect"
            and (session is None or e["session"] == session)]


class PasswordSlot(unittest.TestCase):
    """T-10: the slot opens once per session."""

    def test_second_password_in_a_session_is_flagged(self):
        events, greetings, out, report = run([[
            (b"ACC\r\n", b"Password: ?"), (b"wrong\r\n", b"Password: ?"),
            (PASSWORD + b"\r\n", b"=>"), (b"QUI\r\n", b"\r\n="),
        ]])
        self.assertIn("auth-retry", [v["verdict"] for v in report["violations"]])
        self.assertEqual(report["failed_auth_per_session"], {1: 1})

    def test_disconnect_after_rejection_is_clean(self):
        # The C-19 behaviour: one rejected password, then close without
        # sending anything else. Nothing is left elevated.
        events, greetings, out, report = run([[
            (b"ACC\r\n", b"Password: ?"), (b"wrong\r\n", b"Password: ?"),
        ]])
        self.assertTrue(report["pass"], report["violations"])
        self.assertEqual(report["failed_auth_per_session"], {1: 1})
        self.assertEqual(effects(events), [])


class InheritedState(unittest.TestCase):
    """T-11's reason: what a session closed without QUI leaves for the next."""

    def test_default_gives_each_connection_level_0(self):
        events, greetings, out, report = run([LOGIN, [(b"ID\r\n", b"\r\n=")]],
                                             relay=profile_sel751.RelayState())
        self.assertEqual(greetings[1], b"=")
        self.assertEqual(len(effects(events, session=2)), 0)

    def test_inherited_level_starts_next_connection_elevated(self):
        events, greetings, out, report = run(
            [LOGIN, [(b"SER\r\n", b"=>"), (b"QUI\r\n", b"\r\n=")]],
            relay=profile_sel751.RelayState(inherit="level"))
        self.assertEqual(greetings[1], b"=>")
        self.assertTrue(any("TIDLE" in e for e in effects(events, session=1)))
        self.assertTrue(any("Access Level 1" in e for e in effects(events, session=2)),
                        effects(events))
        # SER answered without any ACC on the second connection.
        self.assertIn(b"TRIP", out)
        self.assertFalse(any(e["event"] == "auth" and e["session"] == 2 for e in events))

    def test_inherited_prompt_reads_first_line_as_password(self):
        # The first session sent ACC and closed at "Password: ?". The next
        # connection's first line is consumed as a password, not a command.
        events, greetings, out, report = run(
            [[(b"ACC\r\n", b"Password: ?")], [(b"ID\r\n", b"Password: ?")]],
            relay=profile_sel751.RelayState(inherit="prompt"))
        auths = [(e["session"], e["accepted"]) for e in events if e["event"] == "auth"]
        self.assertEqual(auths, [(2, False)])
        self.assertFalse(any(e["event"] == "line" and e["text"] == "ID" for e in events))
        self.assertTrue(any("read as a password" in e for e in effects(events, session=2)))
        self.assertIn("device-effect", [v["verdict"] for v in report["violations"]])

    def test_quit_clears_the_inherited_state(self):
        events, greetings, out, report = run(
            [LOGIN + [(b"QUI\r\n", b"\r\n=")], [(b"ID\r\n", b"\r\n=")]],
            relay=profile_sel751.RelayState(inherit="level"))
        self.assertEqual(greetings[1], b"=")
        self.assertTrue(report["pass"], report["violations"])

    def test_state_expires_after_tidle(self):
        events, greetings, out, report = run(
            [LOGIN, [(b"ID\r\n", b"\r\n=")]],
            relay=profile_sel751.RelayState(inherit="level", tidle=0.2), pause=0.4)
        self.assertEqual(greetings[1], b"=")
        self.assertEqual(effects(events, session=2), [])

    def test_inherited_connection_that_sends_nothing_keeps_the_state(self):
        relay = profile_sel751.RelayState(inherit="level")
        events, greetings, out, report = run([LOGIN, [], []], relay=relay)
        self.assertEqual(greetings[1:], [b"=>", b"=>"])
        self.assertGreater(relay.until, time.monotonic())


if __name__ == "__main__":
    unittest.main()
