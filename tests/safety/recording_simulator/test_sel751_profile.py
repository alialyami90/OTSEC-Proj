"""Tests of the SEL-751 documented-behaviour profile, and what it shows about collectors.

Each scenario drives the simulator over Telnet the way a collector would and
checks the recording against A6's minimal SEL-751 register. Behaviour comes
from the SEL-751 Instruction Manual (date code 20260910); results are
`simulated` and say nothing about real firmware.

Run from the repository root:
  python -m unittest tests/safety/recording_simulator/test_sel751_profile.py
"""

import asyncio
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check  # noqa: E402
import profile_sel751  # noqa: E402
import sim  # noqa: E402

PASSWORD = b"canary-acc-5d1e"
REGISTER = check.load_register(os.path.join(HERE, "sel751-collector-register.json"))


async def drive(steps, password=PASSWORD, max_sessions=None, sessions=1, port1=None):
    """steps: list of (bytes to send, prompt marker to wait for or None)."""
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "rec.jsonl")
        rec = sim.Recorder(log)
        cfg = sim.Config(telnet=True, max_sessions=max_sessions,
                         responder_factory=profile_sel751.factory(password=password, port1=port1))
        server = await sim.start_tcp(rec, "127.0.0.1", 0, cfg)
        port = server.sockets[0].getsockname()[1]
        conns, received = [], bytearray()
        for _ in range(sessions):
            conns.append(await asyncio.open_connection("127.0.0.1", port))
            await asyncio.sleep(0.05)
        reader, writer = conns[0]
        received.extend(await asyncio.wait_for(reader.readuntil(b"="), 5))
        for data, marker in steps:
            writer.write(data)
            if marker:
                received.extend(await asyncio.wait_for(reader.readuntil(marker), 5))
        for _, w in conns:
            w.close()
        await asyncio.sleep(0.3)
        server.close()
        await server.wait_closed()
        rec.close()
        with open(log) as f:
            raw = f.read()
    events = [json.loads(line) for line in raw.splitlines()]
    return events, raw, bytes(received), check.check(events, REGISTER)


def run(*args, **kwargs):
    return asyncio.run(drive(*args, **kwargs))


def verdicts(report):
    return sorted(v["verdict"] for v in report["violations"])


class DocumentedProfile(unittest.TestCase):
    def test_well_behaved_collector_passes(self):
        events, raw, out, report = run([
            (b"ACC\r\n", b"Password: ?"), (PASSWORD + b"\r\n", b"=>"),
            (b"ID\r\n", b"=>"), (b"SER\r\n", b"=>"), (b"QUI\r\n", b"\r\n="),
        ])
        self.assertTrue(report["pass"], report["violations"])
        self.assertIn(b"Level 1", out)
        self.assertIn(b"TRIP                     Deasserted", out)
        self.assertNotIn(PASSWORD.decode(), raw)

    def test_line_after_failed_password_is_a_second_attempt(self):
        # Documented: the relay re-prompts "Password: ?" (p. 7.33). A collector
        # that sends QUI after a failure spends a second attempt, not a QUIT.
        events, raw, out, report = run([
            (b"ACC\r\n", b"Password: ?"), (b"wrong\r\n", b"Password: ?"),
            (b"QUI\r\n", b"Password: ?"),
        ])
        auths = [e["accepted"] for e in events if e["event"] == "auth"]
        self.assertEqual(auths, [False, False])
        self.assertFalse(any(e["event"] == "line" and e["text"] == "QUI" for e in events))

    def test_three_failures_pulse_salarm(self):
        events, raw, out, report = run([
            (b"ACC\r\n", b"Password: ?"), (b"a\r\n", b"Password: ?"),
            (b"b\r\n", b"Password: ?"), (b"c\r\n", b"\r\n="),
        ])
        effects = [e["effect"] for e in events if e["event"] == "device_effect"]
        self.assertTrue(any("SALARM" in e for e in effects), effects)
        self.assertIn("device-effect", verdicts(report))

    def test_ser_clear_at_level1_changes_device_state(self):
        events, raw, out, report = run([
            (b"ACC\r\n", b"Password: ?"), (PASSWORD + b"\r\n", b"=>"),
            (b"SER C\r\n", b"=>"), (b"SER\r\n", b"=>"), (b"QUI\r\n", b"\r\n="),
        ])
        self.assertIn(b"No Data Available", out)
        self.assertEqual(verdicts(report), ["device-effect", "state-changing"])

    def test_password_disabled_executes_the_secret_as_a_command(self):
        # Documented: with the Level 1 password disabled, ACC goes straight to
        # Level 1 (p. 7.33). A collector that sends its password anyway has it
        # read as a command line: it reaches the command interpreter and the log.
        events, raw, out, report = run([
            (b"ACC\r\n", b"=>"), (PASSWORD + b"\r\n", b"=>"), (b"QUI\r\n", b"\r\n="),
        ], password=None)
        self.assertIn(PASSWORD.decode(), raw)
        self.assertIn(b"Invalid Command", out)
        self.assertIn("unregistered", verdicts(report))

    def test_close_without_quit_leaves_relay_elevated(self):
        events, raw, out, report = run([
            (b"ACC\r\n", b"Password: ?"), (PASSWORD + b"\r\n", b"=>"),
        ])
        effects = [e["effect"] for e in events if e["event"] == "device_effect"]
        self.assertTrue(any("TIDLE" in e for e in effects), effects)

    def test_third_telnet_session_refused(self):
        events, raw, out, report = run([(b"ID\r\n", b"\r\n=")], max_sessions=2, sessions=3)
        self.assertEqual(report["sessions_refused"], 1)

    def test_show_port1_serves_access_settings(self):
        # For the MAXACC warning test (V-S16): the profile serves Table 4.104
        # factory defaults, MAXACC := 2, unless the scenario overrides them.
        login = [(b"ACC\r\n", b"Password: ?"), (PASSWORD + b"\r\n", b"=>")]
        for port1, expect in ((None, b"MAXACC   := 2"), ({"MAXACC": "1"}, b"MAXACC   := 1"),
                              ({"MAXACC": "C"}, b"MAXACC   := C")):
            events, raw, out, report = run(
                login + [(b"SHO P 1\r\n", b"=>"), (b"QUI\r\n", b"\r\n=")], port1=port1)
            self.assertTrue(report["pass"], report["violations"])
            self.assertIn(expect, out)
        events, raw, out, report = run(
            login + [(b"SHO P 1\r\n", b"=>"), (b"QUI\r\n", b"\r\n=")], port1={"MAXACC": None})
        self.assertNotIn(b"MAXACC", out)

    def test_spanish_port_defeats_an_english_collector(self):
        # For V-S17. With LANG := SPANISH the collector's own SHO P 1 and QUI
        # are not Spanish commands (MOS, SAL), so it cannot read LANG and
        # cannot leave Level 1; and SER D, a read in English, clears the SER.
        login = [(b"ACC\r\n", b"Password: ?"), (PASSWORD + b"\r\n", b"=>")]
        spanish = {"LANG": "SPANISH"}
        events, raw, out, report = run(
            login + [(b"SHO P 1\r\n", b"=>"), (b"QUI\r\n", b"=>")], port1=spanish)
        self.assertIn(b"Invalid Command", out)
        self.assertNotIn(b"LANG", out)
        effects = [e["effect"] for e in events if e["event"] == "device_effect"]
        self.assertTrue(any("TIDLE" in e for e in effects), effects)
        events, raw, out, report = run(
            login + [(b"SER D\r\n", b"=>"), (b"SER\r\n", b"=>")], port1=spanish)
        self.assertIn(b"No Data Available", out)
        self.assertIn("device-effect", verdicts(report))

    def test_level0_cannot_read_ser(self):
        events, raw, out, report = run([(b"SER\r\n", b"\r\n=")])
        self.assertIn(b"Invalid Access Level", out)


class DocumentedIdExamples(unittest.TestCase):
    """The ID line checksum is the byte sum of `"FIELD",` (A6 derivation, checked below)."""

    @staticmethod
    def bad_lines(name):
        path = os.path.join(HERE, "documented", "sel-751", name)
        bad = []
        with open(path, "rb") as f:
            for line in f.read().splitlines():
                m = re.fullmatch(rb'(".*"),"([0-9A-F]{4})"', line)
                if sum(m.group(1) + b",") != int(m.group(2), 16):
                    bad.append(line)
        return bad

    def test_figure_7_38_is_self_consistent(self):
        self.assertEqual(self.bad_lines("id-fig-7-38.txt"), [])

    def test_figure_3_20_was_edited_after_capture(self):
        # Six of twelve checksums fail; three are off by exactly 0x41 ("A"),
        # consistent with an SEL-751A response edited to read SEL-751.
        self.assertEqual(len(self.bad_lines("id-fig-3-20.txt")), 6)



class GrowingSer(unittest.TestCase):
    """ser="grow": SYNTHESIZED rows added at each read (V-S4, V-S6)."""

    def test_no_rows_added_is_figure_10_16(self):
        self.assertEqual(profile_sel751.grown_ser(0), profile_sel751._load("ser-fig-10-16.txt"))

    def test_rows_renumber_newest_first(self):
        lines = profile_sel751.grown_ser(5).split(profile_sel751.CRLF)
        rows = [profile_sel751.SER_ROW.match(l) for l in lines]
        rows = [m for m in rows if m]
        self.assertEqual([int(m[1]) for m in rows], list(range(13, 0, -1)))
        times = [m[3] for m in rows]
        self.assertEqual(times, sorted(times))
        self.assertEqual(len(set(m.groups()[1:] for m in rows)), 13)
        # The figure's rows keep their fields; only their numbers move.
        fig = [profile_sel751.SER_ROW.match(l) for l in profile_sel751._load("ser-fig-10-16.txt").split(profile_sel751.CRLF)]
        self.assertEqual([m.groups()[1:] for m in fig if m], [m.groups()[1:] for m in rows[:8]])

    def test_growth_survives_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "grow")
            self.assertEqual(profile_sel751.SerGrowth(path, 4).read(), 4)
            self.assertEqual(profile_sel751.SerGrowth(path, 4).read(), 8)


class SerFaults(unittest.TestCase):
    """ser="hang" and ser="malformed": SYNTHESIZED faults for V-S12."""

    def ser(self, mode, stx_etx=True):
        r = profile_sel751.SEL751DocResponder(sim.Config(telnet=True), password=PASSWORD, ser=mode, stx_etx=stx_etx)
        r.level = 1
        return r, r.handle(b"SER")

    def test_hang_stops_inside_the_message(self):
        r, reply = self.ser("hang")
        self.assertTrue(reply.out.startswith(b"\x02"))
        self.assertNotIn(b"\x03", reply.out)
        self.assertFalse(reply.out.rstrip().endswith(b"=>"))
        rows = [l for l in reply.out.split(profile_sel751.CRLF) if profile_sel751.SER_ROW.match(l)]
        self.assertEqual([l.split()[0] for l in rows], [b"8", b"7", b"6", b"5"])
        # The relay answers the next line as usual.
        self.assertTrue(r.handle(b"QUI").out.endswith(b"="))

    def test_malformed_damages_one_row_only(self):
        _, good = self.ser("example")
        _, bad = self.ser("malformed")
        diff = [(a, b) for a, b in zip(good.out.split(b"\r\n"), bad.out.split(b"\r\n")) if a != b]
        self.assertEqual(len(diff), 1)
        self.assertIn(b"13:5X:10.003", diff[0][1])
        self.assertIsNone(profile_sel751.SER_ROW.match(diff[0][1]))


class DstSer(unittest.TestCase):
    """ser="dst": SYNTHESIZED rows in a fall-back hour (V-S3)."""

    def test_rows_and_header(self):
        r = profile_sel751.SEL751DocResponder(sim.Config(telnet=True), password=PASSWORD, ser="dst")
        r.level = 1
        out = r.handle(b"SER").out
        self.assertIn(b"Time Source: External", out)
        self.assertNotIn(b"Time Source: Internal", out)
        rows = [profile_sel751.SER_ROW.match(l) for l in out.split(profile_sel751.CRLF)]
        rows = [m for m in rows if m]
        self.assertEqual([int(m[1]) for m in rows], [6, 5, 4, 3, 2, 1])
        times = [m[3] for m in rows]
        self.assertGreater(times[1], times[2])  # the clock stepped back
        self.assertEqual(times.count(b"01:45:00.000"), 2)
        # The header lines other than the report time and source are the figure's.
        fig = profile_sel751._load("ser-fig-10-16.txt")
        self.assertIn(b"FID = SEL-751-R100-V0-Z001001-D20070410", out)
        self.assertEqual(out.count(b"Serial No"), fig.count(b"Serial No"))


if __name__ == "__main__":
    unittest.main()
