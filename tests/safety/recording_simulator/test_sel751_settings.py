"""The SEL-751 profile's SHO settings replies and change injector (B6, P4-B6).

SHO n answers Figure 7.43 (p. 7.78-7.79) for Group n; SHO G and SHO P 1 keep
their earlier layouts. The change injector is a settings file the profile
re-reads at every SHO line, and every SHO reply is noted in the recording
with the settings it printed, so a configuration test has the device side's
own record of what changed between two reads. These tests check the profile
against the figure and against that record, not against any product parser.

Evidence class: simulated (documented-example for the figure's bytes; the
layout of a changed, removed or added setting is ASSUMED, and the
one-per-line, hang and duplicate cases are SYNTHESIZED; see the profile).

Run from the repository root:
  python -m pytest -q tests/safety/recording_simulator/test_sel751_settings.py
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
with open(os.path.join(profile_sel751.DOC, "sho-group-fig-7-43.txt"), encoding="utf-8") as _f:
    FIGURE = _f.read().rstrip("\n").split("\n")
# The figure ends with a blank line before the prompt (p. 7.79).
FIGURE_BYTES = b"\r\n" + b"\r\n".join(l.encode() for l in FIGURE) + b"\r\n\r\n=>"
# The register these tests' collector uses: login, the modelled SHO forms,
# SER and QUI, all read-only (a test register, not the product's).
REGISTER = [dict(e, regex=re.compile(e["pattern"])) for e in (
    {"id": "acc", "pattern": "ACC", "classification": "read-only"},
    {"id": "sho-group", "pattern": "SHO [1-4]", "classification": "read-only"},
    {"id": "sho-g", "pattern": "SHO G", "classification": "read-only"},
    {"id": "sho-p1", "pattern": "SHO P 1", "classification": "read-only"},
    {"id": "ser", "pattern": "SER", "classification": "read-only"},
    {"id": "qui", "pattern": "QUI", "classification": "read-only"},
)]


def figure_settings():
    return profile_sel751.Printed("\n".join(FIGURE)).settings()


def responder(**kw):
    r = profile_sel751.SEL751DocResponder(None, password=None, **kw)
    r.handle(b"ACC")
    return r


class Figure(unittest.TestCase):
    def test_sho_and_sho_1_are_the_figure(self):
        for line in (b"SHO", b"SHO 1", b"SHOW 1", b"sho 1"):
            reply = responder().handle(line)
            self.assertEqual(reply.out, FIGURE_BYTES, line)
            self.assertEqual(reply.notes, [{"what": "settings", "class": "1", "settings": figure_settings()}])

    def test_only_sho_and_show_are_sho(self):
        """Only the command's name, SHO, and its long form, SHOW, answer as
        SHO n (B3 on #248): any other word that starts with SHO falls
        through as unmodelled, so no test passes on a spelling the manual
        does not give."""
        for line in (b"SHOX", b"SHOX 1", b"SHOWS 1", b"SHOWSET 1"):
            reply = responder().handle(line)
            self.assertNotEqual(reply.out, FIGURE_BYTES, line)
            self.assertIn(profile_sel751.UNMODELLED, reply.out, line)
            self.assertEqual(reply.notes, [], line)

    def test_the_figure_as_read(self):
        s = figure_settings()
        self.assertEqual(len(s), 158)
        # Values with spaces are printed bare, not quoted, and a SELOGIC
        # equation keeps its spaces and parentheses.
        self.assertEqual(s["TID"], "FEEDER RELAY")
        self.assertEqual(s["ULTRIP"], "NOT ( 51P1P OR 51G1P OR 51N1P OR 52A )")
        # Names the figure prints without padding.
        self.assertEqual((s["LEA_S_R"], s["SINGLEV"], s["E79"], s["REMTRIP"]), ("180.00", "N", "N", "0"))
        self.assertIn("LEA_S_R := 180.00          LEA_S_SC := 4.80    DELTA_Y   := DELTA", FIGURE)

    def test_the_other_groups(self):
        for n in (2, 3, 4):
            reply = responder().handle(b"SHO %d" % n)
            self.assertEqual(reply.out, FIGURE_BYTES.replace(b"Group 1", b"Group %d" % n))
            self.assertEqual(reply.notes[0]["class"], str(n))

    def test_unmodelled_forms_get_the_placeholder(self):
        for line in (b"SHO 5", b"SHO 0", b"SHO 1 50P1P", b"SHO L 1", b"SHO R", b"SHO F", b"SHO P 2", b"SHO DNP 1"):
            reply = responder().handle(line)
            self.assertIn(profile_sel751.UNMODELLED, reply.out, line)
            self.assertEqual(reply.notes, [], line)

    def test_level_0_is_refused(self):
        r = profile_sel751.SEL751DocResponder(None, password=None)
        self.assertEqual(r.handle(b"SHO 1").out, b"\r\nInvalid Access Level\r\n=")


class Injector(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "settings.json")

    def tearDown(self):
        self.tmp.cleanup()

    def inject(self, overrides):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(overrides, f)
        os.replace(tmp, self.path)

    def test_a_change_between_two_reads_changes_that_cell_only(self):
        r = responder(settings_file=self.path)
        before = r.handle(b"SHO 1")
        self.inject({"1": {"50P1P": "8.00"}})
        after = r.handle(b"SHO 1")
        a = before.out.split(b"\r\n")
        b = after.out.split(b"\r\n")
        self.assertEqual([(x, y) for x, y in zip(a, b) if x != y],
                         [(b"50P1P    := 10.00          50P1D    := 0.00", b"50P1P    := 8.00           50P1D    := 0.00")])
        s0, s1 = before.notes[0]["settings"], after.notes[0]["settings"]
        self.assertEqual({k for k in s0 if s0[k] != s1.get(k)}, {"50P1P"})
        # Other groups are other classes.
        self.assertEqual(r.handle(b"SHO 2").out, FIGURE_BYTES.replace(b"Group 1", b"Group 2"))

    def test_remove_add_and_a_long_value(self):
        self.inject({"1": {"SINGLEV": None, "TID": "A MUCH LONGER FEEDER NAME", "NEW1": "5"}})
        reply = responder(settings_file=self.path).handle(b"SHO 1")
        lines = reply.out.split(b"\r\n")
        self.assertIn(b"VSCONN   := VS             VNOM      := 120.00", lines)
        self.assertIn(b"TID      := A MUCH LONGER FEEDER NAME", lines)
        self.assertEqual(lines[-3:], [b"NEW1     := 5", b"", b"=>"])
        s = reply.notes[0]["settings"]
        self.assertNotIn("SINGLEV", s)
        self.assertEqual((s["TID"], s["NEW1"]), ("A MUCH LONGER FEEDER NAME", "5"))
        self.assertEqual(len(s), 158)

    def test_a_value_too_long_for_its_column(self):
        self.inject({"1": {"CTR": "1200000000000000000"}})
        out = responder(settings_file=self.path).handle(b"SHO 1").out
        # Each cell after it moves two spaces past the one before.
        self.assertIn(b"\r\nCTR      := 1200000000000000000  CTRN     := 120  PTR       := 180.00\r\n", out)

    def test_global_and_port_1(self):
        self.inject({"G": {"DATE_F": "DMY", "PHROT": "ACB"}, "P1": {"MAXACC": "1", "FTPACC": None}})
        r = responder(settings_file=self.path)
        g = r.handle(b"SHO G")
        self.assertEqual(re.findall(rb"(PHROT|DATE_F)\s+:= (\S+)", g.out), [(b"PHROT", b"ACB"), (b"DATE_F", b"DMY")])
        self.assertEqual(g.notes[0]["settings"]["DATE_F"], "DMY")
        # The injected DATE_F is the order dates print in from then on.
        self.assertIn(b"28/02/2007", r.handle(b"SER").out)
        p = r.handle(b"SHO P 1")
        self.assertIn(b"MAXACC   := 1", p.out)
        self.assertNotIn(b"FTPACC", p.out)
        self.assertEqual(p.notes[0]["settings"]["MAXACC"], "1")
        self.assertNotIn("FTPACC", p.notes[0]["settings"])

    def test_no_file_and_an_empty_class(self):
        self.assertEqual(responder(settings_file=self.path).handle(b"SHO 1").out, FIGURE_BYTES)
        self.inject({"2": {"50P1P": "1.00"}})
        self.assertEqual(responder(settings_file=self.path).handle(b"SHO 1").out, FIGURE_BYTES)

    def test_a_broken_file_fails_loudly(self):
        with open(self.path, "w") as f:
            f.write("{")
        with self.assertRaises(ValueError):
            responder(settings_file=self.path).handle(b"SHO 1")


class Synthesized(unittest.TestCase):
    def test_one_per_line_is_the_same_settings(self):
        reply = responder(sho_layout="one-per-line").handle(b"SHO 1")
        self.assertNotEqual(reply.out, FIGURE_BYTES)
        self.assertEqual(reply.notes[0]["settings"], figure_settings())
        self.assertEqual(len(re.findall(rb":=", reply.out)), 158)
        self.assertEqual(max(len(re.findall(rb":=", l)) for l in reply.out.split(b"\r\n")), 1)

    def test_duplicate_names_one_setting_twice(self):
        reply = responder(sho_fault="duplicate").handle(b"SHO 1")
        self.assertEqual(re.findall(rb"(?m)^50P1P\s+:= (\S+)", reply.out), [b"10.00", b"2.50"])
        self.assertEqual(reply.notes[0]["duplicate"], "50P1P")

    def test_hang_stops_inside_the_reply(self):
        r = responder(sho_fault="hang")
        out = r.handle(b"SHO 1").out
        self.assertTrue(FIGURE_BYTES.startswith(out), out[-40:])
        self.assertTrue(out.endswith(b"Incipient Fault 50\r\nE50INC   := 15.00          50IALC   := 1       50ITRC    := 10\r\n\r\n"))
        self.assertNotIn(b"Phase TOC", out)
        # Later lines are answered as usual.
        self.assertTrue(r.handle(b"QUI").out.endswith(b"="))
        framed = responder(sho_fault="hang", stx_etx=True).handle(b"SHO 1").out
        self.assertTrue(framed.startswith(b"\x02Group 1\r\n"))
        self.assertNotIn(b"\x03", framed)

    def test_unknown_switch_refused(self):
        with self.assertRaises(ValueError):
            profile_sel751.SEL751DocResponder(None, sho_layout="wide")
        with self.assertRaises(ValueError):
            profile_sel751.SEL751DocResponder(None, sho_fault="slow")


class Recording(unittest.TestCase):
    """Over Telnet, as a collector reads: the profile events are in the
    recording, and they are not violations."""

    def test_the_recording_holds_what_each_reply_printed(self):
        async def go(tmp):
            log, path = os.path.join(tmp, "rec.jsonl"), os.path.join(tmp, "settings.json")
            rec = sim.Recorder(log)
            cfg = sim.Config(telnet=True, responder_factory=profile_sel751.factory(password=PASSWORD, settings_file=path))
            server = await sim.start_tcp(rec, "127.0.0.1", 0, cfg)
            port = server.sockets[0].getsockname()[1]
            for k, value in enumerate((None, "7.25")):
                if value:
                    with open(path, "w") as f:
                        json.dump({"1": {"51AP": value}}, f)
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                await asyncio.wait_for(reader.readuntil(b"="), 5)
                for line, marker in ((b"ACC", b"Password: ?"), (PASSWORD, b"=>"), (b"SHO 1", b"=>"),
                                     (b"SHO G", b"=>"), (b"SHO P 1", b"=>"), (b"QUI", b"\r\n=")):
                    writer.write(line + b"\r\n")
                    await asyncio.wait_for(reader.readuntil(marker), 5)
                writer.close()
                await asyncio.sleep(0.2)
            server.close()
            await server.wait_closed()
            rec.close()
            with open(log) as f:
                return [json.loads(l) for l in f]

        with tempfile.TemporaryDirectory() as tmp:
            events = asyncio.run(go(tmp))
        report = check.check(events, REGISTER)
        self.assertTrue(report["pass"], report)
        notes = [e for e in events if e["event"] == "profile"]
        self.assertEqual([(e["session"], e["class"]) for e in notes],
                         [(1, "1"), (1, "G"), (1, "P1"), (2, "1"), (2, "G"), (2, "P1")])
        first, second = notes[0]["settings"], notes[3]["settings"]
        self.assertEqual({k for k in first if first[k] != second[k]}, {"51AP"})
        self.assertEqual(second["51AP"], "7.25")


if __name__ == "__main__":
    unittest.main()
