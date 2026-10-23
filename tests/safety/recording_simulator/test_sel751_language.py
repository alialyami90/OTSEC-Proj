"""V-S17: a port set to LANG := SPANISH must stop an English-register collector.

ADR-0005 (A1 rulings 2026-10-23): before ACC the collector sends QUI once at
Level 0 as a language probe and closes without elevating if it is rejected;
if it passes, SHO P 1 is read and collection is refused unless LANG :=
ENGLISH. Whether a Spanish port accepts English command names is
undocumented, so both cases are simulated here.

COLLECTOR below is A6's reference reading of ADR-0005, used to show the
simulator and checker can tell a correct collector from a wrong one. When the
adapter exists, its entry point replaces it and the same assertions apply.
Results are `simulated`.

Run from the repository root:
  python -m unittest tests/safety/recording_simulator/test_sel751_language.py
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

PASSWORD = b"canary-acc-7b2c"
REGISTER = check.load_register(os.path.join(HERE, "sel751-collector-register.json"))
PROMPT_ENDS = (b"Password: ?", b"\r\n=>>", b"\r\n=>", b"\r\n=")


async def until_prompt(reader, ends=PROMPT_ENDS):
    buf = bytearray()
    while not buf.endswith(ends):
        chunk = await asyncio.wait_for(reader.read(4096), 5)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


async def reference_collector(reader, writer, outcome):
    async def send(line):
        writer.write(line + b"\r\n")
        return await until_prompt(reader)

    await until_prompt(reader, b"=")  # greeting: Telnet negotiation, then "="
    if await send(b"QUI") != b"\r\n=":
        outcome["alarm"] = "language probe rejected"
        return
    reply = await send(b"ACC")
    if not reply.endswith(b"Password: ?"):
        await send(b"QUI")
        outcome["alarm"] = "Level 1 reached without a password prompt"
        return
    if not (await send(PASSWORD)).endswith(b"=>"):
        outcome["alarm"] = "authentication failed"
        return
    port1 = dict(re.findall(rb"(\w+)\s*:= (\"[^\"]*\"|\S+)", await send(b"SHO P 1")))
    if port1.get(b"LANG") != b"ENGLISH":
        await send(b"QUI")
        outcome["alarm"] = f"LANG is {port1.get(b'LANG')!r}, not ENGLISH"
        return
    outcome["warnings"] = [n for n in (b"MAXACC", b"FTPACC", b"HTTPACC") if port1.get(n, b"?") != b"1"]
    outcome["ser"] = await send(b"SER")
    await send(b"QUI")


async def naive_collector(reader, writer, outcome):
    """Negative control: no language probe and no LANG check."""
    async def send(line):
        writer.write(line + b"\r\n")
        return await until_prompt(reader)

    await until_prompt(reader, b"=")
    for line in (b"ACC", PASSWORD, b"SER D", b"QUI"):
        await send(line)


async def collect(port1, accepts_english, collector=None):
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "rec.jsonl")
        rec = sim.Recorder(log)
        cfg = sim.Config(telnet=True, responder_factory=profile_sel751.factory(
            password=PASSWORD, port1=port1, spanish_accepts_english=accepts_english))
        server = await sim.start_tcp(rec, "127.0.0.1", 0, cfg)
        reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        outcome = {}
        await (collector or reference_collector)(reader, writer, outcome)
        writer.close()
        await asyncio.sleep(0.3)
        server.close()
        await server.wait_closed()
        rec.close()
        with open(log) as f:
            raw = f.read()
    events = [json.loads(line) for line in raw.splitlines()]
    lines = [e["text"] for e in events if e["event"] == "line"]
    return outcome, events, lines, raw, check.check(events, REGISTER)


def run(port1=None, accepts_english=False, collector=None):
    return asyncio.run(collect(port1, accepts_english, collector))


class SpanishPort(unittest.TestCase):
    def test_english_port_collects(self):
        outcome, events, lines, raw, report = run()
        self.assertTrue(report["pass"], report["violations"])
        self.assertEqual(lines, ["QUI", "ACC", "SHO P 1", "SER", "QUI"])
        self.assertIn(b"TRIP", outcome["ser"])
        self.assertEqual(outcome["warnings"], [b"MAXACC", b"FTPACC", b"HTTPACC"])  # factory defaults are 2

    def test_maxacc_1_but_ftp_and_http_still_warn(self):
        outcome, *_ = run(port1={"MAXACC": "1"})
        self.assertEqual(outcome["warnings"], [b"FTPACC", b"HTTPACC"])

    def test_spanish_rejecting_english_stops_at_the_probe(self):
        # Case (a): zero ACC lines and zero credential bytes reach the device.
        outcome, events, lines, raw, report = run(port1={"LANG": "SPANISH"})
        self.assertEqual(lines, ["QUI"])
        self.assertFalse([e for e in events if e["event"] == "auth"])
        self.assertNotIn(PASSWORD.decode(), raw)
        self.assertIn("probe", outcome["alarm"])
        self.assertTrue(report["pass"], report["violations"])

    def test_spanish_accepting_english_refused_before_ser(self):
        # Case (b): the probe passes, the SHO P 1 LANG check refuses; no SER line.
        outcome, events, lines, raw, report = run(port1={"LANG": "SPANISH"}, accepts_english=True)
        self.assertEqual(lines, ["QUI", "ACC", "SHO P 1", "QUI"])
        self.assertIn("LANG", outcome["alarm"])
        self.assertFalse(any(line.startswith("SER") for line in lines))
        self.assertTrue(report["pass"], report["violations"])

    def test_negative_control_naive_collector_is_caught(self):
        # Without the probe and the LANG check, an English "read" clears the SER.
        outcome, events, lines, raw, report = run(
            port1={"LANG": "SPANISH"}, accepts_english=True, collector=naive_collector)
        self.assertIn("SER D", lines)
        self.assertIn("device-effect", [v["verdict"] for v in report["violations"]])

    def test_lang_missing_from_output_is_refused(self):
        outcome, events, lines, raw, report = run(port1={"LANG": None})
        self.assertIn("LANG", outcome["alarm"])
        self.assertFalse(any(line.startswith("SER") for line in lines))


class ThreeLetterCollisions(unittest.TestCase):
    """Commands match on their first three letters (Command Summary). An
    allowed English line must not be, cut to three letters, a Spanish command
    with a different meaning."""

    @staticmethod
    def spanish():
        path = os.path.join(HERE, "documented", "sel-751", "command-summary-spanish-names.txt")
        with open(path) as f:
            pairs = [line.split() for line in f if line.strip() and not line.startswith("#")]
        return {en[:3]: es[:3] for en, es in pairs}

    def test_allowed_verbs_are_same_or_absent_in_spanish(self):
        en_to_es = self.spanish()
        es_verbs = set(en_to_es.values())
        allow = os.path.join(HERE, "..", "register_review", "allow-corpus.txt")
        with open(allow) as f:
            verbs = {line.split()[0][:3] for line in f if line.strip() and not line.startswith("#")}
        for verb in verbs:
            same_name = en_to_es.get(verb) == verb
            self.assertTrue(same_name or verb not in es_verbs, verb)


if __name__ == "__main__":
    unittest.main()
