"""V-S19: collection is gated on firmware known to be free of the documented
communications-triggered diagnostic restarts (A2 D27).

The SEL-751 firmware history (IM 20260910, firmware revision table) lists
fixed defects in which Telnet traffic, communications access, Ethernet
traffic, or an invalid-size BPDU could cause a diagnostic restart. The
triggers are not documented. A2 proposes reading the FID with ID at Level 0
and stopping unless the FID is on an allowlist at or after every fix. A6
challenge C-23: the ID probe is itself Telnet traffic to the unit it is meant
to protect, so on a pre-fix unit the gate fires after the exposure. The
reference gate below therefore also requires the FID to be known before
connecting (from the asset inventory) and uses ID only to confirm it.

The profile marks a unit vulnerable by recording a device effect for any
session that reaches it. GATED is A6's reading; the adapter replaces it.
Results are `simulated`.

Run from the repository root:
  python -m unittest tests/safety/recording_simulator/test_sel751_firmware_gate.py
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
from test_sel751_language import PROBE_OK, until_prompt  # noqa: E402

PASSWORD = b"canary-acc-91f0"
REGISTER = check.load_register(os.path.join(HERE, "sel751-collector-register.json"))
FIXED = b"SEL-751-R301-V2-Z009005-D20220607"   # Figure 7.38; on the A6 test allowlist
PRE_FIX = b"SEL-751-R300-V2-Z008004-D20200921"  # before "Telnet traffic could cause a diagnostic restart" was fixed (R300-V3)
ALLOWLIST = {FIXED}
DEFECT = "SEL-751 R300-V2: Telnet traffic could cause a diagnostic restart (fixed R300-V3, D20210104)"


def fid_from_id(reply):
    """FID from an ID reply, or None unless its line checksum verifies (AG95-04)."""
    for line in reply.split(b"\r\n"):
        m = re.fullmatch(rb'("FID=([ -~]*?)",)"([0-9A-F]{4})"', line)
        if m:
            return m.group(2) if sum(m.group(1)) & 0xFFFF == int(m.group(3), 16) else None
    return None


async def gated(open_conn, inventory_fid, outcome):
    if inventory_fid not in ALLOWLIST:
        outcome["alarm"] = "inventory FID not on the firmware allowlist; not connecting"
        return
    reader, writer = await open_conn()

    async def send(line):
        writer.write(line + b"\r\n")
        return await until_prompt(reader)

    try:
        await until_prompt(reader, b"=")
        if not PROBE_OK.fullmatch(await send(b"QUI")):
            outcome["alarm"] = "language probe rejected"
            return
        fid = fid_from_id(await send(b"ID"))
        if fid != inventory_fid:
            outcome["alarm"] = f"device FID {fid!r} does not match inventory; stopping at Level 0"
            return
        if not (await send(b"ACC")).endswith(b"Password: ?"):
            outcome["alarm"] = "no password prompt"
            await send(b"QUI")
            return
        await send(PASSWORD)
        outcome["ser"] = await send(b"SER")
        await send(b"QUI")
    finally:
        writer.close()


async def id_probe_only(open_conn, inventory_fid, outcome):
    """A2's proposal without the inventory precondition: connect, then check ID."""
    reader, writer = await open_conn()
    writer.write(b"ID\r\n")
    await until_prompt(reader, b"=")
    fid = fid_from_id(await until_prompt(reader))
    outcome["alarm" if fid not in ALLOWLIST else "fid"] = fid
    writer.close()


async def ungated(open_conn, inventory_fid, outcome):
    reader, writer = await open_conn()
    await until_prompt(reader, b"=")
    for line in (b"ACC", PASSWORD, b"SER", b"QUI"):
        writer.write(line + b"\r\n")
        await until_prompt(reader)
    writer.close()


async def collect(collector, inventory_fid, **profile):
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "rec.jsonl")
        rec = sim.Recorder(log)
        cfg = sim.Config(telnet=True, responder_factory=profile_sel751.factory(password=PASSWORD, **profile))
        server = await sim.start_tcp(rec, "127.0.0.1", 0, cfg)
        port = server.sockets[0].getsockname()[1]
        outcome = {}
        await collector(lambda: asyncio.open_connection("127.0.0.1", port), inventory_fid, outcome)
        await asyncio.sleep(0.3)
        server.close()
        await server.wait_closed()
        rec.close()
        with open(log) as f:
            raw = f.read()
    events = [json.loads(line) for line in raw.splitlines()]
    lines = [e["text"] for e in events if e["event"] == "line"]
    effects = [e["effect"] for e in events if e["event"] == "device_effect"]
    sessions = sum(e["event"] == "session_open" for e in events)
    return outcome, lines, effects, sessions, raw, check.check(events, REGISTER)


def run(collector, inventory_fid, **profile):
    return asyncio.run(collect(collector, inventory_fid, **profile))


class FirmwareGate(unittest.TestCase):
    def test_listed_firmware_collects(self):
        outcome, lines, effects, sessions, raw, report = run(gated, FIXED)
        self.assertEqual(lines, ["QUI", "ID", "ACC", "SER", "QUI"])
        self.assertTrue(report["pass"], report["violations"])

    def test_pre_fix_firmware_in_inventory_is_never_contacted(self):
        outcome, lines, effects, sessions, raw, report = run(
            gated, PRE_FIX, fid=PRE_FIX, vulnerable=DEFECT)
        self.assertEqual(sessions, 0)
        self.assertEqual(effects, [])
        self.assertIn("allowlist", outcome["alarm"])

    def test_device_fid_differs_from_inventory_stops_at_level0(self):
        # Relay replaced or downgraded since the inventory was taken. The gate
        # stops before ACC, but the session has already reached the unit.
        outcome, lines, effects, sessions, raw, report = run(
            gated, FIXED, fid=PRE_FIX, vulnerable=DEFECT)
        self.assertEqual(lines, ["QUI", "ID"])
        self.assertNotIn(PASSWORD.decode(), raw)
        self.assertIn("does not match", outcome["alarm"])
        self.assertEqual(len(effects), 1)  # residual exposure, recorded (C-23)

    def test_bad_id_checksum_is_treated_as_unknown(self):
        outcome, lines, effects, sessions, raw, report = run(gated, FIXED, fid=FIXED, fid_checksum_ok=False)
        self.assertEqual(lines, ["QUI", "ID"])
        self.assertIn("does not match", outcome["alarm"])

    def test_id_probe_alone_exposes_a_pre_fix_unit(self):
        # C-23: without the inventory precondition the gate fires only after
        # the traffic it was meant to prevent.
        outcome, lines, effects, sessions, raw, report = run(
            id_probe_only, None, fid=PRE_FIX, vulnerable=DEFECT)
        self.assertEqual(outcome["alarm"], PRE_FIX)
        self.assertEqual(sessions, 1)
        self.assertTrue(any("diagnostic-restart" in e for e in effects))
        self.assertIn("device-effect", [v["verdict"] for v in report["violations"]])

    def test_negative_control_ungated_collector_is_caught(self):
        outcome, lines, effects, sessions, raw, report = run(
            ungated, None, fid=PRE_FIX, vulnerable=DEFECT)
        self.assertIn("ACC", lines)
        self.assertFalse(report["pass"])

    def test_fid_line_checksum_rule(self):
        # The profile's recomputed FID line verifies under the documented rule;
        # with the original Figure 7.38 FID it reproduces the printed checksum.
        r = profile_sel751.SEL751DocResponder(None, fid=FIXED)
        self.assertIn(b'"FID=SEL-751-R301-V2-Z009005-D20220607","08AF"', r.id)
        self.assertEqual(fid_from_id(r.id), FIXED)


if __name__ == "__main__":
    unittest.main()
