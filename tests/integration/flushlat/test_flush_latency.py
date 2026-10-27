"""Self-test for flush_latency.py on synthetic traces (not evidence of Windows behaviour).

Each case builds a tracerpt-style XML document by hand, so the pairing,
the latency arithmetic and the INCONCLUSIVE gates are exercised on Linux.
Whether real Windows traces have this shape is what the controls in a real
run check.

Run: python3 -I -m unittest discover -s tests/integration/flushlat -p 'test_*.py'
"""

import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("flush_latency", os.path.join(HERE, "flush_latency.py"))
fl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fl)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
DIR = r"\Device\HarddiskVolume3\Temp\TestDiscardStepWALBound1"
TEST, CB, CE = 4242, 5151, 5252


def stamp(tick):
    """100 ns ticks after 2026-10-27T17:00:00 as a SystemTime string."""
    s, f = divmod(tick, 10_000_000)
    m, s = divmod(s, 60)
    return f"2026-10-27T17:{m:02d}:{s:02d}.{f:07d}Z"


def ev(eid, pid, tick, data, provider=fl.KF):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="{stamp(tick)}"/><Execution ProcessID="{pid}" ThreadID="1"/></System>'
            f'<EventData>{fields}</EventData></Event>')


def create(t, fo, name, pid):
    return ev(12, pid, t, {"Irp": "0x9", "FileObject": fo, "FileName": DIR + "\\" + name})


def flush(t, fo, irp, pid):
    return ev(21, pid, t, {"Irp": irp, "FileObject": fo})


def end(t, irp, pid=4):
    return ev(24, pid, t, {"Irp": irp, "Status": "0x0"})


S = 10_000_000  # ticks per second


def trace(body, controls=True, lost=0):
    out = [ev(0, 0, 0, {"EventsLost": str(lost)}, provider="MSNT_SystemTrace")]
    out += [create(1, "0xC1", "control-begin.bin", CB)]
    if controls:
        out += [flush(2, "0xC1", "0xE1", CB), end(3, "0xE1")]
    out += [create(10, "0xD1", "store.db", TEST), create(11, "0xA1", "store.db-wal", TEST)]
    out += body
    out += [create(900 * S, "0xC2", "control-end.bin", CE)]
    if controls:
        out += [flush(900 * S + 1, "0xC2", "0xE2", CE), end(900 * S + 2, "0xE2")]
    return "<Events>" + "".join(out) + "</Events>"


RUN = {"test": "TestDiscardStepWALBound", "run": 1, "test_exit": 0, "test_wall_s": 100.0,
       "test_pid": TEST, "controls": [{"name": "control-begin", "pid": CB}, {"name": "control-end", "pid": CE}]}


def run(xml, stall=30.0, r=RUN):
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
        f.write(xml)
    try:
        return fl.analyse(f.name, r, stall)
    finally:
        os.unlink(f.name)


class FlushLatency(unittest.TestCase):
    def test_ticks_keep_seven_digits(self):
        self.assertEqual(fl.ticks("2026-10-27T17:00:01.0000001Z") - fl.ticks("2026-10-27T17:00:01Z"), 1)
        self.assertEqual(fl.ticks("2026-10-27T17:00:01.5Z") - fl.ticks("2026-10-27T17:00:01Z"), 5_000_000)

    def test_many_slow_flushes_no_stall(self):
        body = []
        for i in range(10):  # ten 2 s WAL flushes, Irp reused each time
            t = (20 + 10 * i) * S
            body += [flush(t, "0xA1", "0xF0", TEST), end(t + 2 * S, "0xF0")]
        body += [flush(200 * S, "0xD1", "0xF1", TEST), end(200 * S + S // 2, "0xF1")]
        r = run(trace(body))
        self.assertEqual(r["verdict"], "NO-STALL", r["problems"])
        self.assertEqual(r["store_flushes"], {"wal": 10, "db": 1})
        self.assertAlmostEqual(r["flush_seconds_total"], 20.5)
        self.assertAlmostEqual(r["flush_share_of_wall"], 0.205)
        self.assertAlmostEqual(r["latency_s"]["max"], 2.0)
        self.assertEqual(r["open_at_trace_end"], [])

    def test_one_long_flush_is_a_stall(self):
        body = [flush(20 * S, "0xA1", "0xF0", TEST), end(20 * S + S // 10, "0xF0"),
                flush(30 * S, "0xA1", "0xF0", TEST), end(30 * S + 45 * S, "0xF0")]
        r = run(trace(body))
        self.assertEqual(r["verdict"], "STALL")
        self.assertAlmostEqual(r["longest"][0]["s"], 45.0)

    def test_open_flush_at_trace_end_is_a_stall(self):
        body = [flush(20 * S, "0xA1", "0xF0", TEST)]
        r = run(trace(body))
        self.assertEqual(r["verdict"], "STALL")
        self.assertEqual(r["open_at_trace_end"][0]["role"], "wal")
        self.assertAlmostEqual(r["open_at_trace_end"][0]["age_s"], 880.0, places=3)

    def test_open_flush_younger_than_threshold_is_reported_not_stall(self):
        body = [flush(895 * S, "0xA1", "0xF0", TEST)]
        r = run(trace(body))
        self.assertEqual(r["verdict"], "NO-STALL")
        self.assertEqual(len(r["open_at_trace_end"]), 1)

    def test_other_pid_store_flush_is_not_counted(self):
        body = [flush(20 * S, "0xA1", "0xF0", 777), end(80 * S, "0xF0"),
                flush(90 * S, "0xA1", "0xF3", TEST), end(91 * S, "0xF3")]
        r = run(trace(body))
        self.assertEqual(r["verdict"], "NO-STALL")
        self.assertEqual(r["store_flushes_by_other_pids"], 1)
        self.assertEqual(r["store_flushes"]["wal"], 1)

    def test_missing_control_is_inconclusive(self):
        body = [flush(20 * S, "0xA1", "0xF0", TEST), end(21 * S, "0xF0")]
        r = run(trace(body, controls=False))
        self.assertEqual(r["verdict"], "INCONCLUSIVE")

    def test_unpaired_control_is_inconclusive(self):
        xml = trace([flush(20 * S, "0xA1", "0xF0", TEST), end(21 * S, "0xF0")])
        xml = xml.replace(end(3, "0xE1"), "")
        r = run(xml)
        self.assertEqual(r["verdict"], "INCONCLUSIVE")
        self.assertEqual(r["controls"]["control-begin"], "unpaired")

    def test_lost_events_are_inconclusive(self):
        r = run(trace([flush(20 * S, "0xA1", "0xF0", TEST), end(21 * S, "0xF0")], lost=3))
        self.assertEqual(r["verdict"], "INCONCLUSIVE")

    def test_no_store_flush_is_inconclusive(self):
        r = run(trace([]))
        self.assertEqual(r["verdict"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
