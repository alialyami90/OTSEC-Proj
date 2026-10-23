"""Self-test for flush_analyse.py on synthetic traces (not evidence of Windows behaviour).

Each case builds a tracerpt-style XML document by hand, so the parser's
interval logic and its INCONCLUSIVE gates are exercised on Linux. Whether real
Windows traces have this shape is what the controls in a real run check.

Run: python3 -I -m unittest discover -s tests/integration/h14 -p 'test_*.py'
"""

import importlib.util
import os
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("flush_analyse", os.path.join(HERE, "flush_analyse.py"))
fa = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fa)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
DIR = r"\Device\HarddiskVolume4\h14\run-full"
PID = 4242


def ev(eid, pid, data, provider="Microsoft-Windows-Kernel-File", task=""):
    fields = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{eid}</EventID>'
            f'<TimeCreated SystemTime="2026-10-23T20:00:00.0000000Z"/>'
            f'<Execution ProcessID="{pid}" ThreadID="1"/></System>'
            f'<EventData>{fields}</EventData><RenderingInfo Culture="en-US"><Task>{task}</Task>'
            f'</RenderingInfo></Event>')


def create(fo, name, pid=PID):
    return ev(12, pid, {"Irp": "0x1", "FileObject": fo, "FileName": DIR + "\\" + name}, task="Create")


def flush(fo, pid=PID):
    return ev(21, pid, {"Irp": "0x2", "FileObject": fo}, task="Flush")


def trace(n, wal_flush_in=None, control=True, lost=0, order=None, other_pid_flush=False):
    wal_flush_in = set(range(1, n + 1)) if wal_flush_in is None else wal_flush_in
    out = [ev(0, 0, {"EventsLost": str(lost)}, provider="MSNT_SystemTrace")]
    out.append(create("0xC1", "control-begin.bin"))
    if control:
        out.append(flush("0xC1"))
    out += [create("0xD1", "events.db"), create("0xA1", "events.db-wal")]
    marks = order or list(range(0, n + 1))
    for i in marks:
        if i >= 1 and i in wal_flush_in:
            out.append(flush("0xA1"))
            if other_pid_flush:
                out.append(flush("0xA1", pid=9))
            if i == 2:
                out.append(flush("0xD1"))  # a checkpoint
        out.append(create(f"0xM{i}", f"ack-{i:06d}"))
    out.append(create("0xC2", "control-end.bin"))
    if control:
        out.append(flush("0xC2"))
    return "<Events>" + "".join(out) + "</Events>"


class FlushAnalyse(unittest.TestCase):
    def run_case(self, xml, mode="FULL", n=5, admin=False):
        with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False) as f:
            f.write(xml)
        try:
            return fa.analyse(f.name, {"pid": PID, "mode": mode, "acks": n, "is_admin": admin, "user": "h14svc"})
        finally:
            os.remove(f.name)

    def test_every_ack_flushed_passes(self):
        r = self.run_case(trace(5))
        self.assertEqual(r["verdict"], "PASS", r)
        self.assertEqual(r["acks_without_wal_flush"], 0)
        self.assertEqual(r["db_flushes"], 1)

    def test_one_unflushed_ack_fails(self):
        r = self.run_case(trace(5, wal_flush_in={1, 2, 4, 5}))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["acks_without_wal_flush"], 1)

    def test_flush_by_another_process_does_not_count(self):
        r = self.run_case(trace(5, wal_flush_in={1, 2, 3, 4}, other_pid_flush=True))
        self.assertEqual(r["verdict"], "FAIL")
        self.assertEqual(r["store_flushes_by_other_pids"], 4)

    def test_missing_control_is_inconclusive(self):
        r = self.run_case(trace(5, control=False))
        self.assertEqual(r["verdict"], "INCONCLUSIVE")

    def test_lost_events_inconclusive(self):
        self.assertEqual(self.run_case(trace(5, lost=3))["verdict"], "INCONCLUSIVE")

    def test_missing_or_reordered_markers_inconclusive(self):
        self.assertEqual(self.run_case(trace(5, order=[0, 1, 2, 4, 5]))["verdict"], "INCONCLUSIVE")
        self.assertEqual(self.run_case(trace(5, order=[0, 1, 3, 2, 4, 5]))["verdict"], "INCONCLUSIVE")

    def test_admin_writer_inconclusive(self):
        self.assertEqual(self.run_case(trace(5), admin=True)["verdict"], "INCONCLUSIVE")

    def test_normal_is_contrast_with_counts(self):
        r = self.run_case(trace(5, wal_flush_in={5}), mode="NORMAL")
        self.assertEqual(r["verdict"], "CONTRAST")
        self.assertEqual(r["acks_without_wal_flush"], 4)
        self.assertEqual(r["longest_unflushed_run"], 4)


if __name__ == "__main__":
    unittest.main()
