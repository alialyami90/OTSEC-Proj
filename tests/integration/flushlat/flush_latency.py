"""How long did each FlushFileBuffers take while a Go test ran? (B6, #230)

Reads the `tracerpt -of XML` dump of an ETW Microsoft-Windows-Kernel-File
trace taken around one run of a store test binary (run_flushlat.ps1). Each
Flush event (21) that the test process issued on a `*.db` or `*.db-wal` file
is paired with the next OperationEnd event (24) for the same Irp, and the
difference of their timestamps is that flush's latency. A flush with no
OperationEnd before the trace stopped is reported as open, with its age at
the trace's last event.

The question is #230's: did the Windows Go job time out because one flush
stalled for minutes, or because many flushes were each slow? A stall shows
as one large latency (or an open flush); a slow disk shows as many moderate
ones whose sum is a large share of the test's run time.

Event IDs and field names (Microsoft-Windows-Kernel-File manifest): 12 Create,
30 CreateNewFile, 21 Flush, 24 OperationEnd; FileObject, FileName, Irp. These
are B6's reading of the manifest (H-14 confirmed 12, 21 and 30). The positive
controls check the rest: control.py's os.fsync on control-begin.bin and
control-end.bin must each appear as a Flush from its own PID with a paired
OperationEnd. If not, the verdict is INCONCLUSIVE and the report lists the
event IDs and field names seen, so the mapping can be corrected.

Verdicts:
  STALL         one flush took at least --stall seconds, or one was still
                open that long when the trace stopped.
  NO-STALL      every store flush completed, each in under --stall seconds.
  INCONCLUSIVE  a control is missing or unpaired, the trace reports lost
                events, or no store flush was seen.

Run: python -I flush_latency.py <trace.xml> <run.json> [--stall SECONDS]
"""

import argparse
import datetime
import json
import sys
import xml.etree.ElementTree as ET

KF = "Microsoft-Windows-Kernel-File"
CREATE_IDS = {12, 30}
FLUSH_ID = 21
END_ID = 24


def local(tag):
    return tag.rsplit("}", 1)[-1]


def ticks(stamp):
    """SystemTime ("2026-10-27T17:27:46.6293741Z", up to 7 fraction digits)
    as integer 100 ns ticks since 1970, so no precision is lost to floats."""
    stamp = stamp.strip().rstrip("Z")
    whole, _, frac = stamp.partition(".")
    t = datetime.datetime.strptime(whole, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return int(t.timestamp()) * 10_000_000 + int((frac + "0000000")[:7])


def events(path):
    """Yield one dict per <Event>: id, pid, ticks, provider, data fields."""
    for _, el in ET.iterparse(path, events=("end",)):
        if local(el.tag) != "Event":
            continue
        ev = {"id": None, "pid": None, "t": None, "provider": None, "data": {}}
        for part in el:
            name = local(part.tag)
            if name == "System":
                for s in part:
                    sn = local(s.tag)
                    if sn == "EventID":
                        ev["id"] = int((s.text or "0").strip())
                    elif sn == "Execution":
                        pid = s.get("ProcessID")
                        ev["pid"] = int(pid, 0) if pid else None
                    elif sn == "TimeCreated" and s.get("SystemTime"):
                        ev["t"] = ticks(s.get("SystemTime"))
                    elif sn == "Provider":
                        ev["provider"] = s.get("Name")
            elif name == "EventData":
                for d in part:
                    if d.get("Name"):
                        ev["data"][d.get("Name")] = (d.text or "").strip()
        el.clear()
        yield ev


def role(filename):
    f = filename.lower().replace("/", "\\")
    if f.endswith(".db-wal"):
        return "wal"
    if f.endswith(".db"):
        return "db"
    if f.endswith("\\control-begin.bin"):
        return "control-begin"
    if f.endswith("\\control-end.bin"):
        return "control-end"
    return None


def irp(data):
    return data.get("Irp") or data.get("IrpPtr")


def pct(sorted_s, p):
    if not sorted_s:
        return None
    return sorted_s[min(len(sorted_s) - 1, int(p * len(sorted_s)))]


def analyse(xml_path, run, stall_s=30.0):
    test_pid = run["test_pid"]
    control_pid = {c["name"]: c["pid"] for c in run["controls"]}
    fo_role = {}
    pending = {}          # Irp -> (role, start ticks, pid)
    done = {"wal": [], "db": []}
    control = {"control-begin": "missing", "control-end": "missing"}
    other_pid_store_flushes = 0
    lost = None
    last_t = None
    ids, field_names = {}, {}

    for ev in events(xml_path):
        data = ev["data"]
        if ev["t"] is not None:
            last_t = ev["t"] if last_t is None else max(last_t, ev["t"])
        if ev["provider"] != KF:
            for key in ("EventsLost", "LostEvents"):
                if key in data:
                    lost = (lost or 0) + int(data[key], 0)
            continue
        ids[ev["id"]] = ids.get(ev["id"], 0) + 1
        field_names.setdefault(ev["id"], sorted(data))
        if ev["id"] in CREATE_IDS and "FileName" in data and data.get("FileObject"):
            fo_role[data["FileObject"]] = role(data["FileName"])
            continue
        if ev["id"] == FLUSH_ID:
            r = fo_role.get(data.get("FileObject"))
            if r is None or irp(data) is None:
                continue
            if r in ("wal", "db") and ev["pid"] != test_pid:
                other_pid_store_flushes += 1
                continue
            if r.startswith("control") and ev["pid"] != control_pid.get(r):
                continue
            pending[irp(data)] = (r, ev["t"], ev["pid"])
            if r.startswith("control"):
                control[r] = "unpaired"
            continue
        if ev["id"] == END_ID and irp(data) in pending:
            r, t0, _ = pending.pop(irp(data))
            secs = (ev["t"] - t0) / 1e7
            if r.startswith("control"):
                control[r] = "paired"
            else:
                done[r].append((secs, t0))

    open_flushes = [{"role": r, "age_s": round((last_t - t0) / 1e7, 3)}
                    for r, t0, _ in pending.values() if not r.startswith("control")]
    all_secs = sorted(s for r in done for s, _ in done[r])
    longest = sorted(((s, r) for r in done for s, _ in done[r]), reverse=True)[:5]
    wall = run.get("test_wall_s")
    flush_total = sum(all_secs)

    problems = []
    for name, state in control.items():
        if state != "paired":
            problems.append(f"positive control {name}: {state} (event IDs, keywords, Irp field or PID attribution wrong)")
    if lost:
        problems.append(f"trace reports {lost} lost events")
    if not all_secs and not open_flushes:
        problems.append("no store flush by the test process was seen")

    worst = max(all_secs[-1:] + [o["age_s"] for o in open_flushes] + [0.0])
    report = {
        "test": run.get("test"), "run": run.get("run"), "test_exit": run.get("test_exit"),
        "test_wall_s": wall, "stall_threshold_s": stall_s,
        "store_flushes": {r: len(done[r]) for r in done},
        "flush_seconds_total": round(flush_total, 3),
        "flush_share_of_wall": round(flush_total / wall, 3) if wall else None,
        "latency_s": {"p50": pct(all_secs, 0.50), "p90": pct(all_secs, 0.90),
                      "p99": pct(all_secs, 0.99), "max": all_secs[-1] if all_secs else None},
        "longest": [{"role": r, "s": round(s, 4)} for s, r in longest],
        "open_at_trace_end": open_flushes,
        "store_flushes_by_other_pids": other_pid_store_flushes,
        "controls": control, "events_lost": lost,
        "kernel_file_event_ids": {str(k): v for k, v in sorted(ids.items(), key=lambda kv: kv[0] or 0)},
        "field_names": {str(k): field_names[k] for k in (12, 21, 24, 30) if k in field_names},
        "problems": problems,
    }
    if problems:
        report["verdict"] = "INCONCLUSIVE"
    elif worst >= stall_s:
        report["verdict"] = "STALL"
    else:
        report["verdict"] = "NO-STALL"
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("xml")
    ap.add_argument("run")
    ap.add_argument("--stall", type=float, default=30.0)
    a = ap.parse_args()
    with open(a.run, encoding="utf-8-sig") as f:
        run = json.load(f)
    print(json.dumps(analyse(a.xml, run, a.stall), indent=2))


if __name__ == "__main__":
    sys.exit(main())
