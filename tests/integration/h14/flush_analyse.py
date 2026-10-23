"""H-14 part 1 (Windows E-02): did every acknowledgement follow a WAL flush?

Reads the `tracerpt -of XML` dump of the ETW Microsoft-Windows-Kernel-File
trace taken around flush_writer.py. It maps each FileObject to its name from
Create events, then walks the events in order. The writer's `ack-NNNNNN`
marker creates cut the trace into intervals, and interval i holds commit i.
For each interval it counts Flush events that the writer issued on
`events.db-wal` and `events.db`.

Event IDs (Microsoft-Windows-Kernel-File manifest): 12 Create, 30 CreateNewFile,
21 Flush. These are A6's reading of the manifest. The positive controls check
them: flush_writer.py's two os.fsync calls must appear as Flush events on
control-*.bin issued by the writer's PID. If they do not, the verdict is
INCONCLUSIVE, and the output lists the event IDs and task names that were seen
so the mapping can be corrected.

Verdicts:
  FULL   PASS when every interval has at least one WAL flush and at least one
         database flush (a checkpoint) happens during the run.
  NORMAL and OFF are contrast runs. They report how many acknowledgements had
         no flush (E-02 on Linux: NORMAL left 1,011 of 1,016 unsynced).
  Any mode is INCONCLUSIVE if markers are missing or out of order, a control
  flush is missing, the trace reports lost events, or the writer ran as an
  administrator.

Run: python -I flush_analyse.py <trace.xml> <writer.json>
"""

import collections
import json
import re
import sys
import xml.etree.ElementTree as ET

CREATE_IDS = {12, 30}
FLUSH_ID = 21
MARK = re.compile(r"[\\/]ack-(\d{6})$", re.I)


def local(tag):
    return tag.rsplit("}", 1)[-1]


def events(path):
    """Yield one dict per <Event>: id, pid, time, task, data fields."""
    for _, el in ET.iterparse(path, events=("end",)):
        if local(el.tag) != "Event":
            continue
        ev = {"id": None, "pid": None, "time": None, "task": None, "provider": None, "data": {}}
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
                    elif sn == "TimeCreated":
                        ev["time"] = s.get("SystemTime")
                    elif sn == "Provider":
                        ev["provider"] = s.get("Name")
            elif name == "EventData":
                for d in part:
                    if d.get("Name"):
                        ev["data"][d.get("Name")] = (d.text or "").strip()
            elif name == "RenderingInfo":
                for r in part:
                    if local(r.tag) == "Task":
                        ev["task"] = (r.text or "").strip()
        el.clear()
        yield ev


def role(filename):
    f = filename.lower().replace("/", "\\")
    if f.endswith("\\events.db-wal"):
        return "wal"
    if f.endswith("\\events.db"):
        return "db"
    if f.endswith("\\control-begin.bin"):
        return "control-begin"
    if f.endswith("\\control-end.bin"):
        return "control-end"
    return None


def analyse(xml_path, writer):
    pid, mode, n = writer["pid"], writer["mode"], writer["acks"]
    fo_role = {}                      # FileObject -> role, from Create events
    last_mark = None                  # index of the last marker seen
    marks_seen, marks_in_order = [], True
    wal = collections.Counter()       # interval -> WAL flushes
    db = collections.Counter()
    control = collections.Counter()
    other_pid_store_flushes = 0
    lost = None
    ids = collections.Counter()
    task_names = {}
    field_names = {}                  # event ID -> Data names, for fixing the mapping

    for ev in events(xml_path):
        data = ev["data"]
        for key in ("EventsLost", "LostEvents"):
            if key in data and ev["provider"] != "Microsoft-Windows-Kernel-File":
                lost = (lost or 0) + int(data[key], 0)
        if ev["provider"] != "Microsoft-Windows-Kernel-File":
            continue
        ids[ev["id"]] += 1
        if ev["task"]:
            task_names.setdefault(ev["id"], ev["task"])
        field_names.setdefault(ev["id"], sorted(data))
        fo = data.get("FileObject")
        if ev["id"] in CREATE_IDS and "FileName" in data:
            m = MARK.search(data["FileName"])
            if m and ev["pid"] == pid:
                i = int(m.group(1))
                if i in marks_seen:
                    continue  # the same create logged twice (e.g. 12 and 30)
                if last_mark is not None and i != last_mark + 1:
                    marks_in_order = False
                marks_seen.append(i)
                last_mark = i
                continue
            if fo:
                fo_role[fo] = role(data["FileName"])
            continue
        if ev["id"] != FLUSH_ID or not fo:
            continue
        r = fo_role.get(fo)
        if r is None:
            continue
        if ev["pid"] != pid:
            if r in ("wal", "db"):
                other_pid_store_flushes += 1
            continue
        if r.startswith("control"):
            control[r] += 1
        elif last_mark is not None and last_mark < n:
            (wal if r == "wal" else db)[last_mark + 1] += 1

    intervals = range(1, n + 1)
    no_wal = [i for i in intervals if wal[i] == 0]
    no_flush = [i for i in intervals if wal[i] == 0 and db[i] == 0]
    longest = run = 0
    for i in intervals:
        run = run + 1 if wal[i] == 0 and db[i] == 0 else 0
        longest = max(longest, run)

    problems = []
    if writer.get("is_admin"):
        problems.append("writer ran as an administrator")
    if sorted(marks_seen) != list(range(0, n + 1)):
        problems.append(f"markers: saw {len(marks_seen)} of {n + 1}")
    if not marks_in_order:
        problems.append("markers out of order in the trace")
    if control["control-begin"] == 0 or control["control-end"] == 0:
        problems.append("positive control flush not found (event IDs, keywords or PID attribution wrong)")
    if lost:
        problems.append(f"trace reports {lost} lost events")

    report = {
        "mode": mode, "acks": n, "writer_user": writer.get("user"), "writer_is_admin": writer.get("is_admin"),
        "synchronous_reported": writer.get("synchronous"), "journal_mode": writer.get("journal_mode"),
        "sqlite": writer.get("sqlite"),
        "markers_seen": len(marks_seen), "markers_in_order": marks_in_order,
        "control_flushes": dict(control), "events_lost": lost,
        "wal_flushes": sum(wal.values()), "db_flushes": sum(db.values()),
        "acks_without_wal_flush": len(no_wal), "acks_without_any_store_flush": len(no_flush),
        "longest_unflushed_run": longest,
        "store_flushes_by_other_pids": other_pid_store_flushes,
        "kernel_file_event_ids": {str(k): v for k, v in sorted(ids.items(), key=lambda kv: kv[0] or 0)},
        "task_names": {str(k): v for k, v in task_names.items()},
        "field_names": {str(k): field_names[k] for k in (12, 21, 30) if k in field_names},
        "problems": problems,
    }
    if problems:
        report["verdict"] = "INCONCLUSIVE"
    elif mode == "FULL":
        report["verdict"] = "PASS" if not no_wal and report["db_flushes"] > 0 else "FAIL"
    else:
        report["verdict"] = "CONTRAST"
    return report


def main():
    with open(sys.argv[2]) as f:
        writer = json.load(f)
    print(json.dumps(analyse(sys.argv[1], writer), indent=2))


if __name__ == "__main__":
    main()
