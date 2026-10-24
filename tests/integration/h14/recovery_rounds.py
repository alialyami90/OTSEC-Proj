"""H-14 part 2 (Windows E-03/E-04, R-A5-5, and the reserve-first order): startup recovery on a full NTFS volume.

This ports E-04 (tests/integration/experiments/store_recovery_rounds.py) so it
runs on Windows. The writer is killed with TerminateProcess (Popen.kill), and
the space check uses shutil.disk_usage.

Second version (Phase 1, after F-013). Changes from the version F-013 ran:

- One scenario per invocation, each on its own fresh volume (run_h14.ps1
  attaches one VHDX per scenario). In F-013 a handle left on events.db
  (WinError 32) stopped the later scenarios at setup.
- This process never opens the store. Every open, including the probes and
  the state check, runs in a short-lived child process, so a handle leaked by
  a failed open dies with that child and cannot change how SQLite treats the
  next open (the first connection to a WAL store rebuilds its -shm).
- Recovery follows ADR-0004 item 8 as amended after F-013: release the reserve
  BEFORE the first open, then prune, incremental_vacuum, checkpoint and
  re-create the reserve. A failed release stops recovery (exit 3) instead of
  continuing; so does a failed open (exit 4) or prune (exit 5), each with a
  `STOP {json}` line saying how far it got. If there is no reserve to release, that is recorded and recovery
  goes on to open the store at full disk (F-013's condition).

Scenarios (--scenario):
  incremental-cursor   INCREMENTAL, prune to the persisted cursor, recovery
                       killed after its prune in round 2. R-A5-5: the restart
                       must prune 0 and nothing above the cursor may be gone.
  incremental-half     INCREMENTAL, prune the oldest half, killed in round 2.
                       A5's experiment rule; the contrast that double-prunes.
  none-half            auto_vacuum NONE, half, no kill. Capacity contrast.
  open-at-full         incremental-cursor without the kill, but every round
                       first opens the full store (two fresh read-only and
                       read-write probes, F-013's order) and then runs the
                       reserve-first recovery. Shows whether releasing the
                       reserve clears a failed open.
  no-reserve           incremental-cursor without the kill and with no reserve
                       file at all, so recovery opens at full disk with
                       nothing to release (the gap carried from F-013).

The question this answers for F-014: does the reserve-first order keep a full
store openable? In the reserve-first scenarios nothing opens the store between
the writer's death and the release; the round records the recovery's own
first read after release.

Pass for each round: recovery done, reserve released or absent as expected,
integrity ok, sequence contiguous, the last acked event present, in cursor
mode min(seq) equal to cursor+1, reserve re-created (where one is used), and
the next writer run wrote at least half of what the previous recovery
pruned. Reported separately, r_a5_5_holds: the recovery restarted after a
kill pruned 0 rows (and, in cursor mode, nothing above the cursor is gone).

This models ADR-0004's rule; it is not the product's store. Uses Python's
sqlite3 and imports no A5 code. Classification: simulated.

Output: one `ROUND {json}` line per finished round, `ERROR {json}` if a step
raises (the scenario then stops; the error records round, step, free space
and the db, -wal and -shm sizes), and a final `RESULT {json}`.

Run (Windows, as the non-admin account; <dir> is on a fresh small NTFS volume):
  python -I recovery_rounds.py --dir <dir> --scenario incremental-cursor
Run (Linux, root, mounts a fresh 4 MiB tmpfs per scenario):
  sudo python3 -I recovery_rounds.py --tmpfs --scenario all
"""

import argparse
import ctypes
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile

RESERVE_BYTES = 512 << 10
PRAGMAS = ["PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL",
           "PRAGMA wal_autocheckpoint=64", "PRAGMA journal_size_limit=262144"]

# name: (auto_vacuum, prune mode, round whose recovery is killed, probe at full, use a reserve)
SCENARIOS = {
    "incremental-cursor": (True, "cursor", 2, False, True),
    "incremental-half": (True, "half", 2, False, True),
    "none-half": (False, "half", None, False, True),
    "open-at-full": (True, "cursor", None, True, True),
    "no-reserve": (True, "cursor", None, False, False),
}
EXPECTED = {
    "incremental-cursor": "pass true, r_a5_5_holds true",
    "incremental-half": "pass true, r_a5_5_holds false (double prune)",
    "none-half": "pass false (capacity not regained)",
    "open-at-full": "unknown: whether the release clears a failed open is the question",
    "no-reserve": "unknown: F-013's condition with nothing to release",
}

WRITER = r"""
import sqlite3, sys, time
path, batch, lag, pragmas = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4:]
db = sqlite3.connect(path, isolation_level=None)
for p in pragmas:
    db.execute(p)
payload = b"x" * 368
while True:
    try:
        db.execute("BEGIN")
        for _ in range(batch):
            last = db.execute("INSERT INTO events(native) VALUES (?)", (payload,)).lastrowid
        db.execute("UPDATE cursor SET seq = max(seq, ?) WHERE consumer = 'fwd'", (last - lag,))
        db.execute("COMMIT")
    except sqlite3.Error as exc:
        print("FULL", type(exc).__name__, exc, flush=True)
        break
    print(last, flush=True)
time.sleep(120)  # hold the connection until the parent kills us
"""

# ADR-0004 item 8 order: release the reserve, then the first open.
RECOVERY = r"""
import json, os, sqlite3, sys, time
path, reserve, mode, stop_after_prune, pragmas = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1", sys.argv[5:]
out = {}
if os.path.exists(reserve):
    try:
        os.remove(reserve)
        out["reserve_release"] = "ok"
    except OSError as exc:
        out["reserve_release"] = f"{type(exc).__name__}: {exc}"
        print("STOP " + json.dumps(out), flush=True)
        sys.exit(3)  # a failed release stops recovery; it never opens the full store
else:
    out["reserve_release"] = "absent"
try:
    db = sqlite3.connect(path, isolation_level=None)
    for p in pragmas:
        db.execute(p)
    out["read_after_release"] = list(db.execute("SELECT COUNT(*), MAX(seq) FROM events").fetchone())
    out["integrity_after_release"] = db.execute("PRAGMA integrity_check").fetchone()[0]
except sqlite3.Error as exc:
    out["read_after_release"] = f"{type(exc).__name__}: {exc}"
    print("STOP " + json.dumps(out), flush=True)
    sys.exit(4)
print("OPENED " + json.dumps(out), flush=True)
if mode == "cursor":
    cut = db.execute("SELECT seq FROM cursor WHERE consumer = 'fwd'").fetchone()[0]
else:
    lo, n = db.execute("SELECT MIN(seq), COUNT(*) FROM events").fetchone()
    cut = lo + n // 2 - 1
out["cut"] = cut
pruned = 0
try:
    while True:
        db.execute("BEGIN")
        k = db.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE seq <= ? ORDER BY seq LIMIT 50)", (cut,)).rowcount
        db.execute("COMMIT")
        pruned += k
        if k == 0:
            break
except sqlite3.Error as exc:
    out.update({"pruned": pruned, "prune_error": f"{type(exc).__name__}: {exc}"})
    print("STOP " + json.dumps(out), flush=True)
    sys.exit(5)
out["pruned"] = pruned
print("PRUNED " + json.dumps(out), flush=True)
if stop_after_prune:
    time.sleep(120)  # parent kills us here
while db.execute("PRAGMA freelist_count").fetchone()[0] > 0 and db.execute("PRAGMA auto_vacuum").fetchone()[0] == 2:
    db.execute("PRAGMA incremental_vacuum(32)").fetchall()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
db.close()
print("DONE", flush=True)
"""

# One fresh connection, one statement, closed; in its own process.
PROBE = r"""
import json, sqlite3, sys
path, kind = sys.argv[1], sys.argv[2]
try:
    if kind == "ro":
        db = sqlite3.connect("file:" + path.replace("\\", "/") + "?mode=ro", uri=True)
    else:
        db = sqlite3.connect(path)
    try:
        if kind == "state":
            integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
            lo, hi, n = db.execute("SELECT MIN(seq), MAX(seq), COUNT(*) FROM events").fetchone()
            cursor = db.execute("SELECT seq FROM cursor WHERE consumer = 'fwd'").fetchone()[0]
            res = {"integrity": integrity, "min": lo, "max": hi, "count": n, "cursor": cursor}
        else:
            n, hi = db.execute("SELECT COUNT(*), MAX(seq) FROM events").fetchone()
            res = f"ok count={n} max={hi}"
    finally:
        db.close()
except sqlite3.Error as exc:
    res = f"{type(exc).__name__}: {exc}"
print(json.dumps(res), flush=True)
"""

# Creates the store; in its own process, like every other open.
CREATE = r"""
import sqlite3, sys
path, auto_vacuum = sys.argv[1], sys.argv[2] == "1"
db = sqlite3.connect(path, isolation_level=None)
if auto_vacuum:
    db.execute("PRAGMA auto_vacuum=INCREMENTAL")  # must precede the first table
db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, native BLOB NOT NULL)")
db.execute("CREATE TABLE cursor(consumer TEXT PRIMARY KEY, seq INTEGER NOT NULL)")
db.execute("INSERT INTO cursor VALUES ('fwd', 0)")
db.close()
"""


def identity():
    out = {"pid": os.getpid()}
    if os.name == "nt":
        buf = ctypes.create_unicode_buffer(257)
        size = ctypes.c_uint32(len(buf))
        ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size))
        out["user"] = buf.value
        out["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    else:
        out["user"] = str(os.getuid())
        out["is_admin"] = os.geteuid() == 0
    return out


def make_reserve(path):
    with open(path, "wb") as f:
        f.write(b"\0" * RESERVE_BYTES)


def run_child(code, *args):
    """Run a short child program; return its last stdout line parsed as JSON."""
    p = subprocess.run([sys.executable, "-I", "-c", code, *args], capture_output=True, text=True, timeout=300)
    if p.returncode != 0:
        raise RuntimeError(f"child exited {p.returncode}: {p.stderr.strip()[-2000:]}")
    lines = p.stdout.strip().splitlines()
    return json.loads(lines[-1]) if lines else None


def run_writer(path, batch, lag):
    child = subprocess.Popen([sys.executable, "-I", "-c", WRITER, path, str(batch), str(lag), *PRAGMAS],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    first_seq = last = None
    err = None
    for line in child.stdout:
        if line.startswith("FULL"):
            err = line.strip()
            break
        last = int(line)
        if first_seq is None:
            first_seq = last - batch + 1
    child.kill()  # SIGKILL on Linux, TerminateProcess on Windows
    child.wait()
    stderr = child.stderr.read().strip()
    return first_seq, last, err, stderr[-2000:] if stderr else None


def run_recovery(path, reserve, mode, kill_after_prune, use_reserve):
    child = subprocess.Popen([sys.executable, "-I", "-c", RECOVERY, path, reserve, mode,
                              "1" if kill_after_prune else "0", *PRAGMAS],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    info, done, stopped = None, False, False
    for line in child.stdout:
        if line.startswith("OPENED "):
            info = json.loads(line[7:])
        elif line.startswith("PRUNED "):
            info = json.loads(line[7:])
            if kill_after_prune:
                child.kill()
                break
        elif line.startswith("STOP "):
            info, stopped = json.loads(line[5:]), True
        elif line.startswith("DONE"):
            done = True
    child.wait()
    err = child.stderr.read().strip()
    reserve_ok = "not used" if not use_reserve else "not reached"
    if done and use_reserve:
        try:
            make_reserve(reserve)
            reserve_ok = "ok"
        except OSError as exc:
            reserve_ok = f"{type(exc).__name__}: {exc}"
            if os.path.exists(reserve):
                os.remove(reserve)
    return info, done, stopped, child.returncode, reserve_ok, err[-2000:] if err else None


def sizes(work):
    out = {"fs_free": shutil.disk_usage(work).free}
    for key, name in (("db", "events.db"), ("wal", "events.db-wal"), ("shm", "events.db-shm"),
                      ("reserve", "reserve.bin")):
        p = os.path.join(work, name)
        out[key] = os.path.getsize(p) if os.path.exists(p) else None
    return out


def probe(work, path):
    """Fresh read-only, then read-write, connection, each in its own process, with file sizes around them."""
    before = sizes(work)
    ro = run_child(PROBE, path, "ro")
    rw = run_child(PROBE, path, "rw")
    return {"sizes_before": before, "read_only": ro, "read_write": rw, "sizes_after": sizes(work)}


def scenario(work, name, rounds, batch, lag):
    auto_vacuum, mode, kill_round, probe_at_full, use_reserve = SCENARIOS[name]
    path = os.path.join(work, "events.db")
    reserve = os.path.join(work, "reserve.bin")
    result = {"scenario": name, "auto_vacuum": "INCREMENTAL" if auto_vacuum else "NONE", "prune": mode,
              "recovery_killed_in_round": kill_round, "probe_at_full": probe_at_full,
              "reserve_used": use_reserve, "order": "reserve-first", "rounds": []}
    out = result["rounds"]
    r, step = 0, "setup"
    try:
        if os.listdir(work):
            raise RuntimeError(f"{work} is not empty; each scenario needs a fresh volume")
        if use_reserve:
            make_reserve(reserve)
        run_child(CREATE, path, "1" if auto_vacuum else "0")

        prev_pruned = None
        for r in range(1, rounds + 1):
            step = "writer"
            first, last, werr, wstderr = run_writer(path, batch, lag)
            written = 0 if first is None else last - first + 1
            row = {"round": r, "written": written, "seq": [first, last], "writer": werr,
                   "writer_stderr": wstderr}
            out.append(row)
            row["capacity_regained"] = prev_pruned is None or 2 * written >= prev_pruned
            row["sizes_at_full"] = sizes(work)
            if probe_at_full:
                step = "probe after writer died at full disk"
                row["probe_at_full"] = probe(work, path)
            killed = None
            if r == kill_round:
                step = "recovery killed after prune"
                killed, _, kstop, _, _, kerr = run_recovery(path, reserve, mode, True, use_reserve)
                row["killed_recovery"] = killed
                row["killed_recovery_stderr"] = kerr
            step = "recovery"
            info, done, stopped, code, reserve_ok, rerr = run_recovery(path, reserve, mode, False, use_reserve)
            row.update({"recovery": info, "recovery_done": done, "recovery_stopped": stopped,
                        "recovery_exit": code, "reserve": reserve_ok, "recovery_error": rerr})
            # The F-014 question, per round: did the recovery's first open after the release read the store?
            first_info = killed if killed is not None else info
            rar = (first_info or {}).get("read_after_release")
            row["opened_after_release"] = isinstance(rar, list)
            step = "probe after recovery"
            row["probe_after_recovery"] = probe(work, path)
            step = "state check"
            st = run_child(PROBE, path, "state")
            if not isinstance(st, dict):
                raise RuntimeError(f"state check: {st}")
            st["contiguous"] = st["max"] is not None and st["max"] - st["min"] + 1 == st["count"]
            st["acked_present"] = st["max"] is not None and st["max"] >= (last or 0)
            row.update({**st, "fs_free": shutil.disk_usage(work).free})
            row["pruned"] = ((info or {}).get("pruned") or 0) + ((killed or {}).get("pruned") or 0)
            if mode == "cursor":
                # Nothing above the persisted boundary may be gone.
                row["above_cursor_intact"] = st["min"] == (info or {}).get("cut", -1) + 1
                if killed is not None:
                    row["restart_pruned"] = (info or {}).get("pruned")
                    row["r_a5_5_holds"] = row["restart_pruned"] == 0 and row["above_cursor_intact"]
            elif killed is not None:
                row["restart_pruned"] = (info or {}).get("pruned")
                row["r_a5_5_holds"] = row["restart_pruned"] == 0
            reserve_fine = reserve_ok == "ok" if use_reserve else True
            row["pass"] = bool(done and reserve_fine and st["integrity"] == "ok" and st["contiguous"]
                               and st["acked_present"] and row["capacity_regained"]
                               and row.get("above_cursor_intact", True))
            print("ROUND " + json.dumps({"scenario": name, **row}), flush=True)
            prev_pruned = row["pruned"]
    except Exception as exc:  # an observation, not a crash: record where and with what sizes
        try:
            sz = sizes(work)
        except OSError as e2:
            sz = f"sizes unavailable: {e2}"
        result["error"] = {"scenario": name, "round": r, "step": step, "sizes": sz,
                           "exception": f"{type(exc).__name__}: {exc}"}
        if out and out[-1]["round"] == r and "pass" not in out[-1]:
            result["error"]["partial_round"] = out[-1]  # includes what was measured before the error
        print("ERROR " + json.dumps(result["error"]), flush=True)
    complete = "error" not in result and len(out) == rounds
    result["pass"] = all(x.get("pass") for x in out) if complete else None
    result["r_a5_5_holds"] = (None if kill_round is None or not complete
                              else all(x.get("r_a5_5_holds", True) for x in out))
    result["opened_after_release_every_round"] = all(x.get("opened_after_release") for x in out) if out else None
    result["expected"] = EXPECTED[name]
    return result


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dir", help="empty directory on a fresh small volume")
    g.add_argument("--tmpfs", action="store_true", help="Linux: mount a fresh 4 MiB tmpfs per scenario (root)")
    ap.add_argument("--scenario", default="all", choices=["all", *SCENARIOS])
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--batch", type=int, default=10, help="events per transaction")
    ap.add_argument("--lag", type=int, default=2000, help="cursor lag in events (cursor mode)")
    args = ap.parse_args()
    names = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    if args.dir and len(names) > 1:
        ap.error("--dir runs one scenario; give --scenario (each scenario needs a fresh volume)")

    results = []
    for name in names:
        mount = None
        if args.tmpfs:
            mount = tempfile.mkdtemp(prefix="otsec-h14-")
            subprocess.run(["mount", "-t", "tmpfs", "-o", "size=4m", "tmpfs", mount], check=True)
            work = mount
        else:
            work = args.dir
            os.makedirs(work, exist_ok=True)
        try:
            results.append(scenario(work, name, args.rounds, args.batch, args.lag))
        finally:
            if mount:
                subprocess.run(["umount", mount], check=False)
                os.rmdir(mount)
    print("RESULT " + json.dumps({
        "experiment": "H-14 part 2: reserve-first startup recovery over repeated exhaustion (E-03, E-04, R-A5-5)",
        "classification": "simulated",
        "identity": identity(),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "batch": args.batch, "lag": args.lag,
        "scenarios": results,
    }), flush=True)


if __name__ == "__main__":
    main()
