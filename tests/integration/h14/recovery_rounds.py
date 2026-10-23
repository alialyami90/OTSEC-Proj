"""H-14 part 2 (Windows E-03/E-04, and R-A5-5): startup recovery on a full NTFS volume.

This ports E-04 (tests/integration/experiments/store_recovery_rounds.py) so it
runs on Windows. The volume is a small NTFS VHDX prepared by run_h14.ps1, the
writer is killed with TerminateProcess (Popen.kill), and the space check uses
shutil.disk_usage. It also adds two things:

- E-03's read check. Before recovery releases the reserve file, it opens the
  full store and reads the count, max(seq) and integrity_check. Then it tries
  one 50-row prune and records whether that fails.
- R-A5-5. In `cursor` mode the prune boundary is a persisted consumer cursor
  (table `cursor`, which the writer advances in the same transaction as the
  insert, LAG events behind, standing in for the forwarder's confirmed
  position), not "the oldest half". A recovery killed after its prune commits
  and then restarted must prune nothing more, and no event above the cursor
  may be gone. `half` mode is A5's experiment rule. It is kept as the contrast
  that reproduces the double prune.

Pass for each round: integrity ok, sequence contiguous, the last acked event
present, in cursor mode min(seq) equal to cursor+1, reserve re-created, and the
next writer run wrote at least half of what the previous recovery pruned.
Reported separately, r_a5_5_holds: the recovery restarted after a kill
pruned 0 rows (and, in cursor mode, nothing above the cursor is gone).

This models ADR-0004's rule; it is not the product's store. Uses Python's
sqlite3 and imports no A5 code. Classification: simulated.

Run (Windows, as the non-admin account; <dir> is on the small NTFS volume):
  python -I recovery_rounds.py --dir <dir>
Run (Linux, root, mounts its own 4 MiB tmpfs):
  sudo python3 -I recovery_rounds.py --tmpfs
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

RECOVERY = r"""
import json, os, sqlite3, sys, time
path, reserve, mode, stop_after_prune, pragmas = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] == "1", sys.argv[5:]
out = {}
db = sqlite3.connect(path, isolation_level=None)
for p in pragmas:
    db.execute(p)
# E-03: reads at full disk, and one prune attempt before any space is freed.
try:
    out["read_at_full"] = list(db.execute("SELECT COUNT(*), MAX(seq) FROM events").fetchone())
    out["integrity_at_full"] = db.execute("PRAGMA integrity_check").fetchone()[0]
except sqlite3.Error as exc:
    out["read_at_full"] = f"{type(exc).__name__}: {exc}"
if mode == "cursor":
    cut = db.execute("SELECT seq FROM cursor WHERE consumer = 'fwd'").fetchone()[0]
else:
    lo, n = db.execute("SELECT MIN(seq), COUNT(*) FROM events").fetchone()
    cut = lo + n // 2 - 1
out["cut"] = cut
pruned = 0
try:
    db.execute("BEGIN")
    pruned = db.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE seq <= ? ORDER BY seq LIMIT 50)", (cut,)).rowcount
    db.execute("COMMIT")
    out["prune_before_release"] = "ok"
except sqlite3.Error as exc:
    pruned = 0
    if db.in_transaction:
        db.execute("ROLLBACK")
    out["prune_before_release"] = f"{type(exc).__name__}: {exc}"
if os.path.exists(reserve):
    os.remove(reserve)
while True:
    db.execute("BEGIN")
    k = db.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE seq <= ? ORDER BY seq LIMIT 50)", (cut,)).rowcount
    db.execute("COMMIT")
    pruned += k
    if k == 0:
        break
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


def run_writer(path, batch, lag):
    child = subprocess.Popen([sys.executable, "-I", "-c", WRITER, path, str(batch), str(lag), *PRAGMAS],
                             stdout=subprocess.PIPE, text=True)
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
    return first_seq, last, err


def run_recovery(path, reserve, mode, kill_after_prune):
    child = subprocess.Popen([sys.executable, "-I", "-c", RECOVERY, path, reserve, mode,
                              "1" if kill_after_prune else "0", *PRAGMAS],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    info, done = None, False
    for line in child.stdout:
        if line.startswith("PRUNED "):
            info = json.loads(line[7:])
            if kill_after_prune:
                child.kill()
                break
        elif line.startswith("DONE"):
            done = True
    child.wait()
    err = child.stderr.read().strip()
    reserve_ok = "not reached"
    if done:
        try:
            make_reserve(reserve)
            reserve_ok = "ok"
        except OSError as exc:
            reserve_ok = f"{type(exc).__name__}: {exc}"
            if os.path.exists(reserve):
                os.remove(reserve)
    return info, done, reserve_ok, err[-300:] if err else None


def state(path, last_acked):
    db = sqlite3.connect(path)
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    lo, hi, n = db.execute("SELECT MIN(seq), MAX(seq), COUNT(*) FROM events").fetchone()
    cursor = db.execute("SELECT seq FROM cursor WHERE consumer = 'fwd'").fetchone()[0]
    db.close()
    return {"integrity": integrity, "min": lo, "max": hi, "count": n, "cursor": cursor,
            "contiguous": hi is not None and hi - lo + 1 == n,
            "acked_present": hi is not None and hi >= last_acked}


def scenario(work, auto_vacuum, mode, kill_round, rounds, batch, lag):
    path = os.path.join(work, "events.db")
    reserve = os.path.join(work, "reserve.bin")
    for name in os.listdir(work):
        os.remove(os.path.join(work, name))
    make_reserve(reserve)
    db = sqlite3.connect(path, isolation_level=None)
    if auto_vacuum:
        db.execute("PRAGMA auto_vacuum=INCREMENTAL")  # must precede the first table
    db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, native BLOB NOT NULL)")
    db.execute("CREATE TABLE cursor(consumer TEXT PRIMARY KEY, seq INTEGER NOT NULL)")
    db.execute("INSERT INTO cursor VALUES ('fwd', 0)")
    db.close()

    out, prev_pruned = [], None
    for r in range(1, rounds + 1):
        first, last, werr = run_writer(path, batch, lag)
        written = 0 if first is None else last - first + 1
        row = {"round": r, "written": written, "seq": [first, last], "writer": werr}
        row["capacity_regained"] = prev_pruned is None or 2 * written >= prev_pruned
        killed = None
        if r == kill_round:
            killed, _, _, _ = run_recovery(path, reserve, mode, kill_after_prune=True)
            row["killed_recovery"] = killed
        info, done, reserve_ok, rerr = run_recovery(path, reserve, mode, kill_after_prune=False)
        st = state(path, last or 0)
        row.update({"recovery": info, "recovery_done": done, "reserve": reserve_ok,
                    "recovery_error": rerr, **st, "fs_free": shutil.disk_usage(work).free})
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
        row["pass"] = bool(done and reserve_ok == "ok" and st["integrity"] == "ok" and st["contiguous"]
                           and st["acked_present"] and row["capacity_regained"]
                           and row.get("above_cursor_intact", True))
        out.append(row)
        prev_pruned = row["pruned"]
    return {"auto_vacuum": "INCREMENTAL" if auto_vacuum else "NONE", "prune": mode,
            "recovery_killed_in_round": kill_round, "rounds": out,
            "pass": all(x["pass"] for x in out),
            "r_a5_5_holds": None if kill_round is None else all(x.get("r_a5_5_holds", True) for x in out)}


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--dir", help="empty directory on a small volume")
    g.add_argument("--tmpfs", action="store_true", help="Linux: mount a 4 MiB tmpfs (root)")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--batch", type=int, default=10, help="events per transaction")
    ap.add_argument("--lag", type=int, default=2000, help="cursor lag in events (cursor mode)")
    args = ap.parse_args()

    mount = None
    if args.tmpfs:
        mount = tempfile.mkdtemp(prefix="otsec-h14-")
        subprocess.run(["mount", "-t", "tmpfs", "-o", "size=4m", "tmpfs", mount], check=True)
        work = mount
    else:
        work = args.dir
        os.makedirs(work, exist_ok=True)
    try:
        plan = [(False, "half", None), (True, "half", 2), (True, "cursor", 2)]
        results = [scenario(work, av, mode, kill, args.rounds, args.batch, args.lag)
                   for av, mode, kill in plan]
    finally:
        if mount:
            subprocess.run(["umount", mount], check=False)
            os.rmdir(mount)
    print(json.dumps({
        "experiment": "H-14 part 2: startup recovery over repeated exhaustion (E-03, E-04, R-A5-5)",
        "classification": "simulated",
        "identity": identity(),
        "platform": sys.platform,
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "batch": args.batch, "lag": args.lag,
        "scenarios": results,
        "expected": "NONE/half: pass false (capacity not regained). INCREMENTAL/half: pass true, "
                    "r_a5_5_holds false (double prune). INCREMENTAL/cursor: pass true, r_a5_5_holds true",
    }, indent=2))


if __name__ == "__main__":
    main()
