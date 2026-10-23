"""Phase 0 experiment E-04: does A5's startup recovery regain capacity, round after round?

Question (re-checks A5 E-A5-3 case 3, commit 9f14154; V-S9, R8.7, R8.8): A5
reports that a store whose writer dies at SQLITE_FULL recovers at startup by
releasing a reserve file, pruning the oldest half in small batches, running
incremental_vacuum a few pages at a time with a checkpoint between steps, and
re-creating the reserve; and that with auto_vacuum=NONE each later round
writes only ~100 events. This re-implements that sequence independently and
adds two things A5's run does not do: the writer is SIGKILLed while still
holding its connection (a crash, not a clean exit), and in one variant the
recovery itself is SIGKILLed after its prune commits and before the vacuum,
so the next start finds the reserve already gone and pages on the freelist.

Pass per round after the first: integrity_check ok, every unpruned acked
event present with contiguous sequence numbers, reserve re-created, and the
next writer run wrote at least half of what the previous recovery pruned
(A5's "capacity regained").

Classification: simulated. Python sqlite3 (independent binding from A5's
modernc.org/sqlite), 4 MiB tmpfs, A5's bounded-WAL pragmas. Needs root.

Run: sudo python3 -I tests/integration/experiments/store_recovery_rounds.py
"""

import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile

ROUNDS = 5
RESERVE_BYTES = 512 << 10
PRAGMAS = ["PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL",
           "PRAGMA wal_autocheckpoint=64", "PRAGMA journal_size_limit=262144"]

WRITER = r"""
import sqlite3, sys, time
path, pragmas = sys.argv[1], sys.argv[2:]
db = sqlite3.connect(path, isolation_level=None)
for p in pragmas:
    db.execute(p)
payload = b"x" * 368
while True:
    try:
        db.execute("BEGIN")
        cur = db.execute("INSERT INTO events(native) VALUES (?)", (payload,))
        db.execute("COMMIT")
    except sqlite3.Error as exc:
        print("FULL", type(exc).__name__, exc, flush=True)
        break
    print(cur.lastrowid, flush=True)
time.sleep(60)  # hold the connection until the parent kills us
"""

RECOVERY = r"""
import os, sqlite3, sys
path, reserve, stop_after_prune, pragmas = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4:]
if os.path.exists(reserve):
    os.remove(reserve)
db = sqlite3.connect(path, isolation_level=None)
for p in pragmas:
    db.execute(p)
lo, n = db.execute("SELECT MIN(seq), COUNT(*) FROM events").fetchone()
cut = lo + n // 2 - 1
pruned = 0
while True:
    db.execute("BEGIN")
    k = db.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events WHERE seq <= ? ORDER BY seq LIMIT 50)", (cut,)).rowcount
    db.execute("COMMIT")
    pruned += k
    if k == 0:
        break
print("PRUNED", pruned, flush=True)
if stop_after_prune:
    import time; time.sleep(60)  # parent kills us here
while db.execute("PRAGMA freelist_count").fetchone()[0] > 0 and db.execute("PRAGMA auto_vacuum").fetchone()[0] == 2:
    db.execute("PRAGMA incremental_vacuum(32)").fetchall()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
db.close()
print("DONE", flush=True)
"""


def make_reserve(path):
    with open(path, "wb") as f:
        f.write(b"\0" * RESERVE_BYTES)


def run_writer(path):
    child = subprocess.Popen([sys.executable, "-I", "-c", WRITER, path, *PRAGMAS],
                             stdout=subprocess.PIPE, text=True)
    first = last = None
    err = None
    for line in child.stdout:
        if line.startswith("FULL"):
            err = line.strip()
            break
        last = int(line)
        first = first or last
    child.send_signal(signal.SIGKILL)
    child.wait()
    return first, last, err


def run_recovery(path, reserve, kill_after_prune):
    child = subprocess.Popen([sys.executable, "-I", "-c", RECOVERY, path, reserve,
                              "1" if kill_after_prune else "0", *PRAGMAS],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    pruned, done = None, False
    for line in child.stdout:
        if line.startswith("PRUNED"):
            pruned = int(line.split()[1])
            if kill_after_prune:
                child.send_signal(signal.SIGKILL)
                break
        elif line.startswith("DONE"):
            done = True
    child.wait()
    err = child.stderr.read().strip()
    if done:
        # The recovery script only touches the reserve path; the parent fills
        # it, so a full disk shows up here as an OSError.
        try:
            make_reserve(reserve)
            reserve_ok = "ok"
        except OSError as exc:
            reserve_ok = f"{type(exc).__name__}: {exc}"
            if os.path.exists(reserve):
                os.remove(reserve)
    else:
        reserve_ok = "not reached"
    return pruned, done, reserve_ok, err[-300:] if err else None


def state(path, last_acked):
    db = sqlite3.connect(path)
    integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
    lo, hi, n = db.execute("SELECT MIN(seq), MAX(seq), COUNT(*) FROM events").fetchone()
    db.close()
    return {"integrity": integrity, "min": lo, "max": hi, "count": n,
            "contiguous": hi is not None and hi - lo + 1 == n,
            "acked_present": hi is not None and hi >= last_acked}


def scenario(mount, auto_vacuum, kill_round):
    path = os.path.join(mount, "events.db")
    reserve = os.path.join(mount, "reserve.bin")
    for name in os.listdir(mount):
        os.remove(os.path.join(mount, name))
    make_reserve(reserve)
    db = sqlite3.connect(path, isolation_level=None)
    if auto_vacuum:
        db.execute("PRAGMA auto_vacuum=INCREMENTAL")  # must precede the first table
    db.execute("CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, native BLOB NOT NULL)")
    db.close()

    rounds, prev_pruned = [], None
    for r in range(1, ROUNDS + 1):
        first, last, werr = run_writer(path)
        written = 0 if first is None else last - first + 1
        row = {"round": r, "written": written, "seq": [first, last], "writer": werr}
        row["capacity_regained"] = prev_pruned is None or 2 * written >= prev_pruned
        if r == kill_round:
            pruned, done, reserve_ok, rerr = run_recovery(path, reserve, kill_after_prune=True)
            row["recovery_killed_after_prune"] = pruned
        pruned, done, reserve_ok, rerr = run_recovery(path, reserve, kill_after_prune=False)
        st = state(path, last or 0)
        row.update({"pruned": pruned, "recovery_done": done, "reserve": reserve_ok,
                    "recovery_error": rerr, **st,
                    "fs_free": os.statvfs(mount).f_bavail * os.statvfs(mount).f_frsize})
        if r == kill_round:
            row["pruned"] = (row.get("recovery_killed_after_prune") or 0) + (pruned or 0)
        row["pass"] = (done and reserve_ok == "ok" and st["integrity"] == "ok"
                       and st["contiguous"] and st["acked_present"] and row["capacity_regained"])
        rounds.append(row)
        prev_pruned = row["pruned"]
    return {"auto_vacuum": "INCREMENTAL" if auto_vacuum else "NONE",
            "recovery_killed_in_round": kill_round, "rounds": rounds,
            "pass": all(x["pass"] for x in rounds)}


def main():
    mount = tempfile.mkdtemp(prefix="otsec-e04-")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=4m", "tmpfs", mount], check=True)
    try:
        results = [scenario(mount, av, kill) for av in (False, True) for kill in (None, 2)]
    finally:
        subprocess.run(["umount", mount], check=False)
        os.rmdir(mount)
    print(json.dumps({
        "experiment": "E-04 startup recovery over repeated exhaustion",
        "classification": "simulated",
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "scenarios": results,
    }, indent=2))


if __name__ == "__main__":
    main()
