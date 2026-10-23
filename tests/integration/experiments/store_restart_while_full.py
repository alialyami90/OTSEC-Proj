"""Phase 0 experiment E-03: can the event store restart while its disk is full?

Question (challenges R8.7, R8.8, V-S9; reviews A5 E-A5-3): A5's E-A5-3 shows
recovery from a full filesystem when the writer stays up and a reserve file
is released. A site node can also crash or reboot while the disk is full. On
restart, with no space freed, can a new process open the SQLite WAL store,
read every acknowledged event (so the forwarder can drain), pass
integrity_check, and delete already-forwarded rows to make room?

Method: mount a 4 MiB tmpfs. A child process commits one event per
transaction (WAL, synchronous=FULL) until SQLITE_FULL, reports its last
acknowledged sequence, and is SIGKILLed while still holding the connection.
A fresh process then opens the store with the disk still full and attempts,
in order: open, count/max read, integrity_check, a forwarder-style range
read, and deleting the oldest 50 rows in one transaction. Run for A5's
default and bounded-WAL settings.

Classification: simulated. Uses Python's sqlite3 module (SQLite 3.45 here),
not A5's Go driver (modernc.org/sqlite); the engine is the same SQLite code
base, the binding is independent. Needs root (mounts tmpfs).

Run: sudo python3 -I tests/integration/experiments/store_restart_while_full.py
"""

import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile

PAYLOAD = b"x" * 368  # same per-event size as A5's experiment
CONFIGS = {
    "default-wal": [],
    "bounded-wal": ["PRAGMA wal_autocheckpoint=64", "PRAGMA journal_size_limit=262144"],
}

WRITER = r"""
import sqlite3, sys, time
path, pragmas = sys.argv[1], sys.argv[2:]
db = sqlite3.connect(path, isolation_level=None)
for p in ["PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL"] + pragmas:
    db.execute(p)
db.execute("CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, native BLOB NOT NULL)")
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


def step(results, name, fn):
    try:
        results[name] = {"ok": True, "value": fn()}
    except Exception as exc:  # noqa: BLE001 - every failure is a result here
        results[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def trial(mount, config):
    path = os.path.join(mount, "events.db")
    for s in ("", "-wal", "-shm"):
        if os.path.exists(path + s):
            os.remove(path + s)
    child = subprocess.Popen([sys.executable, "-I", "-c", WRITER, path, *CONFIGS[config]],
                             stdout=subprocess.PIPE, text=True)
    acked, full_error = 0, None
    for line in child.stdout:
        if line.startswith("FULL"):
            full_error = line.strip()
            break
        acked = int(line)
    child.send_signal(signal.SIGKILL)
    child.wait()

    st = os.statvfs(mount)
    res = {"config": config, "acked": acked, "writer_error": full_error,
           "free_bytes_at_restart": st.f_bavail * st.f_frsize,
           "files": {s or "db": os.path.getsize(path + s)
                     for s in ("", "-wal", "-shm") if os.path.exists(path + s)}}
    steps = {}
    db = None

    def do_open():
        nonlocal db
        db = sqlite3.connect(path, isolation_level=None)
        return db.execute("PRAGMA journal_mode").fetchone()[0]

    step(steps, "open", do_open)
    if db is not None:
        step(steps, "count_max", lambda: list(db.execute("SELECT COUNT(*), MAX(seq) FROM events").fetchone()))
        step(steps, "integrity", lambda: db.execute("PRAGMA integrity_check").fetchone()[0])
        step(steps, "forwarder_read", lambda: len(db.execute(
            "SELECT seq, native FROM events WHERE seq > ? ORDER BY seq", (acked // 2,)).fetchall()))

        def prune():
            db.execute("BEGIN")
            db.execute("DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY seq LIMIT 50)")
            db.execute("COMMIT")
            return 50

        step(steps, "prune_50_forwarded", prune)
        if not steps["prune_50_forwarded"]["ok"]:
            try:
                db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        db.close()
    res["steps"] = steps
    cm = steps.get("count_max", {})
    res["acked_events_readable"] = bool(cm.get("ok")) and cm["value"][1] is not None and cm["value"][1] >= acked
    return res


def main():
    mount = tempfile.mkdtemp(prefix="otsec-e03-")
    subprocess.run(["mount", "-t", "tmpfs", "-o", "size=4m", "tmpfs", mount], check=True)
    try:
        trials = [trial(mount, c) for c in CONFIGS for _ in range(3)]
    finally:
        subprocess.run(["umount", mount], check=False)
        os.rmdir(mount)
    print(json.dumps({
        "experiment": "E-03 store restart while disk full",
        "classification": "simulated",
        "python": sys.version.split()[0],
        "sqlite": sqlite3.sqlite_version,
        "trials": trials,
    }, indent=2))


if __name__ == "__main__":
    main()
