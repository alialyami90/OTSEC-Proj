"""H-14 part 1 (Windows E-02): the writer whose file I/O is traced.

Run as the non-admin account, inside an ETW Kernel-File trace started by
run_h14.ps1. It commits one event per transaction to a WAL store and, after
each commit returns (the acknowledgement), creates an empty marker file
`ack-NNNNNN`. A Create event always reaches ETW with its file name, so the
markers cut the trace into one interval per acknowledgement without relying on
clocks. flush_analyse.py then counts intervals with no FlushFileBuffers on the
WAL.

Two positive controls bracket the run: a write plus os.fsync (FlushFileBuffers
via the C runtime) on `control-begin.bin` and `control-end.bin`. If the trace
does not show those two flushes, the trace or the parser is wrong and the run
is inconclusive, not a pass.

Uses Python's sqlite3 (SQLite's own win32 VFS), not product or A5 code. The
pragmas are ADR-0004's bounded-WAL settings.

Run: python -I flush_writer.py <work-dir> <FULL|NORMAL|OFF> <acks>
"""

import ctypes
import json
import os
import sqlite3
import sys

PAYLOAD = b"x" * 368
PRAGMAS = ["PRAGMA journal_mode=WAL", "PRAGMA wal_autocheckpoint=64",
           "PRAGMA journal_size_limit=262144"]


def identity():
    out = {"pid": os.getpid()}
    if os.name == "nt":
        buf = ctypes.create_unicode_buffer(257)
        size = ctypes.c_uint32(len(buf))
        ctypes.windll.advapi32.GetUserNameW(buf, ctypes.byref(size))
        out["user"] = buf.value
        # True only for an elevated token in the Administrators group.
        out["is_admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    else:
        out["user"] = str(os.getuid())
        out["is_admin"] = os.geteuid() == 0
    return out


def control(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0))
    try:
        os.write(fd, b"control")
        os.fsync(fd)
    finally:
        os.close(fd)


def mark(workdir, i):
    open(os.path.join(workdir, f"ack-{i:06d}"), "xb").close()


def main():
    workdir, mode, acks = sys.argv[1], sys.argv[2].upper(), int(sys.argv[3])
    assert mode in ("FULL", "NORMAL", "OFF")
    os.makedirs(workdir, exist_ok=True)
    info = identity()
    info.update({"mode": mode, "acks": acks, "sqlite": sqlite3.sqlite_version,
                 "python": sys.version.split()[0]})

    control(os.path.join(workdir, "control-begin.bin"))
    db = sqlite3.connect(os.path.join(workdir, "events.db"), isolation_level=None)
    for p in PRAGMAS + [f"PRAGMA synchronous={mode}"]:
        db.execute(p)
    db.execute("CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, native BLOB NOT NULL)")
    info["synchronous"] = db.execute("PRAGMA synchronous").fetchone()[0]
    info["journal_mode"] = db.execute("PRAGMA journal_mode").fetchone()[0]

    mark(workdir, 0)
    for i in range(1, acks + 1):
        db.execute("BEGIN")
        db.execute("INSERT INTO events(native) VALUES (?)", (PAYLOAD,))
        db.execute("COMMIT")
        mark(workdir, i)  # acknowledgement i
    db.close()
    control(os.path.join(workdir, "control-end.bin"))

    with open(os.path.join(workdir, "writer.json"), "w") as f:
        json.dump(info, f, indent=2)
    print(json.dumps(info))


if __name__ == "__main__":
    main()
