"""Phase 0 experiment E-02: is every acknowledged commit synced to disk first?

Question (reviews A5 E-A5-1; R8.7, V-S6): E-A5-1 kills the writer with SIGKILL,
which leaves the OS page cache intact, so it cannot tell a commit that reached
the disk from one that only reached the page cache. A power cut can. This
experiment checks the precondition for power-loss durability directly: between
any two acknowledgements, did the writer call fsync or fdatasync?

Method: run A5's experiment writer (`p0 writer`, which prints each committed
sequence to stdout as its acknowledgement) under strace for a fixed time, then
count acknowledgements (writes to fd 1) not preceded by a successful sync
since the previous acknowledgement. A count above zero means those
acknowledged events could be lost on power failure.

Classification: simulated (container, strace). Shows the sync ordering only;
whether the storage device honours the sync needs hardware (H-11).

Run (needs strace and A5's binary built from platform/experiments/phase0):
  python3 -I tests/integration/experiments/fsync_before_ack.py /path/to/p0
"""

import json
import os
import re
import subprocess
import sys
import tempfile

SYNC = re.compile(r"\b(fsync|fdatasync)\(\d+\)\s+=\s+0")
ACK = re.compile(r"\bwrite\(1,")


def analyse(trace_path):
    acks = syncs = unsynced = run = max_run = 0
    synced_since_ack = False
    with open(trace_path) as f:
        for line in f:
            if SYNC.search(line):
                syncs += 1
                synced_since_ack = True
                run = 0
            elif ACK.search(line):
                acks += 1
                if not synced_since_ack:
                    unsynced += 1
                synced_since_ack = False
                run += 1
                max_run = max(max_run, run)
    return {"acks": acks, "syncs": syncs, "acks_without_sync": unsynced,
            "max_acks_between_syncs": max_run}


def main():
    binary = sys.argv[1]
    results = []
    with tempfile.TemporaryDirectory() as tmp:
        for mode in ("NORMAL", "FULL"):
            db, trace = os.path.join(tmp, f"{mode}.db"), os.path.join(tmp, f"{mode}.trace")
            subprocess.run(
                ["timeout", "-s", "KILL", "1.5", "strace", "-f", "-qq",
                 "-e", "trace=write,fsync,fdatasync", "-o", trace,
                 binary, "writer", "-db", db, "-sync", mode, "-batch", "1"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            results.append({"synchronous": mode, **analyse(trace)})
    print(json.dumps({"experiment": "E-02 fsync before acknowledgement",
                      "classification": "simulated", "writer": "A5 p0 writer, batch 1",
                      "results": results}, indent=2))


if __name__ == "__main__":
    main()
