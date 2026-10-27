"""Dry-run check only (not for main): read_live against a file replaced by
rename, beside the same loop with Python's plain open as the control."""
import json, os, sys, tempfile, threading
sys.path.insert(0, os.path.join(os.getcwd(), "tests", "integration", "slice"))
from slicerun import read_live


def plain(p):
    with open(p, "rb") as f:
        return f.read()


def trial(read):
    p = os.path.join(tempfile.mkdtemp(), "state.json")
    with open(p, "w") as f:
        json.dump({"n": 0}, f)
    stop, errs, reads = threading.Event(), {"read": 0, "replace": 0}, [0]
    first = []

    def reader():
        while not stop.is_set():
            try:
                json.loads(read(p))
                reads[0] += 1
            except Exception as e:
                errs["read"] += 1
                first.append(repr(e))
    t = threading.Thread(target=reader)
    t.start()
    for i in range(3000):
        tmp = p + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"n": i}, f)
        try:
            os.replace(tmp, p)
        except Exception as e:
            errs["replace"] += 1
            first.append(repr(e))
    stop.set()
    t.join()
    return reads[0], errs, first[:3]


for name, fn in (("plain open (control)", plain), ("read_live", read_live)):
    print(name, *trial(fn))
r, e, _ = trial(read_live)
sys.exit(1 if r == 0 or e["read"] or e["replace"] else 0)
