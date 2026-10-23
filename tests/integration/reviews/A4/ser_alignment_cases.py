"""A6 review of A4's SER snapshot alignment (V-S4, C-13), PR #4.

Builds consecutive SEL-751 `SER` reads from A6's transcription of Figure 10.16
(tests/safety/recording_simulator/documented/sel-751/ser-fig-10-16.txt) and
states the expected result of each case by hand (GT-HAND). The expected
results never come from the code under review; A4's `align` is loaded from a
path only to be scored against them.

Documented fact the cases rest on: in the SEL-751 SER report "Row 1 is the
most recently triggered row" (IM 20260910 Table 7.63, p. 7.75), and Figure
10.16 prints rows oldest first, numbered down to 1. So each new event
renumbers every row already shown. Column layout after renumbering (for
example row 10) is ASSUMED to keep the date column where it is.

Run: python3 -I tests/integration/reviews/A4/ser_alignment_cases.py <path to align.py> [<path to sel_ser.py>]
With sel_ser.py, the reads are also rendered as whole SER reports and keyed by
A4's own parse_report and alignment_key (DATE_F = MDY), end to end.
Classification: simulated (documented-example input).
"""

import hashlib
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(HERE, "..", "..", "..", "safety", "recording_simulator",
                   "documented", "sel-751", "ser-fig-10-16.txt")
ROW = re.compile(r"^(\d+)(\s+)(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}\.\d{3}\s+\S+\s+\S.*)$")


def documented_rows():
    """Figure 10.16 rows, oldest first, without their row numbers."""
    with open(FIG) as f:
        return [ROW.match(line.rstrip("\r\n")).group(3) for line in f if ROW.match(line.rstrip("\r\n"))]


def render(events):
    """A SER report body for events listed oldest first: row 1 is the newest."""
    n = len(events)
    return [f"{n - i:<6}{body}" for i, body in enumerate(events)]


def new_event(k):
    return f"02/28/2007   13:55:{k:02d}.000   IN10{k % 10}                    Asserted"


def whole_line(line):
    return hashlib.sha256(line.encode()).hexdigest()  # A4's record_digest: the native row bytes


def without_row_number(line):
    return hashlib.sha256(ROW.match(line).group(3).encode()).hexdigest()


def cases():
    doc = documented_rows()
    extra = [new_event(k) for k in range(1, 6)]
    return [
        {"id": "A1-no-new-events", "prev": render(doc), "new": render(doc),
         "expect": "ok", "expect_added": []},
        {"id": "A2-one-new-event-renumbers-all-rows", "prev": render(doc), "new": render(doc + extra[:1]),
         "expect": "ok", "expect_added": extra[:1]},
        {"id": "A3-row-number-gains-a-digit", "prev": render(doc + extra[:1]), "new": render(doc + extra[:3]),
         "expect": "ok", "expect_added": extra[1:3]},
        {"id": "A4-buffer-full-oldest-dropped", "prev": render(doc), "new": render(doc[2:] + extra[:2]),
         "expect": "ok", "expect_added": extra[:2]},
        {"id": "A5-buffer-cleared-then-one-event", "prev": render(doc), "new": render(extra[:1]),
         "expect": "gap", "expect_added": extra[:1]},
        {"id": "A6-window-shorter-than-new-events (SEL-400 default 20 rows)", "prev": render(doc[:4]),
         "new": render(extra[1:5]), "expect": "gap", "expect_added": extra[1:5]},
        # Two identical rows (same element, state, and millisecond), then one
        # new row. Overlap 2 or 1 both fit; V-S4 and R-A4-2: keep the larger
        # added set ([r, y]) and flag, never drop a row that may be new.
        {"id": "A7-identical-rows-ambiguous", "prev": render([doc[0], doc[0]]),
         "new": render([doc[0], doc[0], extra[0]]), "expect": "ambiguous", "expect_added": [doc[0], extra[0]]},
    ]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_align(path):
    return load(path, "a4_align").align


LABEL = "#        DATE          TIME               ELEMENT             STATE"


def a4_keys(sel_ser):
    """Key each row by A4's parser and key function, from a whole report."""
    def keys(lines):
        raw = ("\r\n".join([LABEL] + lines + ["=>"]) + "\r\n").encode()
        _, items = sel_ser.parse_report(raw, "MDY")
        assert len(items) == len(lines) and all(i["type"] == "row" for i in items), items
        return [sel_ser.alignment_key(i) for i in items]
    return keys


def score(align, key=None, keys=None):
    keys = keys or (lambda lines: [key(x) for x in lines])
    out = []
    for c in cases():
        prev_keys = keys(c["prev"])
        new_keys = keys(c["new"])
        status, added_keys = align(prev_keys, new_keys)
        by_key = {}
        for k, line in zip(new_keys, c["new"]):
            by_key.setdefault(k, ROW.match(line).group(3))
        added = [by_key[k] for k in added_keys]
        out.append({"case": c["id"], "expect": c["expect"], "got": status,
                    "expect_added": len(c["expect_added"]), "got_added": len(added),
                    "pass": status == c["expect"] and added == c["expect_added"]})
    return out


def main(path, sel_ser_path=None):
    align = load_align(path)
    result = {"reviewed": path, "classification": "simulated",
              "keys": {name: score(align, fn) for name, fn in
                       (("whole-line digest (A4 record_digest)", whole_line),
                        ("digest without the row number", without_row_number))}}
    if sel_ser_path:
        result["keys"]["A4 parse_report + alignment_key, end to end"] = score(
            align, keys=a4_keys(load(sel_ser_path, "a4_sel_ser")))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:3])
