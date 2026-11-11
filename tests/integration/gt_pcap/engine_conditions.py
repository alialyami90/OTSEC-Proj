"""What an engine's output must show on each GT-PCAP capture it runs over (D6, P4-4-R1).

Brief P4-4-S2 runs candidate engines over GT-PCAP offline, and its table is
judged by pass conditions that D6 commits first. This file derives them from
the committed label files and from nothing else: no engine was run to write
them, and no engine's output is read here. The rules that turn a label row
into a condition are in docs/phase4/D6-engine-run-pass-conditions.md.

One row per thing an engine must show:

- `protocol`: one per `flow` label row. A record of the engine's, tied to
  the flow by its transport and both (address, port) ends, names the row's
  protocol (the `protocol` column: dnp3 or modbus).
- `service`: one per `service` label row. That protocol is attributed to
  the server end (address, transport, port).
- `function`: one per `function` label row. A record tied to the flow shows
  the request's function code. `objects` are reported beside it.
- `g120`: for each `function` label row of a capture whose labels show
  Secure Authentication in use, one row per message that decides the row's
  `sa`. `show` names the message, as <function code>:<object> from <sender>,
  or says that the exchange holds no group 120 object. A failed exchange
  has two rows: the challenge or aggressive-mode request, and the error.

The captures are the DNP3 ones named in LABEL_DIR/dnp3-cases.json, and the
derived Modbus/TCP capture on a moved port, whose label is beside that
folder (EXTRA).

Usage: python engine_conditions.py LABEL_DIR OUT.tsv
"""

import csv
import json
import os
import sys

COLUMNS = ["capture", "condition", "l4", "src", "sport", "dst", "dport", "code", "objects", "sa", "show", "frames",
           "protocol", "direction"]
# The derived Modbus/TCP capture on a moved port: its label, from LABEL_DIR.
EXTRA = {"modbus-moved-port": os.path.join("..", "modbus", "modbus-moved-port.tsv")}
SA_OUTCOMES = ("challenged", "aggressive", "failed")
NO_G120 = "no group 120 object between the request and its response"


def read_labels(path):
    with open(path, encoding="utf-8", newline="") as f:
        lines = [ln for ln in f.read().split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def holds_sa(rows):
    """Whether a capture's labels show Secure Authentication in use: any
    function row whose sa is challenged, aggressive or failed. Every function
    row of such a capture gets its g120 rows, the unchallenged ones too."""
    return any(r["kind"] == "function" and r["sa"] in SA_OUTCOMES for r in rows)


def g120_shows(row):
    """The messages that decide a function row's sa (C13 section 4.3), one
    per g120 row, from the row's own columns. A failed exchange is a
    challenge, or an aggressive-mode request, followed by the error, so it
    asks for both."""
    master, outstation = row["src"], row["dst"]
    challenge = f"131:g120v1 from {outstation}"
    aggressive = f"{row['code']}:g120v3 from {master}"
    if row["sa"] == "challenged":
        return [challenge]
    if row["sa"] == "aggressive":
        return [aggressive]
    if row["sa"] == "failed":
        code, sender = ("33", master) if row["sa_error_from"] == "master" else ("131", outstation)
        first = aggressive if "g120v3" in row["objects"].split(",") else challenge
        return [first, f"{code}:g120v7 from {sender}"]
    if row["sa"] == "none":
        return [NO_G120]
    raise ValueError(f"a function row with sa {row['sa']!r} in a capture that holds Secure Authentication")


def conditions(label_dir):
    with open(os.path.join(label_dir, "dnp3-cases.json"), encoding="utf-8") as f:
        meta = json.load(f)
    out = []
    paths = {name: name + ".tsv" for name in list(meta["series"]) + list(meta["cases"])}
    for name, path in sorted({**paths, **EXTRA}.items()):
        rows = read_labels(os.path.join(label_dir, path))
        sa = holds_sa(rows)
        for r in rows:
            if r["protocol"] not in ("dnp3", "modbus") or r["kind"] not in ("flow", "service", "function"):
                continue
            base = [name, {"flow": "protocol"}.get(r["kind"], r["kind"]), r["l4"], r["src"], r["sport"], r["dst"],
                    r["dport"], r["code"], r["objects"], r["sa"]]
            # A flow row lists every frame; the condition needs none of them.
            out.append(base + ["", "" if r["kind"] == "flow" else r["frames"], r["protocol"], r["direction"]])
            if r["kind"] == "function" and sa:
                out += [[name, "g120", *base[2:], show, r["frames"], r["protocol"], r["direction"]]
                        for show in g120_shows(r)]
    return out


def render(rows):
    return "\n".join(["\t".join(COLUMNS)] + ["\t".join(r) for r in rows]) + "\n"


def main(label_dir, out_path):
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(conditions(label_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
