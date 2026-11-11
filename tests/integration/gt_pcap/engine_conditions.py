"""What an engine's output must show on each GT-PCAP DNP3 capture (D6, P4-4-R1).

Brief P4-4-S2 runs candidate engines over GT-PCAP offline, and its table is
judged by pass conditions that D6 commits first. This file derives them from
the committed label files and from nothing else: no engine was run to write
them, and no engine's output is read here. The rules that turn a label row
into a condition are in docs/phase4/D6-engine-run-pass-conditions.md.

One row per thing an engine must show:

- `protocol`: one per `flow` label row. A record of the engine's, tied to
  the flow by its transport and both (address, port) ends, names DNP3.
- `service`: one per `service` label row. DNP3 is attributed to that server
  end (address, transport, port).
- `function`: one per `function` label row. A record tied to the flow shows
  the request's function code. `objects` are reported beside it.
- `g120`: one per `function` label row of the five dnp3-sa captures. `show`
  lists each message that decides the row's `sa`, as <function code>:<object>
  from <sender>, or says that the exchange holds no group 120 object.

Usage: python engine_conditions.py LABEL_DIR OUT.tsv
"""

import csv
import json
import os
import sys

COLUMNS = ["capture", "condition", "l4", "src", "sport", "dst", "dport", "code", "objects", "sa", "show", "frames"]
SA_CAPTURES = ("dnp3-sa", "dnp3-sa-failed-outstation", "dnp3-sa-failed-before-ack",
               "dnp3-sa-failed-unauthorized", "dnp3-sa-failed-master")


def read_labels(path):
    with open(path, encoding="utf-8", newline="") as f:
        lines = [ln for ln in f.read().split("\n") if ln and not ln.startswith("#")]
    return list(csv.DictReader(lines, delimiter="\t", quoting=csv.QUOTE_NONE))


def g120_show(row):
    """The messages that decide a function row's sa (C13 section 4.3), from
    the row's own columns."""
    master, outstation = row["src"], row["dst"]
    if row["sa"] == "challenged":
        return f"131:g120v1 from {outstation}"
    if row["sa"] == "aggressive":
        return f"{row['code']}:g120v3 from {master}"
    if row["sa"] == "failed":
        code, sender = ("33", master) if row["sa_error_from"] == "master" else ("131", outstation)
        return f"{code}:g120v7 from {sender}"
    if row["sa"] == "none":
        return "no group 120 object between the request and its response"
    raise ValueError(f"a dnp3-sa function row with sa {row['sa']!r}")


def conditions(label_dir):
    with open(os.path.join(label_dir, "dnp3-cases.json"), encoding="utf-8") as f:
        meta = json.load(f)
    out = []
    for name in sorted(list(meta["series"]) + list(meta["cases"])):
        for r in read_labels(os.path.join(label_dir, name + ".tsv")):
            if r["protocol"] != "dnp3" or r["kind"] not in ("flow", "service", "function"):
                continue
            base = [name, {"flow": "protocol"}.get(r["kind"], r["kind"]), r["l4"], r["src"], r["sport"], r["dst"],
                    r["dport"], r["code"], r["objects"], r["sa"]]
            # A flow row lists every frame; the condition needs none of them.
            out.append(base + ["", "" if r["kind"] == "flow" else r["frames"]])
            if r["kind"] == "function" and name in SA_CAPTURES:
                out.append([name, "g120", *base[2:], g120_show(r), r["frames"]])
    return out


def render(rows):
    return "\n".join(["\t".join(COLUMNS)] + ["\t".join(r) for r in rows]) + "\n"


def main(label_dir, out_path):
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(conditions(label_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
