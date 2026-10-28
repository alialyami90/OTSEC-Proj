"""Counts the settings of each SEL-751 SHOW class from S22's settings sheets
and bounds the bytes of each SHO reply (register revision 5, P4-A2).

Run: python3 -I count_settings.py <751_IM_20260910.txt>

Input: the owner-supplied text of S22 (SEL-751 Instruction Manual, date code
20260910), "SEL-751 Settings Sheets" (pages SET.1 to SET.114). The sheets
list every setting the relay has, with a line that ends in "NAME :=".

What is counted: the lines that end in "NAME :=". A name may appear on more
than one sheet (settings whose range depends on the model), and a reply
prints only the ones the model shows, so the count is an upper bound on the
settings a reply can hold, not a prediction for any model. Settings the
sheets mark "(SELOGIC)" are counted as equations; every other setting is
counted as a short value.

What is assumed, and cannot be read from S22 as a number (documented-untested,
H-13 can settle them with a capture):

  NAME_MAX   16   a setting name is at most 16 characters (C9's settingName).
  VALUE_OTHER 64  the longest printed value that is not an equation: an
                  ALIAS setting holds a Relay Word bit and three texts of at
                  most 15 characters (S22 Relay Word Bit Aliases, SET.97).
  VALUE_SELOGIC 384  an equation holds at most 15 elements and 14 pairs of
                  parentheses (S22 Section 4, SELOGIC Control Equations,
                  p. 4.215). 15 elements of 16 characters, 14 operators of up
                  to 5 characters with their spaces, 28 parentheses with
                  their spaces: 240 + 70 + 56 = 366, rounded up.
  OVERHEAD    6   " := " and CR LF around each setting (the relay prints
                  more than one setting per line, which only shortens this).
  HEADINGS 4096   the headings, blank lines and the reply's own header.

A reply that exceeds its bound is not a configuration the rule may read: it
fails the read and keeps its bytes (C2, C9).
"""

import collections
import re
import sys

NAME_MAX, VALUE_OTHER, VALUE_SELOGIC, OVERHEAD, HEADINGS = 16, 64, 384, 6, 4096

# (key, command, sheet class, how many times the sheet class repeats)
FORMS = [
    ("group.1", "SHO 1", "group", 1), ("group.2", "SHO 2", "group", 1),
    ("group.3", "SHO 3", "group", 1), ("group.4", "SHO 4", "group", 1),
    ("logic.1", "SHO L 1", "logic", 1), ("logic.2", "SHO L 2", "logic", 1),
    ("logic.3", "SHO L 3", "logic", 1), ("logic.4", "SHO L 4", "logic", 1),
    ("global", "SHO G", "global", 1),
    ("port.f", "SHO P F", "port.f", 1), ("port.1", "SHO P 1", "port.1", 1),
    ("port.2", "SHO P 2", "port.2", 1), ("port.3", "SHO P 3", "port.3", 1),
    ("port.4", "SHO P 4", "port.4", 1),
    ("report", "SHO R", "report", 1), ("front-panel", "SHO F", "front-panel", 1),
    ("modbus", "SHO M", "modbus", 1), ("iec-103", "SHO I", "iec-103", 1),
    ("eip.1", "SHO E 1", "eip", 1), ("eip.2", "SHO E 2", "eip", 1), ("eip.3", "SHO E 3", "eip", 1),
    ("dnp.1", "SHO DNP 1", "dnp", 1), ("dnp.2", "SHO DNP 2", "dnp", 1), ("dnp.3", "SHO DNP 3", "dnp", 1),
]

SHEETS = [
    ("Group Settings (SET Command)", "group"),
    ("Logic Settings (SET L Command)", "logic"),
    ("Global Settings (SET G Command)", "global"),
    ("Front-Panel Settings (SET F Command)", "front-panel"),
    ("Touchscreen Settings", "touchscreen"),
    ("Report Settings (SET R Command)", "report"),
    ("Modbus Map Settings (SET M Command)", "modbus"),
    ("EtherNet/IP Assembly Map Settings (SET E Command)", "eip"),
    ("DNP3 Map Settings (SET DNP n Command)", "dnp"),
    ("IEC 60870-5-103 Map Settings (SET I Command)", "iec-103"),
]

DEF = re.compile(r"(?:^|\s)([A-Za-z0-9_]+) *:= *$")


def sheet_lines(path):
    lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    first = next(i for i, l in enumerate(lines) if l.strip() == "Group Settings (SET Command)" and "Identifier" in lines[i + 1])
    last = max(i for i, l in enumerate(lines) if re.search(r"SEL-751 Settings Sheets", l) and re.search(r"SET\.11\d", l))
    return lines, first, last


def count(path):
    lines, first, last = sheet_lines(path)
    pages = [i for i in range(first, last + 1)
             if re.search(r"SEL-751 Settings Sheets", lines[i]) and re.search(r"SET\.\d+", lines[i])]
    bounds = [first] + pages + [last + 1]
    out = collections.defaultdict(lambda: collections.defaultdict(list))
    cur = "group"
    for a, b in zip(bounds, bounds[1:]):
        head = re.sub(r"\s+", " ", " ".join(lines[a:a + 3]))
        for key, cls in SHEETS:
            if key in head:
                cur = cls
        m = re.search(r"PORT ([F1-4])\b", head)
        if "SET PORT p" in head and m:
            cur = "port." + m.group(1).lower()
        prev = a
        for i in range(a, b):
            m = DEF.search(lines[i])
            if not m:
                continue
            label = " ".join(lines[prev:i + 1])
            out[cur][m.group(1)].append("SELOGIC" in label or cur == "logic")
            prev = i + 1
    return out


# The most one read can print, with the transcript cap T (bytes): see the
# record bound in docs/phase4/B2-register-rev5.md.
SNAPSHOT_FIXED, SNAPSHOT_PER_SETTING = 5348, 25 + NAME_MAX


def main():
    cls = count(sys.argv[1])
    print("| Form | Class | Names | Equations | Bound (bytes) |")
    print("| --- | --- | ---: | ---: | ---: |")
    total = 0
    for key, cmd, sheet, _ in FORMS:
        names = cls[sheet]
        n = len(names)
        eq = sum(1 for v in names.values() if any(v))
        bound = HEADINGS + eq * (NAME_MAX + OVERHEAD + VALUE_SELOGIC) + (n - eq) * (NAME_MAX + OVERHEAD + VALUE_OTHER)
        total += bound
        print("| `%s` | %s | %d | %d | %d |" % (cmd, key, n, eq, bound))
    print("| all 24 forms | | %d | | %d |" % (sum(len(cls[s]) for _, _, s, _ in FORMS), total))
    n = sum(len(cls[s]) for _, _, s, _ in FORMS)
    print("\nSnapshot bytes beyond the printed values: %d + %d x %d = %d" % (
        SNAPSHOT_FIXED, n, SNAPSHOT_PER_SETTING, SNAPSHOT_FIXED + n * SNAPSHOT_PER_SETTING))
    print("\nTouchscreen settings on the sheets, in no SHO form (Table 7.67): %d" % len(cls["touchscreen"]))


if __name__ == "__main__":
    main()
