"""Check run.sh's prp-engines.md and exit code against the recorded result (P4-SENSOR-EVAL-GREEN).

The recorded result is prp-engines.recorded.md beside this script: the
table, its closing line and run.sh's exit code from run 45081194524. Every
cell of every row is compared, keyed by (capture, engine); no field is left
out. run.sh exits 1 when a row is not run or fails, which is the recorded
result; a stage before compare.py that fails (the tshark pin, a capture's
hash, docker) also exits non-zero but writes no table, so it reads as missing.

It prints "same as the recorded result" and exits 0 when equal. Otherwise
it prints each difference and exits 1; a missing, empty or unreadable file
is a difference. Usage: python3 -I prp_recorded.py PRP_ENGINES_MD RUN_SH_EXIT
"""
import os
import re
import sys

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prp-engines.recorded.md")
CLOSING = re.compile(r"^(\d+ row\(s\) not run or failed\.|Every row passes\.)$")
EXIT = re.compile(r"^run\.sh exit code: (\d+)$")


def parse(text):
    """The header, the rows by (capture, engine), the closing line and the exit line."""
    lines = text.splitlines()
    table = [l for l in lines if l.startswith("|")]
    rows = {}
    for l in table[2:]:
        cells = [c.strip() for c in l.strip("|").split("|")]
        rows[(cells[0], cells[1] if len(cells) > 1 else "")] = l
    closing = [l for l in lines if CLOSING.match(l)]
    code = [EXIT.match(l).group(1) for l in lines if EXIT.match(l)]
    return (table[0] if table else None), rows, closing, code


def check(path, code, recorded=RECORDED):
    with open(recorded, encoding="utf-8") as f:
        w_head, w_rows, w_close, w_code = parse(f.read())
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, ValueError) as e:
        return [f"{path}: missing or unreadable ({e.__class__.__name__}: {e})"]
    g_head, g_rows, g_close, _ = parse(text)
    if not text.strip() or g_head is None:
        return [f"{path}: empty or has no table"]
    out = [] if g_head == w_head else [f"header: {g_head} (recorded {w_head})"]
    for k, w in w_rows.items():
        g = g_rows.get(k)
        if g is None:
            out.append(f"row {k[0]} / {k[1]}: missing (recorded {w})")
        elif g != w:
            out.append(f"row {k[0]} / {k[1]}: {g} (recorded {w})")
    out += [f"row {k[0]} / {k[1]}: added ({g})" for k, g in g_rows.items() if k not in w_rows]
    if g_close != w_close:
        out.append(f"closing line: {g_close} (recorded {w_close})")
    if [str(code)] != w_code:
        out.append(f"run.sh exit code: {code} (recorded {w_code[0] if w_code else None})")
    return out


def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    d = check(argv[1], argv[2])
    for line in d:
        print("DIFFERS: " + line)
    print(f"prp-engines.md: {len(d)} difference(s) from the recorded result." if d
          else "prp-engines.md: same as the recorded result (run 45081194524).")
    return 1 if d else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
