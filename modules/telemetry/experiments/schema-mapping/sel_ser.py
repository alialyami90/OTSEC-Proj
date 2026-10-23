"""Parse an SEL-751 ASCII SER report into rows, relay messages, and parse
errors. Throwaway experiment, not product code.

After the label line, every non-blank line up to the prompt becomes exactly
one item: a row, a relay message, or a parse error. Nothing is skipped, so a
report in an unexpected layout yields errors, never zero rows and a pass
(A2 review finding 1).
"""
import hashlib
import re

DATE_FORMATS = ("MDY", "YMD", "DMY")
LABEL = re.compile(rb"^#\s+DATE\s+TIME\s+ELEMENT\s+STATE\s*$")
PROMPT = re.compile(rb"^=+>")
ROW = re.compile(rb"^(\d+)\s+(\d{1,4}/\d{1,2}/\d{1,4})\s+(\d{2}:\d{2}:\d{2}\.\d{3})\s+(\S.*?)\s*$")
# Messages the relay adds to the SER (SEL-751 IM 20260910, p. 10.39). The
# manual does not show how they are laid out in a report, so they are matched
# as the whole remainder of a row and flagged as unconfirmed.
RELAY_MESSAGES = (b"Relay Powered Up", b"Relay Settings Changed")
ELEMENT_STATE = re.compile(rb"^(\S+)\s+(\S.*)$")


def parse_date(text, date_f):
    """Return (yyyy, mm, dd) as strings, or raise ValueError if the date does
    not fit DATE_F. DAT output in the manual is unpadded (7/29/2010) and the
    SER example is padded, so both are accepted."""
    a, b, c = text.split("/")
    if date_f == "MDY":
        m, d, y = a, b, c
    elif date_f == "DMY":
        d, m, y = a, b, c
    elif date_f == "YMD":
        y, m, d = a, b, c
    else:
        raise ValueError(f"unknown DATE_F {date_f!r}")
    if len(y) != 4 or not 1 <= int(m) <= 12 or not 1 <= int(d) <= 31:
        raise ValueError(f"date {text!r} does not fit DATE_F={date_f}")
    return y, m.zfill(2), d.zfill(2)


def parse_report(raw, date_f):
    """Return (header_bytes, items). Each item is a dict with type 'row',
    'relay-message' or 'parse-error', the byte offset and line, and fields."""
    if date_f not in DATE_FORMATS:
        raise ValueError("DATE_F must be read from the relay (SHO G) before parsing")
    lines, offset = [], 0
    for line in raw.split(b"\n"):
        lines.append((offset, line))
        offset += len(line) + 1
    label_at = next((i for i, (_, l) in enumerate(lines) if LABEL.match(l.rstrip(b"\r"))), None)
    if label_at is None:
        return raw, [{"type": "parse-error", "offset": 0, "line": raw, "reason": "no SER label line"}]
    header = raw[:lines[label_at][0] + len(lines[label_at][1]) + 1]
    items = []
    for off, line in lines[label_at + 1:]:
        text = line.rstrip(b"\r")
        if PROMPT.match(text):
            break
        if not text.strip():
            continue
        item = {"offset": off, "line": line}
        m = ROW.match(text)
        if not m:
            items.append({**item, "type": "parse-error", "reason": "line is not an SER row"})
            continue
        num, date, tod, rest = m.groups()
        try:
            y, mo, d = parse_date(date.decode(), date_f)
        except ValueError as exc:
            items.append({**item, "type": "parse-error", "reason": str(exc)})
            continue
        base = {"#": num.decode(), "DATE": date.decode(), "TIME": tod.decode(),
                "wall_clock": f"{y}-{mo}-{d}T{tod.decode()}"}
        collapsed = b" ".join(rest.split())
        if collapsed in RELAY_MESSAGES:
            items.append({**item, "type": "relay-message", "key_offset": m.start(2),
                          "fields": {**base, "MESSAGE": collapsed.decode()},
                          "flags": ["layout-unconfirmed"]})
            continue
        es = ELEMENT_STATE.match(rest)
        if not es:
            items.append({**item, "type": "parse-error", "reason": "no ELEMENT and STATE"})
            continue
        items.append({**item, "type": "row", "key_offset": m.start(2),
                      "fields": {**base, "ELEMENT": es.group(1).decode(), "STATE": es.group(2).decode()}})
    return header, items


def alignment_key(item):
    """Digest of the row's native bytes from the DATE field to the end of the
    line, without the row number or trailing CR. The SEL-751 numbers row 1 as
    the newest, so the number changes on every new event (A6 R-A4-1).
    Parse errors key on the whole line, so they still align by content."""
    line = item["line"].rstrip(b"\r")
    return "sha256:" + hashlib.sha256(line[item.get("key_offset", 0):]).hexdigest()
