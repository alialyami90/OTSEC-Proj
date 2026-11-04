"""Bounds the largest C9 difference a SEL-751 read can make (C9 0.4).

Run: python3 -I difference_max.py ../../register/testdata/count_settings.py <751_IM_20260910.txt>

The text is the owner-supplied PDF of S22 (751_IM_20260910.pdf) extracted with
`pdftotext -layout 751_IM_20260910.pdf 751_IM_20260910.txt`. That gives the
same bytes as the project's extract in phase0/manuals-SEL/text/ (checked by C2,
2026-11-04).

It counts the settings of the 24 SHO forms from S22's settings sheets with
count_settings.py, and takes each setting's value width from there (384
characters for an equation, 64 for any other value). The worst difference is
one in which every setting of every form is present in both reads and every
value changed. Its size is the JSON of each change without values (class,
kind, name, sensitive, the field names) plus both reads' values.

Each read's values are bounded twice: by the sheets' widths, and by the run's
max_total_bytes (T, 512 KiB of received bytes), less each setting's name and
the separator the relay prints around it. The separator is not documented as
a minimum (H-13), so three values are shown. A value with a double quote or a
backslash is longer in JSON than as printed; the escape factor shows what 10%
more would cost. Everything here is desk: no relay was read.
"""

import importlib.util
import json
import sys

T = 512 << 10
BOUND = (3 << 19) - (64 << 10)  # MaxDifferenceBytes: RecordCap less RecordHeadroom
SENSITIVE = {"port.1", "port.f", "port.2", "port.3", "port.4"}  # rule sel-751-sho/2


def main():
    spec = importlib.util.spec_from_file_location("count_settings", sys.argv[1])
    cs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cs)
    sheets = cs.count(sys.argv[2])
    items = [(key, name, cs.VALUE_SELOGIC if any(eqs) else cs.VALUE_OTHER)
             for key, _, sheet, _ in cs.FORMS for name, eqs in sheets[sheet].items()]
    n = len(items)
    names = sum(len(name) for _, name, _ in items)
    widths = sum(w for _, _, w in items)

    def change(cls, name):
        return json.dumps({"class": cls, "kind": "changed", "name": name, "from": "", "to": "",
                           "sensitive": cls in SENSITIVE}, separators=(",", ":"))
    ref = {"snapshot_digest": "sha256:" + "0" * 64, "invocation_id": "0" * 36,
           "retrieved_at": "2026-11-04T00:00:00.000000000Z"}
    head = len(json.dumps({"schema": "otsec.config/0.4", "kind": "config.difference", "asset_id": "0" * 36,
                           "rule": "sel-751-sho/2", "target": "device-observed", "from": ref, "to": ref,
                           "changes": []}, separators=(",", ":")))
    fixed = head + sum(len(change(c, nm)) + 1 for c, nm, _ in items)
    print("settings %d, names %d bytes, sheet widths %d bytes" % (n, names, widths))
    print("difference without values: %d bytes; bound %d bytes" % (fixed, BOUND))
    print("| Separator a setting | Values a read | Escape | Difference | Over the bound |")
    print("| ---: | ---: | ---: | ---: | ---: |")
    for sep in (4, 5, 6):
        values = min(widths, T - names - sep * n)
        for esc in (1.0, 1.1):
            d = fixed + int(2 * values * esc)
            print("| %d | %d | %.1f | %d | %d |" % (sep, values, esc, d, d - BOUND))


if __name__ == "__main__":
    main()
