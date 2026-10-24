"""Builds sel-751.json, A2's SEL-751 register content, from A1's Phase 0
conversion (sel-751-phase0.json, which stays pinned) and the SEL-751
instruction manual text.

Run from this directory with
`python3 -I build_sel751.py <S22 text, e.g. $OTSEC_SEL751_TEXT>`. The output
is committed; content_sel751_test.go checks it. The changes from the Phase 0
package are A2's C3 review changes 3 and 4 and the sel.ser.other_args
citation (docs/phase1/reviews/C3-A2.md):

- firmware.known is exactly the FID rows of S22 Tables A.1 to A.5, each cited
  by table, sheet and page. The two R100-V0 strings that are not rows (the
  Figure 10.16 example and the FID-format sample on p. A.1) are gone, and so
  is the R100 branch rule, which no longer has a FID.
- The one FID that appears in two rows (R200-V4, Table A.4 sheets 3 and 4) is
  one entry whose citation names both rows.
- sel.ser.other_args cites S22 Table 7.63 and 7.64 instead of a pseudo-source,
  and is classed unknown with documented-untested evidence.
- sel.id's Figure 3.20 citation is marked as a negative fixture (C-20).
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FID = re.compile(r"\s*(SEL-751-R(\d{3})-V(\d+)-Z\d{6}-D\d{8})\b(.*?)(\d{8})?\s*$")
PAGE = re.compile(r"(?:^\s*(A\.\d+)\s+Firmware, ICD)|(?:Firmware, ICD, and Manual Versions\s+(A\.\d+)\s*$)")
TABLE = re.compile(r"Table (A\.[1-5])\s+R\d00 Series Firmware Revision History \(Sheet (\d+) of (\d+)\)")


def rows(text_path):
    """The FID rows of Tables A.1 to A.5: a row starts with its FID in the
    first column. FIDs quoted inside a summary ("Includes all the functions
    of ...") are not rows."""
    page = table = sheet = None
    out = []
    in_tables = False
    with open(text_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = TABLE.search(line)
            if m:
                in_tables = True
                table, sheet = m.group(1), int(m.group(2))
            elif in_tables and "Table A.6" in line:
                break
            m = PAGE.search(line)
            if m:
                page = m.group(1) or m.group(2)
            m = FID.match(line)
            if m and in_tables:
                out.append({"fid": m.group(1), "branch": "R" + m.group(2), "version": int(m.group(3)),
                            "table": table, "sheet": sheet, "page": page, "manual_date_code": m.group(5)})
    return out


def known(rs):
    by = {}
    for r in rs:
        by.setdefault(r["fid"], []).append(r)
    out = []
    for fid, rr in by.items():
        if len(rr) == 1:
            r = rr[0]
            ref = "Table %s sheet %d p. %s" % (r["table"], r["sheet"], r["page"])
        else:
            ref = "Table %s sheets %s pp. %s: %d rows with one FID (manual date codes %s); the FID cannot tell them apart" % (
                rr[0]["table"], " and ".join(str(r["sheet"]) for r in rr), "-".join(r["page"] for r in rr), len(rr),
                " and ".join(r["manual_date_code"] for r in rr))
        out.append({"fid": fid, "branch": rr[0]["branch"], "version": rr[0]["version"],
                    "citation": {"source": "S22", "ref": ref}})
    return out


def main():
    rs = rows(sys.argv[1])
    with open(os.path.join(HERE, "sel-751-phase0.json"), encoding="utf-8") as f:
        p = json.load(f)
    p["revision"] = 2
    p["issued"] = "2026-10-24"
    p["owner"] = "A2"

    k = known(rs)
    branches = {x["branch"] for x in k}
    p["firmware"]["known"] = k
    p["firmware"]["branches"] = [b for b in p["firmware"]["branches"] if b["branch"] in branches]

    for d in p["denied"]:
        if d["id"] == "sel.ser.other_args":
            d["citations"] = [{"source": "S22", "ref": "Table 7.63 p.7.75 (SER argument forms) and Table 7.64 (SER D)"}]
            d["classification"] = "unknown"
            d["evidence"] = {"class": "documented-untested"}
            d["notes"] = ("Every SER argument form is refused until approved as its own operation. The documented "
                          "range forms (SER n, SER n m, SER date, SER date date) are read-only but not approved; "
                          "SER C and SER R clear the SER and have their own deny rules.")
    for o in p["operations"]:
        if o["id"] == "sel.id":
            for c in o["citations"]:
                if c["ref"].startswith("Figure 3.20"):
                    c["ref"] = "Figure 3.20 p.3.14: negative fixture, 6 of 12 checksums wrong (C-20); not a positive example"

    used = {c["source"] for sec in ("operations", "session_control", "denied") for e in p[sec] for c in e["citations"]}
    used |= {x["citation"]["source"] for x in k}
    p["sources"] = [s for s in p["sources"] if s["id"] in used or not s["id"].startswith("A2-")]

    p["notes"] = [n for n in p["notes"] if not n.startswith("Known firmware IDs:")]
    p["notes"].insert(0, "Revision 2 by A2 (content owner), 2026-10-24, from A1's Phase 0 conversion: C3 review "
                         "changes 3 and 4 and the sel.ser.other_args citation (docs/phase1/reviews/C3-A2.md). "
                         "Allowlist decisions are unchanged.")
    p["notes"].append("Known firmware IDs: %d unique FIDs from %d rows of S22 Tables A.1 to A.5 (A2 extraction, "
                      "reconciled with A6's independent count, 2026-10-24). R200-V4-Z007003-D20170922 is the FID of "
                      "two rows. Three rows (R200-V1, R200-V0, R111) say the version was not released and have no FID."
                      % (len(k), len(rs)))

    with open(os.path.join(HERE, "sel-751.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(p, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
