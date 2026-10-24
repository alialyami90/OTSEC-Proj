"""Convert A2's Phase 0 register draft and SEL-751 firmware allowlist into one
otsec.register/0.1 package (A1, P1-A1 acceptance test "converts with no
information lost").

The output is a starting point for A2, who owns C3 content. Known firmware IDs
are not in the Phase 0 files; they are extracted here from the SEL-751 IM text
(Appendix A) with the FID pattern A6 uses, and A2 must reconcile them with
Appendix A before the package is approved.

Run from the repository root:
  python3 -I contracts/register/testdata/convert_phase0.py \
    docs/phase0/A2-command-register-draft.json \
    docs/phase0/A2-sel751-firmware-allowlist.json \
    docs/phase0/A2-device-feasibility.md docs/phase0/A2-sel-portfolio.md \
    <751_IM text> > contracts/register/testdata/sel-751-phase0.json
"""

import json
import re
import sys

reg_path, allow_path, feas_path, portfolio_path, im_path = sys.argv[1:6]
reg = json.load(open(reg_path))
allow = json.load(open(allow_path))

# Sources: A2's tables (S1-S22 in the feasibility file, S23-S43 in the
# portfolio), plus a pseudo-source for A2's own rulings.
sources, seen = [], set()
for line in list(open(feas_path)) + list(open(portfolio_path)):
    m = re.match(r"^\| (S\d+) \| (.+?) \| (.+?) \|", line)
    if m and m.group(1) not in seen:
        seen.add(m.group(1))
        title = re.sub(r"\*\*", "", m.group(2)).strip()
        src = {"id": m.group(1), "title": title}
        dc = re.search(r"(?:date code )?(\d{8})", m.group(3))
        if dc:
            src["date_code"] = dc.group(1)
        sources.append(src)
sources.append({"id": "A2-P0", "title": "A2 Phase 0 register draft, docs/phase0/A2-command-register-draft.json (a ruling, not a document)"})
known_sources = {s["id"] for s in sources}


def citations(text):
    """Split 'S22 Table 7.17 p.7.32; password behaviour p.7.33' into
    citations. A part without a leading source ID belongs to the previous
    source; text with no source at all cites A2-P0."""
    out, current = [], None
    for part in [p.strip() for p in text.split(";") if p.strip()]:
        m = re.match(r"^(S\d+)\s+(.*)$", part)
        if m and m.group(1) in known_sources:
            current = m.group(1)
            out.append({"source": current, "ref": m.group(2) or part})
        else:
            out.append({"source": current or "A2-P0", "ref": part})
    return out


def evidence(status):
    m = re.match(r"^(documented-untested|unknown|inferred|documented)\s*(?:\((.*)\))?\s*(.*)$", status)
    cls, note = m.group(1), (m.group(2) or m.group(3) or "").strip()
    if cls == "documented":
        cls = "documented-untested"
    ev = {"class": cls}
    if note:
        ev["note"] = note
    return ev


operations, session, denied = [], [], []
phases = {"sel.session.acc": ["auth"], "sel.session.qui": ["probe", "close"]}
for c in reg["commands"]:
    common = {
        "id": c["id"],
        "citations": citations(c["citation"]),
        "evidence": evidence(c["status"]),
        "side_effects": c["side_effects"],
    }
    if c.get("notes"):
        common["notes"] = c["notes"]
    if c["classification"] == "read-only" and c["id"] in phases:
        session.append({**common, "classification": "session-control", "line": c["pattern"],
                        "phases": phases[c["id"]], "access_level": c["access_level"]})
    elif c["classification"] == "read-only":
        o = {**common, "classification": "read-only", "line": c["pattern"],
             "access_level": c["access_level"]}
        if c["id"] == "sel.id":
            # ADR-0005 (c), A3 8.3: ID is sent in probe, before ACC, for the
            # firmware check, and is also an adapter read (C3-A2 change 1).
            o["phases"] = ["probe", "operate"]
        operations.append(o)
    else:
        d = {**common, "classification": "state-changing", "pattern": c["pattern"]}
        if c.get("access_level"):
            d["access_level"] = c["access_level"]
        denied.append(d)

text = open(im_path, errors="replace").read()
fids = sorted(set(re.findall(r"SEL-751-R\d{3}-V\d+-Z\d+-D\d{8}", text)))
known = [{"fid": f, "branch": f.split("-")[2], "version": int(f.split("-")[3][1:]),
          "citation": {"source": "S22", "ref": "Appendix A, firmware revision history"}} for f in fids]
branches_present = sorted({k["branch"] for k in known})

rules = []
for b in allow["branches"]:
    names = [b["branch"]]
    m = re.match(r"^R(\d{3})-R(\d{3})$", b["branch"])
    if m:
        lo, hi = int(m.group(1)), int(m.group(2))
        names = [x for x in branches_present if lo <= int(x[1:]) <= hi]
    status = b["status"]
    conds, basis = [], b["basis"]
    for i, c in enumerate(b["conditions"]):
        if "EHTTP := N" in c:
            conds.append({"id": "fw.%s.ehttp_off" % b["branch"].lower(), "setting": "EHTTP", "equals": "N",
                          "read_by": "sel.settings.show_port1", "reason": c})
        else:
            basis += " Open item: " + c
    for n in names:
        r = {"branch": n, "status": status,
             "min_version": int(b["min_version"][1:]) if b["min_version"].startswith("V") else 0,
             "basis": basis + (" (Phase 0 range %s)" % b["branch"] if len(names) > 1 else ""),
             "evidence": evidence(b["evidence_class"])}
        if conds:
            r["conditions"] = conds
        rules.append(r)

notes = [
    "Converted by A1 on 2026-10-24 from the Phase 0 draft (register status: %s; allowlist status: %s)." % (reg["status"], allow["status"]),
    "Matching (Phase 0): " + reg["matching"],
    "Not representable as lines (Phase 0): " + " | ".join(reg["not_representable_as_lines"]),
    "Language (Phase 0): " + reg["language"],
    "Firmware rule (Phase 0): " + allow["rule_applied"],
    "Firmware match (Phase 0): " + allow["fid_match"],
    "Firmware fixes (Phase 0): " + json.dumps(allow["fixes"], sort_keys=True),
    "Known firmware IDs: %d unique strings extracted from the S22 text by A1 with A6's FID pattern. A6's check counted 84 Appendix A rows; A2 reconciles before approval." % len(known),
]
pkg = {
    "contract": "otsec.register/0.1",
    "family": "sel-751",
    "revision": 1,
    "issued": "2026-10-24",
    "owner": "A2",
    "sources": sources,
    "preconditions": [{
        "id": "pre.lang_english", "setting": "LANG", "equals": "ENGLISH", "read_by": "sel.settings.show_port1",
        "reason": "ADR-0005 (A1 401ebd7, from A6 F-006): command names differ on a Spanish port and 'SER D' clears the SER; refuse to collect unless SHO P 1 parses as English port settings with LANG := ENGLISH."}],
    "warnings": [{
        "id": "warn.%s_above_1" % name.lower(), "setting": name, "max": 1, "read_by": "sel.settings.show_port1",
        "reason": "ADR-0005 (owner decision 2026-10-23 on MAXACC; A1 ruling on FTPACC and HTTPACC from A6 F-006): %s above 1 on Port 1 lets the port reach Level 2; recorded and warned, collection continues. Default 2 (S22 Port 1 settings)." % name}
        for name in ("MAXACC", "FTPACC", "HTTPACC")],
    "operations": operations,
    "session_control": session,
    "denied": denied,
    "firmware": {"known": known, "branches": rules, "not_covered": allow["not_covered"]},
    "notes": notes,
}
json.dump(pkg, sys.stdout, indent=1, ensure_ascii=True)
sys.stdout.write("\n")
