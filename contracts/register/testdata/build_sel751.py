"""Builds sel-751.json, A2's SEL-751 register content, from A1's Phase 0
conversion (sel-751-phase0.json, which stays pinned) and the SEL-751
instruction manual text. sel-751-rev2.json is revision 2 as signed, pinned
so the rollback floor can be tested against it.

Run from this directory with
`python3 -I build_sel751.py <S22 text, e.g. $OTSEC_SEL751_TEXT>`. The output
is committed; content_sel751_test.go checks it. sel-751-rev3.json is
revision 3, written on the way to revision 4 and pinned for the comparisons. The changes from the Phase 0
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

Revision 3 (rev3 below) makes every documented command word a deny-rule
mnemonic, so authz.ValidateSecret refuses a password the relay could read as
a command, and denies the Spanish forms that change state (A1's brief
approval on #99's follow-up). Every word is checked against the text of its
S22 page before anything is written.
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


# Revision 3. Every documented command word of S22: the Relay Command Summary
# (pp. 1 to 9 at the end of the manual, English and Spanish columns) and
# Table C.2 (Compressed ASCII). Each entry is the word as printed and the
# summary page where it first appears; check_words finds each one on that
# page of the text before anything is written. The relay reads the first
# three letters of a command (Command Summary p. 1), so that is the mnemonic.
ENGLISH = [
    ("ACC", 1), ("ID", 1), ("QUIT", 1), ("2AC", 1), ("BRE", 1), ("CEV", 1), ("COM", 1),
    ("COU", 2), ("DATE", 2), ("ETH", 2), ("EVE", 2), ("FIL", 2),
    ("FGS", 3), ("GOOSE", 3), ("GROUP", 3), ("HELP", 3),
    ("HIS", 4), ("HSG", 4), ("HSR", 4), ("IRIG", 4), ("LDP", 4), ("LOG", 4), ("MAC", 4), ("MET", 4),
    ("PING", 5), ("PRP", 5), ("RSTP", 5), ("SER", 5),
    ("SHO", 6), ("STA", 6), ("SUM", 6), ("TAR", 6),
    ("TIME", 7), ("TRI", 7), ("89C", 7), ("89O", 7), ("AFT", 7), ("ANA", 7), ("CAL", 7), ("CLO", 7), ("CON", 7),
    ("COPY", 8), ("INI", 8), ("L_D", 8), ("LOO", 8), ("OPE", 8), ("PARTNO", 8), ("PAS", 8), ("PUL", 8),
    ("R_S", 8), ("SET", 8),
    ("TEST", 9), ("THE", 9), ("VEC", 9),
]
# Spanish words that differ from the English ones, with the English word.
SPANISH = [
    ("SAL", "QUIT", 1), ("INT", "BRE", 1), ("FEC", "DATE", 2), ("GRUPO", "GROUP", 3), ("AYUDA", "HELP", 3),
    ("MED", "MET", 4), ("MOS", "SHO", 6), ("EST", "STA", 6), ("BAN", "TAR", 6), ("HORA", "TIME", 7),
    ("89A", "89O", 7), ("CER", "CLO", 7), ("ABR", "OPE", 8), ("AJU", "SET", 8),
]
COMPRESSED = ["BNAME", "CASCII", "CBRE", "CEVENT", "CHISTORY", "CLDP", "CMETER", "CSE", "CSTATUS", "CSUMMARY",
              "DNAME", "ID", "SNS"]
# Words with an approved line; sel.unapproved.command leaves them out.
APPROVED = {"ACC", "ID", "QUI", "SHO", "SER"}


def summary_pages(text_path):
    """The Relay Command Summary page by page, and the text of Table C.2."""
    with open(text_path, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    start = max(i for i, l in enumerate(lines) if l.strip() == "SEL-751 Relay Command Summary")
    pages, page = {1: []}, 1
    head = re.compile(r"SEL-751 Relay Command Summary (\d)\s*$|^\s*(\d) SEL-751 Relay Command Summary")
    for l in lines[start:]:
        m = head.search(l)
        if m:
            page = int(m.group(1) or m.group(2))
            pages.setdefault(page, [])
        pages[page].append(l)
    c2 = next(i for i, l in enumerate(lines) if "Table C.2   Compressed ASCII Commands" in l)
    end = next(i for i in range(c2, len(lines)) if "Interleaved ASCII" in lines[i])
    return {k: "\n".join(v) for k, v in pages.items()}, "\n".join(lines[c2:end])


def check_words(text_path):
    pages, c2 = summary_pages(text_path)
    if sorted(pages) != list(range(1, 10)):
        sys.exit("command summary pages %s, want 1 to 9" % sorted(pages))
    on = lambda w, t: re.search(r"(?<![\w])%s(?![\w])" % re.escape(w), t)
    for w, pg in ENGLISH:
        if not on(w, pages[pg]):
            sys.exit("%s is not on command summary p. %d" % (w, pg))
    for w, _, pg in SPANISH:
        if not on(w, pages[pg]):
            sys.exit("%s is not on command summary p. %d" % (w, pg))
    for w in COMPRESSED:
        if not on(w, c2):
            sys.exit("%s is not in Table C.2" % w)


def interleave(words):
    """Orders words so that no two neighbours share a first character. Go's
    regexp parser factors a common prefix out of neighbouring alternatives,
    so (CEV|COU) parses as C(?:EV|OU), and authz.ValidateSecret would then
    derive the mnemonic C and refuse every secret that starts with C. Do not
    sort the alternation of sel.unapproved.command."""
    groups = {}
    for w in sorted(words):
        groups.setdefault(w[0], []).append(w)
    out = []
    while groups:
        for k in sorted(groups, key=lambda k: (-len(groups[k]), k)):
            if not out or out[-1][0] != k:
                out.append(groups[k].pop(0))
                if not groups[k]:
                    del groups[k]
                break
        else:
            sys.exit("cannot order %s without neighbours sharing a first character" % sorted(words))
    return out


SUMMARY = "Command Summary p.%d (Spanish column: %s)"


def rev3(p):
    p["revision"] = 3
    p["issued"] = "2026-10-25"
    rules = {d["id"]: d for d in p["denied"]}

    def extend(id, pattern, ref, notes=None):
        d = rules[id]
        d["pattern"] = pattern
        d["citations"].append({"source": "S22", "ref": ref})
        if notes:
            d["notes"] = (d.get("notes", "") + " " + notes).strip()

    def add_after(after, rule):
        i = next(i for i, d in enumerate(p["denied"]) if d["id"] == after)
        p["denied"].insert(i + 1, rule)

    def spanish(id, pattern, ref, side_effects, level=None):
        r = {"id": id, "classification": "state-changing", "pattern": pattern,
             "citations": [{"source": "S22", "ref": ref}], "evidence": {"class": "documented-untested"},
             "side_effects": side_effects,
             "notes": "Spanish form, in its own rule: in one alternation with the English word, Go's regexp "
                      "parser would factor out the shared first letters and authz.ValidateSecret would derive "
                      "a shorter mnemonic."}
        if level:
            r["access_level"] = level
        return r

    extend("sel.disconnect", r"(?i)\s*89(C|O|A)\w*(\s.*)?", SUMMARY % (7, "89A m and 89A n m open disconnects, Level 2"))
    extend("sel.breaker.ope", r"(?i)\s*(OPE|ABR)\w*(\s.*)?", SUMMARY % (8, "ABR opens the breaker"))
    add_after("sel.breaker.clo", spanish("sel.breaker.clo.es", r"(?i)\s*CER\w*(\s.*)?",
                                         SUMMARY % (7, "CER closes the breaker, Level 2"),
                                         "Closes the breaker.", "2"))
    extend("sel.settings.set", r"(?i)\s*(SET|AJU)\w*(\s.*)?", SUMMARY % (8, "AJU changes settings; p.9 AJU ... TERSO"))
    add_after("sel.settings.group", spanish("sel.settings.group.es", r"(?i)\s*GRU\w*\s+\S.*",
                                            SUMMARY % (8, "GRUPO n changes the active group, Level 2"),
                                            "Changes the active settings group.", "2"))
    extend("sel.clock.set", r"(?i)\s*(DAT|TIM|FEC|HOR)\w*\s+\S.*",
           SUMMARY % (2, "FEC sets the date") + "; " + SUMMARY % (7, "HORA sets the time"))
    add_after("sel.met.reset", spanish("sel.met.reset.es", r"(?i)\s*MED\w*\s+R(D|E|M|P)\b.*",
                                       SUMMARY % (5, "MED RD, MED RE, MED RM and MED RP reset meter data, Level 1"),
                                       "Resets demand, energy, max/min or peak meter data.", "1"))
    extend("sel.tar.reset", r"(?i)\s*(TAR|BAN)\w*\s+R\b.*", SUMMARY % (7, "BAN R resets latched targets"))
    extend("sel.sta.args", r"(?i)\s*(STA|EST)\w*\s+\S.*", SUMMARY % (9, "EST C o R clears the self-test status"))
    extend("sel.breaker.data", r"(?i)\s*(BRE|INT)\w*\s+(R|W)\b.*", SUMMARY % (7, "INT R resets and INT W presets breaker wear data"))
    extend("sel.his.clear", r"(?i)\s*HIS\w*\s+(\S+\s+)?(C|R|CA|RA|D|DT|RT)\b.*",
           SUMMARY % (4, "HIS D o R and HIS HIF D o R clear history; HIS HIF DT o RT clears all HIF history"))
    extend("sel.ser.clear", r"(?i)\s*SER\w*\s+(C|R)\b.*",
           SUMMARY % (6, "SER D o R clears the SER; SER D also has sel.ser.d"),
           "Revision 3: the pattern now matches R as its notes always said; revision 2 left SER R to "
           "sel.ser.other_args (unknown).")
    extend("sel.ldp.clear", r"(?i)\s*LDP\w*\s+(C|D)\b.*", SUMMARY % (4, "LDP D clears the load profile"))

    words = {w[:3] for w, _ in ENGLISH} | {w[:3] for w, _, _ in SPANISH} | {w[:3] for w in COMPRESSED}
    order = interleave(sorted(words - APPROVED))
    p["denied"].append({
        "id": "sel.unapproved.command",
        "classification": "unknown",
        "pattern": r"(?i)\s*(" + "|".join(order) + r")\w*(\s.*)?",
        "citations": [{"source": "S22", "ref": "Command Summary pp.1-9 (every command word, English and Spanish columns)"},
                      {"source": "S22", "ref": "Table C.2 p.C.2 (Compressed ASCII commands)"}],
        "evidence": {"class": "documented-untested"},
        "side_effects": "Documented as displays, session control or commands with their own deny rules; none is "
                        "approved. Never sent.",
        "notes": "Every documented command word with no approved line, whole and with any arguments, so that "
                 "each is a command mnemonic for authz.ValidateSecret (C7-A6-3). Earlier rules decide first, so "
                 "a state-changing form still reports its own rule. The alternation is ordered so that no two "
                 "neighbours share a first character (build_sel751.py interleave): do not sort it.",
    })

    p["notes"].insert(0, "Revision 3 by A2 (content owner), 2026-10-25: every documented command word of S22 "
                         "(Command Summary pp.1-9, English and Spanish, and Table C.2) is a deny-rule mnemonic, and "
                         "the Spanish state-changing forms are denied. Allowlist decisions are unchanged.")


def rev4(p):
    """Revision 4 (C3 0.2, D3-2): DATE_F is read with SHO G before SER, so the
    SER's dates are read in the relay's own order, and SHO G's citation names
    the table that holds DATE_F. No line, deny rule or condition changes."""
    p["contract"] = "otsec.register/0.2"
    p["revision"] = 4
    p["issued"] = "2026-10-26"
    for o in p["operations"]:
        if o["id"] == "sel.settings.show_global":
            for c in o["citations"]:
                if c["ref"] == "Table 4.90 p.4.230 (UTC_OFF, DST_BEGM..DST_ENDH, DATE_F)":
                    c["ref"] = "Table 4.90 p.4.230 (UTC_OFF, DST_BEGM..DST_ENDH)"
            o["citations"].append({"source": "S22", "ref": "Table 4.84 p.4.225 (DATE_F: MDY, YMD, DMY; default MDY) and p.4.226"})
    # Keys in the order the Go struct writes them: context before operations.
    rebuilt = {}
    for k, v in p.items():
        if k == "operations":
            rebuilt["context"] = [{
                "id": "ctx.date_f",
                "setting": "DATE_F",
                "read_by": "sel.settings.show_global",
                "for": ["sel.ser.read_all"],
                "values": ["MDY", "YMD", "DMY"],
                "reason": "The relay prints dates in the order DATE_F sets: Month/Day/Year, Year/Month/Day or "
                          "Day/Month/Year (S22 Table 4.84 p.4.225, p.4.226). S22 p.7.31 states it for the date of "
                          "a command response; that the SER rows follow the same setting is inferred, not stated. "
                          "A SER read without DATE_F, or with a value outside these, is not parsed with a guessed "
                          "order (P3-A2).",
            }]
        rebuilt[k] = v
    p.clear()
    p.update(rebuilt)
    p["notes"].insert(0, "Revision 4 by A2 (content owner), 2026-10-26, format otsec.register/0.2 (D3-2): context "
                         "ctx.date_f reads DATE_F with SHO G for SER, and SHO G cites Table 4.84 for DATE_F instead "
                         "of Table 4.90. Lines, deny rules, preconditions and warnings are unchanged.")


# Revision 5 (C3 0.3, P4-A2, D4-13): the 24 SHO forms of S22 Table 7.67 and the
# run that reads them in one session. Each form is (ID suffix, line, Table 7.67
# row, settings sheet class, counted reply bound in bytes). The bounds are
# count_settings.py's, rounded up to a KiB (docs/phase4/B2-register-rev5.md):
# the settings of the class on S22's settings sheets at 16 + 6 + 64 bytes
# each, 16 + 6 + 384 for an equation, plus 4,096 for headings. The 64 and 384
# are assumptions (documented-untested, H-13), not numbers S22 gives.
ROW = {
    "group": "SHO n s: Shows relay settings for Group n (n = 1, 2, 3, or 4)",
    "logic": "SHO L n s: Shows general logic settings for Group n (n = 1, 2, 3, or 4)",
    "global": "SHO G s: Shows global settings",
    "port": "SHO P n s: Shows serial port settings. n specifies the port (1, 2, 3, 4, or F)",
    "report": "SHO R s: Shows report settings such as Sequential Events Recorder (SER) and Event Report (ER) settings",
    "front-panel": "SHO F s: Shows front-panel settings",
    "iec-103": "SHO I: Shows IEC 60870-5-103 settings",
    "modbus": "SHO M s: Shows Modbus User Map settings",
    "eip": "SHO E m s: Shows the EtherNet/IP Assembly Map m settings (m = 1, 2, or 3)",
    "dnp": "SHO DNP m s: Shows DNP Map m settings (m = 1, 2, or 3)",
}
SHEET = {
    "group": "Group Settings (SET Command)", "logic": "Logic Settings (SET L Command)",
    "global": "Global Settings (SET G Command)", "port": "Port Settings (SET P Command)",
    "report": "Report Settings (SET R Command)", "front-panel": "Front-Panel Settings (SET F Command)",
    "iec-103": "IEC 60870-5-103 Map Settings (SET I Command)", "modbus": "Modbus Map Settings (SET M Command)",
    "eip": "EtherNet/IP Assembly Map Settings (SET E Command)", "dnp": "DNP3 Map Settings (SET DNP n Command)",
}
# (ID suffix, line, row, bound). The run sends them in this order after
# SHO P 1 and SHO G, which come first.
FORMS = [
    ("group_1", "SHO 1", "group", 103424), ("group_2", "SHO 2", "group", 103424),
    ("group_3", "SHO 3", "group", 103424), ("group_4", "SHO 4", "group", 103424),
    ("logic_1", "SHO L 1", "logic", 355328), ("logic_2", "SHO L 2", "logic", 355328),
    ("logic_3", "SHO L 3", "logic", 355328), ("logic_4", "SHO L 4", "logic", 355328),
    ("global", "SHO G", "global", 101376),
    ("port_f", "SHO P F", "port", 7168), ("port1", "SHO P 1", "port", 24576),
    ("port_2", "SHO P 2", "port", 9216), ("port_3", "SHO P 3", "port", 9216), ("port_4", "SHO P 4", "port", 9216),
    ("report", "SHO R", "report", 13312), ("front_panel", "SHO F", "front-panel", 30720),
    ("modbus", "SHO M", "modbus", 10240), ("iec103", "SHO I", "iec-103", 13312),
    ("eip_1", "SHO E 1", "eip", 16384), ("eip_2", "SHO E 2", "eip", 16384), ("eip_3", "SHO E 3", "eip", 16384),
    ("dnp_1", "SHO DNP 1", "dnp", 17408), ("dnp_2", "SHO DNP 2", "dnp", 17408), ("dnp_3", "SHO DNP 3", "dnp", 17408),
]
OPTIONAL = {"port_2", "port_3", "port_4", "modbus", "iec103", "eip_1", "eip_2", "eip_3", "dnp_1", "dnp_2", "dnp_3"}
STEP_TIMEOUT_MS = 10_000
RUN_TOTAL_BYTES = 512 * 1024  # T (B1, D4-13)
RUN_DEADLINE_MS = 300_000


def rev5(p):
    """Revision 5 (C3 0.3): every SHO form of Table 7.67 is an operation with
    limits, and sel.config.read_all sends them in one session, SHO P 1 first
    (the LANG precondition and the posture warnings) and then SHO G. Nothing
    else changes: no line, deny rule, precondition, warning, context or
    firmware entry. Only the forms without a setting-name argument are
    approved, so "SHO 1 CTR" and every other "s" form, and a bare "SHO P",
    are unlisted and denied."""
    p["contract"] = "otsec.register/0.3"
    p["revision"] = 5
    p["issued"] = "2026-10-27"
    by_line = {o["line"]: o for o in p["operations"]}
    ids = {}
    for suffix, line, cls, bound in FORMS:
        op = by_line.get(line)
        if op is None:
            op = {
                "id": "sel.settings.show_" + suffix,
                "classification": "read-only",
                "line": line,
                "access_level": "1",
                "citations": [
                    {"source": "S22", "ref": "Table 7.67 p.7.77 ('%s', Access Level 1)" % ROW[cls]},
                    {"source": "S22", "ref": "%s, SEL-751 Settings Sheets (SET.1 to SET.114)" % SHEET[cls]},
                ],
                "evidence": {"class": "documented-untested"},
                "side_effects": "None documented. Output contains configuration values; store as sensitive evidence.",
                "notes": "Approved as this exact line, with no setting-name argument s. Read by the run "
                         "sel.config.read_all.",
            }
            if suffix in OPTIONAL:
                op["notes"] += (" The form exists only on a relay with the option (S22 Table 7.1); a relay without "
                                "it answers Invalid Command, and C9 records the class as absent.")
            p["operations"].append(op)
        ids[line] = op["id"]
        op["limits"] = {"max_reply_bytes": bound, "timeout_ms": STEP_TIMEOUT_MS}
    # The existing two keep their IDs; SHO P 1 and SHO G lead the run.
    lead = ["SHO P 1", "SHO G"]
    order = lead + [l for _, l, _, _ in FORMS if l not in lead]
    p["runs"] = [{
        "id": "sel.config.read_all",
        "steps": [ids[l] for l in order],
        "max_total_bytes": RUN_TOTAL_BYTES,
        "deadline_ms": RUN_DEADLINE_MS,
        "citations": [{"source": "S22", "ref": "Table 7.67 p.7.77 (SHOW Command)"}],
        "evidence": {"class": "documented-untested",
                     "note": "No relay was read. Reply sizes and times are bounds, not measurements (H-13)."},
        "side_effects": "None documented: SHO only displays settings. Output is sensitive configuration evidence.",
        "notes": "One session, 24 forms, SHO P 1 first so LANG := ENGLISH is confirmed before any other line. "
                 "Each step has its own reply and time limit; the run fails as a whole when a step passes its "
                 "limit, the total passes max_total_bytes (T, 512 KiB, D4-13) or the deadline passes, and a relay "
                 "whose settings pass T is not baselined. A form the relay does not have answers Invalid Command "
                 "and costs one send.",
    }]
    # Keys in the order the Go struct writes them: runs after operations.
    rebuilt = {}
    for k, v in p.items():
        if k != "runs":
            rebuilt[k] = v
        if k == "operations":
            rebuilt["runs"] = p["runs"]
    p.clear()
    p.update(rebuilt)
    p["notes"].insert(0, "Revision 5 by B2 (content owner), 2026-10-27, format otsec.register/0.3 (P4-A2, D4-13): "
                         "all 24 SHO forms of S22 Table 7.67 without a setting-name argument are operations with "
                         "reply and time limits, and the run sel.config.read_all reads them in one session. The "
                         "175 touchscreen settings are in the files SET_HMI.zds and CDP.zds (S22 Table 7.80 "
                         "p.7.87), not in any SHO form, and are not read (D4-13). No other line, deny rule, "
                         "precondition, warning, context or firmware entry changes.")


def write(p, name):
    with open(os.path.join(HERE, name), "w", encoding="utf-8", newline="\n") as f:
        json.dump(p, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    check_words(sys.argv[1])
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
    rev3(p)
    write(p, "sel-751-rev3.json")
    rev4(p)
    write(p, "sel-751-rev4.json")
    rev5(p)
    write(p, "sel-751.json")


if __name__ == "__main__":
    main()
