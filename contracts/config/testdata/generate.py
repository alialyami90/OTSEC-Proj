"""Writes the C9 golden examples in transcripts/, valid/ and invalid/.

Run from this directory with `python3 -I generate.py`. The output is
committed; config_test.go checks it and testdata/README.md gives one line per
file.

Every transcript here is constructed. None is a device capture, and every
snapshot says target "simulated". The command lines are the SHO forms of S22
Table 7.67 (SEL-751 instruction manual, date code 20260910), and the
session's framing, prompts and header follow C2's generate.py, with its
assumptions (H-13). The setting lines are copied from S22's printed examples
where S22 prints one: Figure 7.43 for SHO 1, p. G.29 for SHO L and SHO G,
and Figure D.3 for SHO DNP 1, with its "..." elisions left out. Elsewhere
they come from the settings tables with their factory defaults: Port F
from Table 4.103, report settings from Tables 4.121 and 4.125, and
front-panel settings from Table 4.111. Port 1 is C2's SHO P 1 reply. Groups
2 to 4 and logic groups 2 to 4 repeat group 1 under their own heading,
because S22 prints only one group. These layouts are documented-untested.

ASSUMED, not documented: read 2's other layouts. The header printed before
the settings of SHO 1 and SHO 2, one setting per line, another order and
another wrap are what the rule must treat as the same configuration; S22
prints none of them for SHO. Figure 7.43 (pp. 7.78 and 7.79) prints its SHO
reply with no header at all: it starts at "Group 1", runs across a page of
the manual with nothing repeated, and ends at "=>". S22 documents no paging
for SHO. So no golden repeats the header inside one reply, and read 2's
header before the settings is itself assumed. Whether a relay prints or
repeats one is on the widened H-13.

This file tokenizes the replies with its own reading of the rule in
doc.go, so the Go tests check two implementations against each other.
"""

import base64
import copy
import hashlib
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))

SCHEMA = "otsec.config/0.3"
ASSET = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"  # the C1 relay example
INVOCATIONS = {  # invented
    1: "8a2f6c41-5b7e-4d93-a0c2-1e9f3b7d6a51",
    2: "8a2f6c41-5b7e-4d93-a0c2-1e9f3b7d6a52",
    3: "8a2f6c41-5b7e-4d93-a0c2-1e9f3b7d6a53",
}
FID = "SEL-751-R501-V0-Z104101-D20260910"  # S22 Table A.1 p. A.2
CID = "E754"
RED = b"[REDACTED]"
STX, ETX = b"\x02", b"\x03"
RULE = "sel-751-sho/2"

# The rule's classes, in order (config.go RuleSEL751SHO).
CLASSES = [
    ("port.1", "SHO P 1", False, True), ("global", "SHO G", False, False),
    ("group.1", "SHO 1", False, False), ("group.2", "SHO 2", False, False),
    ("group.3", "SHO 3", False, False), ("group.4", "SHO 4", False, False),
    ("logic.1", "SHO L 1", False, False), ("logic.2", "SHO L 2", False, False),
    ("logic.3", "SHO L 3", False, False), ("logic.4", "SHO L 4", False, False),
    ("port.f", "SHO P F", False, True),
    ("port.2", "SHO P 2", True, True), ("port.3", "SHO P 3", True, True), ("port.4", "SHO P 4", True, True),
    ("report", "SHO R", False, False), ("front-panel", "SHO F", False, False),
    ("modbus", "SHO M", True, False), ("iec-103", "SHO I", True, False),
    ("eip.1", "SHO E 1", True, False), ("eip.2", "SHO E 2", True, False), ("eip.3", "SHO E 3", True, False),
    ("dnp.1", "SHO DNP 1", True, False), ("dnp.2", "SHO DNP 2", True, False), ("dnp.3", "SHO DNP 3", True, False),
]

ABSENT = None  # a class the relay answers "Invalid Command" for


def group_body(n, fifty_p1p="10.00", with_ll=True, layout="figure"):
    """S22 Figure 7.43, cut to its first blocks and its Trip/Close Logic.
    layout "one-per-line" prints the same settings one per line, at
    another column; "swapped" prints CTRN before CTR."""
    if layout == "one-per-line":
        config = ["CTR := 120", "CTRN := 120", "PTR := 180.00", "LEA_S_R := 180.00", "LEA_S_SC := 4.80",
                  "DELTA_Y := DELTA", "VSCONN := VS", "SINGLEV := N", "VNOM := 120.00"]
    elif layout == "swapped":
        config = ["CTRN     := 120            CTR      := 120     PTR       := 180.00",
                  "LEA_S_R := 180.00          LEA_S_SC := 4.80    DELTA_Y   := DELTA",
                  "VSCONN   := VS             SINGLEV := N        VNOM      := 120.00"]
    else:
        config = ["CTR      := 120            CTRN     := 120     PTR       := 180.00",
                  "LEA_S_R := 180.00          LEA_S_SC := 4.80    DELTA_Y   := DELTA",
                  "VSCONN   := VS             SINGLEV := N        VNOM      := 120.00"]
    lines = ["Group %d" % n, "Relay Settings", "", "ID Settings",
             "RID      := SEL-751", "TID      := FEEDER RELAY", "", "", "Config Settings"] + config + [
        "", "Line Parameter Settings",
        "Z1MAG    := 2.14           Z1ANG    := 68.86   Z0MAG     := 6.38",
        "Z0ANG    := 72.47          Z0SMAG   := 0.36    Z0SANG    := 84.61"]
    if with_ll:
        lines.append("LL       := 4.84")
    lines += ["", "Fault Locator", "EFLOC    := N", "", "Max Ph Overcurr",
              "50P1P    := %-16s 50P1D    := 0.00" % fifty_p1p, "50P1TC   := 1", "",
              "Trip/Close Logic", "TDURD    := 0.5           CFD      := 1.0"]
    if layout == "one-per-line":
        lines += ["TR       := ORED50T OR ORED51T OR ORED81T", "            OR REMTRIP OR OC OR SV04T"]
    else:
        lines.append("TR       := ORED50T OR ORED51T OR ORED81T OR REMTRIP OR OC OR SV04T")
    lines += ["REMTRIP := 0", "ULTRIP   := NOT ( 51P1P OR 51G1P OR 51N1P OR 52A )", "52A      := 0",
              "52B      := NOT 52A", "CL       := SV03T AND LT02 OR CC", "ULCL     := 0"]
    return lines


LOGIC = ["Latch Bits Eqns", "SET01    := PB01", "RST01    := PB02", "SET02    := PB03", "RST02    := PB04"]

GLOBAL = ["Global Settings", "",
          "PHROT    := ABC     FNOM    := 60      DATE_F := MDY",
          "FAULT    := 50G1P OR 50N1P OR 51P1P OR 51QP OR 50Q1P OR TRIP",
          "IRIGC    := NONE    UTC_OFF := 0.00          DST_BEGM:= OFF", "",
          "IEC 61850 Mode/Behavior Configuration", "SC850BM    := LT02", "SC850TM    := LT01"]

PORT_F = ["Port F",
          "EPORT    := Y              PROTO    := SEL     MAXACC   := 2",
          "SPEED    := 9600           BITS     := 8       PARITY   := N",
          "STOP     := 1              T_OUT    := 5       RTSCTS   := N",
          "LANG     := ENGLISH        AUTO     := N       SLAVEID  := 1"]

PORT_1 = ["Port 1", "", "MAXACC  := 2", "FASTOP  := N", "LANG    := ENGLISH", "EHTTP   := N",
          "FTPACC  := 1", "HTTPACC := 1", "TIDLE   := 15"]

PORT_2 = ["Port 2", "EPORT    := Y              PROTO    := SEL     MAXACC   := 1"]


def report(wrap):
    lines = ["SER Chatter Criteria",
             "ESERDEL  := N              SRDLCNT  := 5      SRDLTIM  := 1.0", "", "Event Report Settings"]
    if wrap == "a":
        lines += ["ER       := R_TRIG 51P1P OR R_TRIG 51G1P OR R_TRIG 50P1P",
                  "            OR R_TRIG 50G1P OR R_TRIG 51N1P OR R_TRIG CF"]
    else:
        lines += ["ER       := R_TRIG 51P1P OR R_TRIG 51G1P", "  OR R_TRIG 50P1P OR R_TRIG 50G1P",
                  "  OR R_TRIG 51N1P OR R_TRIG CF"]
    return lines + ["LER      := 15             PRE      := 5"]


FRONT = ["Front Panel Settings",
         "FP_TO    := 15             FP_CONT  := 10     FP_AUTO  := OVERRIDE",
         "RSTLED   := Y              MAXACC   := 2"]

DNP_1 = ["DNP Map 1 Settings", "", "Binary Input Map", "BI_00    := ENABLED", "BI_01    := TRIP_LED",
         "BI_02    := TLED_01", "BI_03    := TLED_02", "", "Binary Output Map", "BO_00    := RB01",
         "BO_01    := RB02", "BO_02    := RB03", "", "Analog Input Map", "AI_00    := IA_MAG",
         "AI_01    := IB_MAG", "AI_02    := IC_MAG"]


def header(time):
    # S22 p. 7.31, as C2's generate.py prints it.
    return ["SEL-751          Date: 10/27/2026  Time: %s" % time, "FEEDER RELAY     Time Source: Internal"]


def replies(read):
    """Each class's reply lines for read 1, 2 or 3, or ABSENT."""
    r = {
        "group.1": group_body(1), "group.2": group_body(2), "group.3": group_body(3), "group.4": group_body(4),
        "logic.1": LOGIC, "logic.2": LOGIC, "logic.3": LOGIC, "logic.4": LOGIC,
        "global": GLOBAL, "port.f": PORT_F, "port.1": PORT_1, "port.2": ABSENT, "port.3": ABSENT, "port.4": ABSENT,
        "report": report("a"), "front-panel": FRONT, "modbus": ABSENT, "iec-103": ABSENT,
        "eip.1": ABSENT, "eip.2": ABSENT, "eip.3": ABSENT, "dnp.1": DNP_1, "dnp.2": ABSENT, "dnp.3": ABSENT,
    }
    if read == 2:
        # ASSUMED layouts (see the docstring). The same configuration: a
        # header with another time before the settings of SHO 1 and SHO 2, SHO 3 one setting per line with TR
        # wrapped, CTRN before CTR in SHO 4, and ER wrapped at other columns.
        # A header after the first setting line is no header (doc.go), so
        # none is printed there.
        r["group.1"] = header("09:31:07.250") + [""] + group_body(1)
        r["group.2"] = header("09:31:08.000") + [""] + group_body(2)
        r["group.3"] = group_body(3, layout="one-per-line")
        r["group.4"] = group_body(4, layout="swapped")
        r["report"] = report("b")
    if read == 3:
        # 50P1P changed and LL removed in group 1, Port 2 appeared, and DNP
        # map 1 disappeared.
        r["group.1"] = group_body(1, fifty_p1p="9.50", with_ll=False)
        r["port.2"] = PORT_2
        r["dnp.1"] = ABSENT
    return r


def framed(echo, text, prompt):
    return echo + STX + text + ETX + prompt


class Session:
    def __init__(self, minute):
        self.data, self.segments, self.redactions, self.n, self.minute = b"", [], [], 0, minute

    def ts(self):
        t = "2026-10-27T09:%02d:%02d.%dZ" % (self.minute, self.n // 10, self.n % 10)
        return t

    def seg(self, d, phase, b):
        off = len(self.data)
        self.data += b
        self.segments.append({"offset": off, "length": len(b), "dir": d, "phase": phase, "at": self.ts()})
        self.n += 1
        return off

    def run(self, read):
        hdr = ("\r\n".join(header("09:%02d:00" % self.minute)) + "\r\n\r\n").encode()
        self.seg("tx", "probe", b"\r\n")
        self.seg("rx", "probe", b"\r\n=")
        self.seg("tx", "probe", b"QUI\r\n")
        self.seg("rx", "probe", framed(b"QUI\r\n", b"\r\n" + hdr, b"="))
        self.seg("tx", "probe", b"ID\r\n")
        ident = '"FID=%s","0000"\r\n"CID=%s","0000"\r\n' % (FID, CID)
        self.seg("rx", "probe", framed(b"ID\r\n", ident.encode(), b"="))
        self.seg("tx", "auth", b"ACC\r\n")
        self.seg("rx", "auth", b"ACC\r\nPassword: ? ")
        off = self.seg("tx", "auth", RED + b"\r\n")
        self.redactions.append({"offset": off, "length": len(RED), "reason": "credential", "component": "transport"})
        self.seg("rx", "auth", framed(b"", b"\r\n\r\n" + hdr + b"Level 1\r\n", b"=>"))
        sections = []
        for cls, cmd, may_be_absent, sensitive in CLASSES:
            lines = replies(read)[cls]
            self.seg("tx", "operate", cmd.encode() + b"\r\n")
            text = (b"Invalid Command\r\n" if lines is ABSENT else
                    b"\r\n" + "\r\n".join(lines).encode() + b"\r\n\r\n")
            start = self.seg("rx", "operate", framed(cmd.encode() + b"\r\n", text, b"=>"))
            span = {"offset": start + len(cmd) + 3, "length": len(text)}
            assert self.data[span["offset"]:span["offset"] + span["length"]] == text
            sec = {"command": cmd, "class": cls, "state": "absent" if lines is ABSENT else "present",
                   "sensitive": sensitive, "span": span, "sha256": hashlib.sha256(text).hexdigest()}
            if lines is not ABSENT:
                sec["settings"] = tokenize(text.decode())
            sections.append(sec)
        self.seg("tx", "close", b"QUI\r\n")
        self.seg("rx", "close", framed(b"QUI\r\n", b"\r\n" + hdr, b"="))
        return sections

    def transcript(self):
        return {"data": base64.b64encode(self.data).decode(), "sha256": hashlib.sha256(self.data).hexdigest(),
                "segments": self.segments, "redactions": self.redactions}


SETTING = re.compile(r"([A-Z0-9][A-Z0-9_]*) *:= *")


def tokenize(text):
    """B2's Python reading of the rule in doc.go."""
    out, prev = [], "other"
    for line in re.split(r"\r\n|\n|\r", text):
        if line.strip(" ") == "":
            prev = "other"
        elif ":=" in line:
            i = len(line) - len(line.lstrip(" "))
            while True:
                m = SETTING.match(line, i)
                assert m, line
                i = m.end()
                j = line.find("  ", i)
                value = line[i:] .rstrip(" ") if j < 0 else line[i:j]
                assert value and ":=" not in value, line
                out.append({"name": m.group(1), "value": value})
                rest = "" if j < 0 else line[j:].lstrip(" ")
                if not rest:
                    break
                i = len(line) - len(rest)
            prev = "setting"
        elif prev == "setting":
            piece = line.strip(" ")
            assert "  " not in piece, line
            out[-1]["value"] += " " + piece
        else:
            prev = "other"
    names = [s["name"] for s in out]
    assert len(names) == len(set(names)), names
    return out


def snapshot(read, sections, s):
    return {
        "schema": SCHEMA, "kind": "config.snapshot", "asset_id": ASSET, "invocation_id": INVOCATIONS[read],
        "operation_id": "sel.config.read_all", "adapter": {"id": "sel-751-ascii", "version": "0.3.0-example"},
        "register_version": 5, "target": "simulated", "retrieved_at": s.ts(), "rule": RULE,
        "transcript": {"ref": "sha256:" + hashlib.sha256(s.data).hexdigest(),
                       "sha256": hashlib.sha256(s.data).hexdigest(), "length": len(s.data)},
        "sections": sections,
    }


def dump(obj):
    return (json.dumps(obj, indent=2) + "\n").encode()


def digest(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


def difference(a, a_bytes, b, b_bytes):
    """B2's Python reading of Compare."""
    changes = []
    for (cls, _, _, sensitive), x, y in zip(CLASSES, a["sections"], b["sections"]):
        if x["state"] != y["state"]:
            changes.append({"class": cls, "kind": "section-appeared" if y["state"] == "present" else
                            "section-disappeared", "sensitive": sensitive})
        old = {t["name"]: t["value"] for t in x.get("settings", [])}
        new = {t["name"]: t["value"] for t in y.get("settings", [])}
        for n in sorted(set(old) | set(new), key=lambda k: k.encode()):
            if n in old and n in new:
                if old[n] != new[n]:
                    changes.append({"class": cls, "kind": "changed", "name": n, "from": old[n], "to": new[n],
                                    "sensitive": sensitive})
            elif n in new:
                changes.append({"class": cls, "kind": "added", "name": n, "to": new[n], "sensitive": sensitive})
            else:
                changes.append({"class": cls, "kind": "removed", "name": n, "from": old[n], "sensitive": sensitive})

    def ref(s, raw):
        return {"snapshot_digest": digest(raw), "invocation_id": s["invocation_id"], "retrieved_at": s["retrieved_at"]}
    return {"schema": SCHEMA, "kind": "config.difference", "asset_id": a["asset_id"], "rule": a["rule"],
            "target": a["target"], "from": ref(a, a_bytes), "to": ref(b, b_bytes), "changes": changes}


def write(rel, b):
    path = os.path.join(HERE, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(b)


def main():
    snaps, raws = {}, {}
    for read in (1, 2, 3):
        s = Session(minute=10 * read)
        sections = s.run(read)
        write("transcripts/read-%d.json" % read, dump(s.transcript()))
        snaps[read] = snapshot(read, sections, s)
        raws[read] = dump(snaps[read])
        write("valid/snapshot-read-%d.json" % read, raws[read])
    d12 = difference(snaps[1], raws[1], snaps[2], raws[2])
    assert d12["changes"] == [], d12["changes"]
    write("valid/difference-1-2.json", dump(d12))
    d13 = difference(snaps[1], raws[1], snaps[3], raws[3])
    write("valid/difference-1-3.json", dump(d13))

    later = copy.deepcopy(snaps[1])
    later["schema"] = "otsec.config/0.4"
    later["zz_new"] = "a field 0.3 does not know"
    write("valid/later-minor-snapshot.json", dump(later))

    def bad(name, base, f):
        x = copy.deepcopy(base)
        f(x)
        write("invalid/%s.json" % name, dump(x))

    s1, d = snaps[1], d13
    bad("snapshot-missing-class", s1, lambda x: x["sections"].pop())
    bad("snapshot-classes-out-of-order", s1, lambda x: x["sections"].insert(0, x["sections"].pop(1)))
    bad("snapshot-required-class-absent", s1, lambda x: (x["sections"][2].update(state="absent"),
                                                         x["sections"][2].pop("settings")))
    bad("snapshot-absent-with-settings", s1, lambda x: x["sections"][11].update(settings=[{"name": "EPORT", "value": "Y"}]))
    bad("snapshot-present-without-settings", s1, lambda x: x["sections"][0].pop("settings"))
    bad("snapshot-port-not-sensitive", s1, lambda x: x["sections"][0].update(sensitive=False))
    bad("snapshot-unknown-rule", s1, lambda x: x.update(rule="sel-751-sho/3"))
    bad("snapshot-setting-twice", s1, lambda x: x["sections"][6]["settings"].append(dict(x["sections"][6]["settings"][0])))
    bad("snapshot-value-two-spaces", s1, lambda x: x["sections"][0]["settings"][1].update(value="FEEDER  RELAY"))
    bad("snapshot-value-holds-assign", s1, lambda x: x["sections"][0]["settings"][1].update(value="A := B"))
    bad("snapshot-ref-not-transcript", s1, lambda x: x["transcript"].update(ref="sha256:" + "0" * 64))
    bad("snapshot-other-major", s1, lambda x: x.update(schema="otsec.config/1.0"))
    bad("snapshot-unknown-field-in-own-minor", s1, lambda x: x.update(zz_new=1))
    bad("snapshot-wrong-kind", s1, lambda x: x.update(kind="config.baseline"))
    bad("snapshot-without-register-version", s1, lambda x: x.update(register_version=0))
    bad("snapshot-target-documented", s1, lambda x: x.update(target="documented"))
    bad("snapshot-sections-overlap", s1, lambda x: x["sections"][1]["span"].update(offset=x["sections"][0]["span"]["offset"]))
    bad("difference-changed-equal-values", d, lambda x: x["changes"][0].update(**{"to": x["changes"][0]["from"]}))
    bad("difference-added-with-from", d, lambda x: [c.update(**{"from": "N"}) for c in x["changes"] if c["kind"] == "added"][:1])
    bad("difference-out-of-order", d, lambda x: x["changes"].reverse())
    bad("difference-required-section-appeared", d, lambda x: x["changes"].insert(0, {"class": "group.1", "kind": "section-appeared", "sensitive": False}))
    bad("difference-without-changes", d12, lambda x: x.pop("changes"))
    bad("difference-digest-without-prefix", d12, lambda x: x["from"].update(snapshot_digest=x["from"]["snapshot_digest"][7:]))
    bad("difference-sensitive-unmarked", d, lambda x: [c.update(sensitive=False) for c in x["changes"] if c["class"] == "port.2"])


if __name__ == "__main__":
    main()
