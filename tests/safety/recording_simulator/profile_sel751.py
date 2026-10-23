"""SEL-751 documented-behaviour responder for the recording simulator.

Every behaviour here is transcribed by A6 from the SEL-751 Instruction Manual,
date code 20260910 (file 751_IM_20260910.pdf supplied by the project owner),
independently of A2's register and parser. Citations are manual page numbers.
Output is documentation, not device capture: it supports `simulated` claims
only. Anything the manual does not state is marked ASSUMED and kept minimal.

Documented (p. = manual page):
  prompts "=", "=>", "=>>" for Access Levels 0, 1, 2           p. 7.29-7.30
  ACC prompts "Password: ?"; up to three attempts; after the third
    failure SALARM pulses for 1 s and the relay stays at Level 0  p. 7.32-7.33
  with the Level 1 password disabled, ACC goes straight to Level 1  p. 7.33
  successful ACC answers header, "Level 1", "=>"                  p. 7.32
  2AC: SALARM pulses after successful Level 2 access or denial    p. 7.33
  "Invalid Access Level" / "Invalid Command"                      p. 7.31
  commands may be shortened to their first three characters       p. 7.31
  ID (Level 0) answers Figure 7.38                                p. 7.64
  QUIT (Level 0) returns to Level 0                                p. 7.73
  SER (Level 1) answers Figure 10.16 or "No Data Available"       p. 7.75, 10.40
  SER C or R clears the SER records at Level 1                    p. 7.75
  Level 1 clear/reset commands: HIS C|R|CA|RA (p. 7.60), LDP C (p. 7.65),
    MET c R (p. 7.68, asks "Reset Metering Quantities (Y,N)?"), SUM C|R
    (p. 7.81), TAR R (p. 7.82), COM C (p. 7.49), COM PTP C|R, FGS/GOOSE S n C
  Telnet: two concurrent sessions on PORT 1 (p. 7.13); without QUIT the
    relay stays at the elevated level until TIDLE expires (p. 7.16)
  SHO P n (Level 1) shows the settings of port n; Port 1 is Ethernet and
    carries MAXACC, LANG, FTPACC and HTTPACC (Table 7.67 p. 7.77;
    Table 4.104 p. 4.249-4.251, factory defaults)

ASSUMED (not stated in the manual): commands are case-insensitive; no
character echo; an unmodelled but valid command gets a placeholder; the
response text of clear commands is a placeholder; the layout of SHO P 1
output (no figure in the manual shows it) follows the SHO example on p. 7.78.
"""

import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.join(HERE, "documented", "sel-751")
CRLF = b"\r\n"
PROMPTS = {0: b"=", 1: b"=>", 2: b"=>>"}
UNMODELLED = b"[simulator: command not modelled from documentation]"

# (pattern on the upper-cased line, minimum level, effect text with citation)
LEVEL1_EFFECTS = [
    (r"SER\w*\s+[CR]\b.*", "SER records cleared (Table 7.63, p. 7.75)"),
    (r"HIS\w*(\s+\S+)*\s+(C|R|CA|RA)\b.*", "event history cleared (Table 7.37, p. 7.60)"),
    (r"LDP\w*\s+C\b.*", "load profile cleared (Table 7.47, p. 7.65)"),
    (r"SUM\w*\s+[CR]\b.*", "event summary archive cleared (p. 7.81)"),
    (r"TAR\w*\s+R\b.*", "front-panel targets reset (p. 7.82)"),
    (r"COM\w*(\s+PTP)?\s+[CR]\b.*", "communications records or PTP statistics cleared (p. 7.49)"),
    (r"(FGS|GOO)\w*\s+S\s+\S+\s+C\b.*", "GOOSE statistics cleared (p. 7.53-7.55)"),
]
METER_RESET = r"MET\w*\s+\S+\s+R\b.*"
KNOWN_VERBS = {
    "ACC", "2AC", "CAL", "QUI", "ID", "SER", "HIS", "LDP", "SUM", "TAR", "COM", "FGS", "GOO",
    "MET", "STA", "SET", "SHO", "EVE", "CON", "PUL", "OPE", "CLO", "PAS", "COP", "GRO", "R_S",
    "L_D", "FIL", "DAT", "TIM", "IRI", "LOO", "ANA", "HEL", "COU", "HSG", "HSR", "PRP", "RST",
    "89C", "89O", "TES", "BRE", "INI", "LOG",
}
LEVEL2_VERBS = {"SET", "CON", "PUL", "OPE", "CLO", "PAS", "COP", "GRO", "R_S", "L_D", "CAL", "89C", "89O", "TES"}


def _load(name):
    with open(os.path.join(DOC, name), "rb") as f:
        return f.read().replace(b"\r\n", b"\n").rstrip(b"\n").replace(b"\n", CRLF)


def _settings(name):
    with open(os.path.join(DOC, name)) as f:
        pairs = (line.split(":=", 1) for line in f if ":=" in line)
        return {n.strip(): v.strip() for n, v in pairs}


class SEL751DocResponder:
    def __init__(self, cfg, password=None, ser="example", rid=b"751", tid=b"FEEDER RELAY",
                 port1=None):
        self.password = password          # None models "Level 1 password disabled"
        self.level = 0
        self.awaiting = None              # level being authenticated for, or None
        self.attempts = 0
        self.ser = _load("ser-fig-10-16.txt") if ser == "example" else None
        self.id = _load("id-fig-7-38.txt")
        self.rid, self.tid = rid, tid
        self.quit_sent = False
        # Port 1 settings: Table 4.104 factory defaults, then any overrides.
        # An override value of None removes the setting from the output.
        self.port1 = _settings("port1-defaults-table-4-104.txt")
        for name, value in (port1 or {}).items():
            if value is None:
                self.port1.pop(name, None)
            else:
                self.port1[name] = value

    def _show_port1(self):
        cells = [f"{n:<8} := {v}".encode() for n, v in self.port1.items()]
        rows = [b"".join(c.ljust(27) for c in cells[i:i + 3]).rstrip()
                for i in range(0, len(cells), 3)]
        return CRLF + b"Port 1" + CRLF + CRLF + CRLF.join(rows) + CRLF

    def _prompt(self):
        return CRLF + PROMPTS[self.level]

    def _header(self):
        t = time.gmtime()
        stamp = time.strftime("%m/%d/%Y Time: %H:%M:%S", t).encode() + b".000"
        return (self.rid.ljust(42) + b"Date: " + stamp + CRLF +
                self.tid.ljust(42) + b"Time Source: Internal" + CRLF)

    def greeting(self):
        return PROMPTS[0]

    def _password_reply(self, line):
        from sim import Reply
        target = self.awaiting
        ok = target == 1 and self.password is not None and line == self.password
        effects = []
        if ok:
            self.awaiting, self.attempts, self.level = None, 0, 1
            out = CRLF + self._header() + CRLF + b"Level 1" + self._prompt()
        else:
            self.attempts += 1
            if self.attempts >= 3:
                self.awaiting, self.attempts = None, 0
                effects.append("SALARM pulsed 1 s after three failed passwords (p. 7.33)")
                if target == 2:
                    effects.append("SALARM pulsed on denied Level 2 access (p. 7.33)")
                out = self._prompt()
            else:
                out = CRLF + b"Password: ?"
        return Reply(out, secret=True, accepted=ok, effects=effects)

    def handle(self, line):
        from sim import Reply
        if self.awaiting is not None:
            return self._password_reply(line)
        text = line.decode("latin-1").strip().upper()
        if not text:
            return Reply(self._prompt())
        verb = text.split()[0][:3]
        if verb == "ACC":
            if self.password is None:
                self.level = max(self.level, 1)
                return Reply(CRLF + self._header() + CRLF + b"Level 1" + self._prompt())
            self.awaiting = 1
            return Reply(CRLF + b"Password: ?")
        if verb == "QUI":
            self.level = 0
            self.quit_sent = True
            return Reply(self._prompt())
        if verb == "ID":
            return Reply(CRLF + self.id + self._prompt())
        if verb not in KNOWN_VERBS:
            return Reply(CRLF + b"Invalid Command" + self._prompt())
        if self.level < 1 or (verb in LEVEL2_VERBS and self.level < 2):
            return Reply(CRLF + b"Invalid Access Level" + self._prompt())
        if verb == "2AC":
            self.awaiting = 2
            return Reply(CRLF + b"Password: ?",
                         effects=["Level 2 access attempted; SALARM pulses on success or denial (p. 7.33)"])
        for pattern, effect in LEVEL1_EFFECTS:
            if re.fullmatch(pattern, text):
                if pattern.startswith("SER"):
                    self.ser = None
                return Reply(CRLF + UNMODELLED + self._prompt(), effects=[effect])
        if re.fullmatch(METER_RESET, text):
            return Reply(CRLF + b"Reset Metering Quantities (Y,N)?",
                         effects=["metering reset requested; relay asks for Y/N confirmation (p. 7.68)"])
        if text == "SHO P 1":
            return Reply(self._show_port1() + self._prompt())
        if text == "SER":
            body = self.ser if self.ser is not None else b"No Data Available"
            return Reply(CRLF + body + self._prompt())
        return Reply(CRLF + UNMODELLED + self._prompt())

    def on_close(self):
        if self.level > 0:
            return [f"session closed at Access Level {self.level} without QUIT; relay stays "
                    "elevated until TIDLE expires (p. 7.16)"]
        return []


def factory(**kwargs):
    return lambda cfg: SEL751DocResponder(cfg, **kwargs)
