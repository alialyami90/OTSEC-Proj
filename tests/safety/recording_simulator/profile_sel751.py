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
  messages are framed <STX> lines <CRLF> <ETX> (switch stx_etx)  p. 7.28
  Telnet: two concurrent sessions on PORT 1 (p. 7.13); without QUIT the
    relay stays at the elevated level until TIDLE expires (p. 7.16)
  SHO P n (Level 1) shows the settings of port n; Port 1 is Ethernet and
    carries MAXACC, LANG, FTPACC and HTTPACC (Table 7.67 p. 7.77;
    Table 4.104 p. 4.249-4.251, factory defaults)
  Firmware revision history lists fixed defects where communications could
    cause a diagnostic restart, for example "Telnet traffic" (fixed
    R300-V3 and R202-V1, D20210104); triggers undocumented (A2 D27)
  Port 1 LANG := SPANISH: ASCII commands display in Spanish (p. 1.6); in the
    Command Summary, QUIT is SAL, SHO is MOS, and `SER D o R` clears the SER

SYNTHESIZED, not documented (ser="grow", for V-S4 and V-S6): each SER read
adds rows after Figure 10.16's newest, in the figure's layout, and renumbers
every row so row 1 is the newest (Table 7.63, p. 7.75). The added rows
(elements from the figure, one second apart, after its last time) are test
data, not a documentation example, and support only `simulated` claims about
the platform's handling of a buffer that changes between reads.

SYNTHESIZED fault cases, not documented (V-S12): ser="hang" sends the
figure's header and its first four rows, then nothing more for that SER (no
prompt; later lines are answered as usual); ser="malformed" sends the figure
with row 5's TIME damaged ("13:5X:10.003"), so that one row does not parse.

Not stated in the manual, modelled as a switch (A2's C7 review): whether a new
Telnet connection inherits the state a session left behind when it closed
without QUIT, before TIDLE expires (p. 7.16 says only that the relay stays
elevated). RelayState(inherit=None) gives every connection a fresh Level 0
(the default); inherit="level" starts the next connection at the level left
behind; inherit="prompt" also carries a pending "Password: ?" and the failed
attempt count, so the next connection's first line is read as a password.

ASSUMED (not stated in the manual): the QUIT reply (see quit_reply);
commands are case-insensitive; no
character echo; an unmodelled but valid command gets a placeholder; the
response text of clear commands is a placeholder; the layout of SHO P 1
output (no figure in the manual shows it) follows the SHO example on p. 7.78
and the SEL-400 `SHO P 5` example; with LANG := SPANISH the English names of
commands that have a different Spanish name are rejected with the English
error text.
"""

import datetime
import os
import re
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DOC = os.path.join(HERE, "documented", "sel-751")
CRLF = b"\r\n"
PROMPTS = {0: b"=", 1: b"=>", 2: b"=>>"}
UNMODELLED = b"[simulator: command not modelled from documentation]"
# ASSUMED layout for SHO P 1: section headings, KEY := value columns, and
# quoted strings follow the SEL-400 Series IM 20260730 `SHO P 5` example
# (p. 15.49) and the SEL-751 `SHO` example (p. 7.78). Heading names and where
# each section starts are A6's guess from Table 4.104's order.
PORT1_SECTIONS = {
    "EPORT": "Protocol Selection", "IPADDR": "IP Configuration",
    "ETELNET": "Telnet Configuration", "EFTPSERV": "FTP Configuration",
    "E61850": "IEC 61850 Configuration", "EMOD": "Modbus Configuration",
    "EHTTP": "HTTP Server Configuration", "ERSTP": "RSTP Configuration",
    "EFGTX": "Other Protocols",
}

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


def _replace_id_field(block, field, checksum_ok=True):
    """Replace the ID line whose field starts like `field` and recompute its
    checksum: the 16-bit byte sum through the comma before it (SEL AG95-04)."""
    name = field.split(b"=", 1)[0] + b"="
    lines = block.split(CRLF)
    for i, line in enumerate(lines):
        if line.startswith(b'"' + name):
            body = b'"' + field + b'",'
            total = (sum(body) + (0 if checksum_ok else 1)) & 0xFFFF
            lines[i] = body + b'"%04X"' % total
    return CRLF.join(lines)


def _settings(name):
    with open(os.path.join(DOC, name)) as f:
        pairs = (line.split(":=", 1) for line in f if ":=" in line)
        return {n.strip(): v.strip() for n, v in pairs}


class RelayState:
    """State one relay keeps between Telnet connections, shared by every
    responder a factory creates. inherit: None, "level" or "prompt" (see the
    module docstring); tidle: seconds the left-behind state lasts (TIDLE)."""

    def __init__(self, inherit=None, tidle=900.0):
        assert inherit in (None, "level", "prompt")
        self.inherit, self.tidle = inherit, tidle
        self.level, self.awaiting, self.attempts, self.until = 0, None, 0, 0.0

    def take(self):
        if self.inherit is None or time.monotonic() >= self.until:
            return 0, None, 0
        if self.inherit == "level":
            return self.level, None, 0
        return self.level, self.awaiting, self.attempts

    def leave(self, level, awaiting, attempts):
        self.level, self.awaiting, self.attempts = level, awaiting, attempts
        self.until = time.monotonic() + self.tidle if (level > 0 or awaiting) else 0.0


SER_ROW = re.compile(rb"^(\d+)\s+(\d\d/\d\d/\d{4})\s+(\d\d:\d\d:\d\d\.\d{3})\s+(\S+)\s+(\S+)$")
GROW_ELEMENTS = (b"51P1P", b"51AP", b"51P1T", b"TRIP")


def ser_row(num, date, time, element, state):
    """One SER row in Figure 10.16's column layout."""
    return b"%-6d%s   %s   %-25s%s" % (num, date, time, element, state)


def grown_rows(added):
    """The rows of a grown SER buffer, oldest first as printed: Figure
    10.16's eight, then `added` synthesized rows, numbered so the newest is
    row 1. Each row is (date, time, element, state)."""
    rows = []
    for line in _load("ser-fig-10-16.txt").split(CRLF):
        m = SER_ROW.match(line)
        if m:
            rows.append(m.groups()[1:])
    base = datetime.datetime(2007, 2, 28, 13, 54, 11)
    for k in range(added):
        t = base + datetime.timedelta(seconds=k)
        rows.append((t.strftime("%m/%d/%Y").encode(), t.strftime("%H:%M:%S").encode() + b".000",
                     GROW_ELEMENTS[k % 4], b"Asserted" if (k // 4) % 2 == 0 else b"Deasserted"))
    return rows


def grown_ser(added):
    """The SER reply after `added` synthesized rows: the figure's header,
    then every row renumbered (SYNTHESIZED, see the module documentation)."""
    lines = _load("ser-fig-10-16.txt").split(CRLF)
    head = []
    for line in lines:
        if SER_ROW.match(line):
            break
        head.append(line)
    rows = grown_rows(added)
    body = [ser_row(len(rows) - i, *r) for i, r in enumerate(rows)]
    return CRLF.join(head + body)


class SerGrowth:
    """The count of synthesized rows, kept in a file so that it survives a
    simulator restart (the device's buffer does). Each SER read adds `step`."""

    def __init__(self, path, step):
        self.path, self.step = path, step

    def read(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                n = int(f.read().strip() or 0)
        except FileNotFoundError:
            n = 0
        n += self.step
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(n))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        return n


class SEL751DocResponder:
    def __init__(self, cfg, password=None, ser="example", rid=b"751", tid=b"FEEDER RELAY",
                 port1=None, spanish_accepts_english=False, quit_reply=None,
                 fid=None, fid_checksum_ok=True, vulnerable=None, relay=None, stx_etx=False, growth=None):
        self.password = password          # None models "Level 1 password disabled"
        # p. 7.28: "The relay transmits all messages in the following format:
        # <STX><MESSAGE LINE 1><CRLF> ... <LAST MESSAGE LINE><CRLF><ETX>".
        # Documented but untested, so a switch (off by default, as the
        # profile was built). ASSUMED: the prompt follows ETX, outside it.
        self.stx_etx = stx_etx
        self.relay = relay
        self.level, self.awaiting, self.attempts = relay.take() if relay else (0, None, 0)
        self.inherited = self.level > 0 or self.awaiting is not None
        self.elevated_here = False        # this session raised the level
        self.ser = _load("ser-fig-10-16.txt") if ser in ("example", "grow", "hang", "malformed") else None
        self.hang = ser == "hang"
        if ser == "malformed":
            self.ser = self.ser.replace(b"5     02/28/2007   13:54:10.003", b"5     02/28/2007   13:5X:10.003")
        self.growth = growth if ser == "grow" else None
        self.id = _load("id-fig-7-38.txt")
        if fid is not None:
            self.id = _replace_id_field(self.id, b"FID=" + fid, fid_checksum_ok)
        # vulnerable: text naming a documented firmware defect in which
        # communications traffic could cause a diagnostic restart (A2 D27,
        # firmware history in the IM). Its trigger is undocumented, so any
        # session that reaches such a unit is recorded as a device effect.
        self.vulnerable = vulnerable
        self.exposed = False
        self.rid, self.tid = rid, tid
        self.quit_sent = False
        # Port 1 settings: Table 4.104 factory defaults, then any overrides.
        # An override value of None removes the setting from the output.
        self.spanish_accepts_english = spanish_accepts_english  # undocumented
        # The IM documents no QUIT reply. None: the prompt only; "header": a
        # Table 7.16 header, then "Level 0", then the prompt (as ACC answers,
        # p. 7.32); bytes: sent verbatim, for near-miss tests.
        self.quit_reply = quit_reply
        self.port1 = _settings("port1-defaults-table-4-104.txt")
        for name, value in (port1 or {}).items():
            if value is None:
                self.port1.pop(name, None)
            else:
                self.port1[name] = value

    def _show_port1(self):
        out, cells = [b"Port 1"], []

        def flush():
            out.extend(b"".join(c.ljust(max(27, len(c) + 2)) for c in cells[i:i + 3]).rstrip()
                       for i in range(0, len(cells), 3))
            cells.clear()

        for name, value in self.port1.items():
            if name in PORT1_SECTIONS:
                flush()
                out += [b"", PORT1_SECTIONS[name].encode(), b""]
            if " " in value or not value:
                value = '"' + value + '"'
            cells.append(f"{name:<8} := {value}".encode())
        flush()
        return CRLF + CRLF.join(out) + CRLF

    def _prompt(self):
        return CRLF + PROMPTS[self.level]

    def _header(self):
        t = time.gmtime()
        stamp = time.strftime("%m/%d/%Y Time: %H:%M:%S", t).encode() + b".000"
        return (self.rid.ljust(42) + b"Date: " + stamp + CRLF +
                self.tid.ljust(42) + b"Time Source: Internal" + CRLF)

    def _password_reply(self, line):
        from sim import Reply
        target = self.awaiting
        ok = target == 1 and self.password is not None and line == self.password
        effects = []
        if ok:
            self.awaiting, self.attempts, self.level = None, 0, 1
            self.elevated_here = True
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
        inherited, self.inherited = self.inherited, False
        start_level, prompt_inherited = self.level, inherited and self.awaiting is not None
        reply = self._handle(line)
        if inherited:
            what = ("its first line was read as a password at a 'Password: ?' prompt"
                    if prompt_inherited else f"it started at Access Level {start_level}")
            reply.effects = [f"connection inherited the state an earlier session left without QUIT: "
                             f"{what} (switch inherit; p. 7.16 does not say)"] + list(reply.effects)
        if self.vulnerable and not self.exposed:
            self.exposed = True
            reply.effects = list(reply.effects) + [self._exposure()]
        if self.stx_etx and not getattr(reply, "unframed", False):
            reply.out = self._frame(reply.out)
        return reply

    def _frame(self, out):
        """Wrap the message part of a reply in STX ... CRLF ETX (p. 7.28),
        leaving the trailing prompt outside. A reply that is only a prompt
        carries no message and is not framed."""
        for prompt in (PROMPTS[self.level], b"Password: ?"):
            if out.endswith(CRLF + prompt):
                body = out[:-len(CRLF + prompt)]
                break
        else:
            body, prompt = out, b""
        lines = body[len(CRLF):] if body.startswith(CRLF) else body
        if not lines:
            return out
        return b"\x02" + lines + CRLF + b"\x03" + prompt

    def _exposure(self):
        return f"traffic reached firmware with a documented diagnostic-restart defect: {self.vulnerable}"

    def _handle(self, line):
        from sim import Reply
        if self.awaiting is not None:
            return self._password_reply(line)
        text = line.decode("latin-1").strip().upper()
        if not text:
            return Reply(self._prompt())
        verb = text.split()[0][:3]
        if self.port1.get("LANG") == "SPANISH":
            reply = self._spanish(text, verb)
            if reply is not None:
                return reply
        if verb == "ACC":
            if self.password is None:
                self.level = max(self.level, 1)
                return Reply(CRLF + self._header() + CRLF + b"Level 1" + self._prompt())
            self.awaiting = 1
            return Reply(CRLF + b"Password: ?")
        if verb == "QUI":
            self.level = 0
            self.quit_sent = True
            if self.quit_reply == "header":
                return Reply(CRLF + self._header() + CRLF + b"Level 0" + self._prompt())
            if isinstance(self.quit_reply, bytes):
                return Reply(self.quit_reply)
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
            if self.ser is not None and self.growth is not None:
                self.ser = grown_ser(self.growth.read())
            if self.hang:
                lines = self.ser.split(CRLF)
                cut = next(i for i, l in enumerate(lines) if SER_ROW.match(l)) + 4
                # Cut inside the message: STX sent, ETX and the prompt never.
                reply = Reply((b"\x02" if self.stx_etx else CRLF) + CRLF.join(lines[:cut]) + CRLF)
                reply.unframed = True
                return reply
            body = self.ser if self.ser is not None else b"No Data Available"
            return Reply(CRLF + body + self._prompt())
        return Reply(CRLF + UNMODELLED + self._prompt())

    def _spanish(self, text, verb):
        """Port LANG := SPANISH: commands that differ from English (Command
        Summary, English/Spanish table). Returns None to fall through to the
        English handling for commands that are the same in both (ACC, ID, SER)."""
        from sim import Reply
        if verb in ("QUI", "SHO") and not self.spanish_accepts_english:
            # Spanish names are SAL and MOS. Whether the English name is also
            # accepted is undocumented; spanish_accepts_english picks a case.
            return Reply(CRLF + b"Invalid Command" + self._prompt())
        if verb == "SAL":
            self.level, self.quit_sent = 0, True
            return Reply(self._prompt())
        if verb == "MOS":
            if self.level < 1:
                return Reply(CRLF + b"Invalid Access Level" + self._prompt())
            if text == "MOS P 1":
                return Reply(self._show_port1() + self._prompt())
            return Reply(CRLF + UNMODELLED + self._prompt())
        if self.level >= 1 and re.fullmatch(r"SER\w*\s+[DR]\b.*", text):
            self.ser = None
            return Reply(CRLF + UNMODELLED + self._prompt(),
                         effects=["SER records cleared: Spanish 'SER D o R' (Command Summary)"])
        return None

    def greeting(self):
        return PROMPTS[self.level]

    def on_close(self):
        effects = []
        if self.vulnerable and not self.exposed:
            effects.append(self._exposure())
        if self.level > 0 and (self.elevated_here or self.relay is None):
            effects.append(f"session closed at Access Level {self.level} without QUIT; relay stays "
                           "elevated until TIDLE expires (p. 7.16)")
        if self.relay is not None and not self.inherited:
            # A connection that inherited a state and sent nothing leaves it as it was.
            self.relay.leave(self.level, self.awaiting, self.attempts)
        return effects


def factory(**kwargs):
    return lambda cfg: SEL751DocResponder(cfg, **kwargs)
