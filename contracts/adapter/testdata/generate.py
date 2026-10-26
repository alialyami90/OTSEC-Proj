"""Writes the C2 golden examples in invocations/ and results/.

Run from this directory with `python3 -I generate.py`. The output is
committed; adapter_test.go checks it and testdata/README.md gives one line
per file.

Every transcript here is invented. None is a device capture, and every result
says target "simulated". The command lines (QUI, ID, ACC, SHO P 1, SER) and
prompts ("=", "=>", "=>>", "Password: ?") follow S22 (SEL-751 instruction
manual, date code 20260910). The report layouts are modelled on S22 but
approximate: they exist to give spans something to point at, and the Phase 2
parser fixtures, not these files, are the format reference. ID checksums are
"0000" placeholders, not computed. FIDs are real Appendix A rows; serial
numbers, names, addresses and times are invented.
"""

import base64
import copy
import hashlib
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

SCHEMA = "otsec.adapter/0.1"
SCHEMA_0_2 = "otsec.adapter/0.2"  # results that need a 0.2 rule or code (D2-14)
SCHEMA_0_3 = "otsec.adapter/0.3"  # results that need a 0.3 code (A6 on #118)
SCHEMA_0_4 = "otsec.adapter/0.4"  # results that need a 0.4 probe outcome (A6, V-S12)
INV = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"   # invented
ASSET = "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13"  # the C1 relay example
FID = "SEL-751-R501-V0-Z104101-D20260910"       # S22 Table A.1 p. A.2
FID_OTHER = "SEL-751-R500-V1-Z103101-D20260910"  # S22 Table A.1 p. A.2
FID_R402 = "SEL-751-R402-V2-Z102100-D20250731"  # S22 Appendix A (A6 row list); allowed with EHTTP := N
SERIAL = "SIM0000000000001"                      # invented
SERIAL_OTHER = "SIM0000000000002"                # invented
CID = "E754"                                      # shape from S22 Figure 7.38
RED = b"[REDACTED]"
REGISTER_REVISION = 4  # contracts/register/testdata/sel-751.json
SER_FIELDS = ["#", "DATE", "TIME", "ELEMENT", "STATE"]  # the S22 Figure 10.16 header line, as printed
STX, ETX = b"\x02", b"\x03"


def framed(echo, text, prompt):
    """A relay reply: the echoed command line, then the message framed by
    STX and ETX (S22 p. 7.28: "<STX><MESSAGE LINE 1><CRLF> ... <LAST MESSAGE
    LINE><CRLF><ETX>"), then the prompt. A prompt on its own ("=", "=>",
    "Password: ?") is not a message and is not framed, and the prompt follows
    ETX; both are assumptions until H-13 (A6's simulator makes the same
    ones)."""
    if isinstance(text, str):
        text = text.encode()
    return echo + STX + text + ETX + prompt


def ts(n):
    """An invented time, n tenths of a second after 09:15:00."""
    return "2026-10-24T09:15:%02d.%dZ" % (n // 10, n % 10)


class Session:
    """Builds a transcript one segment at a time."""

    def __init__(self):
        self.data = b""
        self.segments = []
        self.redactions = []
        self.facts = {"connected": False, "wake_sent": False, "language_probe": "not-run", "password_prompt": False,
                      "credential_sent": False, "echo_scan": "not-applicable",
                      "access_level": "", "quit_sent": False}
        self.n = 0

    def _seg(self, d, phase, b):
        off = len(self.data)
        self.data += b
        self.segments.append({"offset": off, "length": len(b), "dir": d, "phase": phase, "at": ts(self.n)})
        self.n += 1
        return off

    def tx(self, phase, b):
        return self._seg("tx", phase, b)

    def rx(self, phase, b):
        return self._seg("rx", phase, b)

    def span(self, needle, after=0):
        if isinstance(needle, str):
            needle = needle.encode()
        i = self.data.index(needle, after)
        return {"offset": i, "length": len(needle)}

    def message_span(self):
        """The text of the last received message, inside STX and ETX."""
        seg = self.segments[-1]
        start = self.data.index(STX, seg["offset"]) + 1
        end = self.data.index(ETX, start)
        return {"offset": start, "length": end - start}

    def last_span(self):
        s = self.segments[-1]
        return {"offset": s["offset"], "length": s["length"]}

    # -- stages ------------------------------------------------------------

    def connect(self, prompt=b"\r\n="):
        # The device printed nothing on connect, so the transport sends one
        # line end (allowed only once the failed-auth floor has passed since a
        # session that ended without QUI; C7-A2 change 1).
        self.facts.update(connected=True, wake_sent=True, access_level="0")
        self.tx("probe", b"\r\n")
        self.rx("probe", prompt)          # the prompt comes before any register line

    def probe(self, reply=None):
        self.tx("probe", b"QUI\r\n")
        if reply is None:
            reply = framed(b"QUI\r\n", b"\r\nSEL-751          Date: 10/24/2026  Time: 09:15:00\r\n"
                                        b"FEEDER 1         Time Source: Internal\r\n\r\n", b"=")
            self.facts["language_probe"] = "accepted"
        else:
            self.facts["language_probe"] = "rejected"
        self.rx("probe", reply)

    def ident(self, fid=FID, frame=True, fid_line=True):
        """The ID reply. frame=False leaves out STX and ETX, and
        fid_line=False the FID line: replies the adapter cannot read
        (failed.identity_unreadable, A6 on #118)."""
        self.tx("probe", b"ID\r\n")
        lines = [
            '"FID=%s","0000"' % fid,
            '"BFID=BOOTLDR-R500-V0-Z000000-D20090925","0000"',
            '"CID=%s","0000"' % CID,
            '"DEVID=FEEDER 1","0000"',
            '"DEVCODE=91","0000"',
            '"PARTNO=751501A1A5A0X8C080","0000"',
        ][0 if fid_line else 1:]
        text = ("\r\n".join(lines) + "\r\n").encode()
        reply = framed(b"ID\r\n", text, b"=") if frame else b"ID\r\n" + text + b"="
        start = self.rx("probe", reply)
        self.id_start = start
        return self.span(fid, start) if fid_line else None

    def acc(self, prompt=True):
        self.tx("auth", b"ACC\r\n")
        if prompt:
            self.facts["password_prompt"] = True
            self.rx("auth", b"ACC\r\nPassword: ? ")
        else:
            self.rx("auth", framed(b"ACC\r\n", b"\r\nSEL-751          Date: 10/24/2026  Time: 09:15:02\r\n"
                                                b"FEEDER 1         Time Source: Internal\r\n\r\nLevel 1\r\n", b"=>"))
            self.facts["access_level"] = "1"

    def password(self, outcome="level1", echo=False):
        off = self.tx("auth", RED + b"\r\n")
        self.redactions.append({"offset": off, "length": len(RED), "reason": "credential", "component": "transport"})
        self.facts.update(credential_sent=True, echo_scan="performed")
        if outcome == "rejected":
            # A wrong password is answered with the prompt again (S22 p. 7.33).
            self.rx("auth", b"\r\nPassword: ? ")
            return
        body = b""
        if echo:
            body = RED
        level, prompt = {"level1": (b"Level 1", b"=>"), "level2": (b"Level 2", b"=>>")}[outcome]
        off = self.rx("auth", framed(body, b"\r\n\r\nSEL-751          Date: 10/24/2026  Time: 09:15:03\r\n"
                                           b"FEEDER 1         Time Source: Internal\r\n\r\n" + level + b"\r\n", prompt))
        if echo:
            self.redactions.append({"offset": off, "length": len(RED), "reason": "echo", "component": "transport"})
        self.facts["access_level"] = "2" if outcome == "level2" else "1"

    def sho_p1(self, lang="ENGLISH", maxacc="2", ehttp="N", drop_maxacc=False):
        self.tx("operate", b"SHO P 1\r\n")
        rows = ["Port 1", ""]
        if not drop_maxacc:
            rows.append("MAXACC  := %s" % maxacc)
        rows += ["FASTOP  := N", "LANG    := %s" % lang, "EHTTP   := %s" % ehttp, "FTPACC  := 1",
                 "HTTPACC := 1", "TIDLE   := 15"]
        start = self.rx("operate", framed(b"SHO P 1\r\n", "\r\n".join(rows) + "\r\n\r\n", b"=>"))
        self.p1_start = start
        return start

    def ser(self, serial=SERIAL, bad_row=False, prompt=b"=>", n_rows=None):
        self.tx("operate", b"SER\r\n")
        # Row 1 is the newest (S22 Figure 10.16).
        rows = [
            "1    10/24/2026 09:10:01.251   IN101             Deasserted",
            "2    10/24/2026 09:10:01.004   IN101             Asserted",
        ]
        if bad_row:
            rows.append("3    10/24/2026 09:1#:0?.###   IN102             Asserted")
        if n_rows is not None:
            # Invented rows, one second apart, newest first.
            secs = [9 * 3600 + 10 * 60 - i for i in range(1, n_rows + 1)]
            rows = ["%-4d 10/24/2026 %02d:%02d:%02d.000   IN101             %s"
                    % (i, t // 3600, t // 60 % 60, t % 60, ("Asserted", "Deasserted")[i % 2])
                    for i, t in zip(range(1, n_rows + 1), secs)]
        # The report prints the oldest row first: the highest number at the
        # top and row 1 last (S22 Figure 10.16, the response to SER 8).
        rows.reverse()
        text = framed(b"SER\r\n", "\r\n"
                "SEL-751          Date: 10/24/2026  Time: 09:15:04.112\r\n"
                "FEEDER 1         Time Source: Internal\r\n\r\n"
                "Serial No = %s\r\n"
                "FID = %s     CID = %s\r\n\r\n"
                "#    DATE       TIME           ELEMENT           STATE\r\n" % (serial, FID, CID)
                + "\r\n".join(rows) + "\r\n\r\n", prompt)
        start = self.rx("operate", text)
        self.ser_start = start
        header = self.span("SEL-751          Date", start)
        header["length"] = self.data.index(b"#    DATE", start) - header["offset"]
        records = []
        for r in rows:
            sp = self.span(r, start)
            if bad_row and r.startswith("3 "):
                records.append({"kind": "sel.ser.row", "span": sp, "context_span": header, "parse_ok": False})
                continue
            f = r.split()
            records.append({"kind": "sel.ser.row", "span": sp, "context_span": header, "parse_ok": True,
                            "fields": [{"name": n, "value": v} for n, v in zip(SER_FIELDS, f)]})
        return records

    def quit(self):
        self.tx("close", b"QUI\r\n")
        self.rx("close", framed(b"QUI\r\n", b"\r\nSEL-751          Date: 10/24/2026  Time: 09:15:05\r\n"
                                             b"FEEDER 1         Time Source: Internal\r\n\r\n", b"="))
        self.facts["quit_sent"] = True
        self.facts["access_level"] = self.facts["access_level"] or "0"

    def result(self, status, code=None, identity=None, observations=(), warnings=(), records=(), schema=SCHEMA):
        r = {
            "schema": schema,
            "invocation_id": INV,
            "operation_id": "sel.ser.read_all",
            "adapter": {"id": "sel-751-ascii", "version": "0.1.0-example"},
            "register_version": 0 if code == "refused.register_unverified" else REGISTER_REVISION,
            "target": "simulated",
            "status": status,
            "started_at": ts(0),
            "ended_at": ts(max(self.n, 1)),
            "transcript": {
                "data": base64.b64encode(self.data).decode(),
                "sha256": hashlib.sha256(self.data).hexdigest(),
                "segments": self.segments,
                "redactions": self.redactions,
            },
            "session": self.facts,
            "identity": identity or {"result": "not-checked"},
        }
        if code:
            r["error"] = {"code": code}
        if observations:
            r["observations"] = list(observations)
        if warnings:
            r["warnings"] = list(warnings)
        if records:
            r["records"] = list(records)
        return r


def item(name, expected, observed, span):
    return {"name": name, "expected": expected, "observed": observed, "span": span}


def to_level1(s, fid=FID, echo=False):
    """Connect, probe, check the FID, authenticate. Returns identity items."""
    s.connect()
    s.probe()
    fid_span = s.ident(fid)
    s.acc()
    s.password(echo=echo)
    return [item("firmware_id", fid, fid, fid_span)], fid_span


def maxacc_warning(s):
    return {"code": "warn.maxacc_above_1", "setting": "MAXACC", "observed": "2",
            "span": s.span("MAXACC  := 2", s.p1_start)}


def full(bad_row=False, echo=False, n_rows=None):
    s = Session()
    items, fid_span = to_level1(s, echo=echo)
    s.sho_p1()
    w = maxacc_warning(s)
    recs = s.ser(bad_row=bad_row, n_rows=n_rows)
    ser_span = s.span(SERIAL, s.ser_start)
    items.append(item("serial_number", SERIAL, SERIAL, ser_span))
    s.quit()
    obs = [{"name": "firmware_id", "value": FID, "span": fid_span},
           {"name": "sel.cid", "value": CID, "span": s.span(CID, s.id_start)},
           {"name": "serial_number", "value": SERIAL, "span": ser_span}]
    if n_rows is not None:
        # More rows than max_read_rows: the bytes are kept, nothing is parsed.
        r = s.result("partial", "partial.read_rows_exceeded", {"result": "match", "items": items}, obs, [w])
        r["error"]["detail"] = "%d rows; profile sel-751-ascii max_read_rows is 1024 (D1-12)" % n_rows
        return r
    status, code = ("partial", "partial.parse_errors") if bad_row else ("ok", None)
    return s.result(status, code, {"result": "match", "items": items}, obs, [w], recs)


# -- results: one valid example per outcome --------------------------------

BEFORE_CONNECT = [
    "refused.operation_not_invocable", "refused.invalid_parameters", "refused.limits_out_of_range",
    "refused.register_unverified", "refused.firmware_undeclared", "refused.firmware_not_allowlisted",
    "refused.asset_suspended", "refused.credential_unavailable", "refused.plaintext_not_acknowledged",
    "refused.session_busy", "refused.rate_limited", "failed.connect", "refused.invocation_mismatch",
]


def results():
    out = {"ok": full(), "ok-with-echo": full(echo=True), "partial.parse_errors": full(bad_row=True),
           "partial.read_rows_exceeded": full(n_rows=1025)}

    for code in BEFORE_CONNECT:
        out[code] = Session().result(code.split(".")[0], code)

    s = Session()
    s.connect(prompt=b"\r\n=>")  # a session left at Level 1 (S22 p. 7.16): nothing more is sent
    s.facts["access_level"] = "1"
    out["refused.session_elevated"] = s.result("refused", "refused.session_elevated")

    s = Session()
    s.facts.update(connected=True, access_level="0")
    s.rx("probe", b"\r\nPassword: ? ")  # a session left inside the prompt: nothing is sent, not even the wake
    out["refused.session_pending_password"] = s.result("refused", "refused.session_pending_password")

    s = Session()
    s.connect()
    s.probe(reply=framed(b"QUI\r\n", b"Comando no valido\r\n", b"="))  # invented non-English reply
    out["refused.language_probe_rejected"] = s.result("refused", "refused.language_probe_rejected")

    s = Session()
    s.connect()
    s.probe()
    sp = s.ident(FID_OTHER)
    out["refused.identity_mismatch"] = s.result(
        "refused", "refused.identity_mismatch", {"result": "mismatch", "items": [item("firmware_id", FID, FID_OTHER, sp)]},
        [{"name": "firmware_id", "value": FID_OTHER, "span": sp}])

    # An ID reply the adapter cannot read compares nothing, so it is not an
    # identity mismatch and suspends nothing (0.3, A6 on #118). The first is
    # the documented reply without STX and ETX, as the recording simulator
    # sends it without --profile-stx-etx; the second is framed but has no
    # FID line. ACC is not sent.
    s = Session()
    s.connect()
    s.probe()
    s.ident(frame=False)
    out["failed.identity_unreadable"] = s.result("failed", "failed.identity_unreadable", schema=SCHEMA_0_3)

    s = Session()
    s.connect()
    s.probe()
    s.ident(fid_line=False)
    out["failed.identity_unreadable-no-fid-line"] = s.result("failed", "failed.identity_unreadable", schema=SCHEMA_0_3)

    s = Session()
    s.connect()
    s.probe()
    sp = s.ident()
    s.acc(prompt=False)
    s.quit()
    out["refused.password_prompt_absent"] = s.result(
        "refused", "refused.password_prompt_absent", {"result": "match", "items": [item("firmware_id", FID, FID, sp)]})

    s = Session()
    s.connect()
    s.probe()
    sp = s.ident()
    s.acc()
    s.password(outcome="rejected")
    out["failed.auth_rejected"] = s.result(
        "failed", "failed.auth_rejected", {"result": "match", "items": [item("firmware_id", FID, FID, sp)]})

    # 0.2 (D2-14): a reply at Level 1 ends in "Password: ?". Anything sent now
    # would be a password attempt, so nothing is, not even QUI (C-19). Not
    # seen on a device; A2's FuzzRun found the state.
    # SHO P 1 comes first, as in every Level 1 read (D16), and its posture
    # warning is reported whatever the outcome (A2 on #100).
    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n\r\nPassword: ? ")
    out["failed.unexpected_password_prompt"] = s.result(
        "failed", "failed.unexpected_password_prompt", {"result": "match", "items": items},
        warnings=[maxacc_warning(s)], schema=SCHEMA_0_2)

    # 0.2 (D2-14): the probe reply prints a level prompt. D16 sends nothing
    # after a rejected probe, so this session reached Level 1 and ends
    # without QUI. Invented reply; A2's FuzzRun found the state.
    s = Session()
    s.connect()
    s.probe(reply=framed(b"QUI\r\n", b"Comando no valido\r\n", b"=>"))
    s.facts["access_level"] = "1"
    out["probe-rejected-at-level1"] = s.result("refused", "refused.language_probe_rejected", schema=SCHEMA_0_2)

    s = Session()
    s.connect()
    s.probe()
    sp = s.ident()
    s.acc()
    s.password(outcome="level2")
    s.quit()
    out["failed.unexpected_access_level"] = s.result(
        "failed", "failed.unexpected_access_level", {"result": "match", "items": [item("firmware_id", FID, FID, sp)]})

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1(lang="SPANISH")
    out["refused.language_not_english"] = s.result("refused", "refused.language_not_english",
                                                   {"result": "match", "items": items})

    s = Session()
    items, _ = to_level1(s, fid=FID_R402)
    s.sho_p1(ehttp="Y")
    s.quit()
    out["refused.firmware_condition_not_met"] = s.result("refused", "refused.firmware_condition_not_met",
                                                         {"result": "match", "items": items}, warnings=[maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.ser(serial=SERIAL_OTHER)
    sp = s.span(SERIAL_OTHER, s.ser_start)
    items.append(item("serial_number", SERIAL, SERIAL_OTHER, sp))
    s.quit()
    out["failed.identity_mismatch"] = s.result("failed", "failed.identity_mismatch", {"result": "mismatch", "items": items},
                                               [{"name": "serial_number", "value": SERIAL_OTHER, "span": sp}],
                                               [maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.ser(prompt=b"=")  # the prompt fell back to Level 0 (TIDLE)
    s.facts["access_level"] = "1"
    out["failed.access_level_dropped"] = s.result("failed", "failed.access_level_dropped",
                                                  {"result": "match", "items": items}, warnings=[maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", framed(b"SER\r\n", b"Invalid Command\r\n\r\n", b"=>"))
    s.quit()
    out["failed.device_error"] = s.result("failed", "failed.device_error", {"result": "match", "items": items},
                                          warnings=[maxacc_warning(s)])

    # No prompt after the QUI probe: a slow link or a closed connection is
    # not a language fault, so the probe is unanswered and the code suspends
    # nothing. Nothing more is sent (D16; 0.4, A6 on V-S12).
    s = Session()
    s.connect()
    s.tx("probe", b"QUI\r\n")  # then nothing until the step timeout
    s.facts["language_probe"] = "unanswered"
    out["failed.timeout-probe-unanswered"] = s.result("failed", "failed.timeout", schema=SCHEMA_0_4)

    s = Session()
    s.connect()
    s.tx("probe", b"QUI\r\n")
    s.rx("probe", b"QUI\r\n")  # the echo, then the connection closed
    s.facts["language_probe"] = "unanswered"
    out["failed.transport_closed-probe-unanswered"] = s.result("failed", "failed.transport_closed", schema=SCHEMA_0_4)

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n" + STX + b"\r\nSEL-751   ")  # then nothing until the step timeout
    s.quit()
    out["failed.timeout"] = s.result("failed", "failed.timeout", {"result": "match", "items": items},
                                     warnings=[maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n" + STX + b"\r\nSEL-751   ")  # then the connection closed
    out["failed.transport_closed"] = s.result("failed", "failed.transport_closed", {"result": "match", "items": items},
                                              warnings=[maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n" + STX + b"\r\n" + b"1    10/24/2026 09:10:01.004   IN101             Asserted\r\n" * 3)
    s.quit()
    out["failed.response_too_large"] = s.result("failed", "failed.response_too_large", {"result": "match", "items": items},
                                                warnings=[maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.quit()  # the adapter's next line was refused by the egress check and never sent
    out["failed.egress_violation"] = s.result("failed", "failed.egress_violation", {"result": "match", "items": items})

    # The failed-auth floor could not be recorded before ACC (sel751
    # FloorGate.BeforeACC): ACC is not sent, and at Level 0 no QUI is needed.
    s = Session()
    s.connect()
    s.probe()
    sp = s.ident()
    out["failed.internal"] = s.result(
        "failed", "failed.internal", {"result": "match", "items": [item("firmware_id", FID, FID, sp)]})

    # The wake was answered by the password prompt: the floor should make
    # this impossible, since a session that ended without QUI is left alone
    # until it expires. Nothing more is sent. The wake may have landed as a
    # blank password, so the collector sets the floor for this asset (A3 on
    # #99 and #112).
    s = Session()
    s.connect(prompt=b"\r\nPassword: ? ")
    out["failed.internal-wake-password-prompt"] = s.result("failed", "failed.internal")

    s = Session()
    s.connect()
    out["failed.unknown"] = s.result("failed", "failed.some_code_from_0_5", schema="otsec.adapter/0.5")

    # A setting missing from SHO P 1 raises its warning (A3).
    # As ok in every other respect: records, the serial check and the
    # observations.
    s = Session()
    items, fid_span = to_level1(s)
    s.sho_p1(drop_maxacc=True)
    p1 = s.message_span()  # the whole SHO P 1 message, inside STX and ETX
    recs = s.ser()
    ser_span = s.span(SERIAL, s.ser_start)
    items.append(item("serial_number", SERIAL, SERIAL, ser_span))
    s.quit()
    obs = [{"name": "firmware_id", "value": FID, "span": fid_span},
           {"name": "sel.cid", "value": CID, "span": s.span(CID, s.id_start)},
           {"name": "serial_number", "value": SERIAL, "span": ser_span}]
    out["ok-missing-setting"] = s.result("ok", None, {"result": "match", "items": items}, obs, [
        {"code": "warn.maxacc_above_1", "setting": "MAXACC", "missing": True, "span": p1}], recs)
    return out


# -- results: invalid ------------------------------------------------------

def refresh(r):
    data = base64.b64decode(r["transcript"]["data"])
    r["transcript"]["sha256"] = hashlib.sha256(data).hexdigest()
    return r


def invalid_results(good):
    out = {}
    fid_item = lambda sp: {"result": "match", "items": [item("firmware_id", FID, FID, sp)]}

    # Session rules checked against the bytes (A3 and A6 C2 reviews).
    s = Session()
    s.connect()
    s.probe(reply=framed(b"QUI\r\n", b"Comando no valido\r\n", b"="))
    s.quit()  # D16: nothing more after a rejected probe
    out["quit-after-rejected-probe"] = s.result("refused", "refused.language_probe_rejected")

    s = Session()
    s.facts.update(connected=True, wake_sent=True, access_level="0")
    s.rx("probe", b"\r\nPassword: ? ")
    s.tx("probe", b"\r\n")  # the wake into a password prompt is a password attempt
    out["wake-into-password-prompt"] = s.result("refused", "refused.session_pending_password")

    s = Session()
    s.connect(); s.probe(); sp = s.ident(); s.acc()
    off = s.tx("auth", RED + b"\r\n")  # no reply: the relay may still be in "Password: ?"
    s.redactions.append({"offset": off, "length": len(RED), "reason": "credential", "component": "transport"})
    s.facts.update(credential_sent=True, echo_scan="performed")
    s.quit()
    s.facts["access_level"] = "0"
    out["quit-after-unconfirmed-password"] = s.result("failed", "failed.timeout", fid_item(sp))

    s = Session()
    s.connect(); s.probe(); sp = s.ident()
    s.tx("auth", b"ACC\r\n")
    s.rx("auth", b"ACC\r\n")  # then nothing until the step timeout; a late "Password: ?" would take QUI
    s.quit()
    out["quit-after-unanswered-acc"] = s.result("failed", "failed.timeout", fid_item(sp))

    s = Session()
    s.connect(); s.probe(); sp = s.ident(); s.acc()
    off = s.tx("auth", RED + b"\r\nQUI\r\n")
    s.redactions.append({"offset": off, "length": len(RED), "reason": "credential", "component": "transport"})
    s.facts.update(credential_sent=True, echo_scan="performed")
    s.rx("auth", b"\r\nPassword: ? ")
    out["credential-and-quit-in-one-segment"] = s.result("failed", "failed.auth_rejected", fid_item(sp))

    s = Session()
    s.connect(); s.probe(); sp = s.ident()
    s.tx("auth", b"ACC\r\n")
    s.rx("auth", b"ACC\r\n=")  # no password prompt
    s.facts["password_prompt"] = True
    s.password()
    s.quit()
    out["credential-without-password-prompt"] = s.result("refused", "refused.password_prompt_absent", fid_item(sp))

    s = Session()
    s.connect(); s.probe(); sp = s.ident()
    s.tx("auth", b"2AC\r\n")
    s.rx("auth", b"2AC\r\n" + STX + b"Invalid Command\r\n" + ETX + b"=")
    s.quit()
    out["auth-line-not-acc"] = s.result("refused", "refused.password_prompt_absent", fid_item(sp))

    s = Session()
    s.connect(); s.ident(); s.acc(); s.password()  # no QUI language probe before ACC
    s.quit()
    out["acc-without-language-probe"] = s.result("failed", "failed.egress_violation", fid_item(s.span(FID, s.id_start)))

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n" + STX + b"\r\nSEL-751   ")
    s.tx("operate", b"SER\r\n")  # again, with no prompt between
    s.rx("operate", framed(b"SER\r\n", b"Invalid Command\r\n", b"=>"))
    s.quit()
    out["operate-line-without-prompt"] = s.result("failed", "failed.device_error", {"result": "match", "items": items})

    s = Session()
    items, _ = to_level1(s)
    s.tx("operate", b"SHO P 1\r\n")
    s.rx("operate", b"SHO P 1\r\n" + STX + b"Port 1\r\n\r\nMAXACC  :=")  # a setting, not the "=" prompt
    s.tx("operate", b"SER\r\n")
    s.rx("operate", framed(b"SER\r\n", b"Invalid Command\r\n", b"=>"))
    s.quit()
    out["setting-read-as-prompt"] = s.result("failed", "failed.device_error", {"result": "match", "items": items})

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("close", b"ACC\r\n")
    s.rx("close", b"ACC\r\n=>")
    s.facts["quit_sent"] = True
    out["close-line-not-quit"] = s.result("failed", "failed.egress_violation", {"result": "match", "items": items},
                                          warnings=[maxacc_warning(s)])

    s = Session()
    items, _ = to_level1(s)
    s.sho_p1()
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n" + STX + b"\r\nSEL-751   ")  # then the step timeout, and no QUI
    out["timeout-at-level1-without-quit"] = s.result("failed", "failed.timeout", {"result": "match", "items": items},
                                                     warnings=[maxacc_warning(s)])

    s = Session()
    s.connect()  # "=" received: not elevated
    s.facts["access_level"] = "1"
    out["elevated-with-level0-prompt"] = s.result("refused", "refused.session_elevated")

    r = copy.deepcopy(good["ok"])
    r["session"]["access_level"] = "2"
    out["access-level-without-prompt"] = r

    r = copy.deepcopy(good["ok"])
    r["identity"]["items"] = [it for it in r["identity"]["items"] if it["name"] == "serial_number"]
    out["identity-only-after-password"] = r

    r = copy.deepcopy(good["failed.timeout"])
    r["error"]["detail"] = "SER reply:\r\nSEL-751   "
    out["detail-with-device-text"] = r

    r = copy.deepcopy(good["ok"])
    r["added_in_0_2"] = {"x": 1}
    out["unknown-field-in-own-minor"] = r

    def mut(name, f, rehash=False):
        r = copy.deepcopy(good["ok"])
        f(r)
        out[name] = refresh(r) if rehash else r

    def gap(r):
        r["transcript"]["segments"][3]["offset"] += 1
        r["transcript"]["segments"][3]["length"] -= 1
    mut("segments-gap", gap)
    mut("segments-short", lambda r: r["transcript"]["segments"][-1].update(length=r["transcript"]["segments"][-1]["length"] - 1))

    def extra(r):
        d = base64.b64decode(r["transcript"]["data"]) + b"X"
        r["transcript"]["data"] = base64.b64encode(d).decode()
    mut("bytes-beyond-segments", extra, rehash=True)
    mut("sha256-mismatch", lambda r: r["transcript"].update(sha256="0" * 64))
    mut("phase-backwards", lambda r: r["transcript"]["segments"][-1].update(phase="probe"))

    def plaintext(r):
        d = bytearray(base64.b64decode(r["transcript"]["data"]))
        off = r["transcript"]["redactions"][0]["offset"]
        d[off:off + len(RED)] = b"hunter2xyz"  # invented secret of the marker's length
        r["transcript"]["data"] = base64.b64encode(bytes(d)).decode()
    mut("credential-not-redacted", plaintext, rehash=True)
    mut("credential-without-prompt", lambda r: r["session"].update(password_prompt=False))
    mut("credential-without-echo-scan", lambda r: r["session"].update(echo_scan="not-applicable"))
    mut("credential-without-redaction", lambda r: r["transcript"].update(redactions=[]))

    def cred_rx(r):
        rd = r["transcript"]["redactions"][0]
        rd["reason"] = "echo"
    mut("credential-redaction-labelled-echo", cred_rx)
    mut("ok-without-quit", lambda r: (r["session"].update(quit_sent=False)))

    def ok_with_error(r):
        r["error"] = {"code": "failed.timeout"}
    mut("ok-with-error-code", ok_with_error)
    mut("status-disagrees-with-code", lambda r: r.update(status="failed", error={"code": "refused.session_busy"}))
    mut("unknown-code-at-0.1", lambda r: r.update(status="failed", error={"code": "failed.something_new"}))

    # The probe QUI exemption is 0.2 (D2-14): a 0.1 result validates as it did (A6 on #100).
    r = copy.deepcopy(good["probe-rejected-at-level1"])
    r["schema"] = SCHEMA
    out["probe-rejected-at-level1-at-0.1"] = r

    # The unanswered probe (0.4): its own minor, only with a timeout or a
    # close, never after a reply that ends in a prompt, and nothing after it.
    r = copy.deepcopy(good["failed.timeout-probe-unanswered"])
    r["schema"] = SCHEMA_0_3
    out["probe-unanswered-at-0.3"] = r

    r = copy.deepcopy(good["failed.timeout-probe-unanswered"])
    r["status"], r["error"] = "refused", {"code": "refused.language_probe_rejected"}
    out["probe-unanswered-as-language-fault"] = r

    s = Session()
    s.connect()
    s.tx("probe", b"QUI\r\n")
    s.rx("probe", framed(b"QUI\r\n", b"Comando no valido\r\n", b"="))  # answered, off the grammar
    s.facts["language_probe"] = "unanswered"
    out["probe-unanswered-after-a-prompt"] = s.result("failed", "failed.timeout", schema=SCHEMA_0_4)

    s = Session()
    s.connect()
    s.tx("probe", b"QUI\r\n")
    s.rx("probe", b"QUI\r\n")
    s.tx("probe", b"ID\r\n")
    s.facts["language_probe"] = "unanswered"
    out["probe-unanswered-then-id"] = s.result("failed", "failed.timeout", schema=SCHEMA_0_4)

    # failed.identity_unreadable (0.3): its own minor, identity not-checked,
    # and ID the last line sent, after an accepted probe.
    r = copy.deepcopy(good["failed.identity_unreadable"])
    r["schema"] = SCHEMA_0_2
    out["identity-unreadable-at-0.2"] = r

    r = copy.deepcopy(good["refused.identity_mismatch"])
    r["schema"] = SCHEMA_0_3
    r["error"] = {"code": "failed.identity_unreadable"}
    r["status"] = "failed"
    out["identity-unreadable-with-mismatch"] = r

    # The unframed golden claiming the FID it shows as a match: nothing else
    # is wrong with it (A6 on #122).
    r = copy.deepcopy(good["failed.identity_unreadable"])
    data = base64.b64decode(r["transcript"]["data"])
    i = data.index(FID.encode())
    r["identity"] = {"result": "match", "items": [item("firmware_id", FID, FID, {"offset": i, "length": len(FID)})]}
    out["identity-unreadable-with-match"] = r

    s = Session()
    s.connect()
    s.probe()
    out["identity-unreadable-without-id"] = s.result("failed", "failed.identity_unreadable", schema=SCHEMA_0_3)

    s = Session()
    s.connect()
    s.probe(reply=framed(b"QUI\r\n", b"Comando no valido\r\n", b"="))
    s.ident(frame=False)
    out["identity-unreadable-after-rejected-probe"] = s.result("failed", "failed.identity_unreadable", schema=SCHEMA_0_3)

    # failed.unexpected_password_prompt (0.2, D2-14): its own minor, no QUI,
    # and the bytes must show Level 1 and the prompt.
    r = copy.deepcopy(good["failed.unexpected_password_prompt"])
    r["schema"] = SCHEMA
    out["unexpected-password-prompt-at-0.1"] = r

    s = Session()
    items, _ = to_level1(s)
    s.tx("operate", b"SER\r\n")
    s.rx("operate", b"SER\r\n\r\nPassword: ? ")
    s.quit()
    out["unexpected-password-prompt-then-quit"] = s.result(
        "failed", "failed.unexpected_password_prompt", {"result": "match", "items": items}, schema=SCHEMA_0_2)

    s = Session()
    s.connect()
    s.probe()
    sp = s.ident()
    s.acc()
    s.password(outcome="rejected")
    out["unexpected-password-prompt-for-rejected-password"] = s.result(
        "failed", "failed.unexpected_password_prompt", fid_item(sp), schema=SCHEMA_0_2)
    mut("span-in-sent-bytes", lambda r: r["observations"][0].update(span={"offset": 0, "length": 2}))

    def span_stx(r):
        # Widen the SER header span back over the STX (and the CRLF after it)
        # that opens the message.
        sp = r["records"][0]["context_span"]
        assert base64.b64decode(r["transcript"]["data"])[sp["offset"] - 3:sp["offset"]] == STX + b"\r\n"
        sp.update(offset=sp["offset"] - 3, length=sp["length"] + 3)
    mut("span-includes-stx", span_stx)

    r = copy.deepcopy(good["ok-with-echo"])
    rd = [x for x in r["transcript"]["redactions"] if x["reason"] == "echo"][0]
    r["observations"][0]["span"] = {"offset": rd["offset"], "length": rd["length"]}
    out["span-on-echo-redaction"] = r

    # The probe line goes out before the "=" prompt: drop the wake exchange.
    s = Session()
    s.facts.update(connected=True, access_level="0")
    s.probe()
    out["probe-before-prompt"] = s.result("failed", "failed.internal")

    # The reply ends in "=>": a Level 1 prompt, not the probe grammar.
    s = Session()
    s.connect()
    s.probe(reply=b"QUI\r\n=>")
    s.facts["language_probe"] = "accepted"
    out["probe-accepted-but-reply-off-grammar"] = s.result("failed", "failed.internal")

    def unparsed(r):
        r["records"][0]["parse_ok"] = False
    mut("ok-with-unparsed-record", unparsed)
    mut("identity-mismatch-reported-ok", lambda r: r["identity"]["items"][0].update(observed=FID_OTHER) or r["identity"].update(result="mismatch"))
    mut("warning-without-value", lambda r: r["warnings"][0].pop("observed"))
    mut("simulator-reported-as-device", lambda r: r.update(target="operator-declared"))
    mut("other-major", lambda r: r.update(schema="otsec.adapter/1.0"))

    r = copy.deepcopy(good["failed.auth_rejected"])
    r["session"]["quit_sent"] = True
    # QUI after a rejected password: add a close segment.
    d = base64.b64decode(r["transcript"]["data"])
    r["transcript"]["segments"].append({"offset": len(d), "length": 5, "dir": "tx", "phase": "close", "at": ts(40)})
    r["transcript"]["data"] = base64.b64encode(d + b"QUI\r\n").decode()
    out["auth-rejected-then-quit"] = refresh(r)

    r = copy.deepcopy(good["refused.session_busy"])
    r["session"]["connected"] = True
    out["before-connect-code-but-connected"] = r

    mut("no-register-version", lambda r: r.update(register_version=0))

    r = copy.deepcopy(good["refused.session_elevated"])
    d = base64.b64decode(r["transcript"]["data"])
    r["transcript"]["segments"].append({"offset": len(d), "length": 5, "dir": "tx", "phase": "close", "at": ts(40)})
    r["transcript"]["data"] = base64.b64encode(d + b"QUI\r\n").decode()
    r["session"]["quit_sent"] = True
    out["session-elevated-then-quit"] = refresh(r)

    # A second wake after the prompt: a pending password prompt would take it.
    r = copy.deepcopy(good["refused.identity_mismatch"])
    d = base64.b64decode(r["transcript"]["data"])
    segs = r["transcript"]["segments"]
    cut = segs[2]["offset"]
    new = d[:cut] + b"\r\n" + d[cut:]
    for sg in segs[2:]:
        sg["offset"] += 2
    segs.insert(2, {"offset": cut, "length": 2, "dir": "tx", "phase": "probe", "at": segs[1]["at"]})
    for o in r.get("observations", []):
        o["span"]["offset"] += 2
    for it in r["identity"]["items"]:
        it["span"]["offset"] += 2
    r["transcript"]["data"] = base64.b64encode(new).decode()
    out["wake-after-prompt"] = refresh(r)

    r = copy.deepcopy(good["refused.identity_mismatch"])
    r["identity"]["result"] = "match"
    r["identity"]["items"][0]["observed"] = FID
    out["identity-mismatch-code-with-match"] = r

    r = copy.deepcopy(good["refused.password_prompt_absent"])
    segs = r["transcript"]["segments"]
    d = base64.b64decode(r["transcript"]["data"])
    cut = segs[-2]["offset"]
    r["transcript"]["segments"] = segs[:-2]
    r["transcript"]["data"] = base64.b64encode(d[:cut]).decode()
    r["session"]["quit_sent"] = False
    out["prompt-absent-without-quit"] = refresh(r)

    r = copy.deepcopy(good["refused.language_probe_rejected"])
    r["error"]["code"] = "failed.internal"
    r["status"] = "failed"
    out["probe-rejected-wrong-code"] = r

    r = copy.deepcopy(good["partial.read_rows_exceeded"])
    d = base64.b64decode(r["transcript"]["data"])
    row1 = b"1    10/24/2026 09:09:59.000   IN101             Deasserted"
    f = row1.decode().split()
    r["records"] = [{"kind": "sel.ser.row", "span": {"offset": d.index(row1), "length": len(row1)}, "parse_ok": True,
                     "fields": [{"name": n, "value": v} for n, v in zip(SER_FIELDS, f)]}]
    out["read-rows-exceeded-with-parsed-record"] = r

    r = copy.deepcopy(good["partial.read_rows_exceeded"])
    del r["error"]["detail"]
    out["read-rows-exceeded-without-detail"] = r

    r = copy.deepcopy(good["ok"])
    r["records"][0]["fields"][3]["name"] = "bit"
    out["ser-row-field-renamed"] = r

    r = copy.deepcopy(good["ok"])
    for fld in r["records"][0]["fields"]:
        fld["name"] = {"#": "row"}.get(fld["name"], fld["name"].lower())
    out["ser-row-field-names-lowercase"] = r

    r = copy.deepcopy(good["ok"])
    del r["operation_id"]
    out["no-operation-id"] = r

    r = copy.deepcopy(good["partial.parse_errors"])
    for rec in r["records"]:
        if not rec["parse_ok"]:
            rec["parse_ok"] = True
            rec["fields"] = [{"name": "#", "value": "3"}]
    out["partial-without-unparsed-record"] = r

    r = copy.deepcopy(good["refused.language_not_english"])
    d = base64.b64decode(r["transcript"]["data"])
    r["transcript"]["segments"].append({"offset": len(d), "length": 5, "dir": "tx", "phase": "close", "at": ts(40)})
    r["transcript"]["data"] = base64.b64encode(d + b"QUI\r\n").decode()
    r["session"]["quit_sent"] = True
    out["language-not-english-then-quit"] = refresh(r)
    return out


# -- invocations -----------------------------------------------------------

def invocation(op="sel.ser.read_all", **kw):
    inv = {
        "schema": SCHEMA,
        "invocation_id": INV,
        "requested_at": "2026-10-24T09:14:59Z",
        "principal_ref": "scheduler:site-a-node1",
        "asset_id": ASSET,
        "endpoint_id": "port1-telnet",
        "profile_id": "sel-751-ascii",
        "operation_id": op,
        "credential_ref": "cred_lab751feeder1",
        "expected_identity": [{"name": "firmware_id", "value": FID}, {"name": "serial_number", "value": SERIAL}],
        "limits": {"connect_timeout_ms": 5000, "step_timeout_ms": 10000, "deadline_ms": 120000,
                   "max_response_bytes": 262144, "connect_retries": 1, "min_interval_ms": 60000},
    }
    inv.update(kw)
    return inv


def invocations():
    valid = {"sel-ser-read": invocation(),
             "sel-id-level0": {k: v for k, v in invocation(op="sel.id").items() if k != "credential_ref"}}
    bad = {}
    i = invocation()
    i["command"] = "SER C"
    bad["unknown-field"] = i
    bad["limits-above-ceiling"] = invocation(limits=dict(invocation()["limits"], max_response_bytes=1 << 30))
    bad["deadline-below-step"] = invocation(limits=dict(invocation()["limits"], deadline_ms=1000))
    bad["no-expected-identity"] = invocation(expected_identity=[])
    bad["params-with-free-text"] = invocation(params={"args": "C; ACC"})
    bad["other-major"] = invocation(schema="otsec.adapter/1.0")
    bad["credential-ref-not-c7"] = invocation(credential_ref="cred:site-a:sel-751-feeder1:acc")
    bad["principal-ref-not-c7"] = invocation(principal_ref="scheduler site-a")
    return valid, bad


def case_variant_invocation():
    s = json.dumps(invocation(), indent=2)
    return s[:-2] + ',\n  "OPERATION_ID": "sel.ser.clear"\n}\n'


def write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=False)
        f.write("\n")


def main():
    for d in ("results/valid", "results/invalid", "invocations/valid", "invocations/invalid"):
        p = os.path.join(HERE, d)
        if os.path.isdir(p):
            for f in os.listdir(p):
                if f.endswith(".json"):
                    os.remove(os.path.join(p, f))
    good = results()
    for name, r in good.items():
        write(os.path.join(HERE, "results/valid", name + ".json"), r)
    for name, r in invalid_results(good).items():
        write(os.path.join(HERE, "results/invalid", name + ".json"), r)
    v, b = invocations()
    for name, r in v.items():
        write(os.path.join(HERE, "invocations/valid", name + ".json"), r)
    for name, r in b.items():
        write(os.path.join(HERE, "invocations/invalid", name + ".json"), r)
    with open(os.path.join(HERE, "invocations/invalid", "case-variant-key.json"), "w") as f:
        f.write(case_variant_invocation())
    # Duplicate keys cannot be built with json.dump.
    with open(os.path.join(HERE, "invocations/invalid", "duplicate-key.json"), "w") as f:
        f.write(json.dumps(invocation(), indent=2)[:-2] + ',\n  "operation_id": "sel.ser.clear"\n}\n')


if __name__ == "__main__":
    main()
