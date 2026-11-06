"""Writes the C2 0.7 golden examples for an SNMPv3 session in snmp/.

Run from this directory with `python3 -I generate_snmp.py`. The output is
committed; snmp_test.go checks it and snmp/README.md gives one line per file.
It builds on generate.py's Session, so the segments, times and result
envelope are the ones every other C2 golden has.

Every message here is invented and in its stored form (C2 0.7,
modules/ied/snmpv3): msgData holds the plaintext scoped PDU, and every digest
is zero octets (usm-digest). Nothing was encrypted or signed, and every
result says target "simulated". The BER follows RFC 3412 and RFC 3414 as
recalled, since the RFC texts are not in the project files (desk). The family
is the SEL-2731 and SEL-2741 in RSTP mode (docs/phase4/C2-snmp-family.md).
The engine ID has the documented form, 80 00 7C 4F 03 and then the unit's MAC
(S29 p. 42), with an invented, locally administered MAC. The FID has the
documented form (S29 pp. 7 to 8), but this value is invented. sysName and the
other values are invented.

snmp/register.json is a minimal 0.4 package that holds only the identity run
(C3 0.4), for CheckSNMP. Its firmware list is invented, and nothing reads it.
"""

import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import generate as g  # noqa: E402  (a module of this directory, run with -I from here)

SCHEMA_0_7 = "otsec.adapter/0.7"
RUN = "sel27x1.snmp.identity"
SYSTEM = "sel27x1.snmp.system"
ENTITY = "sel27x1.snmp.entity"
REGISTER_REVISION = 1
ENGINE = bytes.fromhex("80007c4f03020000273101")  # documented form, invented MAC
ENGINE_OTHER = bytes.fromhex("80007c4f03020000273102")
USER = b"otsec-ro"
FID = "SEL-2731M-R102-V1-Z003001-D20260408"  # invented, in the documented form
FID_OTHER = "SEL-2731M-R101-V0-Z003001-D20260101"  # invented
HOST = "sw-bay-1"  # invented

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
ENT_TREE = "1.3.6.1.2.1.47.1.1.1"
ENT_DESCR_1 = "1.3.6.1.2.1.47.1.1.1.1.2.1"
ENT_SW_REV_1 = "1.3.6.1.2.1.47.1.1.1.1.10.1"
ENT_SW_REV_2 = "1.3.6.1.2.1.47.1.1.1.1.10.2"  # a second entity's software revision
ENT_OUTSIDE = "1.3.6.1.2.1.47.1.2.1.1.2.1"  # entLogicalDescr.1: past the subtree, so the walk ends
USM_STATS = "1.3.6.1.6.3.15.1.1.%d.0"  # usmStats: 1 unsupported sec level ... 6 decryption errors
UNSUPPORTED, NOT_IN_TIME, UNKNOWN_USER, UNKNOWN_ENGINE, WRONG_DIGEST, DECRYPTION = 1, 2, 3, 4, 5, 6

GET, GETBULK, RESPONSE, REPORT = 0xA0, 0xA5, 0xA2, 0xA8
AUTH, PRIV, REPORTABLE = 0x01, 0x02, 0x04
DIGEST_MARK = b"\xa5" * 24  # replaced by zeros once its offset is known


# -- BER -------------------------------------------------------------------

def tlv(tag, val):
    n = len(val)
    if n < 0x80:
        return bytes([tag, n]) + val
    ln = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(ln)]) + ln + val


def integer(n, tag=0x02):
    size = 1
    while not -(1 << (8 * size - 1)) <= n < (1 << (8 * size - 1)):
        size += 1
    return tlv(tag, n.to_bytes(size, "big", signed=True))


def octets(b):
    return tlv(0x04, b if isinstance(b, bytes) else b.encode())


def oid(s):
    arcs = [int(a) for a in s.split(".")]
    out = bytes([arcs[0] * 40 + arcs[1]])
    for a in arcs[2:]:
        enc = [a & 0x7F]
        a >>= 7
        while a:
            enc.insert(0, 0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(enc)
    return tlv(0x06, out)


def seq(*parts):
    return tlv(0x30, b"".join(parts))


NULL = b"\x05\x00"


def counter(n):
    return integer(n, 0x41)


def pdu(tag, req, varbinds, status=0, index=0):
    return tlv(tag, integer(req) + integer(status) + integer(index) +
               seq(*[seq(oid(o), v) for o, v in varbinds]))


def scoped(engine, body):
    return seq(octets(engine), octets(b""), body)


def message(msg_id, flags, engine, boots, time, user, body, digest=0):
    """One SNMPv3 message in its stored form. It returns the bytes and the
    digest's offset in them (None without a digest)."""
    mark = DIGEST_MARK[:digest]
    usm = seq(octets(engine), integer(boots), integer(time), octets(user), octets(mark),
              octets(b"\x00\x00\x00\x00\x00\x00\x00\x01" if flags & PRIV else b""))
    m = seq(integer(3), seq(integer(msg_id), integer(1472), octets(bytes([flags])), integer(3)),
            octets(usm), scoped(engine, body))
    if not digest:
        return m, None
    at = m.index(mark)
    return m[:at] + bytes(digest) + m[at + digest:], at


# -- sessions ----------------------------------------------------------------

class SNMP(g.Session):
    """An SNMPv3 identity run: discovery in probe, time synchronization in
    auth, the two steps in operate. msg_id and request_id advance together."""

    def __init__(self):
        super().__init__()
        self.facts.update(connected=False, access_level="")
        self.facts["snmp"] = {"engine_id": "", "authenticated": False}
        self.req = 0
        self.items = []
        self.obs = []

    def send(self, phase, flags, engine, boots, time, body_fn, user=USER, digest=24):
        self.req += 1
        m, at = message(self.req, flags, engine, boots, time, user if flags & AUTH else b"", body_fn(self.req),
                        digest if flags & AUTH else 0)
        off = self.tx(phase, m)
        self.digest(off, at, digest)
        self.facts["connected"] = True

    def recv(self, phase, flags, engine, boots, time, body, user=USER, digest=24):
        m, at = message(self.req, flags, engine, boots, time, user if flags & AUTH else b"", body,
                        digest if flags & AUTH else 0)
        off = self.rx(phase, m)
        self.digest(off, at, digest)
        return off, m

    def digest(self, off, at, n):
        if at is not None:
            self.redactions.append({"offset": off + at, "length": n, "reason": "usm-digest", "component": "transport"})

    def discover(self, engine=ENGINE, expected=ENGINE):
        self.send("probe", REPORTABLE, b"", 0, 0, lambda r: pdu(GET, r, []))
        off, m = self.recv("probe", 0, engine, 1, 3600, pdu(REPORT, self.req, [(USM_STATS % UNKNOWN_ENGINE, counter(1))]))
        e = self.data.index(engine, off)
        self.facts["snmp"]["engine_id"] = engine.hex()
        self.items.append(g.item("snmp_engine_id", expected.hex(), engine.hex(), {"offset": e, "length": len(engine)}))

    def first_request(self, phase, boots, time):
        self.send(phase, AUTH | PRIV | REPORTABLE, ENGINE, boots, time,
                  lambda r: pdu(GET, r, [(SYS_DESCR, NULL), (SYS_NAME, NULL)]))

    def time_sync(self):
        self.first_request("auth", 0, 0)
        self.recv("auth", AUTH, ENGINE, 1, 3600, pdu(REPORT, self.req, [(USM_STATS % NOT_IN_TIME, counter(1))]))
        self.facts["snmp"]["authenticated"] = True

    def system(self, status=0):
        self.first_request("operate", 1, 3600)
        vbs = [(SYS_DESCR, octets("SEL-2731M Managed Ethernet Switch")), (SYS_NAME, octets(HOST))]
        off, _ = self.recv("operate", AUTH | PRIV, ENGINE, 1, 3600, pdu(RESPONSE, self.req, vbs, status, 1 if status else 0))
        if status:
            return
        e = self.data.index(ENGINE, off)
        self.obs.append({"name": "snmp_engine_id", "value": ENGINE.hex(), "span": {"offset": e, "length": len(ENGINE)},
                         "read": {"operation": SYSTEM, "header": "msgAuthoritativeEngineID"}})
        self.obs.append({"name": "hostname", "value": HOST, "span": self.span(HOST, off),
                         "read": {"operation": SYSTEM, "oid": SYS_NAME}})

    def entity(self, fid=FID, increasing=True):
        self.send("operate", AUTH | PRIV | REPORTABLE, ENGINE, 1, 3601,
                  lambda r: tlv(GETBULK, integer(r) + integer(0) + integer(16) + seq(seq(oid(ENT_TREE), NULL))))
        third = ENT_OUTSIDE if increasing else ENT_DESCR_1
        vbs = [(ENT_DESCR_1, octets("SEL-2731M")), (ENT_SW_REV_1, octets(fid)), (third, octets("x"))]
        off, _ = self.recv("operate", AUTH | PRIV, ENGINE, 1, 3601, pdu(RESPONSE, self.req, vbs))
        if not increasing:
            return
        sp = self.span(fid, off)
        self.items.append(g.item("firmware_id", FID, fid, sp))
        if fid != FID:
            return
        read = {"operation": ENTITY, "oid": ENT_SW_REV_1}
        model, version = fid.split("-R")[0], "R" + fid.split("-R")[1].split("-Z")[0]
        self.obs.append({"name": "firmware_id", "value": fid, "span": sp, "read": read})
        self.obs.append({"name": "model", "value": model, "span": {"offset": sp["offset"], "length": len(model)},
                         "read": read})
        self.obs.append({"name": "firmware_version", "value": version,
                         "span": {"offset": sp["offset"] + len(model) + 1, "length": len(version)}, "read": read})

    def entity_unreadable(self, fids):
        """The walk returns these entPhysicalSoftwareRev values: none, or two
        that differ. No FID is compared or reported."""
        self.send("operate", AUTH | PRIV | REPORTABLE, ENGINE, 1, 3601,
                  lambda r: tlv(GETBULK, integer(r) + integer(0) + integer(16) + seq(seq(oid(ENT_TREE), NULL))))
        vbs = [(ENT_DESCR_1, octets("SEL-2731M"))] + [(o, octets(f)) for o, f in zip([ENT_SW_REV_1, ENT_SW_REV_2], fids)]
        self.recv("operate", AUTH | PRIV, ENGINE, 1, 3601, pdu(RESPONSE, self.req, vbs + [(ENT_OUTSIDE, octets("x"))]))

    def identity(self):
        if not self.items:
            return {"result": "not-checked"}
        same = all(i["expected"] == i["observed"] for i in self.items)
        return {"result": "match" if same else "mismatch", "items": self.items}

    def result(self, status, code=None, **kw):
        r = super().result(status, code, self.identity(), self.obs, schema=SCHEMA_0_7, **kw)
        r["operation_id"] = RUN
        r["adapter"] = {"id": "sel-27x1-snmpv3", "version": "0.1.0-example"}
        r["register_version"] = REGISTER_REVISION
        return r


def usm_failure(counter_n):
    """Discovery, then a Report for the first authenticated request. The
    Report does not authenticate: an agent cannot sign for an unknown user or
    a wrong digest."""
    s = SNMP()
    s.discover()
    s.first_request("auth", 0, 0)
    s.recv("auth", 0, ENGINE, 1, 3600, pdu(REPORT, s.req, [(USM_STATS % counter_n, counter(1))]))
    return s


def results():
    out = {}
    s = SNMP()
    s.discover()
    s.time_sync()
    s.system()
    s.entity()
    out["ok"] = s.result("ok")

    s = SNMP()
    s.discover(engine=ENGINE_OTHER)
    out["refused.engine_id_mismatch"] = s.result("refused", "refused.engine_id_mismatch")

    for n, code in [(UNSUPPORTED, "failed.usm_unsupported_sec_level"), (UNKNOWN_USER, "failed.usm_unknown_user"),
                    (WRONG_DIGEST, "failed.usm_wrong_digest"), (DECRYPTION, "failed.usm_decryption_error"),
                    (NOT_IN_TIME, "failed.usm_not_in_time_window")]:
        out[code] = usm_failure(n).result("failed", code)

    s = SNMP()
    s.discover()
    s.time_sync()
    s.system(status=16)  # authorizationError
    out["failed.snmp_error_status"] = s.result("failed", "failed.snmp_error_status")

    s = SNMP()
    s.discover()
    s.time_sync()
    s.system()
    s.entity(increasing=False)
    out["failed.snmp_walk_not_increasing"] = s.result("failed", "failed.snmp_walk_not_increasing")

    for name, fids in [("", []), (".two-fids", [FID, FID_OTHER])]:
        s = SNMP()
        s.discover()
        s.time_sync()
        s.system()
        s.entity_unreadable(fids)
        out["failed.snmp_fid_unreadable" + name] = s.result("failed", "failed.snmp_fid_unreadable")

    s = SNMP()
    s.discover()
    s.time_sync()
    s.system()
    s.entity(fid=FID_OTHER)
    out["failed.identity_mismatch"] = s.result("failed", "failed.identity_mismatch")

    s = SNMP()
    s.discover()
    s.first_request("auth", 0, 0)
    out["failed.timeout"] = s.result("failed", "failed.timeout")

    s = SNMP()
    out["refused.credential_unavailable"] = s.result("refused", "refused.credential_unavailable")
    return out


def invalid_results(good):
    out = {}

    def mut(name, base, f):
        r = json.loads(json.dumps(good[base]))
        f(r)
        out[name] = refresh(r)

    def code(c, status="failed"):
        return lambda r: r.update(status=status, error={"code": c})

    mut("snmp-at-0.6", "ok", lambda r: r.update(schema="otsec.adapter/0.6"))
    mut("line-code-on-snmp", "failed.snmp_error_status", code("failed.device_error"))
    mut("ok-not-authenticated", "ok", lambda r: r["session"]["snmp"].update(authenticated=False))
    mut("snmp-with-quit", "ok", lambda r: r["session"].update(quit_sent=True))
    mut("engine-mismatch-after-auth", "failed.identity_mismatch", code("refused.engine_id_mismatch", "refused"))
    mut("usm-failure-at-discovery", "refused.engine_id_mismatch", code("failed.usm_unknown_user"))
    mut("after-auth-not-authenticated", "failed.usm_unknown_user", code("failed.snmp_error_status"))
    mut("authenticated-before-auth-sent", "refused.engine_id_mismatch",
        lambda r: r["session"]["snmp"].update(authenticated=True))
    mut("no-engine-check-before-auth", "failed.usm_unknown_user",
        lambda r: r.update(identity={"result": "not-checked"}))
    mut("engine-id-item-not-first", "ok", lambda r: r["identity"]["items"].reverse())
    mut("engine-id-item-not-session", "ok", lambda r: r["session"]["snmp"].update(engine_id=ENGINE_OTHER.hex()))
    mut("engine-id-not-hex", "ok", lambda r: r["session"]["snmp"].update(engine_id=ENGINE.hex().upper()))
    mut("observation-without-read", "ok", lambda r: r["observations"][1].pop("read"))
    mut("observation-read-oid-and-header", "ok", lambda r: r["observations"][0]["read"].update(oid=SYS_NAME))
    mut("engine-id-observation-from-oid", "ok",
        lambda r: r["observations"][0].update(read={"operation": SYSTEM, "oid": SYS_NAME}))
    mut("observation-value-not-span", "ok", lambda r: r["observations"][1].update(value="sw-bay-2"))
    mut("observation-read-header-other-field", "ok",
        lambda r: r["observations"][0]["read"].update(header="msgUserName"))

    def credential(r):
        rd = r["transcript"]["redactions"][0]
        rd["reason"] = "credential"
    mut("credential-redaction-on-snmp", "ok", credential)

    def short_digest(r):
        rd = next(x for x in r["transcript"]["redactions"] if segment_of(r, x["offset"])["dir"] == "tx")
        rd["length"] = 20
    mut("sent-digest-20-octets", "ok", short_digest)

    def digest_not_zero(r):
        data = bytearray(base64.b64decode(r["transcript"]["data"]))
        data[r["transcript"]["redactions"][0]["offset"]] = 1
        r["transcript"]["data"] = base64.b64encode(bytes(data)).decode()
    mut("digest-not-zeroed", "ok", digest_not_zero)

    def close_phase(r):
        r["transcript"]["segments"][-1]["phase"] = "close"
    mut("snmp-close-phase", "ok", close_phase)

    def drop_redaction(dir, phase):
        def f(r):
            reds = r["transcript"]["redactions"]
            i = next(i for i, x in enumerate(reds)
                     if segment_of(r, x["offset"])["dir"] == dir and segment_of(r, x["offset"])["phase"] == phase)
            del reds[i]
        return f
    mut("keyed-send-without-digest-redaction", "ok", drop_redaction("tx", "auth"))
    mut("value-from-message-without-digest", "ok", drop_redaction("rx", "operate"))
    mut("authenticated-without-authenticated-answer", "failed.usm_unknown_user",
        lambda r: r["session"]["snmp"].update(authenticated=True))

    mut("fid-unreadable-with-fid-item", "ok", code("failed.snmp_fid_unreadable"))
    mut("fid-unreadable-with-fid-observation", "failed.snmp_fid_unreadable",
        lambda r: r["observations"].append(dict(r["observations"][1], name="firmware_id")))

    mut("not-connected-with-engine-id", "refused.credential_unavailable",
        lambda r: r["session"]["snmp"].update(engine_id=ENGINE.hex()))

    # A line result may carry neither the SNMP facts' codes nor usm-digest.
    sel = json.loads(json.dumps(g.results()["refused.identity_mismatch"]))
    sel.update(schema=SCHEMA_0_7, status="refused", error={"code": "refused.engine_id_mismatch"})
    out["snmp-code-on-line-session"] = refresh(sel)
    return out


def segment_of(r, off):
    return next(s for s in r["transcript"]["segments"] if s["offset"] <= off < s["offset"] + s["length"])


def refresh(r):
    data = base64.b64decode(r["transcript"]["data"])
    r["transcript"]["sha256"] = hashlib.sha256(data).hexdigest()
    return r


def invocation():
    inv = g.invocation(op=RUN, schema=SCHEMA_0_7, endpoint_id="mgmt-snmpv3", profile_id="sel-27x1-rstp",
                       credential_ref="cred_lab2731usm",
                       expected_identity=[{"name": "snmp_engine_id", "value": ENGINE.hex()},
                                          {"name": "firmware_id", "value": FID}])
    return inv


def register():
    cite = [{"source": "T1", "ref": "pp. 46 to 47"}]
    ev = {"class": "documented-untested"}
    limits = {"max_reply_bytes": 1472, "timeout_ms": 3000}
    return {
        "contract": "otsec.register/0.4",
        "family": "sel-27x1-rstp",
        "revision": REGISTER_REVISION,
        "issued": "2026-11-05",
        "owner": "C2",
        "sources": [{"id": "T1", "title": "SEL-2731 and SEL-2741 RSTP-mode user's guide, S29 (test package)"}],
        "preconditions": [], "warnings": [], "context": [], "operations": [],
        "snmp_operations": [
            {"id": SYSTEM, "pdu": "get", "oids": [SYS_DESCR, SYS_NAME], "limits": limits, "citations": cite,
             "evidence": ev, "side_effects": "none: reads two system-group scalars"},
            {"id": ENTITY, "pdu": "getbulk", "subtree": ENT_TREE, "max_repetitions": 16,
             "walk": {"max_varbinds": 512, "max_requests": 32}, "limits": limits,
             "citations": [{"source": "T1", "ref": "pp. 46 and 75"}], "evidence": ev,
             "side_effects": "none: walks entPhysicalTable within the bounds"},
        ],
        "runs": [{"id": RUN, "steps": [SYSTEM, ENTITY], "max_total_bytes": 65536, "deadline_ms": 30000,
                  "citations": cite, "evidence": ev, "side_effects": "none: two reads"}],
        "session_control": [], "denied": [],
        "firmware": {
            "known": [{"fid": FID, "branch": "R102", "version": 1, "citation": {"source": "T1", "ref": "invented"}}],
            "branches": [{"branch": "R102", "status": "allow", "min_version": 0, "basis": "test package",
                          "evidence": {"class": "inferred"}}],
            "not_covered": ["Everything: this is a test package"],
        },
        "notes": ["A test package for contracts/adapter's CheckSNMP. Not a register."],
    }


def main():
    for d in ("snmp/results/valid", "snmp/results/invalid"):
        p = os.path.join(HERE, d)
        if os.path.isdir(p):
            for f in os.listdir(p):
                if f.endswith(".json"):
                    os.remove(os.path.join(p, f))
    good = results()
    for name, r in good.items():
        g.write(os.path.join(HERE, "snmp/results/valid", name + ".json"), r)
    for name, r in invalid_results(good).items():
        g.write(os.path.join(HERE, "snmp/results/invalid", name + ".json"), r)
    g.write(os.path.join(HERE, "snmp/invocation.json"), invocation())
    g.write(os.path.join(HERE, "snmp/register.json"), register())


if __name__ == "__main__":
    main()
