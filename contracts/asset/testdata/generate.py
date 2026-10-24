"""Writes the C1 golden examples in valid/ and invalid/.

Run from this directory with `python3 -I generate.py`. The output is
committed; asset_test.go checks it and testdata/README.md gives one line per
file. Device values come from the SEL-751 instruction manual (S22, date code
20260910) and are documented examples, never device captures: the FID is
from Table A.1, the CID and part number shapes from Figure 7.38. Serial
numbers, addresses, people and times are invented and say so.
"""

import copy
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

T0 = "2026-10-24T09:00:00Z"   # commissioning (invented)
T1 = "2026-10-24T09:15:00.5Z"  # simulator session: the ID reply in the C2 example (invented)
INV = "6f1c2b9e-3d4a-4c1e-9b7a-2f0e8d5c1a30"  # C2 invocation ID (invented)
FID = "SEL-751-R501-V0-Z104101-D20260910"     # S22 Table A.1 p. A.2
FID_OTHER = "SEL-751-R500-V1-Z103101-D20260910"  # S22 Table A.1 p. A.2
# Spans point into the C2 example transcript of invocation INV
# (contracts/adapter/testdata/results/valid/ok.json, an invented simulator
# session shaped after S22 Figure 7.38): the FID value and the CID value in
# the ID reply. C2's tests check that each span selects its value.
FID_AT = 124
CID_AT = 221


def obs(value, cls, method, ref, at, span=None):
    o = {"value": value, "evidence_class": cls,
         "source": {"method": method, "ref": ref, "observed_at": at}}
    if span:
        o["source"]["span"] = {"offset": span[0], "length": span[1]}
    return o


def declared(name, value, by="operator:commissioning-sheet-07"):
    return {"name": name, "value": value, "confidence": "single-source",
            "observations": [obs(value, "operator-declared", "operator-entry", by, T0)]}


def relay():
    return {
        "schema": "otsec.asset/0.1",
        "asset_id": "2b7d4e10-8c3f-4a5b-9e21-7c4f0d6a8b13",
        "node_id": "site-a-node1",
        "attributes": [
            declared("device_class", "protective-relay"),
            declared("vendor", "sel"),
            declared("product_family", "sel-751"),
            {"name": "firmware_id", "value": FID, "confidence": "corroborated",
             "observations": [
                 obs(FID, "operator-declared", "operator-entry", "operator:commissioning-sheet-07", T0),
                 obs(FID, "simulated", "simulator-session", INV, T1, (FID_AT, 33)),
             ]},
            declared("serial_number", "SIM0000000000001"),
            {"name": "sel.cid", "value": "E754", "confidence": "single-source",
             "observations": [obs("E754", "simulated", "simulator-session", INV, T1, (CID_AT, 4))]},
            declared("ip_address", "192.0.2.21"),
        ],
        "endpoints": [{
            "id": "port1-telnet", "transport": "telnet", "host": "192.0.2.21", "port": 23,
            "downstream_security": {
                "level": "plaintext-unauthenticated",
                "acknowledgement": {"by": "admin:lab-admin", "at": T0,
                                    "reason": "Simulated slice only, lab-only credentials (ADR-0005)",
                                    "scope": "lab-only"}}}],
        "identity_binding": {"method": "device-reported", "strength": "spoofable",
                             "attributes": ["firmware_id", "serial_number"],
                             "pre_credential": ["firmware_id"]},
        "profile": {"id": "sel-751-ascii", "version": "0.1"},
    }


def node():
    return {
        "schema": "otsec.asset/0.1",
        "asset_id": "9a0c6e42-1f7b-4d38-a5c9-3e8b2d1f6a07",
        "node_id": "site-a-node1",
        "attributes": [
            declared("device_class", "server"),
            declared("vendor", "sel"),
            declared("product_family", "sel-3355-2"),
            declared("os_name", "Windows 10 Pro"),
            declared("hostname", "site-a-node1"),
        ],
        "identity_binding": {"method": "address-only", "strength": "spoofable", "attributes": []},
        "platform_node": {"posture": [
            {"label": "os-out-of-support", "since": T0,
             "condition": "Owner-accepted risk 2026-10-23 (ADR-0007 item 9): Windows 10 Pro allowed, installer warns",
             "migration_date": "2027-06-30"},
            {"label": "storage-durability-unverified", "since": T0},
        ]},
    }


def rtac():
    return {
        "schema": "otsec.asset/0.1",
        "asset_id": "c41f8a2d-6b0e-4e97-8d13-5a2c9f7b0e64",
        "node_id": "site-a-node1",
        "attributes": [
            declared("device_class", "automation-controller"),
            declared("vendor", "sel"),
            declared("product_family", "sel-rtac"),
            declared("ip_address", "192.0.2.40"),
        ],
        "endpoints": [{
            "id": "syslog-in", "transport": "syslog-udp", "host": "192.0.2.40", "port": 514,
            "downstream_security": {
                "level": "plaintext-unauthenticated",
                "acknowledgement": {"by": "admin:lab-admin", "at": T0,
                                    "reason": "RTAC Syslog is RFC 3164 over UDP only (A2 portfolio section 3)",
                                    "scope": "lab-only"}}}],
        "identity_binding": {"method": "address-only", "strength": "spoofable", "attributes": []},
        "profile": {"id": "sel-rtac-syslog", "version": "0.1"},
    }


def mismatch():
    a = relay()
    a["attributes"][3] = {
        "name": "firmware_id", "value": FID, "confidence": "conflicting",
        "observations": [
            obs(FID, "operator-declared", "operator-entry", "operator:commissioning-sheet-07", T0),
            obs(FID_OTHER, "simulated", "simulator-session", INV, T1, (FID_AT, 33)),
        ]}
    a["suspension"] = {"reason": "identity-mismatch", "since": T1, "ref": INV}
    return a


def later(fn):
    a = relay()
    a["schema"] = "otsec.asset/0.2"
    fn(a)
    return a


LATER = {
    # Each carries a value 0.1 does not know where trust is at stake; the test
    # checks what a 0.1 reader reads (A6 C1 review change 2).
    "later-minor-unknown-binding-method": lambda a: a["identity_binding"].update(
        method="tpm-attested", strength="cryptographic"),
    "later-minor-unknown-source-method": lambda a: attr(a, "firmware_id")["observations"][1].update(
        evidence_class="device-observed", source={"method": "simulator-replay", "ref": INV, "observed_at": T1,
                                                   "span": {"offset": FID_AT, "length": 33}}),
    "later-minor-unknown-confidence": lambda a: attr(a, "firmware_id").update(confidence="verified"),
    "later-minor-unknown-evidence-class": lambda a: attr(a, "sel.cid")["observations"][0].update(
        evidence_class="hardware-verified", source={"method": "adapter-session", "ref": INV, "observed_at": T1,
                                                     "span": {"offset": CID_AT, "length": 4}}),
}


def later_minor():
    a = relay()
    a["schema"] = "otsec.asset/0.3"
    a["attributes"][0] = declared("device_class", "protection-gateway")
    a["field_from_a_later_minor"] = {"anything": True}
    return a


PROFILE_751 = {
    "schema": "otsec.asset/0.1", "kind": "capability-profile",
    "profile_id": "sel-751-ascii", "version": "0.1",
    "vendor": "sel", "product_family": "sel-751", "device_class": "protective-relay",
    "firmware": {"allowlist": "sel-751"},
    "pre_credential": ["firmware_id", "part_number", "sel.cid"],
    "capabilities": [
        {"capability": "identification", "mechanism": "adapter-operation", "operations": ["sel.id"],
         "status": "simulated", "citation": "S22 Table 7.43, Figure 7.38; simulator only (C-10)"},
        {"capability": "event-retrieval", "mechanism": "adapter-operation", "operations": ["sel.ser.read_all"],
         "status": "simulated", "citation": "S22 Table 7.63, Figure 10.16; simulator only (C-10)"},
        {"capability": "time-quality", "mechanism": "adapter-operation", "operations": ["sel.settings.show_global"],
         "status": "documented-untested", "citation": "S22 Table 4.90 (UTC_OFF, DST), Table 7.16 (Time Source)"},
        {"capability": "event-push", "mechanism": "none", "status": "unsupported",
         "citation": "S22 Table 7.5: no Syslog on Port 1"},
        {"capability": "configuration-retrieval", "mechanism": "none", "status": "unknown",
         "notes": "Out of slice 1 (A2 section 8)"},
    ],
    "max_read_rows": 1024,
    "session_limits": {
        "max_concurrent_sessions": 1,
        "min_interval_ms": 60000,
        "password_attempts": 1,
        "idle_timeout_ms": 1800000,
        "failed_auth_floor_ms": 1860000,
        "citation": ("S22 Table 7.63 (SER holds up to 1,024 rows); Table 7.5 note a (Port 1: two Telnet sessions, "
                     "the platform takes one); p. 7.33 (a wrong password re-prompts, the third pulses SALARM, so one "
                     "attempt); p. 7.16 and Table 4.104 sheet 2 (state stays until TIDLE, 1 to 30 min, expires: "
                     "the platform assumes 30 and waits 31). min_interval_ms is a platform choice, not a device fact "
                     "(Phase 0 register proposal)."),
    },
}

PROFILE_RTAC = {
    "schema": "otsec.asset/0.1", "kind": "capability-profile",
    "profile_id": "sel-rtac-syslog", "version": "0.1",
    "vendor": "sel", "product_family": "sel-rtac", "device_class": "automation-controller",
    "firmware": {"allowlist": "none"},
    "capabilities": [
        {"capability": "event-push", "mechanism": "syslog-receive", "status": "documented-untested",
         "citation": ("S23 pp. 635-637 (RFC 3164 over UDP, facility 23, 1,024 bytes); fixture "
                      "tests/fixtures/ied/sel/rtac/documented-example/syslog-user-logon.txt"),
         "notes": ("Only tags the project logs, at or above the destination's threshold, are sent; "
                   "User_Logged_On and User_Logged_Off are logged by default (S23 p. 633). Firmware before "
                   "R150-V8, R151-V6, R152-V2 and R153-V0 (by branch) may send an incorrect time stamp (S23 "
                   "Table A.1), so the event time from older firmware is not trusted (docs/phase1/A2-q5-rtac.md).")},
        {"capability": "identification", "mechanism": "operator-entry", "status": "documented-untested",
         "citation": ("No device shell for monitoring (A2-sel-portfolio.md section 2); Syslog carries only the "
                      "operator-set hostname (S23 p. 636), and no firmware ID")},
        {"capability": "health", "mechanism": "none", "status": "unknown",
         "notes": "Silence is not a health signal: the RTAC sends only what the project logs (C4 source.silent)"},
    ],
}


def mutate(base, fn):
    a = copy.deepcopy(base)
    fn(a)
    return a


def attr(a, name):
    return next(x for x in a["attributes"] if x["name"] == name)


INVALID = {
    "observation-without-evidence-class": (relay, lambda a: attr(a, "vendor")["observations"][0].pop("evidence_class")),
    "attribute-without-observations": (relay, lambda a: attr(a, "vendor").update(observations=[])),
    "corroborated-by-one-class": (relay, lambda a: attr(a, "firmware_id").update(observations=[
        obs(FID, "device-observed", "adapter-session", INV, T1, (FID_AT, 33)),
        obs(FID, "device-observed", "syslog-received", "syslog:192.0.2.21", T1, (0, 33))])),
    "conflicting-value-not-declared": (mismatch, lambda a: attr(a, "firmware_id").update(value=FID_OTHER)),
    "telnet-labelled-encrypted": (relay, lambda a: a["endpoints"][0]["downstream_security"].update(
        level="encrypted-authenticated")),
    "plaintext-without-acknowledgement": (relay, lambda a: a["endpoints"][0]["downstream_security"].pop(
        "acknowledgement")),
    "device-reported-claims-cryptographic": (relay, lambda a: a["identity_binding"].update(strength="cryptographic")),
    "pinned-key-on-plaintext": (relay, lambda a: a["identity_binding"].update(method="pinned-key", strength="cryptographic")),
    "binding-attribute-not-declared": (relay, lambda a: a["identity_binding"].update(
        attributes=["firmware_id", "sel.cid"])),
    "platform-node-on-relay": (relay, lambda a: a.update(platform_node={"posture": []})),
    "os-out-of-support-without-condition": (node, lambda a: a["platform_node"]["posture"][0].pop("condition")),
    "unknown-device-class-at-0.1": (relay, lambda a: a["attributes"].__setitem__(0, declared("device_class", "protection-gateway"))),
    "unprefixed-unknown-attribute": (relay, lambda a: a["attributes"].append(declared("cid", "E754"))),
    "simulator-value-labelled-device": (relay, lambda a: attr(a, "firmware_id")["observations"][1].update(
        evidence_class="device-observed")),
    "session-observation-without-span": (relay, lambda a: attr(a, "sel.cid")["observations"][0]["source"].pop("span")),
    "missing-vendor": (relay, lambda a: a.update(attributes=[x for x in a["attributes"] if x["name"] != "vendor"])),
    "other-major": (relay, lambda a: a.update(schema="otsec.asset/1.0")),
    "serial-labelled-encrypted": (relay, lambda a: a["endpoints"].append({
        "id": "port3-serial", "transport": "serial", "serial_device": "COM3",
        "downstream_security": {"level": "encrypted-authenticated"}})),
    "ssh-authenticated-without-pinned-key": (relay, lambda a: a["endpoints"].append({
        "id": "gateway-ssh", "transport": "ssh", "host": "192.0.2.22", "port": 22,
        "downstream_security": {"level": "encrypted-authenticated"}})),
    "syslog-tls-authenticated-without-pinned-key": (rtac, lambda a: a["endpoints"].append({
        "id": "syslog-tls-in", "transport": "syslog-tls", "host": "192.0.2.40", "port": 6514,
        "downstream_security": {"level": "encrypted-authenticated"}})),
    "acknowledgement-without-scope": (relay, lambda a: a["endpoints"][0]["downstream_security"]["acknowledgement"].pop("scope")),
    "asset-id-from-device-content": (relay, lambda a: a.update(asset_id="sel-751-" + FID.lower())),
    "binding-without-pre-credential": (relay, lambda a: a["identity_binding"].update(
        attributes=["serial_number"], pre_credential=[])),
    "device-reported-on-ip-address": (relay, lambda a: a["identity_binding"].update(
        attributes=["ip_address"], pre_credential=["ip_address"])),
    "pre-credential-not-in-attributes": (relay, lambda a: a["identity_binding"].update(
        attributes=["serial_number"], pre_credential=["firmware_id"])),
    "address-only-with-pre-credential": (rtac, lambda a: a["identity_binding"].update(
        pre_credential=["ip_address"])),
}

INVALID_PROFILES = {
    "profile-adapter-without-allowlist": lambda p: p["firmware"].update(allowlist="none"),
    "profile-claim-without-citation": lambda p: p["capabilities"][0].pop("citation"),
    "profile-pre-credential-operator-only": lambda p: p.update(pre_credential=["firmware_id", "ip_address"]),
    "profile-without-session-limits": lambda p: p.pop("session_limits"),
    "profile-floor-within-idle-timeout": lambda p: p["session_limits"].update(failed_auth_floor_ms=900000),
    "profile-two-password-attempts": lambda p: p["session_limits"].update(password_attempts=2),
    "profile-without-max-read-rows": lambda p: p.pop("max_read_rows"),
    "profile-read-rows-over-ceiling": lambda p: p.update(max_read_rows=4096),
}

# A family the platform only listens to has no sessions and reads nothing.
INVALID_RTAC_PROFILES = {
    "profile-syslog-with-session-limits": lambda p: p.update(session_limits=PROFILE_751["session_limits"]),
    "profile-syslog-with-max-read-rows": lambda p: p.update(max_read_rows=1024),
}


def write(path, obj):
    with open(os.path.join(HERE, path), "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    os.makedirs(os.path.join(HERE, "valid"), exist_ok=True)
    os.makedirs(os.path.join(HERE, "invalid"), exist_ok=True)
    write("valid/sel-751-simulated.json", relay())
    write("valid/sel-751-identity-mismatch.json", mismatch())
    write("valid/site-node.json", node())
    write("valid/sel-rtac-syslog.json", rtac())
    write("valid/later-minor.json", later_minor())
    for name, fn in LATER.items():
        write(f"valid/{name}.json", later(fn))
    write("valid/profile-sel-751-ascii.json", PROFILE_751)
    write("valid/profile-sel-rtac-syslog.json", PROFILE_RTAC)
    for name, (base, fn) in INVALID.items():
        write(f"invalid/{name}.json", mutate(base(), fn))
    for name, fn in INVALID_PROFILES.items():
        write(f"invalid/{name}.json", mutate(PROFILE_751, fn))
    for name, fn in INVALID_RTAC_PROFILES.items():
        write(f"invalid/{name}.json", mutate(PROFILE_RTAC, fn))
    # Keys json.dump cannot produce (A6 C1 review change 3). A6's probe: a
    # case variant after the real binding, which encoding/json alone would
    # let replace it.
    base = json.dumps(relay(), indent=2, ensure_ascii=False)
    tail = ',\n  %s: {"method": "address-only", "strength": "spoofable", "attributes": []}\n}\n'
    for name, key in (("case-variant-key", '"IDENTITY_BINDING"'), ("duplicate-key", '"identity_binding"')):
        with open(os.path.join(HERE, f"invalid/{name}.json"), "w", encoding="utf-8", newline="\n") as f:
            f.write(base[:-2] + tail % key)


if __name__ == "__main__":
    main()
