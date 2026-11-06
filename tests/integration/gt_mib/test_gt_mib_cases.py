"""Checks on GT-MIB's case table itself (C6, P4-3-C6 deliverable 1), not on
the product.

cases.json is written by hand before any agent code exists. This file checks
that it covers every case of the plan (docs/phase4/C6-gt-mib-plan.md section
2), that each expected code is one C2 0.7 defines and may end an SNMP run,
that each egress rule is one C3's check returns, and that the values it
expects are consistent with what the agent serves. The client is not tested
here, and the agent does not exist yet: it waits for the RFC texts.
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
PLAN = os.path.join(ROOT, "docs", "phase4", "C6-gt-mib-plan.md")
CODES = os.path.join(ROOT, "contracts", "adapter", "codes.go")
EGRESS = os.path.join(ROOT, "modules", "security", "snmpegress", "egress.go")

FID = re.compile(r"^(SEL-(?:2731|2741)M)-(R[0-9]{3}-V[0-9]+)-Z[0-9]{6}-D[0-9]{8}$")
HEX = re.compile(r"^(?:[0-9a-f]{2}){5,32}$")


def text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


GT = json.loads(text(os.path.join(HERE, "cases.json")))
CASES = GT["cases"]
OPS = GT["operations"]


def adapter_codes():
    """Every code contracts/adapter defines, and those marked line-only."""
    src = text(CODES)
    codes = set(re.findall(r'Code\s*=\s*"([a-z_.]+)"', src))
    names = dict(re.findall(r'^\s*(\w+)\s+Code\s*=\s*"([a-z_.]+)"', src, re.M))
    line_only = {names[n] for n in re.findall(r"^\s*(\w+):\s*\{[^}]*\blineOnly\}", src, re.M) if n in names}
    return codes, line_only


def plan_ids():
    return re.findall(r"^\| ([IFUWTM][0-9]+[a-z]?) \|", text(PLAN), re.M)


def test_every_plan_case_is_in_the_table():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case IDs"
    for p in plan_ids():
        # A plan case may be split into lettered parts (U4a and U4b).
        assert p in ids or any(i[: len(p)] == p and i[len(p):].isalpha() and i[len(p):].islower() for i in ids), p
    for i in ids:
        base = re.match(r"^[A-Z][0-9]+", i).group(0)
        assert i in plan_ids() or base in plan_ids(), f"{i} is not a plan case"


def test_codes_are_c2_codes_for_snmp():
    codes, line_only = adapter_codes()
    assert "failed.snmp_fid_unreadable" in codes, "C2 0.7's ninth code (D4-54)"
    for c in CASES:
        code = c["expect"]["code"]
        if code is None:
            assert c["expect"].get("refused_at"), f"{c['id']}: no code needs where it is refused"
            continue
        assert code == "ok" or code in codes, f"{c['id']}: {code} is not a C2 code"
        assert code not in line_only, f"{c['id']}: {code} is for line sessions only"
    for k in ("expect_outer", "expect_scoped"):
        code = GT["hostile"][k]["code"]
        assert code is None or code in codes, k


def test_every_snmp_code_is_expected_somewhere():
    codes, _ = adapter_codes()
    snmp = {c for c in codes if c.startswith(("failed.usm_", "failed.snmp_")) or c == "refused.engine_id_mismatch"}
    used = {c["expect"]["code"] for c in CASES} | {GT["hostile"][k]["code"] for k in ("expect_outer", "expect_scoped")}
    assert snmp <= used, sorted(snmp - used)


def test_attributes_agree_with_the_agent():
    system, entity = OPS["system"], OPS["entity"]
    for c in CASES:
        attrs = c["expect"].get("attributes", {})
        for name in c["expect"].get("absent", []):
            assert name not in attrs, (c["id"], name)
        fid = attrs.get("firmware_id", {}).get("value")
        if fid:
            m = FID.match(fid)
            assert m, (c["id"], fid)
            assert attrs.get("model", {}).get("value", m.group(1)) == m.group(1), c["id"]
            assert attrs.get("firmware_version", {}).get("value", m.group(2)) == m.group(2), c["id"]
            assert fid in GT["agent"]["fids"].values(), (c["id"], fid)
        for name, a in attrs.items():
            if "oid" in a:
                inside = a["oid"].startswith(entity["subtree"] + ".")
                assert (a["operation"] == system["id"] and a["oid"] in system["oids"]) or (a["operation"] == entity["id"] and inside), (c["id"], name)
            if "header" in a:
                assert name == "snmp_engine_id" and a["header"] == "msgAuthoritativeEngineID", (c["id"], name)
        if "snmp_engine_id" in attrs:
            assert attrs["snmp_engine_id"]["value"] == GT["agent"]["engine_id"], c["id"]
    assert HEX.match(GT["agent"]["engine_id"])


def test_failure_cases_report_nothing_from_a_fid():
    for c in CASES:
        if c["expect"]["code"] == "failed.snmp_fid_unreadable":
            assert {"firmware_id", "model", "firmware_version"} <= set(c["expect"]["absent"]), c["id"]
            assert c["expect"].get("bytes_kept"), c["id"]


def test_egress_rules_are_the_checks_rules():
    src = text(EGRESS)
    rules = set(re.findall(r'Rule\s*=\s*"([a-z_]+)"', src))
    fields = set(re.findall(r'off\("([a-z_]+)"\)', src))
    named = rules | {"discovery_shape." + f for f in fields}
    for rule in GT["egress"]["rules"]:
        assert rule in named, rule
    near = [x for xs in GT["egress"]["rules"].values() for x in xs if x.startswith("near miss")]
    assert sorted(int(re.match(r"near miss ([0-9]+)", x).group(1)) for x in near) == list(range(1, 14))


def test_hostile_corpus():
    ids = [h["id"] for h in GT["hostile"]["corpus"]] + [h["id"] for h in GT["hostile"]["positive"]]
    assert len(ids) == len(set(ids))
    for h in GT["hostile"]["corpus"]:
        assert set(h.get("layers", GT["hostile"]["layers"])) <= {"outer", "scoped"}, h["id"]


def test_rfc_items_stay_marked_until_the_texts_are_in():
    # The agent waits for the RFC texts. Until then, every RFC-derived layout
    # in this table is listed as unconfirmed, and each names where to check it.
    assert GT["unconfirmed"]
    for u in GT["unconfirmed"]:
        assert u["what"] and re.match(r"^RFC [0-9]+", u["check_in"]), u
    oids = {a["oid"] for c in CASES for a in c["expect"].get("attributes", {}).values() if "oid" in a}
    listed = " ".join(u["what"] for u in GT["unconfirmed"])
    for o in oids:
        column = o.rsplit(".", 1)[0] if o.startswith(OPS["entity"]["subtree"]) else o
        assert column in listed, f"{o} is RFC-derived but not listed as unconfirmed"
