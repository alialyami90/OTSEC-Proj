"""Checks on GT-ADV itself (C6, P4-3-A6), not on the product.

gt_adv.json is written by hand. This file derives each cell again from the
rules in docs/verification.md ("R9 classes and what confirmed needs") as
D4-49 and D4-52 read them, and asserts that the two agree. It also checks
that the rows are real (the FIDs are S22's, and the firmware gate admits
exactly the device-read rows), that the table covers every rule, and that
each rule is pinned: breaking any one rule changes at least one cell.

The matcher (C4, modules/applicability/) does not exist yet. Its acceptance
test will read gt_adv.json, not this derivation.
"""
import json
import os
import re

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
REGISTER = os.path.join(ROOT, "contracts", "register", "testdata", "sel-751.json")
FIG3_20 = os.path.join(ROOT, "tests", "fixtures", "ied", "sel", "751", "documented-example", "id-response-fig3-20.txt")

# C12 (#440): the class and reason tokens.
NA = {"device-read": "not-applicable", "operator": "not-applicable-operator", "passive": "not-applicable-passive"}
CLASSES = {"applicable-by-version", "confirmed", "mitigated"} | set(NA.values())
REASONS = {"outside-range", "product-not-named", "precondition-not-met"}
FID = re.compile(r"^(SEL-[0-9A-Z]+)-(R[0-9]{3})-V([0-9]+)-Z[0-9]{6}-D[0-9]{8}$")
ENDPOINT = re.compile(r"^(R[0-9]{3})-V([0-9]+)$")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


GT = load(os.path.join(HERE, "gt_adv.json"))
IDS = {i["id"]: i for i in GT["identities"]}
ADVS = {a["id"]: a for a in GT["advisories"]}


def product(fid):
    return fid.split("-R")[0].split("-X")[0]


def place(fid):
    """(branch, V) of a FID, or None for a FID the sel-fid scheme cannot place."""
    m = FID.match(fid)
    return (m.group(2), int(m.group(3))) if m else None


def endpoint(e):
    m = ENDPOINT.match(e)
    return m.group(1), int(m.group(2))


def in_range(at, rng, cross_branch=False):
    lo, hi = rng
    if lo is None and hi is None:
        return True
    branch, v = at
    if cross_branch:  # mutant: one global order over (branch, V)
        key = (int(branch[1:]), v)
        lo_k = (int(endpoint(lo)[0][1:]), endpoint(lo)[1]) if lo else (0, 0)
        hi_k = (int(endpoint(hi)[0][1:]), endpoint(hi)[1]) if hi else (10**9, 0)
        return lo_k <= key < hi_k
    b = endpoint(lo or hi)[0]
    if branch != b:
        return False
    return (lo is None or v >= endpoint(lo)[1]) and (hi is None or v < endpoint(hi)[1])


def read(cond, ident):
    """holds, not-met or unread, from the identity's current evidence."""
    if cond["kind"] == "setting":
        if cond["key"] not in ident["settings"]:
            return "unread"
        ok = ident["settings"][cond["key"]] in cond["values"]
        return "holds" if ok == (cond["op"] == "in") else "not-met"
    if cond["kind"] == "control":
        return "holds" if cond["key"] in ident["controls"] else "not-met"
    if cond["kind"] == "service":
        return "unread"  # no read path shows a service before R6.7
    raise AssertionError(cond["kind"])


def derive(ident, adv, mutant=None):
    src = ident["source"]
    na = NA[src]
    if adv["product"] != product(ident["fid"]):
        return {"class": na, "reason": "product-not-named", "evidence": ["identity"]}
    at = place(ident["fid"])
    if at is None:
        if mutant == "unplaced-is-na":
            return {"class": na, "reason": "outside-range", "evidence": ["identity"]}
        return {"class": "applicable-by-version", "evidence": ["identity"], "unread": ["firmware-version"]}
    if not any(in_range(at, r, cross_branch=(mutant == "cross-branch")) for r in adv["ranges"]):
        return {"class": na, "reason": "outside-range", "evidence": ["identity"]}

    pre = {c["name"]: read(c, ident) for c in adv["preconditions"]}
    mit = {c["name"]: read(c, ident) for c in adv["mitigations"]}
    kinds = {c["name"]: c["kind"] for c in adv["preconditions"] + adv["mitigations"]}
    evidence = ["identity"]
    if any(kinds[n] == "setting" and s != "unread" for n, s in {**pre, **mit}.items()):
        evidence.append("settings")
    unread = [n for n, s in pre.items() if s == "unread"]
    stale = src == "device-read" and ident["stale"] and mutant != "ignore-stale"

    held = [n for n, s in mit.items() if s == "holds"]
    # D4-49 Q5: a precondition read false on a device-read identity gives
    # not-applicable, unless a mitigation that holds is that same setting.
    keys = {c["name"]: c.get("key") for c in adv["preconditions"] + adv["mitigations"]}
    false_keys = {keys[n] for n, s in pre.items() if s == "not-met" and kinds[n] == "setting"}
    if src == "device-read" and false_keys and mutant not in ("mitigation-first", "q5-reversed"):
        if not any(kinds[n] == "setting" and keys[n] in false_keys for n in held):
            return {"class": na, "reason": "precondition-not-met", "evidence": evidence}
    if held and mutant != "confirmed-beats-mitigated":
        if mutant == "mitigated-needs-all-read" and unread:
            pass
        else:
            cell = {"class": "mitigated", "evidence": evidence, "unread": unread}
            if any(kinds[n] == "control" for n in held):
                cell["evidence"] = evidence + ["control"]
                cell["attested"] = True
            return cell
    not_met = any(s == "not-met" for s in pre.values())
    if not not_met and (src == "device-read" or mutant == "operator-confirms") and not stale and not unread:
        return {"class": "confirmed", "evidence": evidence}
    cell = {"class": "applicable-by-version", "evidence": evidence, "unread": unread}
    if stale:
        cell["evidence"] = evidence + ["config-change"]
        cell["stale"] = True
    return cell


def norm(cell):
    c = dict(cell)
    c["evidence"] = sorted(c["evidence"])
    if "unread" in c:
        c["unread"] = sorted(c["unread"])
    if c["class"] in ("applicable-by-version", "mitigated"):
        c.setdefault("unread", [])
    c.setdefault("stale", False)
    c.setdefault("attested", False)
    return c


def table(mutant=None):
    return {(a, i): norm(derive(IDS[i], ADVS[a], mutant)) for a in ADVS for i in IDS}


CELLS = [(a, i) for a in ADVS for i in IDS]


def test_table_is_complete():
    assert set(GT["cells"]) == set(ADVS)
    for a in ADVS:
        assert set(GT["cells"][a]) == set(IDS), a


@pytest.mark.parametrize("adv,ident", CELLS)
def test_cell_matches_the_rules(adv, ident):
    want = norm(GT["cells"][adv][ident])
    assert table()[(adv, ident)] == want


@pytest.mark.parametrize("adv,ident", CELLS)
def test_cell_shape(adv, ident):
    c = GT["cells"][adv][ident]
    assert c["class"] in CLASSES
    if c["class"] in NA.values():
        assert c["reason"] in REASONS
        assert "unread" not in c and not c.get("stale") and not c.get("attested")
    else:
        assert "reason" not in c
    if c["class"] == "confirmed":
        assert IDS[ident]["source"] == "device-read" and not IDS[ident]["stale"]
        assert "unread" not in c
    if c["class"] == "applicable-by-version":
        assert "unread" in c


def test_every_advisory_is_test_only():
    for a in GT["advisories"]:
        assert a["test_only"] is True and a["id"].startswith("TEST-ADV-")
        for c in a["preconditions"] + a["mitigations"]:
            assert c["name"] != "firmware-version"  # reserved (C11, C4)
        for c in a["preconditions"]:
            assert c["kind"] != "control"  # mitigations only (C11)


def test_ranges_are_per_branch():
    for a in GT["advisories"]:
        for lo, hi in a["ranges"]:
            if lo and hi:
                assert endpoint(lo)[0] == endpoint(hi)[0], (a["id"], lo, hi)
                assert endpoint(lo)[1] < endpoint(hi)[1], (a["id"], lo, hi)
            for e in (lo, hi):
                assert e is None or ENDPOINT.match(e), e


def test_fids_are_real():
    known = {k["fid"] for k in load(REGISTER)["firmware"]["known"]}
    with open(FIG3_20, encoding="utf-8") as f:
        fig = re.search(r'"FID=([^"]+)"', f.read()).group(1)
    for i in GT["identities"]:
        if i["id"] == "O5":
            assert i["fid"] == fig and i["fid"] not in known and place(i["fid"]) is None
        else:
            assert i["fid"] in known, i


def gate(ident, branches):
    """The register's firmware gate, as the collector applies it before ID."""
    at = place(ident["fid"])
    if at is None or at[0] not in branches:
        return False
    b = branches[at[0]]
    if b["status"] == "deny" or at[1] < b["min_version"]:
        return False
    for c in b.get("conditions", []):
        if ident["settings"].get(c["setting"], c["equals"]) != c["equals"]:
            return False
    return True


def test_firmware_gate_matches_the_sources():
    """D4-49 F1: a relay the gate denies has an operator identity only."""
    branches = {b["branch"]: b for b in load(REGISTER)["firmware"]["branches"]}
    for i in GT["identities"]:
        if i["source"] == "device-read":
            assert gate(i, branches), i["id"]
    assert [i["id"] for i in GT["identities"] if i["source"] == "operator" and gate(i, branches)] == ["O4"]


def test_coverage():
    cells = [norm(c) for a in GT["cells"].values() for c in a.values()]
    got = {c["class"] for c in cells}
    # No passive row: R6.7 is not built, so not-applicable-passive cannot be reached in item 3.
    assert got == CLASSES - {"not-applicable-passive"}
    assert {c["reason"] for c in cells if "reason" in c} == REASONS
    assert any(c["class"] == "mitigated" and c["attested"] for c in cells)
    assert any(c["class"] == "mitigated" and not c["attested"] for c in cells)
    assert any(c["class"] == "mitigated" and c["unread"] for c in cells)  # D4-52
    assert any(c["class"] == "applicable-by-version" and c["stale"] for c in cells)
    assert any(c["unread"] == ["firmware-version"] for c in cells if "unread" in c)


MUTANTS = [
    "cross-branch",               # orders branches as one line
    "ignore-stale",               # confirmed on a stale identity
    "confirmed-beats-mitigated",  # D4-49 Q6 (i) reversed
    "mitigated-needs-all-read",   # D4-52 read strictly
    "q5-reversed",                # a precondition read false leaves it applicable
    "mitigation-first",           # any mitigation beats a precondition read false (Q5)
    "operator-confirms",          # an operator identity confirmed
    "unplaced-is-na",             # an unplaceable FID hidden
]


@pytest.mark.parametrize("mutant", MUTANTS)
def test_each_rule_is_pinned(mutant):
    want = {k: norm(GT["cells"][k[0]][k[1]]) for k in CELLS}
    assert table(mutant) != want, mutant
