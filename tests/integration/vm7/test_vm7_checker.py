"""The V-M7 checker's self-test (C6). A node that does exactly what GT-ADV
and D4-54 say passes every cell; each way a node could get a cell wrong
fails the cell it touches and no other. The node's own run comes with C5's
part 3."""
import copy
import uuid

import pytest

import vm7

GT = vm7.load_gt()
IDENT = {i["id"]: i for i in GT["identities"]}
SET = {"id": "test-adv-set", "version": 3, "issued_at": "2026-11-01T00:00:00Z"}
EVALUATED = "2026-11-06T10:00:05Z"


def inv(*parts):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "/".join(parts)))


def evidence_ids(row, seq):
    i = IDENT[row]
    dev = i["source"] == "device-read"
    ev = {"identity": inv(row, "id") if dev else f"audit:node-1:{seq}"}
    if i["settings"]:
        ev["settings"] = inv(row, "settings")
    if i["stale"]:
        ev["config-change"] = inv(row, "change")
    if i["controls"]:
        ev["control"] = f"audit:node-1:{100 + seq}"
    return ev


def finding(row, adv, cell, ev):
    src = IDENT[row]["source"]
    ident = [{"source": src, "id": ev["identity"], "stale": bool(cell.get("stale"))}]
    if "config-change" in cell["evidence"]:
        ident.append({"source": "device-read", "id": ev["config-change"]})
    pre = [{"name": n, "state": "unread"} for n in cell.get("unread", [])]
    if "settings" in cell["evidence"]:
        pre.append({"name": "web-enabled", "state": "evidenced",
                    "evidence": [{"source": "device-read", "id": ev["settings"]}]})
    mit = []
    if cell["class"] == "mitigated":
        kind = "control" if "control" in cell["evidence"] else "settings"
        mit.append({"name": "m", "operator_attested": kind == "control",
                    "evidence": [{"source": "operator" if kind == "control" else "device-read", "id": ev[kind]}]})
    f = {"schema": "otsec.finding/0.1", "advisory": adv, "set": dict(SET), "revision": 1,
         "class": cell["class"], "evaluated_utc": EVALUATED,
         "identity": {"product": "SEL-751", "version": IDENT[row]["fid"], "source": src, "evidence": ident},
         "preconditions": pre, "mitigations": mit}
    if "reason" in cell:
        f["reason"] = cell["reason"]
    return f


def perfect():
    assets = {}
    for seq, row in enumerate(IDENT, 1):
        ev = evidence_ids(row, seq)
        assets[row] = {"identity": {"source": IDENT[row]["source"], "evidence_id": ev["identity"]},
                       "last_evaluation": {"set_id": SET["id"], "version": SET["version"], "at": EVALUATED,
                                           "identity_evidence_id": ev["identity"]},
                       "evidence": ev, "findings": {}}
    for row, adv, cell in vm7.cells(GT):
        if cell.get("reason") != "product-not-named":
            assets[row]["findings"][adv] = [finding(row, adv, cell, assets[row]["evidence"])]
    return {"set": dict(SET), "assets": assets}


def failing(obs):
    return {k: v for k, v in vm7.check(GT, obs).items() if v}


def test_gt_adv_has_128_cells():
    assert sum(1 for _ in vm7.cells(GT)) == 128


def test_a_perfect_node_passes_every_cell():
    assert failing(perfect()) == {}


def first(pred):
    for row, adv, cell in vm7.cells(GT):
        if pred(row, cell):
            return row, adv, cell
    raise AssertionError("GT-ADV has no such cell")


def mutate(row, adv, fn):
    obs = perfect()
    fn(obs, obs["assets"][row], obs["assets"][row]["findings"].get(adv))
    return failing(obs)


# Each mutant: (name, cell picker, mutation, a phrase the failure names).
MUTANTS = [
    ("class", lambda r, c: c["class"] == "confirmed",
     lambda o, a, f: f[-1].update({"class": "applicable-by-version"}), "class"),
    ("reason", lambda r, c: c.get("reason") == "outside-range",
     lambda o, a, f: f[-1].update({"reason": "precondition-not-met"}), "reason"),
    ("old set", lambda r, c: c["class"] == "confirmed",
     lambda o, a, f: f[-1]["set"].update({"version": 2}), "set"),
    ("confirmed on operator", lambda r, c: r.startswith("O") and c["class"] == "applicable-by-version",
     lambda o, a, f: f[-1].update({"class": "confirmed"}), "confirmed on a operator"),
    ("unread dropped", lambda r, c: c.get("unread"),
     lambda o, a, f: f[-1].update({"preconditions": [p for p in f[-1]["preconditions"] if p["state"] != "unread"]}), "unread"),
    ("settings not cited", lambda r, c: "settings" in c["evidence"],
     lambda o, a, f: a["evidence"].update({"settings": inv("other")}), "settings evidence"),
    ("config change not cited", lambda r, c: "config-change" in c["evidence"],
     lambda o, a, f: f[-1]["identity"].update({"evidence": f[-1]["identity"]["evidence"][:1]}), "config-change"),
    ("control not cited", lambda r, c: "control" in c["evidence"],
     lambda o, a, f: a["evidence"].update({"control": "audit:node-1:999"}), "control evidence"),
    ("not stale", lambda r, c: c.get("stale"),
     lambda o, a, f: [e.update({"stale": False}) for e in f[-1]["identity"]["evidence"]], "stale"),
    ("not attested", lambda r, c: c.get("attested"),
     lambda o, a, f: [m.update({"operator_attested": False}) for m in f[-1]["mitigations"]], "attested"),
    ("operator cited as a device read", lambda r, c: r.startswith("O") and "reason" not in c,
     lambda o, a, f: f[-1]["identity"]["evidence"][0].update({"id": "audit:node-1"}), "form"),
    ("device read cited as an audit ref", lambda r, c: r.startswith("D") and c["class"] == "confirmed",
     lambda o, a, f: f[-1]["identity"]["evidence"][0].update({"id": "audit:node-1:5"}), "form"),
    ("exploitability", lambda r, c: c["class"] == "confirmed",
     lambda o, a, f: f[-1].update({"exploitable": True}), "exploitability"),
    ("revision chain", lambda r, c: c["class"] == "confirmed",
     lambda o, a, f: f.append(dict(f[-1], revision=2, **{"from": "mitigated"})), "revision 2"),
    ("finding missing", lambda r, c: c["class"] == "mitigated",
     lambda o, a, f: a["findings"].pop(f[-1]["advisory"]), "no stored finding"),
    # D4-54: a product-not-named cell with no stored finding.
    ("pnn, no completed evaluation", lambda r, c: c.get("reason") == "product-not-named",
     lambda o, a, f: a.update({"last_evaluation": None}), "no completed evaluation"),
    ("pnn, evaluation under an old set", lambda r, c: c.get("reason") == "product-not-named",
     lambda o, a, f: a["last_evaluation"].update({"version": 2}), "version 2"),
    ("pnn, evaluation under another set", lambda r, c: c.get("reason") == "product-not-named",
     lambda o, a, f: a["last_evaluation"].update({"set_id": "other"}), "set other"),
    ("pnn, evaluation on an older identity record", lambda r, c: c.get("reason") == "product-not-named",
     lambda o, a, f: a["identity"].update({"evidence_id": inv("newer")}), "not the newest"),
]


@pytest.mark.parametrize("name,pick,fn,phrase", MUTANTS, ids=[m[0] for m in MUTANTS])
def test_each_mutant_fails_its_cell(name, pick, fn, phrase):
    row, adv, _ = first(pick)
    bad = mutate(row, adv, fn)
    assert (row, adv) in bad, f"{name}: the cell passed"
    assert any(phrase in r for r in bad[(row, adv)]), bad[(row, adv)]
    others = {k for k in bad if k[0] != row}
    assert not others, f"{name} failed cells on other rows: {sorted(others)}"


def test_a_stored_pnn_finding_is_checked_as_a_finding():
    # Once an entry has a stored finding, a change to product-not-named is
    # stored as a revision (D4-54), and that revision is held to the cell.
    row, adv, cell = first(lambda r, c: c.get("reason") == "product-not-named" and r.startswith("D"))
    obs = perfect()
    a = obs["assets"][row]
    first_rev = finding(row, adv, {"class": "applicable-by-version", "evidence": ["identity"], "unread": []}, a["evidence"])
    second = dict(finding(row, adv, cell, a["evidence"]), revision=2, previous="h", **{"from": "applicable-by-version"})
    a["findings"][adv] = [first_rev, second]
    assert failing(obs) == {}
    second["class"] = "not-applicable-operator"
    assert (row, adv) in failing(obs)


def test_restart_changes_nothing():
    before = perfect()
    assert vm7.check_restart(before, copy.deepcopy(before)) == []


def test_restart_that_rewrites_policy_apply_fails():
    # A chain prune then a restart must not write a new policy.apply record
    # and revise every operator finding (D4-54).
    before = perfect()
    after = copy.deepcopy(before)
    for row in ("O1", "O3"):
        a = after["assets"][row]
        a["evidence"]["identity"] = "audit:node-1:500"
        for revs in a["findings"].values():
            revs.append(dict(revs[-1], revision=2, **{"from": revs[-1]["class"]}))
    bad = vm7.check_restart(before, after)
    assert any(b.startswith("O1: identity evidence") for b in bad)
    assert any(b.startswith("O3 ") and "changed" in b for b in bad)


MISMATCH_ID = inv("D1", "mismatch")
MISMATCH_FID = "SEL-751-R402-V2-Z102100-D20250731"


def after_mismatch():
    obs = perfect()
    a = obs["assets"]["D1"]
    adv = "TEST-ADV-07"
    prev = a["findings"][adv][-1]
    a["findings"][adv].append(dict(prev, revision=2, previous="h", **{
        "from": prev["class"], "class": "applicable-by-version",
        "identity": dict(prev["identity"], evidence=[
            dict(prev["identity"]["evidence"][0], stale=True),
            {"source": "device-read", "id": MISMATCH_ID}]),
        "preconditions": [{"name": "firmware-version", "state": "unread"}]}))
    a["identity_read"] = {"invocation_id": a["evidence"]["identity"], "read_at": EVALUATED,
                          "mismatch": {"invocation_id": MISMATCH_ID, "read_at": EVALUATED, "fid": MISMATCH_FID}}
    return obs


def test_mismatch_passes_before_and_after_restart():
    obs = after_mismatch()
    a = obs["assets"]["D1"]
    assert vm7.check_mismatch(a, "TEST-ADV-07", MISMATCH_ID, MISMATCH_FID, a["evidence"]["identity"]) == []
    assert vm7.check_restart(obs, copy.deepcopy(obs)) == []


@pytest.mark.parametrize("name,fn,phrase", [
    # A restart that forgot the mismatch FID turns the finding into a false
    # product-not-named downgrade (D4-54).
    ("false downgrade", lambda a, f: f.update({"class": "not-applicable", "reason": "product-not-named"}), "class"),
    ("version read", lambda a, f: f.update({"preconditions": []}), "firmware-version"),
    ("not stale", lambda a, f: f["identity"]["evidence"][0].update({"stale": False}), "stale"),
    ("mismatch not cited", lambda a, f: f["identity"].update({"evidence": f["identity"]["evidence"][:1]}), "not cited"),
    ("mismatch as the latest read", lambda a, f: a["identity_read"].update({"invocation_id": MISMATCH_ID}), "last confirming read"),
    ("confirming read removed", lambda a, f: a["identity_read"].pop("invocation_id"), "last confirming read"),
    ("mismatch lost", lambda a, f: a["identity_read"].update({"mismatch": None}), "keeps mismatch"),
    ("mismatch FID changed", lambda a, f: a["identity_read"]["mismatch"].update({"fid": "SEL-751-R501-V0-Z104101-D20260910"}), "keeps mismatch"),
], ids=lambda x: x if isinstance(x, str) else "")
def test_mismatch_mutants_fail(name, fn, phrase):
    obs = after_mismatch()
    a = obs["assets"]["D1"]
    fn(a, a["findings"]["TEST-ADV-07"][-1])
    bad = vm7.check_mismatch(a, "TEST-ADV-07", MISMATCH_ID, MISMATCH_FID, inv("D1", "id"))
    assert any(phrase in b for b in bad), bad


def test_mismatch_revision_that_restart_rewrites_fails():
    before = after_mismatch()
    after = copy.deepcopy(before)
    revs = after["assets"]["D1"]["findings"]["TEST-ADV-07"]
    revs.append(dict(revs[-1], revision=3, **{"from": "applicable-by-version", "class": "not-applicable", "reason": "product-not-named"}))
    assert any("D1 TEST-ADV-07" in b for b in vm7.check_restart(before, after))
