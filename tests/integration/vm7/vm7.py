"""V-M7's per-cell check over GT-ADV (C6, P4-3-C6 deliverable 3).

This is the oracle half of V-M7 on the binaries. The runner, which starts the
real node and collector against the simulator, waits for C5's part 3. It
gathers what the node stored and showed into an `observed` dict (below), and
`check` decides each of GT-ADV's 128 cells from it. Nothing here starts a
process or reads a store, so the rules can be pinned now and run the moment
part 3 lands.

V-M7 (docs/verification.md), per cell: the class equals GT-ADV's; every
finding lists the evidence IDs that made it so; an operator or passive
identity never yields `confirmed`; an unread precondition leaves the finding
`applicable-by-version` with it named; a later contradicting read
reclassifies and records the change (the reclassification scenarios, not the
cells); no finding states that a device is exploitable.

D4-54 (#455) decides how a `product-not-named` cell reads: the node stores
no finding for it when the entry had none before. The cell passes only when
no finding is stored for it, the asset's last completed evaluation ran under
the set in use, and that evaluation is later than the asset's newest
identity record. "Later" is read as C5 proposed on #458: the evaluation
names the newest identity record's evidence ID. The node evaluates after
storing the identity, so on the test clock the two times can be equal, and
RFC 3339 strings with different fraction lengths do not compare in order.
An operator-only asset has no identity record, so there the evaluation
names the declared identity's policy.apply record (`audit:<node>:<seq>`)
instead, and the IDs are matched the same way (C1, after C4 on #459).

The observed dict, one per run under one set (field names from C5 on #458):

    {
      "set": {"id": str, "version": int, "issued_at": str},
      "assets": {
        "<row id>": {
          "identity": {"source": str, "evidence_id": str},  # status.identity's newest record, or
                                                            # an operator row's policy.apply ref
          "last_evaluation": {"set_id": str, "version": int, "at": str,
                              "identity_evidence_id": str} | None,  # status.applicability
          "evidence": {                                     # the IDs the run made
            "identity": str,       # the ID read's invocation, or the operator record's audit ref
            "settings": str,       # the configuration read's snapshot evidence, if any
            "config-change": str,  # the change retrieved after the ID read, if any
            "control": str,        # the recorded control's audit ref, if any
          },
          "findings": {"<advisory>": [<C12 finding dict>, ...]},   # every stored revision, in order
          "identity_read": {"invocation_id": str, "read_at": str,   # the identity.read document:
                            "mismatch": {"invocation_id": str,      # the last confirming read,
                                         "read_at": str,            # and the mismatch apart
                                         "fid": str,
                                         "declared_sha256": str} | None},  # operator rows only (D4-55)
        },
      },
    }
"""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
GT_ADV = os.path.join(HERE, "..", "gt_adv", "gt_adv.json")

EXPLOIT = re.compile(r"exploit", re.I)
# C12's evidence ID forms, each tied to its source.
ID_FORM = {
    "device-read": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    "operator": re.compile(r"^audit:[^:]+:[0-9]+$"),
}


def load_gt(path=GT_ADV):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cells(gt):
    """Every (row, advisory, expected cell) of GT-ADV."""
    for adv, rows in gt["cells"].items():
        for row, cell in rows.items():
            yield row, adv, cell


def _keys(x):
    """Every key in a JSON value, at any depth."""
    if isinstance(x, dict):
        for k, v in x.items():
            yield k
            yield from _keys(v)
    elif isinstance(x, list):
        for v in x:
            yield from _keys(v)


def _evidence(f):
    """Every piece of evidence a finding cites, anywhere in it."""
    out = list(f["identity"].get("evidence", []))
    for p in f.get("preconditions", []):
        out += p.get("evidence", [])
    for m in f.get("mitigations", []):
        out += m.get("evidence", [])
    return out


def _ids(f):
    return [e["id"] for e in _evidence(f)]


def check_cell(row, adv, cell, asset, set_):
    """The reasons cell (row, adv) fails, or [] when it passes."""
    revs = asset.get("findings", {}).get(adv, [])
    if cell.get("reason") == "product-not-named" and not revs:
        ev = asset.get("last_evaluation")
        if ev is None:
            return ["no stored finding and no completed evaluation"]
        bad = []
        if ev["version"] != set_["version"] or ev["set_id"] != set_["id"]:
            bad.append(f"the last completed evaluation ran under set {ev['set_id']} version {ev['version']}, not the set in use")
        if ev["identity_evidence_id"] != asset["identity"]["evidence_id"]:
            bad.append(f"the last completed evaluation ran on identity record {ev['identity_evidence_id']}, not the newest, {asset['identity']['evidence_id']}")
        return bad
    if not revs:
        return [f"no stored finding, want {cell['class']}"]

    f, bad = revs[-1], []
    if f["class"] != cell["class"]:
        bad.append(f"class {f['class']}, want {cell['class']}")
    if f.get("reason", "") != cell.get("reason", ""):
        bad.append(f"reason {f.get('reason', '')!r}, want {cell.get('reason', '')!r}")
    if f["set"]["version"] != set_["version"] or f["set"]["id"] != set_["id"]:
        bad.append(f"decided under set {f['set']}, not the set in use")
    if f["identity"]["source"] != asset["identity"]["source"]:
        bad.append(f"identity source {f['identity']['source']}, the asset's is {asset['identity']['source']}")
    if f["class"] == "confirmed" and f["identity"]["source"] != "device-read":
        bad.append(f"confirmed on a {f['identity']['source']} identity")
    for e in _evidence(f):
        form = ID_FORM.get(e["source"])
        if form and not form.match(e["id"]):
            bad.append(f"{e['source']} evidence {e['id']!r} is not in that source's form")
    unread = sorted(p["name"] for p in f.get("preconditions", []) if p["state"] == "unread")
    if unread != sorted(cell.get("unread", [])):
        bad.append(f"unread preconditions {unread}, want {sorted(cell.get('unread', []))}")
    cited = _ids(f)
    for kind in cell.get("evidence", []):
        want = asset["evidence"].get(kind)
        if not want:
            bad.append(f"the run made no {kind} evidence to cite")
        elif want not in cited:
            bad.append(f"the {kind} evidence {want} is not cited")
    # GT-ADV states stale only where it decides the class; confirmed must
    # rest on current evidence (C12).
    stale = any(e.get("stale") for e in f["identity"].get("evidence", []))
    if cell.get("stale") and not stale:
        bad.append("the identity is not marked stale")
    if f["class"] == "confirmed" and stale:
        bad.append("confirmed on stale evidence")
    attested = any(m.get("operator_attested") for m in f.get("mitigations", []))
    if attested != bool(cell.get("attested")):
        bad.append(f"operator-attested {attested}, want {bool(cell.get('attested'))}")
    if any(EXPLOIT.search(k) for k in _keys(f)):
        bad.append("a field names exploitability")
    for i, r in enumerate(revs):
        if r["revision"] != i + 1 or (i > 0 and r.get("from") != revs[i - 1]["class"]):
            bad.append(f"revision {i + 1} does not follow its predecessor")
            break
    return bad


def check(gt, observed):
    """Each cell's failures, keyed (row, advisory); a passing cell maps to []."""
    out = {}
    for row, adv, cell in cells(gt):
        asset = observed["assets"].get(row)
        out[(row, adv)] = ["the row has no asset in the run"] if asset is None else check_cell(row, adv, cell, asset, observed["set"])
    return out


def check_restart(before, after):
    """What a restart (or a chain prune and a restart) changed that it must
    not: no finding is added or revised, and each asset's identity evidence
    keeps its ID, so an operator row still cites the same policy.apply
    record (D4-54)."""
    bad = []
    for row, a in before["assets"].items():
        b = after["assets"].get(row)
        if b is None:
            bad.append(f"{row}: gone after the restart")
            continue
        if a["evidence"].get("identity") != b["evidence"].get("identity"):
            bad.append(f"{row}: identity evidence {a['evidence'].get('identity')} became {b['evidence'].get('identity')}")
        for adv in sorted(set(a.get("findings", {})) | set(b.get("findings", {}))):
            if a.get("findings", {}).get(adv, []) != b.get("findings", {}).get(adv, []):
                bad.append(f"{row} {adv}: the findings changed across the restart")
    return bad


def check_mismatch(asset, adv, mismatch_id, mismatch_fid, confirming):
    """A later mismatch (#451, D4-54), on a device-read asset or, by C1's
    later ruling, an operator-only one: the newest finding is
    applicable-by-version with the version unread, the identity stale and
    the mismatch cited, whether or not the entry names the reported model;
    the identity.read document keeps the mismatch apart, and the last
    confirming read as its latest read. An operator-only asset has no
    confirming read (confirming is None), so the document has none. Run it
    before and after a restart."""
    revs = asset.get("findings", {}).get(adv, [])
    if not revs:
        return [f"{adv}: no stored finding after the mismatch"]
    f, bad = revs[-1], []
    if f["class"] != "applicable-by-version":
        bad.append(f"{adv}: class {f['class']} after the mismatch, want applicable-by-version")
    if "firmware-version" not in [p["name"] for p in f.get("preconditions", []) if p["state"] == "unread"]:
        bad.append(f"{adv}: firmware-version is not named unread")
    if not any(e.get("stale") for e in f["identity"].get("evidence", [])):
        bad.append(f"{adv}: the identity is not marked stale")
    # C12 0.1 cannot cite device-read evidence on an operator identity, so
    # an operator finding does not cite the mismatch (C1, a C12 0.2 item).
    if f["identity"]["source"] != "operator" and mismatch_id not in _ids(f):
        bad.append(f"{adv}: the mismatch read {mismatch_id} is not cited")
    rd = asset.get("identity_read") or {}
    if f["identity"]["source"] != asset["identity"]["source"]:
        bad.append(f"{adv}: identity source {f['identity']['source']} after the mismatch, the asset's is {asset['identity']['source']}")
    if rd.get("invocation_id") != confirming:
        bad.append(f"identity.read's latest read is {rd.get('invocation_id')}, want the last confirming read {confirming}")
    mm = rd.get("mismatch") or {}
    if mm.get("fid") != mismatch_fid or mm.get("invocation_id") != mismatch_id:
        bad.append(f"identity.read keeps mismatch {mm or None}, want FID {mismatch_fid!r} from {mismatch_id}")
    return bad
