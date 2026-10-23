"""A6 independent check of A2's SEL-751 firmware allowlist (D27, V-S19, C-23).

Reads the SEL-751 IM firmware revision history (Appendix A) from the
manual's text, splits it into one record per FID row, and finds every row
whose notes match each restart or lock-up fix by A6's own phrase list. It
then compares the rows found with the rows A2 lists for that fix, and checks
that every "allow" branch's minimum version is at or after each
collector-traffic fix A6 finds on that branch.

Run: python3 -I tests/safety/firmware_review/check_allowlist.py <751_IM text> <allowlist.json>
Classification: desk (documentation only).
"""

import json
import re
import sys

FID = re.compile(r"SEL-751-R(\d{3})-V(\d+)-Z\d+-D(\d{8})")
# A6's phrases, written from reading Appendix A, not from A2's file.
FIXES = {
    "F1": r"certain Ethernet traffic could cause\s+diagnostic restarts",
    "F2": r"Telnet traffic could cause a diagnostic\s+restart",
    "F3": r"crafted Ethernet traffic could cause the relay to perform a diagnostic",
    "F4": r"\(BPDU\) packet of invalid size could cause the relay to perform a\s+diagnostic restart",
    "F5": r"accessing the relay via\s+communications ports,.*?could cause\s+a diagnostic restart",
    "F6": r"Ethernet port could lock up",
    "F7": r"denial-of-service condition in the web\s+server that could trigger diagnostic restarts",
}
COLLECTOR_TRAFFIC = {"F1", "F2", "F5"}  # A6: Telnet/Ethernet/comms access, which a collector generates


def rows(text):
    start = text.index("Firmware Revision History") if "Firmware Revision History" in text else 0
    body = text[start:]
    hits = [m for m in FID.finditer(body)]
    out = []
    for i, m in enumerate(hits):
        # A row is a FID that begins a table row (followed by its notes), not
        # an "Includes all the functions of <FID>" reference.
        before = body[max(0, m.start() - 40):m.start()]
        if "functions of" in before:
            continue
        end = next((h.start() for h in hits[i + 1:]
                    if "functions of" not in body[max(0, h.start() - 40):h.start()]), len(body))
        out.append({"branch": "R" + m.group(1), "v": int(m.group(2)), "d": m.group(3),
                    "notes": " ".join(body[m.end():end].split())})
    return out


def main(manual, allowlist):
    with open(manual) as f:
        recs = rows(f.read())
    with open(allowlist) as f:
        a2 = json.load(f)
    found = {k: sorted({f"{r['branch']}-V{r['v']}" for r in recs if re.search(p, r["notes"], re.S)})
             for k, p in FIXES.items()}
    report = {"rows_parsed": len(recs), "fixes": {}, "branches": []}
    for k, mine in found.items():
        listed = sorted(re.match(r"(R\d{3}-V\d+)", x).group(1) for x in a2["fixes"][k]["listed_on"])
        report["fixes"][k] = {"a6_found": mine, "a2_listed": listed, "agree": mine == listed}
    for b in a2["branches"]:
        if not b["status"].startswith("allow"):
            continue
        minv = int(b["min_version"].lstrip("V"))
        problems = []
        for k in sorted(COLLECTOR_TRAFFIC):
            on_branch = [int(x.split("-V")[1]) for x in found[k] if x.startswith(b["branch"] + "-")]
            if on_branch and min(on_branch) > minv:
                problems.append(f"{k} fixed at V{min(on_branch)} but min_version is V{minv}")
            if not on_branch:
                problems.append(f"{k} not listed on {b['branch']} (inherited, inferred)")
        report["branches"].append({"branch": b["branch"], "status": b["status"],
                                   "min_version": b["min_version"], "notes": problems})
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main(*sys.argv[1:3])
