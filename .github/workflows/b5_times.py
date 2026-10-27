"""Summarizes go test -json output: each package's elapsed time and result,
then the slowest top-level tests of platform/node and platform/store."""
import json
import sys

pkgs, tests = {}, {}
with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
    for line in f:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        a, p, t = e.get("Action"), e.get("Package", ""), e.get("Test")
        if a in ("pass", "fail", "skip") and "Elapsed" in e:
            if t is None:
                pkgs[p] = (a, e["Elapsed"])
            elif "/" not in t:
                tests[(p, t)] = (a, e["Elapsed"])

print("== packages (elapsed s, result)")
for p, (a, s) in sorted(pkgs.items(), key=lambda kv: -kv[1][1]):
    print(f"{s:9.2f}  {a:4}  {p}")
for want in ("otsec.local/otsec/platform/node", "otsec.local/otsec/platform/store"):
    rows = sorted(((s, a, t) for (p, t), (a, s) in tests.items() if p == want), reverse=True)
    total = sum(s for s, _, _ in rows)
    print(f"\n== {want}: {len(rows)} tests, sum {total:.1f} s; slowest 25")
    for s, a, t in rows[:25]:
        print(f"{s:9.2f}  {a:4}  {t}")
