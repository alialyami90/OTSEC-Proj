"""Check suricata.ps1's suricata.json against the recorded result (P4-SENSOR-EVAL-GREEN).

The recorded result is suricata.recorded.json beside this script: the
"result" member is suricata.json of run 45081194524 after result() below.
result() keeps every field of suricata.json except two parts that change
without the experiment changing:

- msiexec_npcap_lines: each MSI log line's "MSI (s) (pid:tid) [time]: "
  prefix, which carries a process id and a time. The rest of each line is kept.
- imports[].resolves_to: the path where the image's DLL search finds each
  import (one sits under a JDK folder named by the image's JDK version). Only
  whether it resolves is kept, so a wpcap.dll that starts resolving differs.

It prints "same as the recorded result" and exits 0 when equal. Otherwise
it prints each difference and exits 1; a missing, empty or unreadable file
is a difference. Usage: python -I suricata_recorded.py SURICATA_JSON
"""
import json
import os
import re
import sys

RECORDED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "suricata.recorded.json")
MSI_PREFIX = re.compile(r"^MSI \([a-z]\) \([0-9A-Fa-f]+:[0-9A-Fa-f]+\) \[[0-9:]+\]: ")


def result(raw):
    r = dict(raw)
    if isinstance(r.get("msiexec_npcap_lines"), list):
        r["msiexec_npcap_lines"] = [MSI_PREFIX.sub("", str(l)) for l in r["msiexec_npcap_lines"]]
    if isinstance(r.get("imports"), list):
        r["imports"] = [{"dll": i.get("dll"), "resolves": i.get("resolves_to") is not None}
                        if isinstance(i, dict) else i for i in r["imports"]]
    return r


def diff(want, got, path="suricata.json"):
    if isinstance(want, dict) and isinstance(got, dict):
        out = []
        for k in want:
            out += diff(want[k], got[k], f"{path}.{k}") if k in got else [f"{path}.{k}: missing (recorded {json.dumps(want[k])})"]
        out += [f"{path}.{k}: added ({json.dumps(got[k])})" for k in got if k not in want]
        return out
    if isinstance(want, list) and isinstance(got, list) and len(want) == len(got):
        return [d for i, (w, g) in enumerate(zip(want, got)) for d in diff(w, g, f"{path}[{i}]")]
    return [] if want == got else [f"{path}: {json.dumps(got)} (recorded {json.dumps(want)})"]


def check(path, recorded=RECORDED):
    with open(recorded, encoding="utf-8") as f:
        want = json.load(f)["result"]
    try:
        with open(path, encoding="utf-8-sig") as f:
            got = json.load(f)
    except (OSError, ValueError) as e:
        return [f"{path}: missing, empty or unreadable ({e.__class__.__name__}: {e})"]
    if not isinstance(got, dict):
        return [f"{path}: not a JSON object"]
    return diff(want, result(got))


def main(argv):
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    d = check(argv[1])
    for line in d:
        print("DIFFERS: " + line)
    print(f"suricata.json: {len(d)} difference(s) from the recorded result." if d
          else "suricata.json: same as the recorded result (run 45081194524).")
    return 1 if d else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
