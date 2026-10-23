"""Check a recording simulator log against a command register.

Every command line the simulator received must fully match a register entry
classified read-only. Anything else is a violation: a line matching a
state-changing entry, a line matching no entry, or a line containing control
bytes. Empty lines (a bare Enter to wake a prompt) are allowed.

Also reports, for V-S13: failed authentication attempts per session and the
peak number of concurrent sessions.

Register format (JSON): {"commands": [{"id": "...", "pattern": "<regex>",
"classification": "read-only" | "state-changing"}]}. Patterns are matched with
re.fullmatch against the line exactly as received, so parameters are part of
the classification (challenge C-01 in docs/verification.md).

Run: python check.py --log rec.jsonl --register register.json
Exit status: 0 if no violations, 1 otherwise.
"""

import argparse
import json
import re
import sys

CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def load_register(path):
    with open(path) as f:
        entries = json.load(f)["commands"]
    for e in entries:
        if e["classification"] not in ("read-only", "state-changing"):
            raise ValueError(f"bad classification in register entry {e['id']}")
        e["regex"] = re.compile(e["pattern"])
    return entries


def classify(text, register):
    if CONTROL.search(text):
        return "control-bytes", None
    hits = [e for e in register if e["regex"].fullmatch(text)]
    if any(e["classification"] == "state-changing" for e in hits):
        return "state-changing", [e["id"] for e in hits]
    if hits:
        return "read-only", [e["id"] for e in hits]
    return "unregistered", None


def check(events, register):
    commands, violations = [], []
    failed_auth, open_sessions, peak = {}, set(), 0
    for ev in events:
        kind = ev["event"]
        if kind == "session_open":
            open_sessions.add(ev["session"])
            peak = max(peak, len(open_sessions))
        elif kind == "session_close":
            open_sessions.discard(ev["session"])
        elif kind == "auth" and not ev["accepted"]:
            failed_auth[ev["session"]] = failed_auth.get(ev["session"], 0) + 1
        elif kind in ("exec", "line"):
            text = ev["text"]
            if kind == "line" and not text.strip():
                continue
            verdict, ids = classify(text, register)
            row = {"session": ev["session"], "via": kind, "text": text,
                   "verdict": verdict, "register_ids": ids}
            commands.append(row)
            if verdict != "read-only":
                violations.append(row)
        elif kind == "break":
            violations.append({"session": ev["session"], "via": "break",
                               "text": "", "verdict": "break-signal",
                               "register_ids": None})
    return {
        "commands_received": len(commands),
        "violations": violations,
        "failed_auth_per_session": failed_auth,
        "peak_concurrent_sessions": peak,
        "pass": not violations,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True)
    ap.add_argument("--register", required=True)
    args = ap.parse_args()
    with open(args.log) as f:
        events = [json.loads(line) for line in f if line.strip()]
    report = check(events, load_register(args.register))
    print(json.dumps(report, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
