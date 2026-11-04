"""V-M4's alarm oracle (C4's draft, for C6's independent review): the
departure alarms a node raised on the GT-INJ series, checked against
events.json.

The node writes each departure alarm as a C10 health event of type
baseline.departure (contracts/baseline Alarm.Health). The harness reads the
node's store and gives check() three things:

- the alarms: each a health body ({"type", "related", "details"});
- ids: each EventID the harness sent, in its "node:stream:seq" form, mapped
  to the series event id ("ev-01646");
- assets: each GT-INJ asset in the run, its asset_id mapped to the series
  name ("gt-inj-syslog").

Only the expectations of the assets in the run are checked, so the Syslog
half can run before gt-inj-ser does.

check() returns (failures, report). The run passes when failures is empty.
These are the failures:

- an assets map that is empty, or names something other than the
  series' assets;
- an alarm that is not a well-formed departure, or does not read as one;
- an alarm citing an event the harness did not send;
- an alarm whose key differs from its text;
- a departure alarm before the acknowledgement;
- an alarm citing a control event;
- an expected alarm that is missing, or an alarm that is not expected;
- a departure with expect_rules that no alarm of its own kind detects.
  An alarm detects a departure when it has the departure's asset, type and
  rule and cites one of the departure's events. For absence, the alarm
  falls within the gap instead: after gap_from and no later than the next
  occurrence of the type.

The report gives recall per kind and precision, which is the number of
alarms that detect an injected departure over all departure alarms
(events.json "pass").

Evidence class: whatever the run's is. The series is synthetic, so a pass
supports a simulated claim only.
"""

import datetime
import hashlib

DEPARTURE = "baseline.departure"
# C10's rule names (contracts/baseline Rule), as the series' kinds.
RULES = {"new-type": "new", "repeats": "repeats", "rate": "rate", "time": "time", "absence": "absence"}


def _utc(s):
    # C10 times are RFC 3339 with up to nine fractional digits; Python
    # keeps six, and every GT-INJ time is whole milliseconds.
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, zone = rest[:rest.index("+")], rest[rest.index("+"):]
        s = f"{head}.{frac[:6]}{zone}"
    return datetime.datetime.fromisoformat(s)


def _id(e):
    return f"{e['node_id']}:{e['stream']}:{e['seq']}"


def _type(key, text):
    """The alarm's type in events.json's form: [element, state] for SER,
    [facility, severity, template] for Syslog. Returns (type, error)."""
    parts = [p.replace("%7C", "|").replace("%25", "%") for p in key.split("|")]
    if parts[0] == "ser" and len(parts) == 3:
        if text != f"{parts[1]} {parts[2]}":
            return None, f"key {key} is not the type of its text {text!r}"
        return [parts[1], parts[2]], None
    if parts[0] == "syslog" and len(parts) == 5 and parts[3] == "template":
        want = "sha256:" + hashlib.sha256(text.encode()).hexdigest()
        if parts[4] != want:
            return None, f"key {key} is not the template of its text {text!r}"
        return [int(parts[1]), int(parts[2]), text], None
    return None, f"key {key} is not a GT-INJ type"


def read(alarms, ids, assets):
    """The alarms in events.json's form, and the failures found reading
    them."""
    out, failures = [], []
    for n, h in enumerate(alarms):
        try:
            a, errs = _read1(n, h, ids, assets)
        except (KeyError, ValueError, TypeError, AttributeError) as e:
            a, errs = None, [f"alarm {n}: malformed: {e!r}"]
        failures += errs
        if a is not None:
            out.append(a)
    return out, failures


def _read1(n, h, ids, assets):
    """One alarm in events.json's form, or None, and its failures."""
    d = h.get("details") or {}
    where = f"alarm {n} ({d.get('rule')} at {d.get('at_utc')})"
    if h.get("type") != DEPARTURE or d.get("rule") not in RULES or d.get("asset_id") not in assets:
        return None, [f"{where}: not a departure of a GT-INJ asset in the run: {h.get('type')} {d.get('asset_id')}"]
    typ, err = _type(d.get("key", ""), d.get("key_text", ""))
    if err:
        return None, [f"{where}: {err}"]
    failures, cited = [], []
    for e in h.get("related") or []:
        if _id(e) not in ids:
            failures.append(f"{where}: cites {_id(e)}, which the harness did not send")
        else:
            cited.append(ids[_id(e)])
    return {"rule": RULES[d["rule"]], "asset": assets[d["asset_id"]], "type": typ,
            "at": _utc(d["at_utc"]), "events": sorted(cited)}, failures


def _gap_end(series, dep):
    """The first occurrence of an absence departure's type after its gap
    starts, or the end of the test period."""
    start = _utc(dep["gap_from"])
    removed = {_utc(t) for t in dep.get("removed", [])}
    for e in series["events"]:
        t = _utc(e["received_utc"])
        if e["asset"] == dep["asset"] and t > start and t not in removed and _kind_type(e) == dep["type"]:
            return t
    return _utc(series["period"]["test_end"])


def _kind_type(e):
    if e["source"] == "ser":
        return [e["element"], e["state"]]
    t, digits = [], False
    for c in e["msg"]:
        if c.isascii() and c.isdigit():
            if not digits:
                t.append("#")
            digits = True
            continue
        digits = False
        t.append(c)
    return [e["facility"], e["severity"], "".join(t)]


def _detects(a, dep, series):
    if a["asset"] != dep["asset"] or a["type"] != dep["type"] or a["rule"] != dep["kind"]:
        return False
    if dep["kind"] == "absence":
        return _utc(dep["gap_from"]) < a["at"] <= _gap_end(series, dep)
    return bool(set(a["events"]) & set(dep["events"]))


def _key(a):
    return (a["rule"], a["asset"], tuple(a["type"]), a["at"], tuple(sorted(a["events"])))


def check(series, alarms, ids, assets):
    # A map naming no asset of the series would want nothing and pass with
    # no alarms (C6 on #403).
    known = set(series["period"]["first_event"])
    names = set(assets.values())
    if not names or names - known or len(names) != len(assets):
        return [f"assets {assets} must name each of the series' assets {sorted(known)} at most once, and at least one"], {}
    got, failures = read(alarms, ids, assets)
    ack = _utc(series["period"]["baseline_ack"])
    for a in got:
        if a["at"] < ack:
            failures.append(f"{a['rule']} {a['asset']} {a['type']} at {a['at']}: before the acknowledgement {ack}")
    controls = {e for c in series["controls"] for e in c["events"]}
    for a in got:
        if set(a["events"]) & controls:
            failures.append(f"{a['rule']} {a['asset']} {a['type']} at {a['at']}: cites control events {sorted(set(a['events']) & controls)}")

    want = [dict(x, at=_utc(x["at"]), events=sorted(x["events"])) for x in series["expected_alarms"] if x["asset"] in names]
    left = [_key(a) for a in got]
    for w in want:
        if _key(w) in left:
            left.remove(_key(w))
        else:
            failures.append(f"missing {w['rule']} {w['asset']} {w['type']} at {w['at']} citing {w['events']}")
    for k in left:
        failures.append(f"unexpected {k[0]} {k[1]} {list(k[2])} at {k[3]} citing {list(k[4])}")

    deps = [d for d in series["departures"] if d["asset"] in names]
    recall = {}
    for dep in deps:
        if not dep["expect_rules"]:
            continue
        hit = any(_detects(a, dep, series) for a in got)
        r = recall.setdefault(dep["kind"], [0, 0])
        r[0] += hit
        r[1] += 1
        if not hit:
            failures.append(f"{dep['id']} ({dep['kind']} {dep['asset']} {dep['type']} at {dep['at']}): no alarm of its kind detects it")
    true = sum(1 for a in got if any(_detects(a, d, series) for d in deps))
    report = {"recall": {k: f"{h}/{n}" for k, (h, n) in sorted(recall.items())},
              "precision": f"{true}/{len(got)}", "alarms": len(got)}
    return failures, report
