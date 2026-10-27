"""GT-INJ: B6's labelled injection schedules for V-M2 (configuration
changes, R3.6) and V-M4 (event-behaviour departures, R4.8).

Run from the repository root:  python3 -I tests/integration/gt_inj/generate.py

It writes three files next to itself:

  config.json          V-M2's seven cases, three changes of each, one asset
                       per change, with the approval each change gets and
                       the outcome it must have.
  events.json          an event series for two assets: an observation
                       period, the operator's acknowledgement, then a test
                       period with at least three injected departures of
                       each R4.8 kind, and one departure before the
                       acknowledgement that must raise nothing.
  events-heldout.json  a benign series from the same generator with another
                       seed, as long as the observation period, to replay
                       after the acknowledgement: it must raise nothing.

docs/verification.md defines GT-INJ: written from a fixed seed before the
implementation exists, and committed before the test first runs against the
product. Everything here is synthetic and supports `simulated` claims only.

The expected alarms in events.json come from this file's own reading of the
five rules ("R4.8 observation period and measures"), with the parameters in
PARAMS. The rules' parameters are not yet fixed by a contract (C10, P4-A4);
when they are, PARAMS is set to them and the files are regenerated, before
any product test has run. Where the verification text leaves a choice open,
the reading taken is stated next to the rule below, so a product that reads
it otherwise is a question for B1, not a silent mismatch.
"""
import bisect
import datetime as dt
import json
import os
import random
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tests", "safety", "recording_simulator"))
import profile_sel751  # noqa: E402

SCHEMA = "gt-inj/1"
CONFIG_SEED = 202610271
EVENTS_SEED = 202610272
HELDOUT_SEED = 202610273

# ---------------------------------------------------------------------------
# V-M2: configuration changes
# ---------------------------------------------------------------------------

# Each change is on its own asset, read by its own simulator, so no change
# depends on what the node did with another (re-baselining after an
# approved change is the node's design, P4-A5, and is not assumed here).
# Times are seconds from the asset's start. R0 is the baseline read, which
# the operator acknowledges. Rm is a read that still finds the baseline, so
# the platform knows the change came after it (C8 0.5's unchanged_at). The
# change is made with the simulator's injector (--profile-settings) before
# R1, the read that must see it. An approval covers the change when its
# window overlaps (Rm, R1) and the collector accepted it before R1's
# decision (C8 0.5 ApprovalCovers): a window that ended before Rm does not.
TIMELINE = {"R0": 0, "baseline_ack": 30, "Rm": 105, "change": 120, "R1": 180}

# The seven cases of V-M2, in its order. window is [start, end] in the
# asset's seconds; recorded is when the approval enters the audit chain;
# claims is the creation time written in the approval's own text.
CASES = {
    "approved": dict(approval=dict(device="self", window=[90, 600], recorded=60, claims=60, approver=True),
                     alarm=False, linked=True, refused=False),
    "no-approval": dict(approval=None, alarm=True, linked=False, refused=False),
    "other-device": dict(approval=dict(device="other", window=[90, 600], recorded=60, claims=60, approver=True),
                         alarm=True, linked=False, refused=False),
    # Ended at 100, before Rm found the configuration unchanged.
    "window-ended": dict(approval=dict(device="self", window=[50, 100], recorded=40, claims=40, approver=True),
                         alarm=True, linked=False, refused=False),
    # Recorded after R1 saw the change; its text claims an earlier time.
    # "Prior" is the audit chain's order, never the text (V-M2).
    "backdated": dict(approval=dict(device="self", window=[90, 600], recorded=240, claims=60, approver=True),
                      alarm=True, linked=False, refused=False),
    # A refused approval approves nothing, so the change alarms (B1, D4-9).
    "non-approver": dict(approval=dict(device="self", window=[90, 600], recorded=60, claims=60, approver=False),
                         alarm=True, linked=False, refused=True),
    # R1 prints the same settings one per line (--profile-sho-layout
    # one-per-line): a difference in bytes only (R3.3).
    "non-semantic": dict(approval=None, alarm=False, linked=False, refused=False),
}
REPEATS = 3


def figure_settings():
    with open(os.path.join(profile_sel751.DOC, "sho-group-fig-7-43.txt"), encoding="utf-8") as f:
        return profile_sel751.Printed(f.read().rstrip("\n")).settings()


def changed_value(rng, v):
    """Another value of the same printed form."""
    if v in ("Y", "N"):
        return "N" if v == "Y" else "Y"
    whole, _, frac = v.partition(".")
    step = 10 ** -len(frac) if frac else 1
    n = float(v)
    k = rng.choice([1, 2, 3, 4, 5]) * (1 if n < 5 * step or rng.random() < 0.5 else -1)
    return f"{n + k * step:.{len(frac)}f}"


def config_series():
    rng = random.Random(CONFIG_SEED)
    settings = figure_settings()
    pool = sorted(n for n, v in settings.items()
                  if v in ("Y", "N") or v.replace(".", "", 1).isdigit())
    order = [c for c in CASES for _ in range(REPEATS)]
    rng.shuffle(order)
    names = rng.sample(pool, len(order))
    changes = []
    for i, (case, name) in enumerate(zip(order, names), 1):
        c = CASES[case]
        group = rng.choice([1, 2, 3, 4])
        entry = {"id": f"cfg-{i:02d}", "asset": f"gt-inj-cfg-{i:02d}", "case": case,
                 "approval": c["approval"]}
        if case == "non-semantic":
            entry["inject"] = {"layout": "one-per-line"}
            entry["expect_changes"] = []
        else:
            old = settings[name]
            new = changed_value(rng, old)
            # The simulator's settings file: {class: {setting: value}}.
            entry["inject"] = {"layout": "figure", "settings": {str(group): {name: new}}}
            entry["expect_changes"] = [{"class": f"group.{group}", "name": name, "kind": "changed", "from": old, "to": new}]
        entry["expect"] = {"alarm": c["alarm"], "approval_linked": c["linked"], "approval_refused": c["refused"],
                           "stored": ["snapshot R0", "snapshot R1", "difference R0 to R1"]}
        changes.append(entry)
    return {
        "schema": SCHEMA, "series": "config", "seed": CONFIG_SEED, "evidence": "synthetic (simulated)",
        "source": "settings and values from B6's transcription of S22 Figure 7.43 "
                  "(tests/safety/recording_simulator/documented/sel-751/sho-group-fig-7-43.txt)",
        "timeline": TIMELINE,
        "other_device": "gt-inj-cfg-other",
        "pass": "per change: alarm exactly when expect.alarm, within one retrieval cycle of R1; "
                "an approved change links its approval; a non-approver's approval is refused and recorded; "
                "both snapshots and the difference are stored in every case; prior means audit-chain order.",
        "changes": changes,
    }


# ---------------------------------------------------------------------------
# V-M4: event-behaviour departures
# ---------------------------------------------------------------------------

# Proposed until C10 fixes them (see the module text). The names are C10's
# learner parameters as B4 gave them on #251, which B4 adopted as defaults.
PARAMS = {
    "observation": {"min_days": 14, "min_events": 200},
    # Rule 2: more than repeats_n of a type within repeats_window_s, when the
    # baseline's most in any such window was below repeats_n.
    "repeats_n": 5, "repeats_window_s": 600,
    # Rule 3 (B1, D4-9): one bound per type, rate_factor_pct of the most the
    # baseline saw in any clock-hour bucket (buckets from the Unix epoch on
    # received time), and never below rate_min. Hour of day is rule 4's.
    "rate_bucket_s": 3600, "rate_factor_pct": 300, "rate_min": 2,
    # Rule 5: a type is periodic with at least periodic_min_occurrences and
    # every gap within periodic_spread_pct of the interval, the upper middle
    # of the sorted gaps; it is absent when not seen within the interval
    # plus absence_tolerance_pct of it.
    "periodic_min_occurrences": 11, "periodic_spread_pct": 10, "absence_tolerance_pct": 50,
}

START = dt.datetime(2026, 11, 2, tzinfo=dt.timezone.utc)
DAY = 86400
TEST_DAYS = 7

# Types: key -> hours (UTC) it may occur in. Non-periodic events fall only
# on the slots :05 and :35 (+0 to 20 s), at most one per slot, so any
# 10-minute window holds at most one, any hour at most two.
SER_TYPES = {
    ("IN101", "Asserted"): range(6, 21), ("IN101", "Deasserted"): range(6, 21),
    ("52A", "Asserted"): range(6, 21), ("52A", "Deasserted"): range(6, 21),
    ("SALARM", "Asserted"): range(1, 23), ("OUT101", "Asserted"): range(8, 17),
    ("LOP", "Asserted"): range(2, 22),
}
# A Syslog type is defined by (facility, severity, msgid, text). Its key is
# facility, severity and the text with each digit run made "#" (D4-4 item
# 4, B1's ruling on #251): the msgid is the sender's choice and is not in
# the key. So a new text under a known msgid is a new type, and a known
# text under another msgid is not.
SYSLOG_TYPES = {
    (4, 6, "LOGIN", "Level 1 login on port {n}"): range(7, 19),
    (4, 5, "LOGOUT", "Logout on port {n}"): range(7, 19),
    (16, 6, "PORTSTAT", "Port {n} status enabled"): range(1, 23),
    (16, 4, "LINKDOWN", "Ethernet link {n} down"): range(2, 22),
}
# Every 3600 s at :00:00 + 0 to 30 s, on the syslog asset.
PERIODIC = (16, 6, "HEARTBEAT", "Heartbeat sequence {n}")
NEW_TYPES = {"gt-inj-ser": [("TRIP", "Asserted"), ("51P1T", "Asserted"), ("OUT103", "Asserted"), ("50G1T", "Asserted")],
             # The first reuses the known msgid LOGIN with a new text.
             "gt-inj-syslog": [(4, 6, "LOGIN", "Firmware upload started on port {n}"),
                               (4, 4, "ACCFAIL", "Access denied for level 2 on port {n}"),
                               (16, 3, "CFGWRITE", "Settings written to group {n}"),
                               (16, 2, "PWRUP", "Power up {n}")]}
ASSETS = {"gt-inj-ser": SER_TYPES, "gt-inj-syslog": SYSLOG_TYPES}
SLOTS = (5 * 60, 35 * 60)
P_COUNT = (0.72, 0.22, 0.06)  # per type, hour and day: 0, 1 or 2 events


def template(msg):
    return re.sub(r"[0-9]+", "#", msg)


def key_of(e):
    return (e["element"], e["state"]) if "element" in e else (e["facility"], e["severity"], template(e["msg"]))


def make_event(asset, key, t, msgid=None):
    """An event of type definition key at t. A Syslog text's number varies
    with t, so types never differ by their digits alone."""
    e = {"asset": asset, "received_utc": iso(t)}
    if asset == "gt-inj-ser":
        e.update(source="ser", element=key[0], state=key[1])
    else:
        e.update(source="syslog", facility=key[0], severity=key[1], msgid=msgid or key[2],
                 msg=key[3].format(n=(t // 3600) % 9 + 1))
    e["t"] = t
    return e


def tkey(asset, key):
    """The type key of type definition key."""
    return key_of(make_event(asset, key, 0))


def seconds_of(t):
    return t


def iso(t):
    return (START + dt.timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def benign_day(rng, day, peak=frozenset()):
    """One day of benign events for both assets. A type in peak fills every
    slot of every hour it may occur in."""
    out = []
    for asset, types in ASSETS.items():
        for key, hours in types.items():
            for h in hours:
                n = 2 if key in peak else rng.choices((0, 1, 2), P_COUNT)[0]
                slots = SLOTS if n == 2 else rng.sample(SLOTS, n)
                for s in slots:
                    out.append(make_event(asset, key, day * DAY + h * 3600 + s + rng.randint(0, 20)))
    for h in range(24):
        out.append(make_event("gt-inj-syslog", PERIODIC, day * DAY + h * 3600 + rng.randint(0, 30)))
    return out


def baseline(events):
    """B6's reading of what the baseline learns, per type: the hours seen,
    the most in one clock-hour bucket, the most in any w_s window, and the
    interval of a periodic type."""
    p = PARAMS
    by = {}
    for e in events:
        by.setdefault((e["asset"], key_of(e)), []).append(e["t"])
    out = {}
    for k, ts in by.items():
        ts.sort()
        buckets = {}
        for t in ts:
            buckets[t // p["rate_bucket_s"]] = buckets.get(t // p["rate_bucket_s"], 0) + 1
        w = p["repeats_window_s"]
        most_w = max(bisect.bisect_right(ts, t + w - 1) - i for i, t in enumerate(ts))
        gaps = sorted(b - a for a, b in zip(ts, ts[1:]))
        interval = None
        if len(ts) >= p["periodic_min_occurrences"]:
            med = gaps[len(gaps) // 2]
            spread = p["periodic_spread_pct"] / 100
            if all(abs(g - med) <= spread * med for g in gaps):
                interval = med
        out[k] = {"hours": sorted({(t % DAY) // 3600 for t in ts}), "most_per_bucket": max(buckets.values()),
                  "most_per_window": most_w, "interval": interval, "last": ts[-1]}
    return out


def evaluate(base, events, start, end):
    """The departures the five rules find in events (after the
    acknowledgement at start, up to end), as alarms: rule, asset, type,
    at, and the event IDs that broke the baseline (none for absence)."""
    p = PARAMS
    alarms = []
    by = {}
    for e in sorted(events, key=lambda e: e["t"]):
        by.setdefault((e["asset"], key_of(e)), []).append(e)
    for k, es in by.items():
        b = base.get(k)
        asset, key = k
        name = list(key)
        if b is None:
            alarms.append(dict(rule="new", asset=asset, type=name, at=es[0]["t"], events=[es[0]["id"]]))
            continue
        ts = [e["t"] for e in es]
        # 2. repeats: one alarm per run of events that each close a window
        # holding more than n, raised at the first of them and listing the
        # events of the window it closed (C10, B4 on #251).
        n, w = p["repeats_n"], p["repeats_window_s"]
        if b["most_per_window"] < n:
            open_run = False
            for i, e in enumerate(es):
                lo = bisect.bisect_left(ts, e["t"] - w + 1)
                if i + 1 - lo > n:
                    if not open_run:
                        alarms.append(dict(rule="repeats", asset=asset, type=name, at=e["t"], events=[x["id"] for x in es[lo:i + 1]]))
                    open_run = True
                else:
                    open_run = False
        # 3. rate: one alarm per bucket over the bound, at the event that
        # passed it.
        bound = max(p["rate_factor_pct"] * b["most_per_bucket"] // 100, p["rate_min"])
        buckets = {}
        for e in es:
            buckets.setdefault(e["t"] // p["rate_bucket_s"], []).append(e)
        for bk, xs in sorted(buckets.items()):
            if len(xs) > bound:
                alarms.append(dict(rule="rate", asset=asset, type=name, at=xs[bound]["t"], events=[x["id"] for x in xs]))
        # 4. time: each event at an hour the baseline never saw the type in.
        for e in es:
            if (e["t"] % DAY) // 3600 not in b["hours"]:
                alarms.append(dict(rule="time", asset=asset, type=name, at=e["t"], events=[e["id"]]))
    # 5. absence: from the last occurrence (before or after start), each
    # time the next is later than interval x (1 + tolerance).
    for k, b in base.items():
        if not b["interval"]:
            continue
        limit = b["interval"] * (100 + p["absence_tolerance_pct"]) // 100
        ts = [b["last"]] + [e["t"] for e in by.get(k, [])]
        ts.append(end)
        for a, c in zip(ts, ts[1:]):
            if c - a > limit and a + limit >= start:
                alarms.append(dict(rule="absence", asset=k[0], type=list(k[1]), at=a + limit, events=[]))
    alarms.sort(key=lambda a: (a["at"], a["rule"], a["asset"]))
    return alarms


def number(events, prefix):
    events.sort(key=lambda e: (e["t"], e["asset"], json.dumps(key_of(e))))
    for i, e in enumerate(events, 1):
        e["id"] = f"{prefix}-{i:05d}"


def event_series():
    rng = random.Random(EVENTS_SEED)
    obs_days = PARAMS["observation"]["min_days"]
    keys = [(a, k) for a, ts in ASSETS.items() for k in ts]
    # A peak day for each type inside the observation period, so the
    # baseline sees the densest the generator ever makes (B6's construction:
    # benign events then never exceed it, whatever the seed).
    peaks = {}
    for a, k in keys:
        peaks.setdefault(rng.randrange(1, obs_days - 1), set()).add(k)
    events = []
    for day in range(obs_days + 1 + TEST_DAYS):
        events += benign_day(rng, day, frozenset(peaks.get(day, ())))
    first = {a: min(e["t"] for e in events if e["asset"] == a) for a in ASSETS}
    period_end = max(first.values()) + obs_days * DAY
    for a in ASSETS:
        n = sum(1 for e in events if e["asset"] == a and e["t"] < first[a] + obs_days * DAY)
        assert n >= PARAMS["observation"]["min_events"], (a, n)
    ack = period_end + 3600

    departures = []
    remove = set()  # (asset, key, bucket) whose benign events an injection replaces

    def inject(kind, asset, key, ts, **extra):
        evs = [make_event(asset, key, t) for t in ts]
        for e in evs:
            e["injected"] = f"dep-{len(departures) + 1:02d}"
        events.extend(evs)
        departures.append(dict(id=f"dep-{len(departures) + 1:02d}", kind=kind, asset=asset, type=list(key_of(make_event(asset, key, 0))),
                               at=ts[0] if ts else extra["gap_from"], **extra))

    # Before the acknowledgement: a new type, which must raise nothing.
    inject("new", "gt-inj-ser", NEW_TYPES["gt-inj-ser"][3], [period_end + 1800], before_ack=True)

    test0 = (obs_days + 1) * DAY
    # Days of the test period, two injections a day at least 6 h apart.
    plan = ["new", "repeats", "rate", "time", "absence"] * 3
    rng.shuffle(plan)
    slots = [test0 + d * DAY + h * 3600 for d in range(TEST_DAYS) for h in (3, 9, 15)]
    rng.shuffle(slots)
    slots = sorted(slots[:len(plan)])
    news = {a: list(v[:3]) for a, v in NEW_TYPES.items()}
    for kind, base_t in zip(plan, slots):
        day = base_t // DAY
        if kind == "absence":
            asset, key = "gt-inj-syslog", PERIODIC
            gone = [e for e in events if e["asset"] == asset and key_of(e) == tkey(asset, key)
                    and base_t <= e["t"] < base_t + 4 * 3600]
            for e in gone:
                events.remove(e)
            inject(kind, asset, key, [], gap_from=base_t, removed=[iso(e["t"]) for e in gone])
            continue
        asset = rng.choice(sorted(ASSETS))
        if kind == "new":
            inject(kind, asset, news[asset].pop(0), [base_t + 20 * 60])
            continue
        if kind == "time":
            # At 23:20 that day: no non-periodic type occurs at 23.
            base_t = base_t - base_t % DAY + 23 * 3600
            key = rng.choice([k for k, hs in ASSETS[asset].items() if (base_t % DAY) // 3600 not in hs])
            inject(kind, asset, key, [base_t + 20 * 60])
            continue
        key = rng.choice([k for k, hs in ASSETS[asset].items() if (base_t % DAY) // 3600 in hs])
        remove.add((asset, tkey(asset, key), base_t // 3600))
        if kind == "repeats":
            # n + 1 within a minute, and no more than the rate bound in the hour.
            inject(kind, asset, key, [base_t + 20 * 60 + 10 * i for i in range(PARAMS["repeats_n"] + 1)])
        else:
            # factor x 2 + 1 in the hour, spaced so no w_s window holds n.
            k = PARAMS["rate_factor_pct"] * 2 // 100 + 1
            inject(kind, asset, key, [base_t + 120 + i * (3480 // k) for i in range(k)])
    events = [e for e in events if "injected" in e or (e["asset"], key_of(e), e["t"] // 3600) not in remove]
    # Controls: three benign LOGIN events in the test period sent with
    # another msgid. Their key is unchanged, so they must raise nothing.
    logins = [e for e in events if e["t"] >= test0 and "injected" not in e and e.get("msgid") == "LOGIN"
              and key_of(e) == key_of(make_event("gt-inj-syslog", list(SYSLOG_TYPES)[0], 0))]
    for e in rng.sample(logins, 3):
        e["msgid"], e["control"] = "LOGIN-B", True
    number(events, "ev")
    controls = [dict(what="a known Syslog text under another msgid is not a new type (D4-4 item 4)",
                     events=[e["id"] for e in events if e.get("control")], expect_rules=[])]
    by_dep = {}
    for e in events:
        if "injected" in e:
            by_dep.setdefault(e["injected"], []).append(e["id"])

    base = baseline([e for e in events if e["t"] < period_end])
    end = (obs_days + 1 + TEST_DAYS) * DAY
    alarms = evaluate(base, [e for e in events if e["t"] >= ack], ack, end)
    pre = evaluate(base, [e for e in events if period_end <= e["t"] < ack], period_end, ack)
    for d in departures:
        d["events"] = by_dep.get(d["id"], [])
        if d["kind"] == "absence":
            lo = seconds_of(d["gap_from"])
            d["expect_rules"] = sorted({a["rule"] for a in alarms if a["asset"] == d["asset"] and a["type"] == d["type"]
                                        and a["rule"] == "absence" and lo <= a["at"] <= lo + 5 * 3600})
            continue
        if d.get("before_ack"):
            d["expect_rules"] = []
            continue
        d["expect_rules"] = sorted({a["rule"] for a in alarms if set(a["events"]) & set(d["events"])})
    # The schedule's own checks: every injected departure is found by its
    # own rule, the benign part raises nothing, and the pre-acknowledgement
    # departure would have alarmed (so "nothing before the ack" is not
    # vacuous).
    for d in departures:
        if not d.get("before_ack"):
            assert d["kind"] in d["expect_rules"], d
    benign = [a for a in alarms if not any(set(a["events"]) & set(d["events"]) for d in departures)
              and not (a["rule"] == "absence" and any(d["kind"] == "absence" and d["asset"] == a["asset"]
                                                      and d["gap_from"] <= a["at"] <= d["gap_from"] + 5 * 3600
                                                      for d in departures))]
    assert not benign, benign
    assert any(a["rule"] == "new" for a in pre), pre
    assert not any(set(a["events"]) & set(controls[0]["events"]) for a in alarms)
    for e in events:
        e.pop("t")
        e.pop("injected", None)
        e.pop("control", None)
    for a in alarms:
        a["at"] = iso(a["at"])
    for d in departures:
        d["at"] = iso(d["at"])
        if "gap_from" in d:
            d["gap_from"] = iso(d["gap_from"])
    return {
        "schema": SCHEMA, "series": "events", "seed": EVENTS_SEED, "evidence": "synthetic (simulated)",
        "params": PARAMS,
        "type_key": "SER: element and state; Syslog: facility, severity and the text with each digit run made # "
                    "(D4-4 item 4; msgid is not in the key)",
        "clock": "received_utc, the platform's receive time",
        "period": {"first_event": {a: iso(t) for a, t in first.items()}, "end": iso(period_end),
                   "baseline_ack": iso(ack), "test_end": iso(end)},
        "pass": "zero departure alarms before baseline_ack; each departure with expect_rules raises at least its "
                "own kind's rule citing its events (absence: within the gap); recall per kind is reported; "
                "precision is alarms citing an injected departure over all departure alarms; "
                "expected_alarms is B6's reading under params.",
        "departures": departures,
        "controls": controls,
        "expected_alarms": alarms,
        "events": events,
    }


def heldout_series(start_day):
    rng = random.Random(HELDOUT_SEED)
    obs_days = PARAMS["observation"]["min_days"]
    events = []
    for day in range(start_day, start_day + obs_days):
        events += benign_day(rng, day)
    number(events, "ho")
    return events


def main():
    cfg = config_series()
    ev = event_series()
    # The held-out series starts where the test period starts, so it can be
    # replayed after the acknowledgement in place of the injected one.
    start_day = PARAMS["observation"]["min_days"] + 1
    ho = heldout_series(start_day)
    # Check it against the baseline the injected series learnt.
    ev_full = json.loads(json.dumps(ev))
    for e in ev_full["events"]:
        e["t"] = int((dt.datetime.strptime(e["received_utc"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc) - START).total_seconds())
    period_end = int((dt.datetime.strptime(ev["period"]["end"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc) - START).total_seconds())
    base = baseline([e for e in ev_full["events"] if e["t"] < period_end])
    end = (start_day + PARAMS["observation"]["min_days"]) * DAY
    # The heartbeat before the held-out series is the observation period's
    # last; nothing between them is removed.
    ho_alarms = evaluate(base, ho, start_day * DAY, end)
    assert not ho_alarms, ho_alarms[:3]
    for e in ho:
        e.pop("t")
    held = {"schema": SCHEMA, "series": "events-heldout", "seed": HELDOUT_SEED, "evidence": "synthetic (simulated)",
            "params": PARAMS, "replay": "after events.json's baseline_ack, in place of its test period",
            "pass": "departure alarms per asset-day at most 0 (proposed bound for synthetic series)",
            "expected_alarms": [], "events": ho}
    for name, doc in (("config.json", cfg), ("events.json", ev), ("events-heldout.json", held)):
        with open(os.path.join(HERE, name), "w", newline="\n") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")


if __name__ == "__main__":
    main()
