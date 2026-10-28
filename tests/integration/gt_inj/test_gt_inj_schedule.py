"""Checks on the committed GT-INJ schedules themselves (B6), not on the
product: what they inject is what they say, and the expected alarms follow
from the committed events under B6's reading of the rules. The product's
acceptance tests read these files; they are written by P4-A4 and P4-A5's
test owners once the products exist."""
import collections
import datetime as dt
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import generate as g  # noqa: E402


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


def seconds(ts):
    t = dt.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt.timezone.utc)
    return int((t - g.START).total_seconds())


@pytest.fixture(scope="module")
def cfg():
    return load("config.json")


@pytest.fixture(scope="module")
def ev():
    d = load("events.json")
    for e in d["events"]:
        e["t"] = seconds(e["received_utc"])
    return d


def test_config_has_every_case_three_times(cfg):
    count = collections.Counter(c["case"] for c in cfg["changes"])
    assert count == {case: g.REPEATS for case in g.CASES}
    assert len({c["asset"] for c in cfg["changes"]}) == len(cfg["changes"])
    assert cfg["other_device"] not in {c["asset"] for c in cfg["changes"]}


def test_config_expectations_follow_the_case(cfg):
    for c in cfg["changes"]:
        want = g.CASES[c["case"]]
        assert c["approval"] == want["approval"], c["id"]
        assert c["expect"]["alarm"] == want["alarm"], c["id"]
        assert c["expect"]["approval_linked"] == want["linked"], c["id"]
        assert c["expect"]["approval_refused"] == want["refused"], c["id"]
        a = c["approval"]
        if a is None:
            continue
        tl = cfg["timeline"]
        change, rm, r1 = tl["change"], tl["Rm"], tl["R1"]
        assert tl["R0"] < tl["baseline_ack"] < rm < change < r1
        # C8 0.5's ApprovalCovers from the times: the window overlaps
        # (Rm, R1), and the approval is in the chain before R1's decision.
        covers = a["window"][0] < r1 and a["window"][1] > rm and a["recorded"] < r1
        valid = a["device"] == "self" and covers and a["approver"]
        # Only "approved" is a valid prior approval; "backdated" claims a
        # time before the change but was recorded after R1.
        assert valid == (c["case"] == "approved"), c["id"]
        assert a["window"][1] - a["window"][0] <= 24 * 3600
        if c["case"] == "backdated":
            assert a["claims"] < change < r1 < a["recorded"]


def test_config_changes_are_real_figure_settings(cfg):
    fig = g.figure_settings()
    for c in cfg["changes"]:
        if c["case"] == "non-semantic":
            assert c["inject"] == {"layout": "one-per-line"} and c["expect_changes"] == []
            continue
        (cls, settings), = c["inject"]["settings"].items()
        (name, new), = settings.items()
        (ch,) = c["expect_changes"]
        assert ch == {"class": f"group.{cls}", "name": name, "kind": "changed", "from": fig[name], "to": new}
        assert new != fig[name]
        # The same printed form: Y/N, or the same number of decimals.
        form = lambda v: "YN" if v in ("Y", "N") else len(v.partition(".")[2])
        assert form(new) == form(fig[name]), c["id"]


def test_config_injection_reaches_the_simulator(cfg, tmp_path):
    """Each injection, given to the simulator as written, prints exactly
    the expected change, and the non-semantic case prints the same
    settings."""
    p = g.profile_sel751
    plain = p.SEL751DocResponder(None)._show_group(1)[1]["settings"]
    for c in cfg["changes"]:
        inj = c["inject"]
        path = tmp_path / f"{c['id']}.json"
        path.write_text(json.dumps(inj.get("settings", {})))
        r = p.SEL751DocResponder(None, settings_file=str(path), sho_layout=inj["layout"])
        for n in (1, 2, 3, 4):
            out, note = r._show_group(n)
            want = dict(plain)
            for ch in c["expect_changes"]:
                if ch["class"] == f"group.{n}":
                    want[ch["name"]] = ch["to"]
            assert note["settings"] == want, (c["id"], n)
            if inj["layout"] == "one-per-line":
                assert out != p.SEL751DocResponder(None)._show_group(n)[0]


def test_events_observation_period(ev):
    p = g.PARAMS
    end = seconds(ev["period"]["end"])
    for asset, first in ev["period"]["first_event"].items():
        n = sum(1 for e in ev["events"] if e["asset"] == asset and seconds(first) <= e["t"] < seconds(first) + p["min_duration_s"])
        assert n >= p["min_events"], asset
        assert seconds(first) + p["min_duration_s"] <= end
    assert seconds(ev["period"]["baseline_ack"]) > end


def test_events_three_departures_of_each_kind(ev):
    after = [d for d in ev["departures"] if not d.get("before_ack") and not d.get("catch_up")]
    assert collections.Counter(d["kind"] for d in after) == {k: 3 for k in ("new", "repeats", "rate", "time", "absence")}
    ack = seconds(ev["period"]["baseline_ack"])
    for d in after:
        assert seconds(d["at"]) > ack
        assert d["kind"] in d["expect_rules"], d["id"]
    before = [d for d in ev["departures"] if d.get("before_ack")]
    assert before and all(seconds(d["at"]) < ack and d["expect_rules"] == [] for d in before)


def _alarms(ev, events, start, end):
    base = g.baseline([e for e in ev["events"] if e["t"] < seconds(ev["period"]["end"])])
    out = g.evaluate(base, events, start, end)
    for a in out:
        a["at"] = g.iso(a["at"])
    return out


def test_events_expected_alarms_follow_from_the_events(ev):
    ack, end = seconds(ev["period"]["baseline_ack"]), seconds(ev["period"]["test_end"])
    assert _alarms(ev, [e for e in ev["events"] if e["t"] >= ack], ack, end) == ev["expected_alarms"]


def test_events_every_alarm_is_an_injected_departure(ev):
    """Precision 1 under B6's reading: the benign part raises nothing."""
    deps = ev["departures"]
    for a in ev["expected_alarms"]:
        if a["rule"] == "absence":
            assert any(d["kind"] == "absence" and seconds(d["gap_from"]) <= seconds(a["at"]) <= seconds(d["gap_from"]) + 5 * 3600
                       for d in deps), a
        else:
            assert any(set(a["events"]) <= set(d["events"]) for d in deps), a


def test_events_before_the_ack_would_alarm(ev):
    """The departure before the acknowledgement is one the rules find, so
    "no alarm before the ack" is not met vacuously."""
    end, ack = seconds(ev["period"]["end"]), seconds(ev["period"]["baseline_ack"])
    pre = _alarms(ev, [e for e in ev["events"] if end <= e["t"] < ack], end, ack)
    (d,) = [d for d in ev["departures"] if d.get("before_ack")]
    assert any(a["rule"] == "new" and a["events"] == d["events"] for a in pre)


def test_heldout_raises_nothing(ev):
    """The held-out series starts at the acknowledgement and, armed there
    (D4-15), raises nothing."""
    ho = load("events-heldout.json")
    for e in ho["events"]:
        e["t"] = seconds(e["received_utc"])
    ack = seconds(ev["period"]["baseline_ack"])
    start = min(e["t"] for e in ho["events"])
    assert ack <= start < ack + 3600
    assert ho["seed"] != ev["seed"] and max(e["t"] for e in ho["events"]) - ack >= (g.OBS_DAYS - 1) * g.DAY
    assert _alarms(ev, ho["events"], ack, max(e["t"] for e in ho["events"]) + 1) == []


def test_absence_is_armed_at_the_acknowledgement(ev):
    """D4-15: a periodic type that goes silent while the baseline waits for
    the acknowledgement and never returns alarms once, at exactly ack +
    interval + tolerance. The arming B6 read before (from the last
    occurrence only, nothing whose deadline fell before ack) raises
    nothing for it: the hole the ruling closes."""
    end, ack = seconds(ev["period"]["end"]), seconds(ev["period"]["baseline_ack"])
    test_end = seconds(ev["period"]["test_end"])
    hb = g.tkey("gt-inj-syslog", g.PERIODIC)
    base = g.baseline([e for e in ev["events"] if e["t"] < end])
    b = base[("gt-inj-syslog", hb)]
    limit = b["interval"] + g.ceil_div(b["interval"] * g.PARAMS["absence_tolerance_pct"], 100)
    # Not vacuous: the last heartbeat's own deadline passed before ack, so
    # only the arming at ack can raise the alarm.
    assert b["last"] + limit < ack
    silent = [e for e in ev["events"] if e["t"] >= ack and g.key_of(e) != hb]
    got = [a for a in g.evaluate(base, silent, ack, test_end) if a["rule"] == "absence"]
    assert [(a["asset"], tuple(a["type"]), a["at"]) for a in got] == [("gt-inj-syslog", hb, ack + limit)]
    old = [a for a in g.evaluate(base, silent, ack, test_end, reanchor=False) if a["rule"] == "absence"]
    assert old == []


def test_events_syslog_key_is_the_template(ev):
    """D4-4 item 4: no two Syslog type definitions share a key, a new type
    reuses a known msgid with a new text, and the controls (a known text
    under another msgid) raise nothing."""
    keys = [g.tkey("gt-inj-syslog", k) for k in list(g.SYSLOG_TYPES) + [g.PERIODIC] + g.NEW_TYPES["gt-inj-syslog"]]
    assert len(set(keys)) == len(keys)
    known_ids = {k[2] for k in g.SYSLOG_TYPES}
    news = [d for d in ev["departures"] if d["kind"] == "new" and d["asset"] == "gt-inj-syslog"]
    by_id = {e["id"]: e for e in ev["events"]}
    assert any(by_id[d["events"][0]]["msgid"] in known_ids for d in news)
    (ctl,) = [c for c in ev["controls"] if "msgid" in c["what"]]
    assert len(ctl["events"]) == 3 and all(by_id[i]["msgid"] not in known_ids for i in ctl["events"])
    assert not any(set(a["events"]) & set(ctl["events"]) for a in ev["expected_alarms"])


def test_events_expected_alarms_are_hold_free(ev):
    """C10's alarm bounds change nothing here: no two expected alarms of one
    (asset, rule, type) fall within alarm_hold_s, and no asset has more
    than max_alarms_per_hold in any alarm_hold_s, so a product that holds
    alarms as C10 says must raise every expected alarm."""
    hold, most = g.PARAMS["alarm_hold_s"], g.PARAMS["max_alarms_per_hold"]
    at = lambda a: seconds(a["at"])
    by = collections.defaultdict(list)
    for a in ev["expected_alarms"]:
        by[(a["asset"], a["rule"], json.dumps(a["type"]))].append(at(a))
    for k, ts in by.items():
        ts.sort()
        assert all(b - a >= hold for a, b in zip(ts, ts[1:])), k
    for asset in {a["asset"] for a in ev["expected_alarms"]}:
        ts = sorted(at(a) for a in ev["expected_alarms"] if a["asset"] == asset)
        assert all(sum(1 for u in ts if t <= u < t + hold) <= most for t in ts), asset


def test_events_rate_alarms_list_up_to_the_break(ev):
    """C10: a rate alarm lists the bucket's events up to and including the
    one that passed the bound, so bound + 1 of them, the last at the
    alarm's time."""
    base = g.baseline([e for e in ev["events"] if e["t"] < seconds(ev["period"]["end"])])
    by_id = {e["id"]: e for e in ev["events"]}
    for a in ev["expected_alarms"]:
        if a["rule"] != "rate":
            continue
        b = base[(a["asset"], tuple(a["type"]))]
        bound = max(-(-g.PARAMS["rate_factor_pct"] * b["most_per_bucket"] // 100), g.PARAMS["rate_min"])
        assert len(a["events"]) == bound + 1, a
        assert by_id[a["events"][-1]]["t"] == seconds(a["at"]), a


def test_events_catch_up_rows_are_type_only(ev):
    """D4-4 item 2 as D4-9 amends it: SER rows aligned first-read or
    gap-before count toward the new-type rule only. The first read is the
    SER stream's earliest, in the observation period; the gap-before read
    is after the acknowledgement; neither raises anything, and the new type
    read in the gap-before backlog still alarms."""
    al = collections.Counter(e.get("alignment") for e in ev["events"])
    assert set(al) == {None, *g.CATCH_UP}, al
    assert all(e["asset"] == "gt-inj-ser" for e in ev["events"] if e.get("alignment"))
    ser = [e for e in ev["events"] if e["asset"] == "gt-inj-ser"]
    t0 = min(e["t"] for e in ser)
    first = [e for e in ser if e.get("alignment") == "first-read"]
    assert {e["t"] for e in first} == {t0} and [e for e in ser if e["t"] == t0] == first
    assert t0 == seconds(ev["period"]["first_event"]["gt-inj-ser"]) < seconds(ev["period"]["end"])
    ack = seconds(ev["period"]["baseline_ack"])
    gap = [e for e in ser if e.get("alignment") == "gap-before"]
    assert len({e["t"] for e in gap}) == 1 and gap[0]["t"] > ack
    by_id = {e["id"]: e for e in ev["events"]}
    for c in ev["controls"]:
        if "alignment" in c:
            assert c["events"] and all(by_id[i].get("alignment") == c["alignment"] for i in c["events"]), c["what"]
        assert c["expect_rules"] == [] and not any(set(a["events"]) & set(c["events"]) for a in ev["expected_alarms"])
    (cu,) = [d for d in ev["departures"] if d.get("catch_up")]
    assert cu["catch_up"] == "gap-before" and cu["kind"] == "new" and cu["expect_rules"] == ["new"]
    assert by_id[cu["events"][0]]["t"] == gap[0]["t"]
    assert any(a["rule"] == "new" and a["events"] == cu["events"] for a in ev["expected_alarms"])


def test_events_catch_up_is_not_vacuous(ev):
    """Taken as full, the first-read backlog would hide a repeats or rate
    departure on gt-inj-ser, and the gap-before backlog would raise
    repeats, rate and time: so a product that ignores the alignment fails
    these schedules."""
    end, ack, test_end = (seconds(ev["period"][k]) for k in ("end", "baseline_ack", "test_end"))
    lost, extra = g.catch_up_counterfactual(ev["events"], end, ack, test_end, ev["departures"])
    assert {d["kind"] for d in lost} & {"repeats", "rate"} and all(d["asset"] == "gt-inj-ser" for d in lost), lost
    (gap,) = [c for c in ev["controls"] if c.get("alignment") == "gap-before"]
    assert {a["rule"] for a in extra if set(a["events"]) & set(gap["events"])} == {"repeats", "rate", "time"}, extra
