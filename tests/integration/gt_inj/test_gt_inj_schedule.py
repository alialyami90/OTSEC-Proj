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
        change, r1 = cfg["timeline"]["change"], cfg["timeline"]["R1"]
        in_window = a["window"][0] <= change <= a["window"][1]
        prior = a["recorded"] < r1
        valid = a["device"] == "self" and in_window and prior and a["approver"]
        # The case's own definition, from the times: only "approved" is a
        # valid prior approval; "backdated" claims a time before the change
        # but was recorded after R1.
        assert valid == (c["case"] == "approved"), c["id"]
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
    p = g.PARAMS["observation"]
    end = seconds(ev["period"]["end"])
    for asset, first in ev["period"]["first_event"].items():
        n = sum(1 for e in ev["events"] if e["asset"] == asset and seconds(first) <= e["t"] < seconds(first) + p["min_days"] * g.DAY)
        assert n >= p["min_events"], asset
        assert seconds(first) + p["min_days"] * g.DAY <= end
    assert seconds(ev["period"]["baseline_ack"]) > end


def test_events_three_departures_of_each_kind(ev):
    after = [d for d in ev["departures"] if not d.get("before_ack")]
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
    ho = load("events-heldout.json")
    for e in ho["events"]:
        e["t"] = seconds(e["received_utc"])
    start = min(e["t"] for e in ho["events"])
    assert start > seconds(ev["period"]["baseline_ack"])
    assert ho["seed"] != ev["seed"] and len({e["t"] // g.DAY for e in ho["events"]}) >= g.PARAMS["observation"]["min_days"]
    assert _alarms(ev, ho["events"], start - start % g.DAY, max(e["t"] for e in ho["events"]) + 1) == []
