"""Self-tests of V-M4's alarm oracle (alarms.py), not tests of the product.
The alarms here are built from events.json's own expected_alarms in the
form the node writes them (contracts/baseline Alarm.Health), and then
changed one way at a time, so each check is shown able to fail. Nothing
here is node output."""
import copy
import hashlib
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import alarms as oracle  # noqa: E402

NODE = "site-a-node1"
ASSETS = {"5e3a1c2d-9b8f-4e7a-8c6d-1f2e3d4c5b6a": "gt-inj-ser", "7c4b2d3e-ac9a-4f8b-9d7e-2a3f4e5d6c7b": "gt-inj-syslog"}
BY_NAME = {v: k for k, v in ASSETS.items()}


@pytest.fixture(scope="module")
def series():
    with open(os.path.join(HERE, "events.json"), encoding="utf-8") as f:
        return json.load(f)


def eid(series_id):
    seq = int(series_id.rsplit("-", 1)[1])
    return {"node_id": NODE, "stream": "gtinj/sent", "seq": seq}


def ids_of(series):
    return {oracle._id(eid(e["id"])): e["id"] for e in series["events"]}


def health(rule, asset, typ, at, events):
    if len(typ) == 2:
        key, text = f"ser|{typ[0]}|{typ[1]}", f"{typ[0]} {typ[1]}"
    else:
        key, text = f"syslog|{typ[0]}|{typ[1]}|template|sha256:{hashlib.sha256(typ[2].encode()).hexdigest()}", typ[2]
    return {"type": oracle.DEPARTURE, "related": [eid(e) for e in events],
            "details": {"rule": rule, "asset_id": BY_NAME[asset], "key": key, "key_text": text, "at_utc": at}}


def expected(series):
    return [health(x["rule"], x["asset"], x["type"], x["at"], x["events"]) for x in series["expected_alarms"]]


def test_the_expected_alarms_pass(series):
    failures, report = oracle.check(series, expected(series), ids_of(series), ASSETS)
    assert failures == []
    assert report["precision"] == "16/16"
    assert report["recall"] == {"absence": "3/3", "new": "4/4", "rate": "3/3", "repeats": "3/3", "time": "3/3"}


def test_the_syslog_half_checks_only_its_asset(series):
    syslog = {k: v for k, v in ASSETS.items() if v == "gt-inj-syslog"}
    mine = [h for h in expected(series) if h["details"]["asset_id"] in syslog]
    failures, report = oracle.check(series, mine, ids_of(series), syslog)
    assert failures == []
    assert report["alarms"] == sum(1 for x in series["expected_alarms"] if x["asset"] == "gt-inj-syslog")
    # The SER alarms are not the Syslog half's, so a run of that half that
    # raised them would be wrong.
    failures, _ = oracle.check(series, expected(series), ids_of(series), syslog)
    assert failures and all("not a departure of a GT-INJ asset in the run" in f for f in failures)


def test_a_missing_alarm_fails(series):
    hs = expected(series)
    gone = hs.pop(1)
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any(f.startswith("missing repeats") for f in failures), failures
    assert any("dep-03" in f and "no alarm of its kind" in f for f in failures), failures
    assert gone["details"]["rule"] == "repeats"


def test_an_alarm_before_the_acknowledgement_fails(series):
    dep = next(d for d in series["departures"] if d.get("before_ack"))
    hs = expected(series) + [health(dep["kind"], dep["asset"], dep["type"], dep["at"], dep["events"])]
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("before the acknowledgement" in f for f in failures), failures
    assert any(f.startswith("unexpected new gt-inj-ser") for f in failures), failures


def test_an_alarm_citing_a_control_fails(series):
    hs = expected(series)
    hs[0]["related"].append(eid(series["controls"][0]["events"][0]))
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("cites control events" in f for f in failures), failures


def test_a_key_that_is_not_its_text_fails(series):
    hs = expected(series)
    hs[0]["details"]["key_text"] += " (changed)"
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("is not the template of its text" in f for f in failures), failures


def test_an_absence_outside_its_gap_fails(series):
    hs = expected(series)
    n = next(i for i, x in enumerate(series["expected_alarms"]) if x["rule"] == "absence")
    hs[n]["details"]["at_utc"] = series["expected_alarms"][n]["at"].replace("T15:", "T14:")
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any(f.startswith("missing absence") for f in failures), failures
    assert any("dep-06" in f and "no alarm of its kind" in f for f in failures), failures


def test_an_event_not_sent_fails(series):
    hs = expected(series)
    hs[0]["related"].append({"node_id": NODE, "stream": "gtinj/sent", "seq": 999999})
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("which the harness did not send" in f for f in failures), failures


def test_another_health_type_fails(series):
    hs = expected(series)
    hs[0] = copy.deepcopy(hs[0])
    hs[0]["type"] = "eventbaseline.active"
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("not a departure" in f for f in failures), failures
    assert any(f.startswith("missing new gt-inj-syslog") for f in failures), failures


# C6 on #403: an assets map that names no asset of the series wants
# nothing, so it would pass a node that raised nothing.
@pytest.mark.parametrize("assets", [{}, {"7c4b2d3e-ac9a-4f8b-9d7e-2a3f4e5d6c7b": "gt-inj-syslg"},
                                    {"a": "gt-inj-syslog", "b": "gt-inj-syslog"}])
def test_a_wrong_assets_map_fails(series, assets):
    failures, _ = oracle.check(series, [], ids_of(series), assets)
    assert failures and "must name each of the series' assets" in failures[0], failures


def test_a_duplicate_alarm_fails(series):
    hs = expected(series)
    hs.append(copy.deepcopy(hs[0]))
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert failures == [f for f in failures if f.startswith("unexpected new gt-inj-syslog")] and len(failures) == 1, failures


def test_an_alarm_citing_another_event_fails(series):
    hs = expected(series)
    n = next(i for i, x in enumerate(series["expected_alarms"]) if x["rule"] == "new" and x["asset"] == "gt-inj-syslog")
    own = series["expected_alarms"][n]["events"][0]
    other = next(e["id"] for e in series["events"] if e["asset"] == "gt-inj-syslog" and e["id"] != own)
    hs[n]["related"] = [eid(other)]
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any(f.startswith("missing new gt-inj-syslog") for f in failures), failures
    assert any(f.startswith("unexpected new gt-inj-syslog") for f in failures), failures
    assert any("dep-02" in f and "no alarm of its kind" in f for f in failures), failures


def test_an_alarm_of_another_rule_fails(series):
    hs = expected(series)
    n = next(i for i, x in enumerate(series["expected_alarms"]) if x["rule"] == "repeats")
    hs[n]["details"]["rule"] = "rate"
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any(f.startswith("missing repeats") for f in failures), failures
    assert any("dep-03" in f and "no alarm of its kind" in f for f in failures), failures


def test_a_ser_key_that_is_not_its_text_fails(series):
    hs = expected(series)
    n = next(i for i, x in enumerate(series["expected_alarms"]) if x["asset"] == "gt-inj-ser")
    hs[n]["details"]["key_text"] = "TRIP Deasserted"
    failures, _ = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("is not the type of its text" in f for f in failures), failures


@pytest.mark.parametrize("change", [lambda d: d.pop("at_utc"), lambda d: d.update(key=d["key"].replace("syslog|4|", "syslog|x|", 1))])
def test_a_malformed_alarm_is_reported(series, change):
    hs = expected(series)
    change(hs[0]["details"])
    failures, report = oracle.check(series, hs, ids_of(series), ASSETS)
    assert any("malformed" in f for f in failures), failures
    assert report["alarms"] == len(hs) - 1
