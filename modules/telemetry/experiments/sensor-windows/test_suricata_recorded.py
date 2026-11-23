"""suricata_recorded.py (P4-SENSOR-EVAL-GREEN, acceptance test 1): the
recorded result against itself passes, and each control fails. Run:
python -m pytest -q modules/telemetry/experiments/sensor-windows/test_suricata_recorded.py"""
import copy
import json

import pytest

import suricata_recorded as sr


def raw():
    """A suricata.json as suricata.ps1 writes it, rebuilt from the recorded result."""
    with open(sr.RECORDED, encoding="utf-8") as f:
        r = copy.deepcopy(json.load(f)["result"])
    r["msiexec_npcap_lines"] = [("MSI (s) (60:2C) [23:05:14:147]: " + l) if i < 3 else l
                                for i, l in enumerate(r["msiexec_npcap_lines"])]
    r["imports"] = [{"dll": i["dll"], "resolves_to": ("C:\\Windows\\System32\\" + i["dll"]) if i["resolves"] else None}
                    for i in r["imports"]]
    return r


def run(tmp_path, data):
    p = tmp_path / "suricata.json"
    p.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return sr.check(str(p))


def test_recorded_against_itself(tmp_path):
    assert run(tmp_path, raw()) == []


def test_msi_process_id_and_time_are_left_out(tmp_path):
    r = raw()
    r["msiexec_npcap_lines"] = [l.replace("(60:2C) [23:05:14:147]", "(64:10) [23:04:36:387]") for l in r["msiexec_npcap_lines"]]
    assert run(tmp_path, r) == []


def test_import_path_is_left_out(tmp_path):
    r = raw()
    r["imports"][0]["resolves_to"] = "C:\\hostedtoolcache\\other\\" + r["imports"][0]["dll"]
    assert run(tmp_path, r) == []


@pytest.mark.parametrize("change, where", [
    (lambda r: r.update(starts=True), "suricata.json.starts"),
    (lambda r: r["start"].update(exit=1), "suricata.json.start.exit"),
    (lambda r: r.pop("npcap_at_end"), "suricata.json.npcap_at_end: missing"),
    (lambda r: [i.update(resolves_to="C:\\Windows\\System32\\wpcap.dll") for i in r["imports"] if i["dll"] == "wpcap.dll"],
     "suricata.json.imports["),
    (lambda r: r["msiexec_npcap_lines"].__setitem__(3, "Property(S): WIXUI_EXITDIALOGOPTIONALTEXT = other"),
     "suricata.json.msiexec_npcap_lines[3]"),
    # D6's N1 on #800: a capture added, an import added, an import removed
    (lambda r: r["captures"].update({"added.pcap": {"status": "ran"}}), "suricata.json.captures.added.pcap: added"),
    (lambda r: r["imports"].append({"dll": "extra.dll", "resolves_to": None}), "suricata.json.imports: "),
    (lambda r: r["imports"].pop(0), "suricata.json.imports: "),
])
def test_control_differs(tmp_path, change, where):
    r = raw()
    change(r)
    d = run(tmp_path, r)
    assert d and all(l.startswith(where) for l in d), d


def test_missing_file(tmp_path):
    assert "missing, empty or unreadable" in sr.check(str(tmp_path / "absent.json"))[0]


def test_empty_file(tmp_path):
    assert "missing, empty or unreadable" in run(tmp_path, "")[0]


def test_main_exit_codes(tmp_path, capsys):
    p = tmp_path / "suricata.json"
    p.write_text(json.dumps(raw()), encoding="utf-8")
    assert sr.main(["x", str(p)]) == 0
    assert "same as the recorded result" in capsys.readouterr().out
    p.write_text("", encoding="utf-8")
    assert sr.main(["x", str(p)]) == 1
    assert "DIFFERS:" in capsys.readouterr().out
