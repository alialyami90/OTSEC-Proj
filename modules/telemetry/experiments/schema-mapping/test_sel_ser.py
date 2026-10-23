"""Tests for sel_ser.py. Inputs other than the manual figure are made here by
editing that figure's bytes. They are test inputs, not device output, and
the layouts they assume (YMD rows, relay-message rows) are unconfirmed."""
import os
import unittest

from sel_ser import parse_report

HERE = os.path.dirname(os.path.abspath(__file__))
FIG = open(os.path.join(HERE, "documented", "sel751-fig10.16.txt"), "rb").read()


def types(items):
    return [i["type"] for i in items]


class SelSerTest(unittest.TestCase):
    def test_manual_figure_mdy(self):
        _, items = parse_report(FIG, "MDY")
        self.assertEqual(types(items), ["row"] * 8)
        self.assertEqual(items[0]["fields"]["wall_clock"], "2007-02-28T13:54:09.602")
        self.assertEqual(items[-1]["fields"]["STATE"], "Deasserted")

    def test_wrong_date_f_is_errors_not_silence(self):
        _, items = parse_report(FIG, "YMD")
        self.assertEqual(types(items), ["parse-error"] * 8)

    def test_ymd_rows_parse_under_ymd(self):
        raw = FIG.replace(b"02/28/2007", b"2007/02/28")
        _, items = parse_report(raw, "YMD")
        self.assertEqual(types(items), ["row"] * 8)
        self.assertEqual(items[0]["fields"]["wall_clock"], "2007-02-28T13:54:09.602")

    def test_ymd_rows_under_mdy_are_errors(self):
        raw = FIG.replace(b"02/28/2007", b"2007/02/28")
        _, items = parse_report(raw, "MDY")
        self.assertEqual(types(items), ["parse-error"] * 8)

    def test_dmy_is_not_mdy(self):
        _, items = parse_report(FIG.replace(b"02/28/2007", b"28/02/2007"), "DMY")
        self.assertEqual(items[0]["fields"]["wall_clock"], "2007-02-28T13:54:09.602")

    def test_unpadded_date(self):
        _, items = parse_report(FIG.replace(b"02/28/2007", b"2/28/2007"), "MDY")
        self.assertEqual(items[0]["fields"]["wall_clock"], "2007-02-28T13:54:09.602")

    def test_unknown_line_is_an_error(self):
        raw = FIG.replace(b"1     02/28/2007", b"garbage line\n1     02/28/2007")
        _, items = parse_report(raw, "MDY")
        self.assertEqual(types(items), ["row"] * 7 + ["parse-error", "row"])

    def test_relay_messages_not_split(self):
        raw = FIG.replace(b"51P1T                    Deasserted", b"Relay Powered Up").replace(
            b"TRIP                     Deasserted", b"Relay  Settings Changed")
        _, items = parse_report(raw, "MDY")
        msgs = [i for i in items if i["type"] == "relay-message"]
        self.assertEqual([m["fields"]["MESSAGE"] for m in msgs], ["Relay Powered Up", "Relay Settings Changed"])
        self.assertTrue(all("layout-unconfirmed" in m["flags"] for m in msgs))

    def test_no_label_line(self):
        _, items = parse_report(FIG.replace(b"ELEMENT", b"ELEMNT"), "MDY")
        self.assertEqual(types(items), ["parse-error"])

    def test_stops_at_prompt(self):
        _, items = parse_report(FIG + b"8     02/28/2007   13:54:09.602   X  Y\n", "MDY")
        self.assertEqual(len(items), 8)

    def test_date_f_required(self):
        with self.assertRaises(ValueError):
            parse_report(FIG, None)

    def test_crlf(self):
        _, items = parse_report(FIG.replace(b"\n", b"\r\n"), "MDY")
        self.assertEqual(types(items), ["row"] * 8)


if __name__ == "__main__":
    unittest.main()
