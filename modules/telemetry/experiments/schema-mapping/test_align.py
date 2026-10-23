import unittest

import os

from align import align, align_full
from sel_ser import alignment_key, parse_report

FIG = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "documented", "sel751-fig10.16.txt"), "rb").read()


def keys(raw):
    return [alignment_key(i) for i in parse_report(raw, "MDY")[1]]


def renumber(raw, extra_rows):
    """Append rows to the figure and renumber so row 1 is the newest, as the
    SEL-751 does (Table 7.63). Test input made from the manual figure, not
    device output; the column layout after renumbering is assumed."""
    head, rest = raw.split(b"STATE\n", 1)
    body, tail = rest.split(b"=>", 1)
    rows = [l.split(None, 1)[1] for l in body.split(b"\n") if l.strip()] + extra_rows
    n = len(rows)
    lines = [str(n - i).encode().ljust(6) + r for i, r in enumerate(rows)]
    return head + b"STATE\n" + b"\n".join(lines) + b"\n=>" + tail


class AlignTest(unittest.TestCase):
    def test_first_read(self):
        self.assertEqual(align(None, ["a", "b"]), ("first-read", ["a", "b"]))

    def test_no_change(self):
        self.assertEqual(align(["a", "b"], ["a", "b"]), ("ok", []))

    def test_append(self):
        self.assertEqual(align(["a", "b"], ["a", "b", "c"]), ("ok", ["c"]))

    def test_append_with_front_drop(self):
        self.assertEqual(align(["a", "b", "c"], ["b", "c", "d", "e"]), ("ok", ["d", "e"]))

    def test_identical_rows_kept_separate(self):
        # Two genuine identical rows arrive; a per-row key would merge them
        # with the one already seen. The "a" row anchors the alignment.
        self.assertEqual(align(["a", "x"], ["a", "x", "x", "x"]), ("ok", ["x", "x"]))

    def test_identical_rows_without_anchor_are_flagged(self):
        # Overlap of 2 or of 1 both fit: either [y] or [x, y] is new.
        # Overlap of 1 is used so the possibly-new "x" is kept, and flagged.
        self.assertEqual(align_full(["x", "x"], ["x", "x", "y"]), ("ambiguous", ["x", "y"], 1))

    def test_wrapped_past_previous_read(self):
        self.assertEqual(align(["a", "b"], ["c", "d"]), ("gap", ["c", "d"]))

    def test_cleared_then_new_rows(self):
        self.assertEqual(align(["a", "b"], ["z"]), ("gap", ["z"]))

    def test_cleared_and_empty(self):
        self.assertEqual(align(["a", "b"], []), ("gap", []))

    def test_row_removed_from_middle(self):
        self.assertEqual(align(["a", "b", "c"], ["a", "c", "d"]), ("gap", ["a", "c", "d"]))

    def test_sel_renumbering_is_not_a_gap(self):
        new_row = b"02/28/2007   13:55:01.000   IN101                    Asserted"
        status, added = align(keys(FIG), keys(renumber(FIG, [new_row])))
        self.assertEqual((status, len(added)), ("ok", 1))

    def test_sel_row_number_gains_a_digit(self):
        rows = [b"02/28/2007   13:55:%02d.000   IN10%d                    Asserted" % (k, k) for k in range(1, 4)]
        prev = keys(renumber(FIG, rows[:1]))
        new = keys(renumber(FIG, rows))
        self.assertEqual(len(new), 11)
        self.assertEqual(align(prev, new), ("ok", new[-2:]))

    def test_sel_cleared_is_a_gap(self):
        self.assertEqual(align(keys(FIG), [])[0], "gap")


if __name__ == "__main__":
    unittest.main()
