import unittest

from align import align


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
        self.assertEqual(align(["x", "x"], ["x", "x", "y"]), ("ambiguous", ["y"]))

    def test_wrapped_past_previous_read(self):
        self.assertEqual(align(["a", "b"], ["c", "d"]), ("gap", ["c", "d"]))

    def test_cleared_then_new_rows(self):
        self.assertEqual(align(["a", "b"], ["z"]), ("gap", ["z"]))

    def test_cleared_and_empty(self):
        self.assertEqual(align(["a", "b"], []), ("gap", []))

    def test_row_removed_from_middle(self):
        self.assertEqual(align(["a", "b", "c"], ["a", "c", "d"]), ("gap", ["a", "c", "d"]))


if __name__ == "__main__":
    unittest.main()
