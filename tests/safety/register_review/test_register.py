"""Review a command register against A6's independent corpora.

Guards against the register being too permissive, the one failure every
read-only layer that consumes the register would share (L2-L4 and the
recording-simulator checker). Pass: every deny-corpus line classifies as
anything other than read-only; every allow-corpus line classifies read-only.

Run from the repository root, naming the register under review:
  OTSEC_REGISTER=path/to/register.json python -m unittest tests/safety/register_review/test_register.py
Skipped when OTSEC_REGISTER is unset.
"""

import codecs
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "recording_simulator"))

import check  # noqa: E402


def corpus(name):
    with open(os.path.join(HERE, name), encoding="ascii") as f:
        for raw in f:
            raw = raw.rstrip("\n")
            if raw.startswith("#") or not raw:
                continue
            yield codecs.decode(raw, "unicode_escape")


@unittest.skipUnless(os.environ.get("OTSEC_REGISTER"), "OTSEC_REGISTER not set")
class RegisterReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.register = check.load_register(os.environ["OTSEC_REGISTER"])

    def test_deny_corpus_never_read_only(self):
        for line in corpus("sel-deny-corpus.txt"):
            with self.subTest(line=line):
                verdict, _ = check.classify(line, self.register)
                self.assertNotEqual(verdict, "read-only")

    def test_allow_corpus_read_only(self):
        for line in corpus("allow-corpus.txt"):
            with self.subTest(line=line):
                verdict, _ = check.classify(line, self.register)
                self.assertEqual(verdict, "read-only")


if __name__ == "__main__":
    unittest.main()
