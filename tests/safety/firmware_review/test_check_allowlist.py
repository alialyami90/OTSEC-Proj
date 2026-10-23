"""Self-test of check_allowlist.py: the class check passes only when every
allowed branch that relies on inheritance carries "inferred (owner-accepted)".

Needs the SEL-751 IM text (pdftotext output) and an allowlist:
  OTSEC_SEL751_TEXT=<751_IM text> OTSEC_ALLOWLIST=<allowlist.json> \\
    python -m unittest tests/safety/firmware_review/test_check_allowlist.py
Skipped when either is unset.
"""

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import check_allowlist  # noqa: E402

TEXT, ALLOW = os.environ.get("OTSEC_SEL751_TEXT"), os.environ.get("OTSEC_ALLOWLIST")


def run(allowlist):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(allowlist, f)
    try:
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = check_allowlist.main(TEXT, f.name)
        return status, json.loads(out.getvalue())
    finally:
        os.remove(f.name)


@unittest.skipUnless(TEXT and ALLOW, "OTSEC_SEL751_TEXT or OTSEC_ALLOWLIST not set")
class ClassCheck(unittest.TestCase):
    def setUp(self):
        with open(ALLOW) as f:
            self.base = json.load(f)

    def test_plain_inferred_fails(self):
        a = json.loads(json.dumps(self.base).replace(check_allowlist.OWNER_ACCEPTED, "inferred"))
        self.assertEqual(run(a)[0], 1)

    def test_owner_accepted_class_passes(self):
        a = json.loads(json.dumps(self.base))
        for b in a["branches"]:
            if b["status"].startswith("allow"):
                b["evidence_class"] = check_allowlist.OWNER_ACCEPTED
        status, report = run(a)
        self.assertEqual(status, 0, report)

    def test_dropping_a_listed_fix_is_caught(self):
        a = json.loads(json.dumps(self.base))
        a["fixes"]["F2"]["listed_on"] = a["fixes"]["F2"]["listed_on"][:1]
        for b in a["branches"]:
            b["evidence_class"] = check_allowlist.OWNER_ACCEPTED
        self.assertEqual(run(a)[0], 1)
