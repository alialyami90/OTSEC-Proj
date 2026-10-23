# Safety tests

Owner: A6. Independent OT safety verification. Nothing here may target production equipment; lab hardware tests (H-xx in [docs/verification.md](../../docs/verification.md)) need explicit authorization and a dated log.

## Contents

- [recording_simulator/](recording_simulator/): SSH or raw TCP/Telnet endpoint that records every byte a collector sends (in-band passwords recorded as auth events, never stored), and `check.py`, which classifies each received line against a command register and flags non-printable bytes and lines sent before the prompt. Oracle for V-S5, V-S7 (b), V-S10, V-S13, V-S14. Class `simulated`.
- [register_review/](register_review/): A6's independent deny and allow corpora. Run against any command register with `OTSEC_REGISTER=<register.json> python3 -m unittest tests/safety/register_review/test_register.py`. A register change that makes any deny-corpus line read-only fails. Standard library only.

Run the self-test (Python 3.9+, test-only dependency pinned in `recording_simulator/requirements.txt`):

```
python3 -m venv .venv && .venv/bin/pip install -r tests/safety/recording_simulator/requirements.txt
.venv/bin/python -m unittest -v tests/safety/recording_simulator/test_selftest.py
```

The tooling language is provisional until the toolchain ADR (blocker B-06).
