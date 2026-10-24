# Slice suite (A6, P2-A6)

The end-to-end test of the Phase 2 slice: the recording simulator as a
SEL-751, then the collector, the node store, the forwarder, and an upstream
RELP collector. Each runs as a separate process (D2-3). Evidence class:
`simulated`. Nothing here is hardware evidence (risk 3).

| File | What it is |
| --- | --- |
| `harness.py` | Starts processes that print a JSON `ready` line with their port (`--port 0`). Makes throwaway TLS material with the `openssl` command line. |
| `relp_receiver.py` | The upstream collector for the Windows leg, where rsyslog does not run. RELP over TLS with client certificates. It acknowledges a frame only after fsyncing it, and can drop, reject or `serverclose` the Nth frame (V-S6). Standard library only, and no code shared with the forwarder. |
| `relp_client.py` | A minimal RELP sender used only to test the receiver itself. |
| `test_relp_receiver.py` | The receiver does what the forwarder tests rely on: offers, durable acknowledgement, a pipelined window, `close`, the frame grammar, fault injection at exactly the Nth frame, and mutual TLS. |
| `conftest.py` | `need()`: a check that cannot run skips, or fails when `OTSEC_SLICE_REQUIRED=1`. |

The tests that drive the product binaries join as each component merges.

## Requirements

- Python 3.12 or later, with `pytest` and `asyncssh==2.24.1` (the simulator's SSH transport).
- `openssl` on `PATH` for the TLS tests. Git for Windows ships one.
- Go, to build the binaries, once they exist.
- The Linux leg also needs `rsyslog` with `imrelp` and TLS support (`rsyslog`, `rsyslog-relp`, and `rsyslog-openssl` or `rsyslog-gnutls`).

## Run

```
python -m pytest -q tests/integration/slice
OTSEC_SLICE_REQUIRED=1 python -m pytest -q tests/integration/slice   # integration job and exit-gate runs
```
