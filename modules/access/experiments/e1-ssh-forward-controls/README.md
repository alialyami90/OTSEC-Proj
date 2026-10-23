# E1: what a stock SSH gateway can and cannot enforce

Owner: A3. Phase 0 throwaway experiment. Not product code and not a language choice. Evidence class: `simulated` (loopback mocks, no real IED, no real network).

## Question

For engineering access (R2) and attack path AP-6 in `docs/threat-model.md`: can a stock OpenSSH gateway pin a user's session to one device and port, block shells and reverse tunnels, and revoke a live session? And does destination pinning constrain what *operations* reach the device?

## Setup

`run.sh` (needs root) creates a throwaway local user with a real `/bin/bash` login shell, a key restricted with `restrict,port-forwarding,permitopen="127.0.0.2:9100",command="/bin/false"`, and an `sshd` on `127.0.0.1:22022` with forwarding limited to local, no listen, no agent, no X11, no tunnel, no TTY. `mock_ied.py` runs three line-oriented listeners (approved device, another device, another port on the approved device) and logs every connection and line it receives. `probe.py` sends one line and reports the reply. Everything is removed on exit.

## Run

```
sudo bash run.sh
```

Exit status 0 when all checks match expectations. Recorded output: `results-2026-10-23.txt` (OpenSSH 9.6p1, Ubuntu 24.04 container).

## Checks

| ID | Expectation |
| --- | --- |
| T0 | Precondition: the key authenticates. Without it, T2–T5 could "pass" because of an authentication failure; an early run did exactly that. |
| T1 | Approved device:port reachable through a local forward. |
| T2 | Another device is refused, and that device logs zero connections. |
| T3 | Another port on the approved device is refused, zero connections. |
| T4 | Remote command refused after successful authentication. The test account has a real `/bin/bash` login shell, so the refusal comes from the key's forced `command="/bin/false"`, not from a `nologin` shell. (The first version used `nologin`, which masked the key restriction; A1 flagged this in review.) |
| T4b | Interactive shell with a forced TTY (`ssh -tt`) refused: PTY allocation denied and no shell output. |
| T5 | Reverse forward refused; nothing listens on the gateway. |
| T6 | Limitation check: a `WRITE` line passes through the approved tunnel and reaches the device. Destination pinning does not constrain operations. |
| T7 | Limitation check: the device sees only the gateway's address, so per-user attribution exists only in gateway audit. |
| T8 | Termination: killing the per-session `sshd` processes closes a held application connection. Latency recorded. |
| T9 | Limitation check (A6 probe): after T8, the same key immediately re-establishes access. Killing sessions is termination, not revocation. |
| T9r | Revocation: remove the key from the authorized keys, then kill sessions; re-authentication is denied. The decisive evidence is the `Permission denied (publickey)` on reconnect (the "held tunnel" probe only shows the local listener is gone). |
| T10 | `ssh -W` stdio forward to an unapproved device refused; 0 connections at the device (A6 probe). |
| T11 | sftp subsystem refused (A6 probe). |

## Limits

Loopback only; mock devices are not IED simulators; no Telnet, FTP, or serial; revocation done by killing processes by name (a product would track session PIDs); OpenSSH has no session lifetime, so expiry must be an external timer using the same kill path. On OpenSSH 9.8 and later the per-session process may appear as `sshd-session`, so the `pkill` pattern in T8 would need updating.
