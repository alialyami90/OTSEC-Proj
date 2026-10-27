# GT-INJ schedules (B6)

These are labelled injection schedules for V-M2 (configuration changes, R3.6) and V-M4 (event-behaviour departures, R4.8), as `docs/verification.md` defines GT-INJ. They are written from fixed seeds by `generate.py` and committed **before** any product test runs against them.

**Everything here is synthetic. The schedules support `simulated` claims only.** Nothing comes from a device.

| File | What it holds |
| --- | --- |
| `config.json` | V-M2's seven cases, with three changes of each. Each change is on its own asset and its own simulator. It lists the setting changed (a Figure 7.43 group setting, injected with the simulator's `--profile-settings`), the approval the change gets (device, window, when it is recorded in the audit chain, the time its text claims, and whether the principal is an approver), and the outcome the change must have. |
| `events.json` | Two assets, `gt-inj-ser` (SER element and state) and `gt-inj-syslog` (facility, severity and msgid), observed for 14 days. Then come the acknowledgement and a 7-day test period with three injected departures of each R4.8 kind: new type, repeats, rate, time and absence. One more new type comes before the acknowledgement and must raise nothing. Each departure lists its events, and the file lists the alarms B6's reading of the rules expects. |
| `events-heldout.json` | 14 benign days from the same generator with another seed. They are replayed after the acknowledgement in place of the test period, and must raise no departure alarm. |
| `generate.py` | Writes the three files. Its docstring states the parameters (`PARAMS`) and each reading B6 took where the verification text leaves a choice. |
| `test_gt_inj_schedule.py` | Checks the schedules themselves, not the product. Each case appears three times with the expectation its definition gives. Each change is a real Figure 7.43 setting in the same printed form, and the simulator prints exactly that change. The expected alarms follow from the committed events. Every alarm is an injected departure. The departure before the acknowledgement would have alarmed. The held-out series raises nothing. |

## How the benign series is kept within the baseline

Non-periodic events fall only on the slots `:05` and `:35` (plus 0 to 20 s), at most once per slot. Each type occurs only in its own hours, all between 01:00 and 22:59. The observation period holds a peak day for every type, on which every slot of every one of its hours is filled. So no benign event can be denser than the baseline saw, by construction and for any seed, as long as the rule parameters satisfy all of these:
- a repeats window under 30 minutes;
- a rate factor of at least 1;
- an absence tolerance above the heartbeat's 30 s jitter.

The heartbeat is the only periodic type. It falls at `:00:00` plus 0 to 30 s.

## Readings B6 took

Each of these is open for B1 to confirm.

- **Rule 3 (rate):** the bound is the factor times the most the baseline saw in any one clock-hour bucket. It is not a bound per hour of day, because the hour of day is rule 4's.
- **V-M2 non-approver:** a refused approval approves nothing, so the change alarms. V-M2's "alarm exactly for" list does not name this case.
- **Repeats and rate injections:** they replace that type's benign events in that hour, so that each injection breaks only its own rule.

## When the parameters change

The parameters are proposed until C10 and the P4-A4 brief fix them. When that happens, set `PARAMS` and run `python3 -I tests/integration/gt_inj/generate.py`, then commit the new files before any product test has run against them. A regenerated schedule after a product test has run is a new GT-INJ series, and it is recorded as such.
