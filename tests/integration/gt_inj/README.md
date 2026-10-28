# GT-INJ schedules (B6)

These are labelled injection schedules for V-M2 (configuration changes, R3.6) and V-M4 (event-behaviour departures, R4.8), as `docs/verification.md` defines GT-INJ. They are written from fixed seeds by `generate.py` and committed **before** any product test runs against them.

**Everything here is synthetic. The schedules support `simulated` claims only.** Nothing comes from a device.

| File | What it holds |
| --- | --- |
| `config.json` | V-M2's seven cases, with three changes of each. Each change is on its own asset and its own simulator. It lists the setting changed (a Figure 7.43 group setting, injected with the simulator's `--profile-settings`), the approval the change gets (device, window, when it is recorded in the audit chain, the time its text claims, and whether the principal is an approver), and the outcome the change must have. |
| `events.json` | Two assets, `gt-inj-ser` (keyed on SER element and state) and `gt-inj-syslog` (keyed on facility, severity and the message text with each digit run made `#`; the msgid is not in the key, D4-4 item 4), observed for 14 days. Then come the acknowledgement and a 7-day test period with three injected departures of each R4.8 kind: new type, repeats, rate, time and absence. One more new type comes before the acknowledgement and must raise nothing. One Syslog new type reuses a known msgid with a new text, and three controls send a known text under another msgid, which must raise nothing. Two SER catch-up backlogs are controls too (see below). Each departure lists its events, and the file lists the alarms B6's reading of the rules expects. |
| `events-heldout.json` | 14 benign days from the same generator with another seed. They are replayed after the acknowledgement in place of the test period, and must raise no departure alarm. |
| `generate.py` | Writes the three files. Its docstring states the parameters (`PARAMS`) and each reading B6 took where the verification text leaves a choice. |
| `test_gt_inj_schedule.py` | Checks the schedules themselves, not the product. Each case appears three times with the expectation its definition gives. Each change is a real Figure 7.43 setting in the same printed form, and the simulator prints exactly that change. The expected alarms follow from the committed events. Every alarm is an injected departure. The departure before the acknowledgement would have alarmed. The held-out series raises nothing. Catch-up rows are type-only, and a product that ignored their alignment would fail. |

## How the benign series is kept within the baseline

Non-periodic events fall only on the slots `:05` and `:35` (plus 0 to 20 s), at most once per slot. Each type occurs only in its own hours, all between 01:00 and 22:59. The observation period holds a peak day for every type, on which every slot of every one of its hours is filled. So no benign event can be denser than the baseline saw, by construction and for any seed, as long as the rule parameters satisfy all of these:
- a repeats window under 30 minutes;
- a rate factor of at least 1;
- an absence tolerance above the heartbeat's 30 s jitter.

The heartbeat is the only periodic type. It falls at `:00:00` plus 0 to 30 s.

## Readings, as B1 ruled them (D4-9)

- **Rule 3 (rate):** one bound per type: `rate_factor_pct` of the most the baseline saw in any one clock-hour bucket, rounded up, never below `rate_min` (C10 `RateBound`). There is no bound per hour of day, because the hour of day is rule 4's. A rate alarm lists the bucket's events up to and including the one that passed the bound (C10).
- **Rule 5 (absence):** the tolerance is `absence_tolerance_pct` of the interval, rounded up (C10 `Tolerance`), and the spread test is in integers: `|gap - median| x 100 <= median x periodic_spread_pct`.
- **Repeats window (C10):** "within `repeats_window_s`" is the events of `(t - repeats_window_s, t]` in whole seconds, so two occurrences exactly `repeats_window_s` apart are in different windows (C10 `Params.RepeatsWindowS`).
- **Absence boundary (C10):** with deadline = last + interval + tolerance, an occurrence in `(last, deadline]` is in time, so one exactly at the deadline is in time; the alarm is raised at the deadline only when nothing came by then (C10 `Params.AbsenceTolerancePct`).
- **Alarm bounds (C10):** one alarm per (asset, rule, type) per `alarm_hold_s` and at most `max_alarms_per_hold` per asset per hold. No expected alarm meets either bound, so they do not change the expectations (`test_events_expected_alarms_are_hold_free`).
- **Catch-up (D4-4 item 2 as D4-9 amends it, C10 `Use`):** a SER row whose `alignment` is `first-read` or `gap-before` is type-only. It enters the type set and counts toward the new-type rule, and no other rule learns from it or fires on it. A row without `alignment` is aligned `ok`. The series has two backlogs:
  - The SER stream's first read, a minute before its first benign row, returns `repeats_n + 1` rows of every SER type at one received time. If learned in full, it would lift every type's most-per-window and most-per-bucket, and a repeats or rate departure on `gt-inj-ser` would raise nothing.
  - On the fourth test day at 23:40, one gap-before read returns 7 rows of a known type, at an hour no SER type was seen in. That is over its repeats and rate bounds. The same read returns one row of a new type (`81D1T`). Only the new type alarms, as departure `catch_up: gap-before`. Taken in full, the backlog would raise repeats, rate and time (`test_events_catch_up_is_not_vacuous`).
- **V-M2 non-approver:** an approval refused for any reason covers nothing, so the change alarms.
- **V-M2 window ended:** C8 0.5 covers a change when the approval's window overlaps the time between the last read that found the baseline (`Rm`) and the read that found the change (`R1`). The schedule therefore has a read `Rm` after the window ends and before the change.
- **Repeats and rate injections:** each replaces that type's benign events in that hour, so it breaks only its own rule.
- **Repeats alarm:** it lists the n + 1 events in the window that the breaking event closed (C10, B4 on #251).

## When the parameters change

`PARAMS` carries C10's parameter names (`contracts/baseline` `Params`, #254) at the learner defaults B4 adopted, so `events.json`'s `params` decodes strictly into `baseline.Params` (`tests/contract`). If C10 or the P4-A4 brief changes them, set `PARAMS` and run `python3 -I tests/integration/gt_inj/generate.py`, then commit the new files before any product test has run against them. A regenerated schedule after a product test has run is a new GT-INJ series, and it is recorded as such.
