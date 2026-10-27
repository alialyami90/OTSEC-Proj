# C10 golden examples

All of these are **synthetic**. The test helpers `valid()` and `validAlarm()` in `baseline_test.go` and `alarm_test.go` generated them, and they are frozen here. No device and no simulator produced any value: the node ID, asset ID, stream, times, counts, template hash and event IDs are illustrative. A baseline learnt from these values would say nothing about a real device (V-M4).

## Valid

| File | What it shows |
| --- | --- |
| `baseline-synthetic.json` | A first baseline (version 1, no `previous`) over 14 days, with one 2 h `failed.timeout` gap that extended the period, so `collected_s` is the period less the gap. Two SER types and one Syslog template type. `counts.events` is `full` + `type_only` + `unkeyed` + `not_counted`. Each type's `hours_utc` sums to its `full`. The Syslog type is periodic: its tolerance is `Tolerance(5040, absence_tolerance_pct 10)` = 504 s. |
| `alarm-repeats.json` | A repeats alarm: the rule's two parameters in order, the baseline's `max_per_window`, the observation, the received clock, six breaking events with `events_total` 6, and one possible duplicate that was not counted. |

## Invalid

| File | Why it fails |
| --- | --- |
| `baseline-counts-do-not-sum.json` | `counts.events` is one more than the sum of its parts. |
| `baseline-relearn-without-previous.json` | Version 2 without `previous`: a re-learn must name the hash of the baseline it replaces. |
| `alarm-rate-on-device-clock.json` | The rate rule names the device clock; only the time rule may use device time, and only where the offset is known (D4-4 item 1). |
