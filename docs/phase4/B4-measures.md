# V-M4 measures for the event-behaviour learner and detector (P4-A4, R4.8)

B4, 2026-10-28. Everything here is `simulated`: it is B6's synthetic GT-INJ series (`tests/integration/gt_inj/events.json`, seed 202610272, and `events-heldout.json`) run through the learner and detector as they are on `main` (`modules/detection/eventbaseline`). No device was contacted, and none of this is B6's independent V-M4 run. Go 1.27.3, Linux.

Every figure below is printed by a test. Run them all with:

```
go test ./modules/detection/eventbaseline -run 'TestV_M4|TestGTINJ' -v -count=1
```

All eight tests pass, in under a second. `-race` also passes for the package. The tests are in `gtinj_test.go` (B4, #287) and `measures_test.go` (this change). They share one harness: the learner is fed the 14 observation days (2026-11-02 to 2026-11-16), the baseline is activated at B6's acknowledgement (2026-11-16T07:34:08Z), and the detector is fed the events after it.

## The V-M4 pass items

| V-M4 item | Result | Test, and the command that reproduces it |
| --- | --- | --- |
| Recall per departure kind, 100% | new 4 of 4, repeats 3 of 3, rate 3 of 3, time 3 of 3, absence 3 of 3. Every kind has at least the 3 injected departures V-M4 asks for. | `TestV_M4RecallPrecisionLatency`: `go test ./modules/detection/eventbaseline -run TestV_M4RecallPrecisionLatency -v -count=1` |
| Precision | 16 of 16 alarms match an injected departure. The series is fed in full, the departure before the acknowledgement included. | the same test |
| Held-out benign series within the agreed bound | 0 alarms over 28.0 asset-days (2 assets, 14.0 days, 1188 events): 0.000 per asset-day against the bound of 0 (*proposed*, for synthetic series). | `TestV_M4HeldOutAlarmsPerAssetDay` and `TestGTINJHeldOutRaisesNothing`: `go test ./modules/detection/eventbaseline -run 'TestV_M4HeldOut|TestGTINJHeldOut' -v -count=1` |
| Zero alarms during the period and before the acknowledgement | None. The learner has no alarm output at all. A detector given every event of the series, the period's and the departure `dep-01` (a new type 30 minutes before the acknowledgement) included, raises no alarm dated before the acknowledgement, and raises exactly the alarms it raises when only the events from the acknowledgement on are fed: events before it leave no state behind. A `Tick` before the acknowledgement is refused with `ErrOrder` and raises nothing. | `TestV_M4NoAlarmBeforeTheAcknowledgement`: `go test ./modules/detection/eventbaseline -run TestV_M4NoAlarm -v -count=1` |
| Every alarm carries the rule, the baseline value, the parameters, the observation and the event IDs | All 16 do. `Alarm.Validate` fixes the form (C10); the test checks the content against the baseline the alarm was raised against: the baseline hash and version; the parameters equal the series' parameters, in the rule's order; the baseline value states the baseline's own `max_per_window`, `max_per_bucket` and bound (`RateBound`), UTC hours seen, or interval and tolerance for that type; the cited events are in order, all of the alarm's type, and none received after the alarm. Absence alone cites none. The test logs all 16 alarms as an operator would see them. | `TestV_M4EveryAlarmExplainsItself`: `go test ./modules/detection/eventbaseline -run TestV_M4Every -v -count=1` |
| The same input gives the same alarms | Two runs record byte-identical baselines and raise identical alarms. When `Tick` is called changes no alarm **if every `Tick` is a watermark**: no later than the received time of any event still to be observed (#303: `TestDetectorAlarmsDoNotDependOnTicks`, once #303 is merged). A `Tick` past an unobserved event makes that event's `Observe` return `ErrOrder` and loses its alarm (B6's probe on #303), which `TestDetectorTickIsAWatermark` pins. So the claim is conditional on the feeder: it must tick with a watermark, never with the wall clock, and a store stall that delays an event's `Observe` by seconds is exactly when a wall-clock tick would overtake it. This report's harness ticks every 60 s of simulated time, always before the next event, so its figures hold under the condition. | `TestGTINJSameInputSameAlarms`: `go test ./modules/detection/eventbaseline -run TestGTINJSameInput -v -count=1` |
| A baseline is recorded when the period ends, is active only after the acknowledgement, and does not change silently | **Not measured here.** The learner side is tested: it records only when both minima are met, an interval with a V-S12 failure does not count, and the recorded bytes and hash are stable. The lifecycle (recording, awaiting acknowledgement, the signed `node.baseline_ack` in the audit chain, a re-learn that records the old and the new baseline) belongs to the node. B5's feeder PR is where V-M4 can test it. | `go test ./modules/detection/eventbaseline -run 'TestLearner|TestGTINJ' -v -count=1`; the rest waits on B5 |

## Alarms and latency

The 16 expected alarms, by rule: new-type 4 (one of them a catch-up row), repeats 3, rate 3, time 3, absence 3, the same counts as the recall rows above. The departure before the acknowledgement and the three msgid controls (a known text under another message ID) raise nothing, as B6's series requires, and `TestGTINJAlarmsAreExactlyTheExpectedOnes` checks each alarm's rule, asset, type, time and cited event IDs against B6's list.

**Detection latency**, from the received time of the event that broke the baseline to the alarm's `AtUTC` (the contract defines `AtUTC` as that time, or for absence the time the interval ran out):

| Kind | Result in the harness | How it is measured |
| --- | --- | --- |
| new type, repeats, rate, time | 0 s, for all 13 alarms | The alarm is returned by the `Observe` call of the last event it cites, the event that broke the baseline (the one that closed the repeats window or passed the rate bound), and `AtUTC` is that event's received time. The test fails if a later call raises it or `AtUTC` is another time. |
| absence | 37 s to 57 s after the deadline, with a `Tick` every 60 s of simulated time | `AtUTC` is the deadline: the last occurrence + interval + tolerance. The three alarms came from the first `Tick` after the deadline. The alarm cannot be raised before the deadline (`TestDetectorAbsence`), so for absence the time from the last heartbeat to the alarm is the interval + tolerance (3601 s + 1801 s, 90 minutes) plus the `Tick` cadence. |

The detector is synchronous, so these figures leave out what a deployment adds: the collection cycle (a SER row's received time is the poll that read it, not the moment the device recorded it), storage, delivery to the feeder, and how often the node ticks. B5's feeder sets the last. V-M4's target, within one collection cycle, cannot be shown until the feeder exists. The only claim here is that the detector adds nothing to it for the event-driven rules, and at most one `Tick` cadence for absence.

## What this cannot show

- **The real false-positive rate.** The held-out series is built so that no benign event can be denser or at a new hour than the baseline saw (`tests/integration/gt_inj/README.md`, "How the benign series is kept within the baseline"), so 0 alarms is close to a property of the generator. A real device has drifting rates, maintenance windows, and message text B6 did not think of. It needs a real device's event history over at least one observation period (14 days, 200 events), from a site or a lab relay. Until then the figure is a regression check, not an estimate.
- **Recall on departures nobody injected.** The five rules are deterministic, and recall of 100% means the rules fire when their own definition is met on this series, not that the five rules find every departure that matters.
- **Parameter fit.** The parameters are B6's proposals (5 repeats in 600 s, a rate bound of 300% of the baseline's most in a clock hour with a minimum of 2, and so on); a real device may need others. The learner records them in every baseline, so a change is a new baseline.
- **Two assets, 14 days.** One SER asset and one Syslog asset. Types per asset are at most 4096 (`max_types` keeps the highest counts).
- **The lifecycle on the real binaries**, and B6's independent V-M4 run on them.

## Mutation check

Each of these breaks a named measure, and the tests fail on it (run locally, not committed): the time rule switched off (recall 0 of 3 for time, and the alarm count); the pre-acknowledgement early return in `Observe` removed (an alarm for `dep-01`, which the no-alarm test and the recall and precision test catch); a wrong `max_per_bucket` in a rate alarm's baseline value (the content test). The earlier mutants for each rule's boundary are in `docs/phase4/B4-learner.md`.

## Next

- B5: the feeder (C5 reads sorted by received time, the V-S12 alignment keys, `node.baseline_ack`) is where the lifecycle row can be tested and a collection-cycle latency measured. It must tick with a watermark (see the determinism row), and a test of the feeder should delay an event's `Observe` past a tick to show it.
- B6: the independent V-M4 run, on the real binaries.
- A real device history, when the owner can provide it, to measure the false-positive rate.
