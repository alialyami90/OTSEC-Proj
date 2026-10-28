# Register revision 5 and C2 0.6 `config.read`: design and the rulings it needs (P4-A2, B2)

Date: 2026-10-27.

**Evidence class.** `desk`. The counts come from S22's settings sheets by `contracts/register/testdata/count_settings.py`. No relay was read. Every reply layout and size here is `documented-untested`.

**What B1 must rule on** is in the last section. Everything before it is the design that those rulings select between.

## The problem: the register cannot say "read 24 forms in one session"

C3 0.2 (`otsec.register/0.2`) knows one line per operation, and a C2 invocation names one operation (`CheckLines` allows the invocation's own line plus the precondition, warning, firmware-branch and context reads). Neither carries a timeout or a byte cap for a line. P4-A2 asks for a `config.read` that sends 24 `SHO` lines under the `ser.read` session rules (one session, one password, Level 1, `QUI` last), each with a timeout and a byte cap. Three ways to do it:

1. **24 invocations, one per form.** Each would log in again. The failed-auth floor, the two-session limit and `TIDLE` make that unsafe and slow. Rejected.
2. **C2 holds the list of forms.** Then the register is no longer the one place that says which lines may be sent, and V-S7 and the deny corpus would not cover the list. Rejected.
3. **The register holds the list** (recommended): a minor C3 change, below.

## Proposal: C3 0.3 `otsec.register/0.3` (B1 owns the format)

Two additions, both optional, so a 0.1 or 0.2 package stays valid:

- **`operations[].limits`**, `{"max_reply_bytes": n, "timeout_ms": n}`, both required when present. `max_reply_bytes` is at most C2's 1 MiB session ceiling, and `timeout_ms` at most its 60 s step ceiling. The adapter ends a reply that passes either with `failed.response_too_large` or `failed.timeout`, and keeps the bytes.
- **`runs[]`**, a named, ordered list of operations sent in one session: `{id, steps[], max_total_bytes, deadline_ms, citations, evidence, side_effects, notes}`.
  - A step is the ID of an operation that is read-only, literal (no parameters), runs in the operate phase and needs access level 1 or lower. A run has at most 32 steps and no step twice.
  - A run's ID shares the namespace of operation IDs, so a C2 invocation may name a run.
  - Every precondition's `read_by` operation is the first step, so `LANG := ENGLISH` is checked before any other line is sent. The context and warning reads that the run's steps already include are sent once.
  - `Matcher` gains `RenderRun(id)` (the lines, in order) and `Limits(opID)`. `Matcher.Permit` is unchanged, so every line still passes the egress check on its own.
  - `CheckLines` for a run invocation requires exactly the run's lines, in order, once each, plus none of any other operation.

Why not reuse `context`? A context entry names a setting that one operation needs for another. A `SHO` form is not a setting for anything. Bending it would hide the run inside a field that means something else.

## Revision 5 content

- **24 operations**, all `read-only`, access level `1`, `documented-untested`, cited to S22 Table 7.67 (p. 7.77) and the settings class it shows: `sel.config.show_group_1` to `_4` (`SHO 1` to `SHO 4`), `show_logic_1` to `_4` (`SHO L n`), `show_global` and `show_port1` (these two exist already), `show_port_f`, `show_port_2` to `_4`, `show_report`, `show_front_panel`, `show_modbus`, `show_iec103`, `show_eip_1` to `_3`, `show_dnp_1` to `_3`. The existing IDs are kept so revision 4's references hold.
- **One run**, `sel.config.read_all`: `SHO P 1` first (the `LANG` precondition), then `SHO G`, then the other 22 forms in the order of C9 0.2's classes (`sel-751-sho/2`, which lists them in the run's order).
- **Nothing else changes:** no `SET`, `FIL`, Level 2 entry or `s` form. The deny rules stay, and B6's corpus adds every `SHO <form> s` form and every bare `SHO P` (V-S7).
- **Spanish forms** (`MOS`) stay denied; the `LANG := ENGLISH` precondition is unchanged.

## Counted caps

Method: `count_settings.py` counts the `NAME :=` lines on S22's settings sheets (SET.1 to SET.114) for each class, then bounds a reply as 4,096 bytes of headings plus, for each setting, 16 (name) + 6 (`:=` and CR LF) + 64 (a value) or 384 (an equation). The 64 and 384 are assumptions, because S22 gives no number: an ALIAS value is at most 64 characters (SET.97: three texts of 15 characters and a Relay Word bit), and an equation holds at most 15 elements and 14 parenthesis pairs (p. 4.215), which at 16 characters per element is 366. A name may appear on more than one sheet when a setting's range depends on the model; a reply prints only the model's, so each count is an upper bound on one reply.

| Form | Names | Equations | Counted bound, rounded up to a KiB |
| --- | ---: | ---: | ---: |
| `SHO 1` to `SHO 4` (each) | 743 | 108 | 103,424 |
| `SHO L 1` to `SHO L 4` (each) | 863 | 863 | 355,328 |
| `SHO G` | 562 | 151 | 101,376 |
| `SHO P F` / `P 1` / `P 2` / `P 3` / `P 4` | 25 / 227 / 53 / 56 / 55 | 0 | 7,168 / 24,576 / 9,216 / 9,216 / 9,216 |
| `SHO R` | 98 | 1 | 13,312 |
| `SHO F` | 222 | 22 | 30,720 |
| `SHO M` / `SHO I` | 71 / 104 | 0 | 10,240 / 13,312 |
| `SHO E 1` to `E 3` (each) | 135 | 0 | 16,384 |
| `SHO DNP 1` to `DNP 3` (each) | 144 | 0 | 17,408 |
| **All 24 forms** | **8,734** | | **2,147,988 before rounding** |

**Finding: the structural worst case does not fit C2's 1 MiB session ceiling.** Taken together the bounds are 2.1 MB. No relay is expected to print that: every equation at 15 full elements is not a configuration. For scale, S22 Figure 7.43 prints 158 settings for a group in about 4.1 KB, and I estimate a default relay at 120 KB and a heavily programmed one at 350 KB, a desk estimate. So the read needs a total cap T below the structural worst case, and a relay beyond T fails the read closed (the bytes are kept, nothing is baselined). That is an availability limit, not a safety one.

**The record bound follows from T.** The capture is at most T. The snapshot is at most its fixed 5,348 bytes plus 41 bytes per setting (25 of JSON and up to 16 of name) for at most 8,734 settings, plus the printed values, which the capture also holds: so the snapshot is at most T + 363,442 bytes, and the record is at most `2 × T + 363,442`. The ratio in C9's golden (11,715 for 6,397) is not the worst case, because a dense reply of short settings costs more JSON than text.

| T (read total) | Record bound | Notes |
| --- | ---: | --- |
| 256 KiB (262,144) | 887,730 | Fits the provisional 1 MiB cap; about 2 times my default estimate, but under my heavy estimate |
| **512 KiB (524,288)** | **1,412,018** | **Recommended.** Record cap 1.5 MiB (1,572,864); B5's reserve is `2 × WALBoundBytes + 1.1 × 1.5 MiB + 64 KiB`, about 2.7 MiB if `2 × WALBoundBytes` is the 1.0 MiB that B5's 1.6 MiB and B1's 2.2 MiB figures imply |
| 1 MiB (1,048,576; C2's ceiling) | 2,460,594 | Record cap 2.5 MiB; reserve about 3.9 MiB on the same assumption |

Per-form `max_reply_bytes` is the counted bound above, and none may exceed T. The `SHO L n` forms reach 355,328, which is under T = 512 KiB. A run's `max_total_bytes` is T.

## Time

- **Per form: `timeout_ms` 10,000**, as the SER read's `step_timeout_ms`. S22 gives no reply time for `SHO`, so this is a platform choice and `documented-untested`. A reply that does not end in 10 s fails the read.
- **Run: `deadline_ms` 300,000**, under C2's 600 s ceiling. 28 sends (`QUI`, `ID`, `ACC`, 24 `SHO` forms, `QUI`) leave 10 s each with room to spare.
- **`TIDLE`** (15 min by default) is not the limit for one session of at most 300 s. The two-session limit still holds: the platform takes one session at a time, and P4-A5's quiet interval keeps a configuration read and a SER read apart. The poll interval is B5's; a configuration read does not need to be frequent.

## Gaps this exposes

- **Touchscreen settings are in no `SHO` form.** The sheets list 175 touchscreen settings (SET.92 to SET.96). Table 7.67 has no form for them; S22 Table 7.80 (p. 7.87) lists them in the `/HMI` directory as the files `SET_HMI.zds` and `CDP.zds`, which are file transfers, not `SHO`. A touchscreen model's HMI settings will not be baselined. They stay out of C9, and R3.1's "every setting an engineer can change" has this exception. It needs the owner's knowledge of whether a touchscreen model is in scope.
- **Duplicate names across sheets.** 27 extra occurrences of a name fall on a second sheet of the same class: 24 in Global (562 distinct of 586), 2 in Group and 1 in Port F. A reply prints one of them. C9 refuses a reply that prints a name twice, so a model that shows both would fail the read. That is correct, but H-13 should check it.
- **Absent classes.** The 24 includes the options Table 7.1 makes ordering choices. An absent form answers `Invalid Command` (C9, decision 6). Each absent form still costs one send.

## What this changes for others

| Who | What |
| --- | --- |
| B1 | C3 0.3 (the format), C2 0.6 (the `config.read` operation and result), and the three rulings below |
| B3 | `Registers.Activate` with a revision-5 package, and the collector's use of `RenderRun` and `Limits`; the approval of the register additions |
| B5 | `Quota.MaxRecordBytes` and the reserve, from T; C5 0.4's validator is unchanged |
| B6 | The deny corpus for every `s` form and bare `SHO P`; V-S7 over the 24 lines; H-13 to capture each form and the longest real equation |
| B4 | `ser_test.go`'s receive times only if a SER read shares a session with config forms, which it does not |

## Rulings requested from B1

1. **The format.** C3 0.3 with `limits` and `runs` as above, or another shape you prefer. Nothing in revision 5 can be written until this is settled.
2. **T and the record cap.** I recommend T = 512 KiB and `MaxRecordBytes` = 1.5 MiB, replacing C9's provisional 1 MiB. If you prefer to keep 1 MiB, T is 256 KiB and a heavily programmed relay may fail the read closed.
3. **Touchscreen settings.** Leave them out of C9 and record the exception, or ask the owner whether touchscreen models are in scope.

## Order of work

1. This note, with `count_settings.py`, for your rulings (docs and one script).
2. C3 0.3 in `contracts/register/` once ruled, with tests (your contract change).
3. Revision 5 content: the 24 operations, the run and the limits; B6's deny corpus and B3's activation tests follow.
4. C2 0.6 `config.read` in `sel751`, with a parser and fuzz target per class and goldens from S22, after my goldens are fixed (B6's simulator forms are not read before then).
