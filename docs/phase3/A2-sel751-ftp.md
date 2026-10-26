# SEL-751 FTP assessment (A2, P3-A2, ADR-0008 decision 4)

**Status:** documented-untested throughout. Every statement below is from S22, the SEL-751 instruction manual (date code 20260910), or is marked as an inference from it. Nothing was tried on a relay or a simulator. No FTP code exists or is planned in Phase 3.

ADR-0008 decision 4 asks three questions before the configuration rung for the SEL-751 is chosen. What does `FTPACC := 1` permit? Are `/REPORTS` and the settings files readable at that level? What does the manual say about writes at Level 1?

## What the manual states

| Fact | Citation | Class |
| --- | --- | --- |
| The relay is an FTP server on Ethernet Port 1 only. It allows two FTP sessions at a time and refuses a third. | S22 p. 7.15 (File Transfer Protocol (FTP) and MMS File Transfer); p. 7.87 (FTP: "Ethernet only") | `documented-untested` |
| The login user name is the Port 1 setting `FTPUSER`. The password is **the password of the access level `FTPACC` names**, so with `FTPACC := 1` it is the Level 1 password, the same one the Telnet collector sends after `ACC`. "FTP does not encrypt passwords before sending them to the server." | S22 p. 7.15 (Access Control) | `documented-untested` |
| `FTPACC` takes the values 1, 2 and C. **The factory default is 2.** `EFTPSERV` (enable FTP) defaults to Y, `FTPUSER` to `FTPUSER`, `FTPIDLE` to 5 min (range 5–255), and the default password pair is FTPUSER / TAIL. | S22 Table 4.104, sheet 2, p. 4.250; p. 7.15 | `documented-untested` |
| An FTP session left open blocks later connections until `FTPIDLE` expires. | S22 p. 7.16 (Using FTP and MMS) | `documented-untested` |
| The FTP tree has `/` (CFG.TXT, CFG.XML, ERR.TXT, SET_61850.CID), `/SETTINGS` (FTP only), `/REPORTS`, `/EVENTS` and, on touchscreen models, `/HMI`. | S22 Table 7.80, p. 7.87 | `documented-untested` |
| `/REPORTS` is labelled **read-only**. It holds SER.TXT and CSER.TXT (the `SER` and `CSER` responses), plus BRE, HIS, CHI, LDP and CLDP. "Each time you request a report, the relay stores its corresponding command response in the designated text file", so SER.TXT is the `SER` report as the command prints it. | S22 Table 7.82 and the paragraph before it, p. 7.89 | `documented-untested` |
| `/SETTINGS`: SET_ALL.TXT (all classes) and CFG.TXT are **read-only**. Each SET_cn.TXT (one per class and instance, Global being SET_G.TXT) is **read and write**. "The relay only allows you to write to the individual SET_cn files." A write is checked by reading ERR.TXT afterwards. | S22 pp. 7.88–7.89, Table 7.81 | `documented-untested` |
| Calibration settings appear in CFG.TXT and SET_ALL.TXT "only when the file is read at Access Level C". | S22 pp. 7.87, 7.89 | `documented-untested` |
| A firmware upgrade over FTP needs `FTPACC := 2` or `C` **and** `EETHFWU := Y`. Each attempt pulses SALARM and writes an SER entry. | S22 p. B.16 | `documented-untested` |
| On the terminal file interface, `FIL DIR`, `FIL READ` and `FIL SHOW` are Level 1, and **`FIL WRITE` is Level 2**. | S22 Table 7.29, p. 7.53 | `documented-untested` |

## Answers

1. **What `FTPACC := 1` permits.** The manual states only that the FTP login then uses the Level 1 password (p. 7.15). It never states, for FTP, which files each level may read or write. So "what Level 1 permits over FTP" is **unknown**. It is inferred, not stated, from the terminal file interface (Table 7.29: reads at Level 1, writes at Level 2).
2. **Whether `/REPORTS` and the settings files are readable at that level.** The manual marks `/REPORTS`, SET_ALL.TXT and CFG.TXT read-only. It never names the level that reading them needs. Two inferences say Level 1 is enough, and both are `documented-untested`, not stated. First, the equivalent commands (`SER`, `SHO`, `FIL READ`) are Level 1. Second, calibration settings are withheld "unless read at Access Level C", which implies reads happen at lower levels.
3. **What the manual says about writes at Level 1.** Nothing, for FTP. The only level stated for a file write is Level 2 for `FIL WRITE` on the terminal, and `FTPACC := 2` or C for a firmware upload. Whether an FTP session at `FTPACC := 1` can write SET_cn.TXT is **unknown**. This matters for safety: a Level 1 credential that can write settings is not a monitoring credential.

## What this means for the configuration and event rungs

- **No FTP rung for the SEL-751 until a hardware test answers question 3.** The test is a Level 1 FTP session that tries a STOR to SET_G.TXT on a lab relay that is out of service, with the owner's authorization, and the result read back from ERR.TXT and the settings. Until then, an FTP collector would hold a credential whose write power the documents don't bound.
- **The test must not change the relay (A3 on #183).**
  - Read SET_G.TXT first, then STOR exactly those bytes back, so a write that succeeds changes no setting.
  - Record SALARM and the SER before and after the attempt.
  - Use a lab credential set for the test, never the factory FTPUSER / TAIL pair (D2-11).
  - Read `/REPORTS/SER.TXT` twice and compare the two reads (below).
  - Write down every step before the session. The owner's authorization covers that written procedure.
- **FTP adds no confidentiality over Telnet** and adds a second cleartext path for the same Level 1 password (p. 7.15). It does not lift ADR-0005's plaintext acknowledgement. It also adds a session that blocks others for `FTPIDLE` if not closed, the same failure mode as `TIDLE` (D18).
- **What FTP would gain:** SET_ALL.TXT is the whole configuration in one read-only file, which is better for a baseline (R3) than many `SHO` reads. SER.TXT is the same report as `SER`. FTP needs no `ACC`, so no SALARM-counted password prompt, but whether a failed FTP login pulses SALARM is **unknown**: the manual lists "unsuccessful password entry attempts" among SALARM causes generally (S22 p. 11.13, Self-Test; p. 7.33) and doesn't say whether FTP is included.
- **The `FTPACC` default is 2**, so a relay commissioned with defaults gives FTP the Level 2 password. A platform that asked for FTP access would need the owner to set `FTPACC := 1` first, and A3's objection (D7, D8) applies until question 3 is answered.

The command-line rung (`SHO` at Level 1 over Telnet, already in the register) therefore stays the SEL-751 configuration rung for Phase 4 planning. FTP is recorded as `documented-untested`, blocked on one hardware test.

## Contrast: the SEL-400 series documents what the SEL-751 leaves open

The SEL-400 series manual (S32) answers for its relays the questions S22 leaves open, and it is the reason the matrix lists the 400 series, not the SEL-751, as the rung-2 candidate:

- Directory access levels: root, `SETTINGS`, `REPORTS` and `EVENTS` read at Level 1, `UPGRADE` at Level 2 (Table 15.8 p. 15.21).
- Per settings file: every file reads at Level 1, and none writes at Level 1; writes need P, A, O or 2 depending on the class (Table 15.9 pp. 15.23–15.24).
- The FTP login is an access-level command (`ACC`, `2AC`, ...) and its password; one FTP connection; three failed logins in a minute pulse SALARM and BADPASS (p. 15.16). The FTP server is off by default (Table 12.15 p. 12.12).

It also documents a hazard S22 does not mention for the SEL-751: report files, `SER.TXT` among them, clear when retrieved over a serial port (Table 15.10 note b, p. 15.24), and an SEL-451 release note (R324, D20200229) says firmware was changed to "retain stored data after successful reads of SER.TXT ... over Ethernet connections" (S32, SEL-451 part, p. A.9). Earlier firmware may therefore clear the SER on an FTP read (`inferred`). S22 says nothing either way for the SEL-751, so whether reading `SER.TXT` clears anything on a SEL-751 is `unknown`, and the hardware test above should read it twice and compare.
