# V-M3 for the SEL-751: the desk check of every matrix cell, and the method cases (C6)

C6, 2026-11-04. This is V-M3's desk half for the SEL-751 (R3.7, D4-40 point 3).

**What was checked.** Every cell of the SEL-751 block in `docs/device-capabilities.md` on `main` at `68e3d57` (C2's desk check, #378), against its citation. The source is S22, the SEL-751 Instruction Manual, date code 20260910. It is read from the owner-supplied copy in the project files (`phase0/manuals-SEL/751_IM_20260910.pdf`), extracted to text with `pdftotext -layout`. Page numbers are the manual's own.

**Evidence class.** `desk`. No device was contacted, and nothing here is hardware-verified.

## Result: 8 rows, 3 findings, no classification wrong

Every classification in the block is supported by its citation, and no cell claims more than S22 shows. There are three findings. Two are citations to add, and one is a wording that misstates what an output does. All three are C2's to change, and none changes V-M3's selection rule. C2 made all three in #388, which C1 merged on 2026-11-04 after C6 checked each one against S22.

| Row | Cell checked | S22 says | Result |
| --- | --- | --- | --- |
| Asset identification | `ID` at Level 0. The fields FID, BFID, CID, DEVID, DEVCODE, PARTNO, CONFIG, SPECIAL and two display-package lines, each with a 4-hex checksum. | Table 7.43 gives `ID` at access level 0. Figure 7.38 shows the 10 lines in that form. Both are on p. 7.64. | Confirmed. The checksums are tested in `modules/ied/sel751` (`identity_test.go`, `parse_test.go`). |
| Configuration retrieval | `SHO` forms at Level 1, with 24 forms in the run. | Table 7.67 (p. 7.77) lists `SHO n`, `SHO L n`, `SHO G`, `SHO P n` (1 to 4 and F), `SHO R`, `SHO F`, `SHO I`, `SHO M`, `SHO E m` and `SHO DNP m`, all at level 1. That makes 4 + 4 + 1 + 5 + 1 + 1 + 1 + 1 + 3 + 3 = 24. | Confirmed. The register's `sel.config.read_all` has exactly these 24 lines, all at level 1, with `SHO P 1` and `SHO G` first. |
| Configuration retrieval | `FTPACC` default 2. | Port 1 settings: `FTPACC := 2`, with the range 1, 2, C. | Confirmed. |
| Configuration retrieval | The touchscreen settings: 175 in `/HMI` (`SET_HMI.zds`, `CDP.zds`), with no `SHO` form, cited to Table 7.80, p. 7.87. | Table 7.80 (p. 7.87) names the two files in `/HMI`. It does not give a count. The settings sheets SET.92 to SET.96 ("Touchscreen Settings", shown if the front-panel MOT option is A/B) hold 175 setting lines. No `SHO` form in Table 7.67 covers them. | **Finding 1.** The count is right, but its source is SET.92 to SET.96, not Table 7.80. Please cite both, as `phase4/B2-register-rev5.md` already does. |
| Event / SER retrieval | `SER` at Level 1: up to 1,024 rows, row 1 the newest, range and date forms. | Table 7.63 (p. 7.75): "as many as 1024 rows. Row 1 is the most recently triggered row". `row1 row2`, `date1` and `date1 date2` are listed. Level 1. | Confirmed. |
| Event / SER retrieval | `CSE` Compressed ASCII at Level 1, with its format unknown. | Table C.2 lists `CSE`, "Sequence Of Events Data", at access level 1. S22 gives no response format for it. | Confirmed, including "format unknown". |
| Event / SER retrieval | Relay local time, `UTC_OFF` only with SNTP, DST from the Global settings. | Global setting `UTC_OFF` (−24 to 24 h). The text states that it is not used when a source other than SNTP updates the relay time. Local time comes from `UTC_OFF` and `DST_BEGM`. | Confirmed. |
| Syslog emission | `unsupported`: no Syslog in Table 7.5. | Table 7.5 (p. 7.13) lists no Syslog on any port. The word does not appear anywhere in S22. | Confirmed. |
| Available CLI commands | `ACC`, `ID`, `SER`, `QUI` and the 24 `SHO` forms, read-only. "Level 1 is not read-only." | As in the rows above. Table 7.63 also lists `SER C or R` (clear or reset the SER) at level 1. | Confirmed. The register holds `ID` and `SER` as operations, `ACC` and `QUI` as session lines, and the 24 `SHO` lines, and no `SER C` or `SER R`. Table 7.63 is direct evidence for "Level 1 is not read-only". |
| Remote engineering | `unsupported` for SSH and TLS on the relay. Telnet and HTTP are cleartext. | Table 7.5: Port 1 carries Telnet and a web server (HTTP). It lists no SSH, TLS or HTTPS, and none of those words appears in S22. | Confirmed. |
| Known firmware differences | Register revision 5 lists 78 FIDs from Appendix A. | All 78 register FIDs appear in S22. S22 holds two more FID strings: the `R100-V0-Z001001-D20110601` format example in Appendix A's introduction, and the FID in Figure 10.16's example header. Neither is a firmware table entry. | Confirmed. The branch rules are `inferred` and owner-accepted, so they have no citation to check. |
| Operational limitations | 3 bad passwords and every Level 2 or C access pulse SALARM for 1 s. | p. 7.33: after three incorrect entries "the relay pulses the SALARM Relay Word bit for one second", and it does the same after a successful Level 2 or C access, or a denied one. | Confirmed. |
| Operational limitations | SALARM "by default closes OUT101" and is SER4. | Table 4.83: `OUT101 := HALARM OR SALARM`, with `OUT101FS := Y` (fail-safe) by default. `SER4 := SALARM`. In fail-safe mode the output coil is energized while the relay is healthy and is de-energized when the equation asserts (p. 2.31). | **Finding 2.** By default, SALARM *de-energizes* OUT101 for 1 s. Whether a contact closes or opens then depends on how the contact is wired, which S22 cannot say for a site. Please write "operates OUT101 (fail-safe by default: its coil de-energizes for 1 s)". The SER4 half is confirmed. |
| Operational limitations | 2 concurrent Telnet sessions. `TIDLE` 15 min. `FASTOP` default N. `MAXACC` caps the port's level. | Table 7.5 note a: Port 1 supports "two Telnet" sessions. Port settings: `TIDLE := 15` (1 to 30 min), `FASTOP := N`, `MAXACC := 2` (1, 2, C). | Confirmed. |
| Operational limitations | The web server uploads firmware at Level 2. | p. 3.10 (File Management, Figure 3.15): "upgrading the relay firmware (Access Level 2)". | **Finding 3.** The claim is right, but it is cited to none of the listed pages (pp. 7.33, Table 7.5, Section 4). Please add S22 p. 3.10. |

**Not re-read.** S4, S5, S7, S8, S9 and S16 are cited beside S22 in the Syslog, remote-engineering and safety rows. In each of those rows, S22 alone supports the classification, so this check rests on S22.

## The method cases (V-M3's non-vacuous half, D4-40 point 3)

These are in `tests/safety/rung/rung_c6_test.go` (desk: the configuration and the register are read, and no binary runs). Each way a node configuration could try to choose another configuration method is pinned:

| Attempt | Where it is refused | Test |
| --- | --- | --- |
| A field naming a method (`method`, `config_method` or `rung`), at the top level, in a schedule entry or in an endpoint | At start, by the node's strict decode (`unknown field`) and C1's strict decode of the asset | `TestC6MethodFieldIsRefusedAtStart` (9 cases, each naming the field) |
| An endpoint on transport `ftp` | At start, by C1's closed transport set (`is not one of the 0.2 values`) | `TestC6FTPEndpointIsRefusedAtStart` |
| A schedule entry whose operation names an FTP read (`sel.config.ftp_read`) | **Not at start.** The node checks only the operation's form. The guard is the signed register, which holds no FTP operation, no FTP run and no line that is one of V-M3's FTP commands. The collector refuses an operation the register does not hold (`authz.RefuseUnknownOperation`, C3's `TestRunRefusals` in `modules/security/collector`) before it connects. | `TestC6FTPOperationHasNoRegisterEntry` |

**For C1.** The third row is a fact about the ruling: an FTP *operation* is refused at run time, not at start. That fails closed, and nothing reaches the device, but D4-40's "refused at start" holds only for a field or a transport. If the node should refuse an operation the signed register does not hold at start, that is a node change for C5. The test logs which way it is, and it does not need to change either way.
