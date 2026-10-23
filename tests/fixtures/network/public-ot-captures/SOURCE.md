# Public OT captures (referenced, not vendored)

Owner: A4. Registered 2026-10-23 for the Phase 0 engine coverage experiment (`modules/telemetry/experiments/ids-coverage/`).

The capture files are **not committed**. None of the sources states redistribution terms, so this directory holds only the manifest. `modules/telemetry/experiments/ids-coverage/fetch_captures.sh` downloads each file from a commit-pinned URL and verifies its SHA-256 against [MANIFEST.tsv](MANIFEST.tsv). A hash mismatch fails the fetch.

None of these captures comes from this project's equipment, and none is a substation recording made by the project. They are public test material. Using them proves what an engine does with these bytes, not how any device in a customer substation behaves.

## Sources

| Files | Origin | Capture date (from packets) | Who captured | Nature | Redactions |
| --- | --- | --- | --- | --- | --- |
| `dnp3-read.pcap`, `dnp3-write.pcap`, `dnp3-select-operate.pcap` | Wireshark SampleCaptures wiki ("Source: pcapr.net by bw"), mirrored in `automayt/ICS-pcap` at commit `13b7ae3` | 2006 | unknown individual ("bw") | Lab or test traffic, single exchanges | unknown |
| `dnp3-malformed.pcap` | `automayt/ICS-pcap` at `13b7ae3` | unknown | unknown | Malformed DNP3, likely fuzzer output | unknown |
| `dnp3-digitalbond-part1.pcap`, `dnp3-digitalbond-part2.pcap`, `modbus-digitalbond-part1.pcap`, `modbus-digitalbond-part2.pcap` | Digital Bond test data, mirrored in `automayt/ICS-pcap` at `13b7ae3` | 2004 to 2006 | Digital Bond | Lab test traffic | unknown |
| `modbus.pcap` | `automayt/ICS-pcap` at `13b7ae3` | unknown | unknown | Unknown | unknown |
| `iec104.pcap`, `iec104-sq.pcapng` | Wireshark SampleCaptures wiki (gitlab.com/wireshark/wireshark wiki uploads) | 2013 (`iec104.pcap`) | unknown contributor | Lab or test traffic | unknown |
| `mms.pcap.gz` (gunzipped to `mms.pcap`) | Wireshark SampleCaptures wiki | 2005 (gzip header) | unknown contributor | MMS traffic, origin not described | unknown |
| `goose-*.pcapng` | `smartgridadsc/IEC61850SecurityDataset` at commit `120dd2b` (Biswas et al., "A Synthesized Dataset for Cybersecurity Study of IEC 61850 based Substation", IEEE SmartGridComm 2019) | 2019-05 | ADSC Singapore | **Synthesized** GOOSE traffic from 18 simulated IEDs: normal, three disturbance scenarios, and labeled attack scenarios with the injected frame numbers given in the dataset README | none stated |

## Labels

The `label` column in the manifest comes from the source, never from this project's tools:

- `attack:frames=N,M` are the injected frame numbers stated in the IEC61850SecurityDataset README for that file.
- `benign` and `benign-disturbance` are the dataset's Normal and Disturbance scenarios.
- `read-only`, `write`, `select-operate`, `malformed` are the capture names given by the source.
- `unlabeled` means no ground truth beyond the protocol.

## Evidence class

Results computed on these files are `simulated` in the sense of `docs/device-capabilities.md`: they exercise engines against recorded traffic that is not from the target environment, and for GOOSE the traffic itself is synthesized.
