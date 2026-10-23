"""Hostile device outputs for V-S15 / C-08 style tests. Each case is device
text that reaches the forwarder as part of a parsed record."""
FORGED = b"<10>1 2026-10-23T00:00:00Z forged-host forged - FORGED - injected line"
CASES = {
    "plain": b"51P1P Asserted",
    "embedded-lf-forgery": b"51P1P Asserted\n" + FORGED,
    "embedded-crlf-forgery": b"51P1P Asserted\r\n" + FORGED,
    "octet-count-forgery": b"51P1P Asserted 75 " + FORGED,
    "sd-breakout": b'x"] [otsec@32473 origin="platform"] forged',
    "backslashes": b"C:\\path\\] \\\"",
    "ansi-escape": b"\x1b[2J\x1b[31mRELAY OK\x1b[0m",
    "nul-and-bell": b"abc\x00def\x07",
    "invalid-utf8": b"\xff\xfe\xc3\x28 bad",
    "oversize-10k": b"A" * 10240,
}
