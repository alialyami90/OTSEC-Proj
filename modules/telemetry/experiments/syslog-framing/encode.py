"""Throwaway RFC 5424 encoder used to test framing and escaping choices
against an independent receiver (rsyslog). Not product code.

Two encoders are compared:
  naive   device text placed verbatim in MSG, newline (non-transparent) framing
  profile the draft A4 forwarding profile: octet-counted framing (RFC 6587
          section 3.4.1, as RFC 5425 requires), device text only inside an
          SD-PARAM, RFC 5424 section 6.3.3 escaping, and base64 for any value
          that is not printable UTF-8. HEADER TIMESTAMP is the collector
          receive time; the device's own timestamp travels verbatim in SD.
"""
import base64
import hashlib

SD_ID = "otsec@32473"  # 32473 is the documentation-only PEN from RFC 5612.


def sd_escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def printable_utf8(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in text):
        return None
    return text


def device_text_param(raw, budget):
    """Return SD-PARAMs carrying device bytes losslessly, or a reference if
    they do not fit in the remaining budget. Never truncates silently."""
    text = printable_utf8(raw)
    if text is not None:
        param = f'dtext="{sd_escape(text)}"'
    else:
        param = f'dtext_b64="{base64.b64encode(raw).decode()}"'
    if len(param.encode()) <= budget:
        return param
    return f'dtext_omitted="1" dlen="{len(raw)}" dsha256="{hashlib.sha256(raw).hexdigest()}"'


def profile_message(event, max_octets=2048):
    head = f"<{event['pri']}>1 {event['received_at']} {event['collector']} otsec - {event['msgid']} "
    fixed = (f'[{SD_ID} eid="{event["event_id"]}" origin="{event["origin"]}" '
             f'asset="{sd_escape(event["asset_id"])}" dts="{sd_escape(event["device_ts_native"])}" '
             f'dprec="{event["precision"]}" doff="{event["offset"]}" ')
    msg = " " + event["summary"]
    budget = max_octets - len((head + fixed + "]" + msg).encode()) - 1
    sd = fixed + device_text_param(event["device_bytes"], budget) + "]"
    out = (head + sd + msg).encode()
    assert len(out) <= max_octets, len(out)
    return out


def octet_frame(msg):
    return str(len(msg)).encode() + b" " + msg


def naive_message(event):
    text = event["device_bytes"].decode("utf-8", "replace")
    return (f"<{event['pri']}>1 {event['received_at']} {event['collector']} otsec - "
            f"{event['msgid']} - {text}").encode() + b"\n"


def legacy_3164_message(event, max_octets=1024):
    """RFC 3164-style rendering for collectors that do not parse RFC 5424.
    The HEADER carries second-resolution, yearless time (RFC 3164 4.1.2), so
    every time and identity field travels inside MSG as the same SD element
    the RFC 5424 profile uses; the collector sees it as text. 1024 is the RFC
    3164 limit."""
    t = event["received_at"]  # e.g. 2026-10-23T15:00:00.123456Z
    month = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()[int(t[5:7]) - 1]
    head = f"<{event['pri']}>{month} {int(t[8:10]):2d} {t[11:19]} {event['collector']} otsec: "
    fixed = (f'[{SD_ID} eid="{event["event_id"]}" rcv="{t}" origin="{event["origin"]}" '
             f'asset="{sd_escape(event["asset_id"])}" dts="{sd_escape(event["device_ts_native"])}" '
             f'dprec="{event["precision"]}" doff="{event["offset"]}" ')
    msg = " " + event["summary"]
    budget = max_octets - len((head + fixed + "]" + msg).encode()) - 1
    out = (head + fixed + device_text_param(event["device_bytes"], budget) + "]" + msg).encode()
    assert len(out) <= max_octets, len(out)
    return out


def lf_frame(msg):
    """RFC 6587 3.4.2 non-transparent framing. Safe only because the profile
    never puts a control character in a message (device text that is not
    printable UTF-8 is base64-encoded); checked, not assumed."""
    assert b"\n" not in msg and b"\x00" not in msg, "LF or NUL in message"
    return msg + b"\n"
