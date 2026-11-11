"""The checker: a product's C13 observations against GT-PCAP's labels
(D6, P4-4-R1 deliverable 4; GT-PCAP plan section 1; C13 section 11).

These are V-M6's pass conditions for one capture, written from
`docs/verification.md` and the label file, never from an engine's or a
sensor's output:

- every labelled `service` is recorded: server address, transport, port and
  protocol; against its asset, where the record has the node's object; and
  never by port alone on a capture whose port was moved (C13 section 11);
- every labelled `flow` is recorded once: its `end` records, summed by key,
  give the label's packets and bytes (so a PRP duplicate counted twice
  fails), and its direction and client are the label's;
- every labelled `function` is recorded with its code, its objects (unless
  the label holds `?`), its `sa` and `sa_error_from`. An empty `sa` in the
  label means the record carries none;
- every observation cites its packets: each cited frame's hash is one of
  the frames the label row lists (for a service, any frame of its flow),
  and its number too when the product read the GT file itself (`file:`
  capture IDs);
- nothing is recorded that no label holds: an extra service, flow or
  function is listed, and counts against precision.

A missed row is listed by kind, never left out (R6.1). check() returns the
problems and the counts; V-M6's target is recall and precision of 1 on the
labelled set. The observations may be channel records or the node's stored
form. Stdlib only, and it shares no code with any product package.

Not checked here, because the labels' `flow`, `service` and `function` rows
do not hold it: the node's `dnp3_no_sa` flag and the alerts each `case` row
expects (they are judged at the node, against the `case` rows), redactions
against `secret-slot` rows (no labelled capture holds a secret yet), and
`insecure`, `encrypted`, `identity` and `undecoded` records, which have no
label rows on `main` to be compared with.
"""


def _key(l4, a, ap, b, bp):
    return (l4,) + tuple(sorted([(a, str(ap)), (b, str(bp))]))


def _obs_key(o):
    ip = o["ip"]
    return _key(ip["l4"], ip["src"], ip["sport"], ip["dst"], ip["dport"])


def _row_key(r):
    return _key(r["l4"], r["src"], r["sport"], r["dst"], r["dport"])


def _cites(o, row, what, bad):
    want = dict(zip(row["frame_sha256"].split(","), row["frames"].split(",")))
    by_file = o["citation"]["capture_id"].startswith("file:")
    for f in o["citation"]["frames"]:
        if f["sha256"] not in want:
            bad.append(f"{what}: cites a frame that does not show it (sha256 {f['sha256'][:12]}, frame {f['n']})")
        elif by_file and str(f["n"]) != want[f["sha256"]]:
            bad.append(f"{what}: cites frame {f['n']}, the label has that frame as {want[f['sha256']]}")


def check(rows, observations, moved_port=False):
    """Compare one capture's label rows with the observations a product made
    of it. Returns {"problems", "labelled", "matched", "observations",
    "extra", "recall", "precision"}."""
    bad, used, matched, labelled = [], set(), 0, 0
    obs = [o for o in observations if o.get("type") == "observation"]
    flows = [r for r in rows if r["kind"] == "flow"]

    for r in rows:
        if r["kind"] == "service":
            labelled += 1
            what = f"service {r['dst']} {r['l4']}/{r['dport']} {r['protocol']}"
            hit = [i for i, o in enumerate(obs) if o["kind"] == "service" and o["protocol"] == r["protocol"]
                   and (o["ip"]["dst"], o["ip"]["l4"], str(o["ip"]["dport"])) == (r["dst"], r["l4"], r["dport"])]
            if not hit:
                bad.append(f"missed {what}")
                continue
            matched += 1
            used.update(hit)
            o = obs[hit[0]]
            if moved_port and o["service"]["basis"] != "content":
                bad.append(f"{what}: found by {o['service']['basis']}, not by content, on a moved port")
            asset = o.get("node", {}).get("dst_asset")
            if asset is not None and asset != r["asset"]:
                bad.append(f"{what}: recorded against {asset}, the label says {r['asset']}")
            flow = next(f for f in flows if (f["dst"], f["dport"], f["l4"]) == (r["dst"], r["dport"], r["l4"]))
            _cites(o, flow, what, bad)
        elif r["kind"] == "flow":
            labelled += 1
            what = f"flow {r['src']}:{r['sport']} {r['dst']}:{r['dport']}/{r['l4']}"
            hit = [i for i, o in enumerate(obs) if o["kind"] == "flow" and _obs_key(o) == _row_key(r)]
            ends = [obs[i] for i in hit if obs[i]["flow"]["phase"] == "end"]
            if not ends:
                bad.append(f"missed {what}" if not hit else f"{what}: no end record")
                continue
            matched += 1
            used.update(hit)
            got = (sum(o["flow"]["packets"] for o in ends), sum(o["flow"]["bytes"] for o in ends))
            if got != (int(r["packets"]), int(r["bytes"])):
                bad.append(f"{what}: {got[0]} packets and {got[1]} bytes over its end records, the label has "
                           f"{r['packets']} and {r['bytes']}")
            for o in (obs[i] for i in hit):
                if o["protocol"] != r["protocol"]:
                    bad.append(f"{what}: protocol {o['protocol']}, the label says {r['protocol']}")
                if o["direction"] != r["direction"]:
                    bad.append(f"{what}: direction {o['direction']}, the label says {r['direction']}")
                elif r["direction"] == "client-server" and (o["ip"]["src"], str(o["ip"]["sport"])) != (r["src"], r["sport"]):
                    bad.append(f"{what}: the client is recorded as {o['ip']['src']}:{o['ip']['sport']}")
                _cites(o, r, what, bad)
        elif r["kind"] == "function":
            labelled += 1
            objects = None if r["objects"] == "?" else sorted(x for x in r["objects"].split(",") if x)
            what = f"function {r['code']} {r['objects']} sa={r['sa'] or 'unknown'} on {r['src']}:{r['sport']} to {r['dst']}:{r['dport']}"
            same = [i for i, o in enumerate(obs) if o["kind"] == "function" and _obs_key(o) == _row_key(r)
                    and str(o["function"]["code"]) == r["code"]
                    and (objects is None or sorted(o["function"]["objects"]) == objects)]
            hit = [i for i in same if i not in used and obs[i]["function"].get("sa", "") == r["sa"]
                   and obs[i]["function"].get("sa_error_from", "") == r["sa_error_from"]]
            if not hit:
                seen = sorted({obs[i]["function"].get("sa", "unknown") for i in same})
                bad.append(f"missed {what}" + (f": recorded with sa {', '.join(seen)}" if seen else ""))
                continue
            matched += 1
            used.add(hit[0])
            o = obs[hit[0]]
            if (o["ip"]["src"], str(o["ip"]["sport"])) != (r["src"], r["sport"]):
                bad.append(f"{what}: the request is recorded as sent by {o['ip']['src']}:{o['ip']['sport']}")
            _cites(o, r, what, bad)

    extra = [o for i, o in enumerate(obs) if i not in used and o["kind"] in ("service", "flow", "function")]
    for o in extra:
        ip, body = o["ip"], o[o["kind"]]
        bad.append(f"extra {o['kind']} with no label row: {ip['src']}:{ip['sport']} {ip['dst']}:{ip['dport']}/{ip['l4']} "
                   f"{o['protocol']} {body}")
    judged = [o for o in obs if o["kind"] in ("service", "flow", "function")]
    return {"problems": bad, "labelled": labelled, "matched": matched, "observations": len(judged), "extra": len(extra),
            "recall": matched / labelled if labelled else None,
            "precision": (len(judged) - len(extra)) / len(judged) if judged else None}
