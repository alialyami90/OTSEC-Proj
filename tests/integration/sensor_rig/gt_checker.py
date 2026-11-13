"""The checker: a product's C13 observations against GT-PCAP's labels
(D6, P4-4-R1 deliverable 4; GT-PCAP plan section 1; C13 section 11).

These are V-M6's pass conditions for one capture, written from
`docs/verification.md` and the label file, never from an engine's or a
sensor's output:

- every labelled `service` is recorded: server address, transport, port and
  protocol; against its asset, where the record has the node's object; and
  never by port alone on a capture whose port was moved (C13 section 11);
- every labelled `flow` is recorded once, with both of its observations
  (C13 section 4.3): a `start`, which is what the node's detector reads, and
  its `end` records, which summed by key give the label's packets and bytes
  (so a PRP duplicate counted twice fails). Its direction and client are
  the label's, and a TCP flow that carried a labelled function never ends
  with `syn_only: true`, which only a dial that carried nothing may;
- every labelled `function` is recorded with its code, its objects (unless
  the label holds `?`), its `sa` and `sa_error_from`, and for Modbus its
  unit. An empty `sa` in the label means the record carries none. It cites
  the request first;
- every labelled `insecure` use is flagged, with its reason (V-M6's list;
  today the derived Modbus capture's `modbus-tcp`);
- every observation cites its packets: each cited frame's hash is one of
  the frames the label row lists (for a service, any frame of a labelled
  flow with the server at either end),
  and its number too when the product read the GT file itself (`file:`
  capture IDs);
- nothing is recorded that no label holds: an extra service, flow,
  function or insecure record is listed, and counts against precision.

A missed row is listed by kind, never left out (R6.1). check() returns the
problems and the counts; V-M6's target is recall and precision of 1 on the
labelled set. The observations may be channel records or the node's stored
form. Stdlib only, and it shares no code with any product package.

Not checked here: the node's `dnp3_no_sa` flag, which is how DNP3 without
Secure Authentication is flagged, and the alerts each `case` row expects
(both are judged at the node, against the `case` rows); redactions against
`secret-slot` rows (no labelled capture holds a secret yet); and
`encrypted`, `identity` and `undecoded` records, which have no label rows
on `main` to be compared with.
"""


def writers(net):
    """The asset table's authorized writers as (client address, server
    address, class). `net` is `net` in dnp3-cases.json, which names hosts in
    three places: `masters`, `outstation` and, once a second relay exists,
    `outstations`. A name found in none of them is an error, never a writer
    quietly left out: a test that judged `unauthorized-write` without it
    would expect an alert that the node rightly never raises (D4 on #623)."""
    hosts = {**net["masters"], net["outstation"]["name"]: net["outstation"], **net.get("outstations", {})}
    out = []
    for client, server, cls in net["authorized_writers"]:
        for name in (client, server):
            if name not in hosts:
                raise KeyError(f"authorized_writers names {name}, which no table of the capture set holds")
        out.append((hosts[client]["ip"], hosts[server]["ip"], cls))
    return out


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
            # Its frames: those of every labelled flow with the server at
            # either end, since a service's key is the same whichever flow
            # carries it (C13 0.2's CH-49; D4's N3 on #648).
            mine = [f for f in flows if f["l4"] == r["l4"]
                    and (r["dst"], r["dport"]) in ((f["src"], f["sport"]), (f["dst"], f["dport"]))]
            service_frames = {k: ",".join(f[k] for f in mine) for k in ("frames", "frame_sha256")}
            for o in (obs[i] for i in hit):  # every record of the key, not the first alone
                if moved_port and o["service"]["basis"] != "content":
                    bad.append(f"{what}: found by {o['service']['basis']}, not by content, on a moved port")
                asset = o.get("node", {}).get("dst_asset")
                if asset is not None and asset != r["asset"]:
                    bad.append(f"{what}: recorded against {asset}, the label says {r['asset']}")
                _cites(o, service_frames, what, bad)
        elif r["kind"] == "flow":
            labelled += 1
            what = f"flow {r['src']}:{r['sport']} {r['dst']}:{r['dport']}/{r['l4']}"
            hit = [i for i, o in enumerate(obs) if o["kind"] == "flow" and _obs_key(o) == _row_key(r)]
            ends = [obs[i] for i in hit if obs[i]["flow"]["phase"] == "end"]
            starts = [obs[i] for i in hit if obs[i]["flow"]["phase"] == "start"]
            if not hit:
                bad.append(f"missed {what}")
                continue
            used.update(hit)
            if not starts:
                # The detector reads the start: with none, unknown-pair and
                # unresolved-address never fire on this flow (D4 on #626).
                bad.append(f"{what}: no start record")
            if not ends:
                bad.append(f"{what}: no end record")
            if not starts or not ends:
                continue
            matched += 1
            carried = any(f["kind"] == "function" and _row_key(f) == _row_key(r) for f in rows)
            if carried and any(o["flow"].get("syn_only") for o in ends):
                bad.append(f"{what}: an end says syn_only, and the flow carried a labelled function")
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
            unit = r["note"][len("unit="):] if r["note"].startswith("unit=") else None  # Modbus: in the key (C13 4.2)
            same = [i for i, o in enumerate(obs) if o["kind"] == "function" and _obs_key(o) == _row_key(r)
                    and str(o["function"]["code"]) == r["code"]
                    and (objects is None or sorted(o["function"]["objects"]) == objects)
                    and (unit is None or str(o["function"].get("unit")) == unit)]
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
            if o["citation"]["frames"][0]["sha256"] != r["frame_sha256"].split(",")[0]:
                bad.append(f"{what}: does not cite the request first")
            _cites(o, r, what, bad)
        elif r["kind"] == "insecure":
            labelled += 1
            reason = r["note"][len("reason="):] if r["note"].startswith("reason=") else ""
            what = f"insecure {reason} on {r['src']}:{r['sport']} to {r['dst']}:{r['dport']}/{r['l4']}"
            hit = [i for i, o in enumerate(obs) if o["kind"] == "insecure" and _obs_key(o) == _row_key(r)
                   and o["insecure"]["reason"] == reason]
            if not hit:
                bad.append(f"missed {what}")
                continue
            matched += 1
            used.update(hit)
            flow = next(f for f in flows if _row_key(f) == _row_key(r))
            for o in (obs[i] for i in hit):
                _cites(o, flow, what, bad)

    judged_kinds = ("service", "flow", "function", "insecure")
    extra = [o for i, o in enumerate(obs) if i not in used and o["kind"] in judged_kinds]
    for o in extra:
        ip, body = o["ip"], o[o["kind"]]
        bad.append(f"extra {o['kind']} with no label row: {ip['src']}:{ip['sport']} {ip['dst']}:{ip['dport']}/{ip['l4']} "
                   f"{o['protocol']} {body}")
    judged = [o for o in obs if o["kind"] in judged_kinds]
    return {"problems": bad, "labelled": labelled, "matched": matched, "observations": len(judged), "extra": len(extra),
            "recall": matched / labelled if labelled else None,
            "precision": (len(judged) - len(extra)) / len(judged) if judged else None}
