#!/bin/sh
# E-D4-02 (ADR-0009's PRP row): do Zeek and Suricata record each flow once
# on PRP doubled captures? For each of GT-PCAP's PRP pairs (D6, #529) it
# runs both engines on the -ab capture (both LAN copies) and on the -a
# capture (LAN A only), then compares per-flow packet counts. ADR-0009's
# pass condition: each flow recorded once, with counts equal to -a's.
# Usage: run.sh CAPTURE_CACHE WORK_DIR
# Needs: suricata 7.x on PATH, docker with zeek/zeek:8.0.4, python3.
# Reads files only; contacts no device. Evidence class: simulated (Linux).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root="$here/../../../.."
cache=$1
work=$2
zeek_image=zeek/zeek:8.0.4
mkdir -p "$work/prp"
{
  echo "suricata: $(suricata -V 2>&1 | head -1)"
  echo "zeek:     $(docker run --rm "$zeek_image" zeek --version)"
} > "$work/versions.txt"
for f in dnp3-read dnp3-write dnp3-select-operate dnp3-malformed dnp3-digitalbond-part1 dnp3-digitalbond-part2 modbus modbus-digitalbond-part1 modbus-digitalbond-part2; do
  python3 "$root/tests/integration/gt_pcap/prp.py" "$cache/$f.pcap" "$work/prp" > /dev/null
done
(cd "$work/prp" && sha256sum -c "$root/tests/fixtures/network/gt-pcap/prp-derived.sha256" > /dev/null)
for pcap in "$work"/prp/*.pcap; do
  name=$(basename "$pcap" .pcap)
  out="$work/out/$name"
  mkdir -p "$out/suricata" "$out/zeek"
  suricata -r "$pcap" -l "$out/suricata" -k none \
    --set stream.midstream=true \
    --set app-layer.protocols.dnp3.enabled=yes \
    --set app-layer.protocols.modbus.enabled=yes > /dev/null 2>&1 || echo "suricata failed on $name"
  docker run --rm -v "$work/prp:/pcaps:ro" -v "$out/zeek:/out" -w /out "$zeek_image" \
    zeek -C -r "/pcaps/$name.pcap" LogAscii::use_json=T > /dev/null 2>&1 || echo "zeek failed on $name"
done
python3 -I "$here/compare.py" "$work/out" | tee "$work/prp-engines.md"
cat "$work/versions.txt"
