#!/bin/sh
# Run Suricata, Zeek, and tshark over every capture in MANIFEST.tsv, then
# summarize. Usage: run_all.sh [capture-cache] [work-dir]
# Needs: suricata 7.x and tshark on PATH; docker with zeek/zeek:8.0.4.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
manifest="$here/../../../../tests/fixtures/network/public-ot-captures/MANIFEST.tsv"
cache=${1:-${OTSEC_CAPTURE_CACHE:-$HOME/.cache/otsec-captures}}
work=${2:-$(mktemp -d)}
zeek_image=zeek/zeek:8.0.4
mkdir -p "$work"
{
  echo "suricata: $(suricata -V 2>&1 | head -1)"
  echo "tshark:   $(tshark -v 2>/dev/null | head -1)"
  echo "zeek:     $(docker run --rm "$zeek_image" zeek --version)"
} > "$work/versions.txt"

grep -v '^#' "$manifest" | cut -f1 | sed 's/\.gz$//' | sort -u > "$work/captures.txt"
while read -r name; do
  pcap="$cache/$name"
  out="$work/$name"
  rm -rf "$out"; mkdir -p "$out/suricata" "$out/suricata-midstream" "$out/zeek"
  # Highest dissected layer per frame, as Wireshark sees it (reference dissector).
  tshark -r "$pcap" -T fields -e frame.protocols 2>/dev/null > "$out/tshark-protocols.txt" || true
  suricata -r "$pcap" -l "$out/suricata" -S "$here/control-ops.rules" -k none \
    --set app-layer.protocols.dnp3.enabled=yes \
    --set app-layer.protocols.modbus.enabled=yes \
    --set app-layer.protocols.enip.enabled=yes > /dev/null 2>&1
  # Same again with midstream pickup, for sessions whose TCP handshake predates
  # the capture (common for long-lived SCADA polling sessions).
  suricata -r "$pcap" -l "$out/suricata-midstream" -S "$here/control-ops.rules" -k none \
    --set stream.midstream=true \
    --set app-layer.protocols.dnp3.enabled=yes \
    --set app-layer.protocols.modbus.enabled=yes \
    --set app-layer.protocols.enip.enabled=yes > /dev/null 2>&1
  docker run --rm -v "$cache:/pcaps:ro" -v "$out/zeek:/out" -w /out "$zeek_image" \
    zeek -C -r "/pcaps/$name" LogAscii::use_json=T policy/misc/unknown-protocols > /dev/null 2>&1
done < "$work/captures.txt"

python3 -I "$here/summarize.py" "$work" "$here/results/coverage.md"
for f in goose-normal goose-disturbance-busbar goose-disturbance-breaker-failure goose-disturbance-underfrequency goose-ms-as1 goose-ms-as2 goose-ms-as3 goose-ms-as4 goose-composite; do
  echo "== $f"
  python3 -I "$here/goose_seq_check.py" "$cache/$f.pcapng"
done > "$here/results/goose-seq-check.txt"
cp "$work/versions.txt" "$here/results/versions.txt"
echo "work dir: $work"
