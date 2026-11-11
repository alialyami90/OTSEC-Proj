#!/bin/sh
# E-D4-03 (D4, brief P4-4-S2, ADR-0009): the provisional engine on Linux.
# Pinned Zeek, stock, with a probe script of the project's own, and with
# the ICSNPP-DNP3 and ICSNPP-Modbus packages; pinned Suricata, with and
# without stream.midstream=true, as the comparison. Every engine runs in its
# pinned container with no network, over files only. Nothing here captures
# a network or contacts a device. Evidence class: simulated (Linux).
#
# Usage:
#   run.sh dnp3 WORK          GT-PCAP's DNP3 captures, rebuilt by D6's
#                             dnp3_cases.py and checked against dnp3.sha256,
#                             against the committed labels and, where it is
#                             in the checkout, D6's engine-pass-conditions.tsv
#   run.sh public WORK CACHE  MANIFEST.tsv's captures (already fetched into
#                             CACHE by fetch_captures.sh) and the captures in
#                             extra-captures.tsv
#   run.sh prp WORK CACHE     GT-PCAP's PRP pairs, labelled by tshark 4.2.2
#                             through D6's prp_check.py (tshark on PATH)
# Needs: docker, python3, curl, sha256sum. No apt package except tshark for
# the prp mode. Writes WORK/<mode>.md and WORK/versions.txt. The tables hold
# no pass condition of their own: the conditions are D6's (brief P4-4-S2).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
mode=$1
work=$2
mkdir -p "$work"
work=$(cd "$work" && pwd)
. "$here/pins.env"

# 1. The pins, checked before anything fetched runs.
docker pull -q "$ZEEK_IMAGE" > /dev/null
docker pull -q "$SURICATA_IMAGE" > /dev/null
zv=$(docker run --rm --network none "$ZEEK_IMAGE" zeek --version)
sv=$(docker run --rm --network none --entrypoint suricata "$SURICATA_IMAGE" -V 2>&1 | head -1)
case "$zv" in "$ZEEK_VERSION") ;; *) echo "Zeek image is not $ZEEK_VERSION: $zv" >&2; exit 1 ;; esac
case "$sv" in *"$SURICATA_VERSION"*) ;; *) echo "Suricata image is not $SURICATA_VERSION: $sv" >&2; exit 1 ;; esac
pkgs=$work/pkgs
rm -rf "$pkgs"
while read -r _ path; do
  repo=${path%%/*}
  case $repo in
    icsnpp-dnp3) commit=$ICSNPP_DNP3_COMMIT ;;
    icsnpp-modbus) commit=$ICSNPP_MODBUS_COMMIT ;;
  esac
  mkdir -p "$pkgs/$(dirname "$path")"
  curl -fsSL --retry 3 -o "$pkgs/$path" "https://raw.githubusercontent.com/cisagov/$repo/$commit/${path#*/}"
done < "$here/icsnpp.sha256"
(cd "$pkgs" && sha256sum -c --quiet "$here/icsnpp.sha256")
# Suricata's own suricata.yaml from the image, with only the eve types for
# DNP3 and Modbus added: the stock file comments out dnp3 and lists no
# modbus, so stock eve would hold no DNP3 function code. Checked by -T.
docker run --rm --network none --entrypoint cat "$SURICATA_IMAGE" /etc/suricata/suricata.yaml > "$work/suricata.yaml"
sed -i -E 's/^( +)#- dnp3$/\1- dnp3\n\1- modbus/' "$work/suricata.yaml"
grep -qE '^ +- dnp3$' "$work/suricata.yaml" && grep -qE '^ +- modbus$' "$work/suricata.yaml" || {
  echo "could not enable the dnp3 and modbus eve types in the image's suricata.yaml" >&2; exit 1; }
docker run --rm --network none -v "$work/suricata.yaml:/cfg/suricata.yaml:ro" --entrypoint suricata \
  "$SURICATA_IMAGE" -T -c /cfg/suricata.yaml --disable-detection > "$work/suricata-T.txt" 2>&1 || {
  cat "$work/suricata-T.txt" >&2; exit 1; }
docker run --rm --network none "$ZEEK_IMAGE" cat /usr/local/zeek/share/zeek/base/protocols/dnp3/consts.zeek > "$work/zeek-dnp3-consts.zeek"
{
  echo "zeek:      $zv"
  echo "zeek image: $ZEEK_IMAGE"
  echo "suricata:  $sv"
  echo "suricata image: $SURICATA_IMAGE"
  echo "icsnpp-dnp3:   $ICSNPP_DNP3_COMMIT (every file checked against icsnpp.sha256)"
  echo "icsnpp-modbus: $ICSNPP_MODBUS_COMMIT (every file checked against icsnpp.sha256)"
  echo "suricata.yaml: the image's own, with eve types dnp3 and modbus added (sha256 $(sha256sum < "$work/suricata.yaml" | cut -c1-64))"
} > "$work/versions.txt"

# 2. Every configuration over one directory of captures.
zeek_run() {
  docker run --rm --network none -v "$pcaps:/pcaps:ro" -v "$out:/out" -v "$here:/exp:ro" -v "$pkgs:/pkgs:ro" \
    "$ZEEK_IMAGE" sh /exp/in-container.sh zeek "$@"
}
suricata_run() {
  docker run --rm --network none -v "$pcaps:/pcaps:ro" -v "$out:/out" -v "$here:/exp:ro" \
    -v "$work/suricata.yaml:/cfg/suricata.yaml:ro" --entrypoint sh "$SURICATA_IMAGE" /exp/in-container.sh suricata \
    "$@" --set app-layer.protocols.dnp3.enabled=yes --set app-layer.protocols.modbus.enabled=yes
}
engines() {
  pcaps=$1
  out=$2
  mkdir -p "$out"
  zeek_run zeek
  zeek_run zeek-probe /exp/probe.zeek
  zeek_run zeek-icsnpp /pkgs/icsnpp-dnp3/scripts /pkgs/icsnpp-modbus/scripts
  suricata_run suricata
  suricata_run suricata-midstream --set stream.midstream=true
}

case $mode in
  dnp3)
    gt=$root/tests/fixtures/network/gt-pcap/dnp3
    rm -rf "$work/dnp3"
    python3 "$root/tests/integration/gt_pcap/dnp3_cases.py" "$work/dnp3" > /dev/null
    (cd "$work/dnp3" && sha256sum -c --quiet "$gt/dnp3.sha256")
    engines "$work/dnp3" "$work/out-dnp3"
    python3 -I "$here/table.py" dnp3 "$work/out-dnp3" "$gt" "$work" "$root" > "$work/dnp3.md"
    ;;
  public)
    cache=$3
    rm -rf "$work/public"
    mkdir -p "$work/public"
    grep -v '^#' "$root/tests/fixtures/network/public-ot-captures/MANIFEST.tsv" | cut -f1 | sed 's/\.gz$//' | while read -r n; do
      cp "$cache/$n" "$work/public/" 2>/dev/null || echo "not fetched: $n"
    done
    grep -v '^#' "$here/extra-captures.tsv" | while IFS="$(printf '\t')" read -r n sha url proto; do
      curl -fsSL --retry 5 --retry-delay 20 -o "$work/public/$n" "$url" || echo "not fetched: $n"
      echo "$sha  $work/public/$n" | sha256sum -c --status || { echo "MISMATCH or missing: $n"; rm -f "$work/public/$n"; }
    done
    engines "$work/public" "$work/out-public"
    python3 -I "$here/table.py" public "$work/out-public" > "$work/public.md"
    ;;
  prp)
    cache=$3
    rm -rf "$work/prp" "$work/labels"
    for f in dnp3-read dnp3-write dnp3-select-operate dnp3-malformed dnp3-digitalbond-part1 dnp3-digitalbond-part2 modbus modbus-digitalbond-part1 modbus-digitalbond-part2; do
      python3 "$root/tests/integration/gt_pcap/prp.py" "$cache/$f.pcap" "$work/prp" > /dev/null
    done
    (cd "$work/prp" && sha256sum -c --quiet "$root/tests/fixtures/network/gt-pcap/prp-derived.sha256")
    python3 "$root/tests/integration/gt_pcap/prp_check.py" "$work/prp" "$work/labels"
    echo "tshark:    $(tshark -v | head -1)" >> "$work/versions.txt"
    engines "$work/prp" "$work/out-prp"
    # E-D4-02's own checker, per configuration. It exits 1 on any failed
    # row, and every row fails while no stage discards PRP duplicates
    # (E-D4-02), so its exit code is recorded, not obeyed.
    rc=0
    python3 -I "$root/modules/telemetry/experiments/prp-engines/compare.py" "$work/out-prp" "$work/labels" \
      zeek zeek-probe zeek-icsnpp suricata suricata-midstream > "$work/prp.md" || rc=$?
    echo "compare.py exit code: $rc" >> "$work/prp.md"
    ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
cat "$work/$mode.md" "$work/versions.txt"
