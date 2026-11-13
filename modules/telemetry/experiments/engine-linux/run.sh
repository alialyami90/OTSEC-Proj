#!/bin/sh
# E-D4-03 (D4, brief P4-4-S2, ADR-0009): the provisional engine on Linux.
# Pinned Zeek, stock, with a probe script of the project's own, and with
# the ICSNPP-DNP3 and ICSNPP-Modbus packages; pinned Suricata, with and
# without stream.midstream=true, as the comparison. Every engine runs in its
# pinned container with no network, over files only. Nothing here captures
# a network or contacts a device. Evidence class: simulated (Linux).
#
# Usage:
#   run.sh dnp3 WORK CACHE    GT-PCAP's DNP3 captures, rebuilt by D6's
#                             dnp3_cases.py and checked against dnp3.sha256;
#                             the derived modbus-moved-port, rebuilt by D6's
#                             movedport.py from CACHE's modbus.pcap and checked
#                             against its hash, with modbus.pcap as its
#                             control; all against the committed labels and,
#                             where it is in the checkout, D6's
#                             engine-pass-conditions.tsv. The same captures
#                             then reach each Zeek configuration through a
#                             pipe, and Suricata through a FIFO (the pipe
#                             case, D4-87)
#   run.sh public WORK CACHE  MANIFEST.tsv's captures (already fetched into
#                             CACHE by fetch_captures.sh) and the captures in
#                             extra-captures.tsv
#   run.sh prp WORK CACHE     GT-PCAP's PRP pairs, labelled by tshark 4.2.2
#                             through D6's prp_check.py (tshark on PATH);
#                             then P4-4-E2's measurement of the Modbus
#                             signature (sig, below), whose table is appended
#                             to prp.md: this is the job with the pinned
#                             tshark that its labeller and modbus_label.py
#                             need, and the workflow file is not changed
# Needs: docker, python3, curl, sha256sum. No apt package except tshark for
# the prp mode. Writes WORK/<mode>.md and WORK/versions.txt. The tables hold
# no pass condition of their own: the conditions are D6's (briefs P4-4-S2
# and P4-4-E2).
#
# P4-4-E2 (D4-90) adds a sixth configuration, `zeek-modbus-sig`: Zeek with
# the project's script and the Modbus/TCP content signature
# (modbus-sig.zeek), an experiment that is not adopted. It is S0 in D6's
# conditions for it, and `zeek-probe`, the approved configuration, is S1.
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
docker run --rm --network none "$ZEEK_IMAGE" cat /usr/local/zeek/share/zeek/base/protocols/modbus/consts.zeek > "$work/zeek-modbus-consts.zeek"
{
  echo "zeek:      $zv"
  echo "zeek image: $ZEEK_IMAGE"
  echo "suricata:  $sv"
  echo "suricata image: $SURICATA_IMAGE"
  echo "icsnpp-dnp3:   $ICSNPP_DNP3_COMMIT (every file checked against icsnpp.sha256)"
  echo "icsnpp-modbus: $ICSNPP_MODBUS_COMMIT (every file checked against icsnpp.sha256)"
  echo "suricata.yaml: the image's own, with eve types dnp3 and modbus added (sha256 $(sha256sum < "$work/suricata.yaml" | cut -c1-64))"
  # The engines' own words for reading a capture, cited by the pipe case.
  echo "zeek --help, -r: $(docker run --rm --network none "$ZEEK_IMAGE" zeek --help 2>&1 | grep -e '--readfile' | head -1 || true)"
  echo "suricata --help, -r: $(docker run --rm --network none --entrypoint suricata "$SURICATA_IMAGE" --help 2>&1 | grep -e '-r <path>' | head -1 || true)"
} > "$work/versions.txt"
# A later mode rewrites versions.txt, so the pipe case's options are kept in
# a file of their own and copied in each time.
cat "$work/pipe-options.txt" >> "$work/versions.txt" 2> /dev/null || true

# Every table opens with what ran and whether it counts (D1 and D6 on #625):
# a run counts only on refs/heads/main with D6's pass conditions present and
# equal to the reviewed file pinned in pins.env.
header() {
  commit=${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown)}
  ref=${GITHUB_REF:-local}
  cond=$root/tests/integration/gt_pcap/engine-pass-conditions.tsv
  if [ -f "$cond" ]; then ch=$(sha256sum < "$cond" | cut -c1-64); else ch=absent; fi
  if [ "$ch" = "$CONDITIONS_SHA256" ]; then pinned="equals the pin"; else pinned="differs from the pin $CONDITIONS_SHA256"; fi
  if [ "$ref" = refs/heads/main ] && [ "$ch" = "$CONDITIONS_SHA256" ]; then
    kind=counted
  else
    kind="rehearsal: not the counted result"
  fi
  # P4-4-E2 (D6's `judge-counted`): its measurement counts only from
  # refs/heads/main with D6's conditions for it, engine-pass-conditions.tsv,
  # the corpus manifest and the corpus labels each equal to its pin.
  why=
  for p in "tests/integration/gt_pcap/modbus-signature-conditions.tsv $MODBUS_SIGNATURE_CONDITIONS_SHA256" \
           "tests/integration/gt_pcap/engine-pass-conditions.tsv $CONDITIONS_SHA256" \
           "tests/fixtures/network/modbus-sig-corpus/corpus.tsv $MODBUS_SIG_CORPUS_SHA256" \
           "tests/fixtures/network/modbus-sig-corpus/labels.tsv $MODBUS_SIG_LABELS_SHA256"; do
    f=${p% *}
    pin=${p##* }
    if [ ! -f "$root/$f" ]; then h=absent; else h=$(sha256sum < "$root/$f" | cut -c1-64); fi
    pins="${pins:-}- $f SHA-256: $h ($( [ "$h" = "$pin" ] && echo "equals the pin" || echo "differs from the pin ${pin:-(none)}"))
"
    [ "$h" = "$pin" ] || why="${why:+$why; }$f is not at its pin"
  done
  [ "$ref" = refs/heads/main ] || why="${why:+$why; }not refs/heads/main"
  if [ -n "$why" ]; then sig="rehearsal: not the counted result ($why)"; else sig="counted"; fi
  printf '%s\n' "- Run, for E-D4-03's conditions: $kind" "- Run, for P4-4-E2 (the Modbus signature, \`zeek-modbus-sig\`): $sig" \
    "- Commit: $commit" "- Ref: $ref" "- engine-pass-conditions.tsv SHA-256: $ch ($pinned)"
  printf '%s\n' "$pins"
  pins=
}

# 2. Every configuration over one directory of captures.
# Each takes the in-container mode first (zeek or zeek-pipe; suricata or
# suricata-fifo), then the configuration's name and its arguments.
# The pipe case adds $locked: every capability dropped, no new privileges,
# and the runner's own user, which is not root (D3 on #630). The file runs
# keep Docker's defaults, which is what E-D4-03 first ran.
locked=
zeek_run() {
  docker run --rm --network none $locked -v "$pcaps:/pcaps:ro" -v "$out:/out" -v "$here:/exp:ro" -v "$pkgs:/pkgs:ro" \
    "$ZEEK_IMAGE" sh /exp/in-container.sh "$@"
}
suricata_run() {
  docker run --rm --network none $locked -v "$pcaps:/pcaps:ro" -v "$out:/out" -v "$here:/exp:ro" \
    -v "$work/suricata.yaml:/cfg/suricata.yaml:ro" --entrypoint sh "$SURICATA_IMAGE" /exp/in-container.sh \
    "$@" --set app-layer.protocols.dnp3.enabled=yes --set app-layer.protocols.modbus.enabled=yes
}
engines() {
  pcaps=$1
  out=$2
  mkdir -p "$out"
  zeek_run zeek zeek
  zeek_run zeek zeek-probe /exp/probe.zeek
  zeek_run zeek zeek-icsnpp /pkgs/icsnpp-dnp3/scripts /pkgs/icsnpp-modbus/scripts
  zeek_run zeek zeek-modbus-sig /exp/probe.zeek /exp/modbus-sig.zeek
  suricata_run suricata suricata
  suricata_run suricata suricata-midstream --set stream.midstream=true
}
# The pipe case (D4-87): the same three Zeek configurations, each reading
# its capture from stdin through a pipe, and Suricata from a FIFO, as a
# note. Still --network none.
# Its own output directory, created by the runner's user so that the
# unprivileged containers can write there. If an engine fails under these
# options, that is a finding and the row stays: the options are not relaxed.
pipes() {
  pcaps=$1
  out=$2
  mkdir -p "$out"
  locked="--cap-drop ALL --security-opt no-new-privileges --user $(id -u):$(id -g)"
  echo "pipe case containers (Zeek pipe and Suricata FIFO): --network none $locked" > "$work/pipe-options.txt"
  cat "$work/pipe-options.txt" >> "$work/versions.txt"
  zeek_run zeek-pipe zeek-pipe
  zeek_run zeek-pipe zeek-probe-pipe /exp/probe.zeek
  zeek_run zeek-pipe zeek-icsnpp-pipe /pkgs/icsnpp-dnp3/scripts /pkgs/icsnpp-modbus/scripts
  locked=
}
# Suricata through a FIFO, as a note, run after the judged tables are written.
fifos() {
  pcaps=$1
  out=$2
  locked="--cap-drop ALL --security-opt no-new-privileges --user $(id -u):$(id -g)"
  suricata_run suricata-fifo suricata-fifo
  locked=
}

# P4-4-E2 (D4-90): the Modbus signature against D6's conditions for it
# (tests/integration/gt_pcap/modbus-signature-conditions.tsv). Every corpus
# member (tests/fixtures/network/modbus-sig-corpus/corpus.tsv) is fetched at
# its pin, or written by its writer, and checked; one that fails is left out
# and its rows read "not run". A held-out Modbus capture on 502 is moved to
# 15020 by D6's movedport.py, checked against its pin, and labelled there by
# D6's modbus_label.py with the pinned tshark (held-502); a synthesized one
# off 502 is labelled as written (held-other). The corpus's labels are
# regenerated by corpus_label.py and compared with the committed ones, which
# decide. S1 (`zeek-probe`) and S0 (`zeek-modbus-sig`) then run over every
# file, and likely_server_ports is printed under each (ports.zeek).
sig() {
  cache=$1
  s=$work/sig
  corpus=$root/tests/fixtures/network/modbus-sig-corpus
  gp=$root/tests/integration/gt_pcap
  rm -rf "$s"
  mkdir -p "$s/pcaps" "$s/fetch" "$s/labels"
  python3 "$gp/dnp3_cases.py" "$s/gt" > /dev/null
  python3 "$here/synth_corpus.py" "$s/synth"
  grep -v '^#' "$corpus/corpus.tsv" | tail -n +2 | while IFS="$(printf '\t')" read -r n sha url src lic proto mb sport moved seen; do
    case $url in
      writer:*dnp3_cases.py) f=$s/gt/$n ;;
      writer:*synth_corpus.py) f=$s/synth/$n ;;
      *) f=$cache/$n
         if ! echo "$sha  $f" | sha256sum -c --status 2> /dev/null; then
           f=$s/fetch/$n
           curl -fsSL --retry 5 --retry-delay 20 -o "$f" "$url" || echo "not fetched: $n"
         fi ;;
    esac
    if ! echo "$sha  $f" | sha256sum -c --status; then
      echo "MISMATCH or missing, left out: $n"
      continue
    fi
    case $n in *.gz) n=${n%.gz}; gunzip -c "$f" > "$s/pcaps/$n" ;; *) cp "$f" "$s/pcaps/$n" ;; esac
    st=${n%.*}
    # Empty fields are written `-`: a tab is whitespace to `read`, so an
    # empty field would shift the next one into its place.
    if [ "$moved" != - ]; then
      if python3 "$gp/movedport.py" "$s/pcaps/$n" "$s/pcaps" > /dev/null \
        && echo "$moved  $s/pcaps/$st-moved-port.pcap" | sha256sum -c --status; then
        python3 "$gp/modbus_label.py" "$s/pcaps/$n" "$s/pcaps/$st-moved-port.pcap" 15020 "$s/labels/$st-moved-port.tsv" \
          || { echo "modbus_label.py refused $st-moved-port; its flows are listed and in no count"; rm -f "$s/labels/$st-moved-port.tsv"; }
      else
        echo "the moved capture of $n did not check out; it is left out, and its held-out flows are listed"
        rm -f "$s/pcaps/$st-moved-port.pcap"
      fi
    fi
    case $mb in tcp/15020)
      python3 "$gp/modbus_label.py" "$s/pcaps/$n" "$s/pcaps/$n" 15020 "$s/labels/$st.tsv" \
        || { echo "modbus_label.py refused $st; its flows are listed and in no count"; rm -f "$s/labels/$st.tsv"; } ;;
    esac
  done
  python3 -I "$here/flows.py" "$s/pcaps"/* > "$s/flows.tsv"
  python3 -I "$here/corpus_label.py" "$corpus/corpus.tsv" "$s/pcaps" "$s/flows.tsv" "$s/labels.tsv"     || { echo "corpus_label.py failed; the labels are not regenerated in this run"; rm -f "$s/labels.tsv"; }
  pcaps=$s/pcaps
  out=$s/out
  mkdir -p "$out"
  zeek_run zeek zeek-probe /exp/probe.zeek
  zeek_run zeek zeek-modbus-sig /exp/probe.zeek /exp/modbus-sig.zeek
  for c in "zeek-probe /exp/probe.zeek" "zeek-modbus-sig /exp/probe.zeek /exp/modbus-sig.zeek"; do
    set -- $c
    cfg=$1
    shift
    docker run --rm --network none -v "$pcaps:/pcaps:ro" -v "$here:/exp:ro" "$ZEEK_IMAGE" \
      zeek -C -r /pcaps/synth-modbus-server-first.pcap "$@" /exp/ports.zeek > "$s/ports-$cfg.txt" 2>&1 || true
    sed "s/^/$cfg: /" "$s/ports-$cfg.txt"
  done
  {
    echo "S1, zeek-probe: probe.zeek $(sha256sum < "$here/probe.zeek" | cut -c1-64)"
    echo "S0, zeek-modbus-sig: probe.zeek $(sha256sum < "$here/probe.zeek" | cut -c1-64)"
    echo "S0, zeek-modbus-sig: modbus-sig.zeek $(sha256sum < "$here/modbus-sig.zeek" | cut -c1-64)"
    echo "S0, zeek-modbus-sig: modbus-sig.sig $(sha256sum < "$here/modbus-sig.sig" | cut -c1-64)"
  } > "$s/hashes.txt"
  { header; python3 -I "$here/table.py" sig "$s" "$root" "$work"; } > "$work/sig.md"
  # Until labels.tsv is committed, the labels this run wrote go into the
  # artifact, whole, so that they can be reviewed and committed as written.
  if [ ! -f "$corpus/labels.tsv" ] && [ -f "$s/labels.tsv" ]; then
    printf '\n### labels.tsv as this run wrote it (SHA-256 %s), for review and commit\n\n```\n' \
      "$(sha256sum < "$s/labels.tsv" | cut -c1-64)" >> "$work/sig.md"
    cat "$s/labels.tsv" >> "$work/sig.md"
    printf '```\n' >> "$work/sig.md"
  fi
}

case $mode in
  dnp3)
    cache=$3
    gt=$root/tests/fixtures/network/gt-pcap
    rm -rf "$work/dnp3"
    python3 "$root/tests/integration/gt_pcap/dnp3_cases.py" "$work/dnp3" > /dev/null
    (cd "$work/dnp3" && sha256sum -c --quiet "$gt/dnp3/dnp3.sha256")
    # The derived Modbus case (D6's note, section 3) and its control: the
    # source is checked against MANIFEST.tsv, the derived capture against its
    # pinned hash. If either check fails, both are left out and their rows
    # read "unknown (not run)".
    src_sha=$(grep '^modbus\.pcap	' "$root/tests/fixtures/network/public-ot-captures/MANIFEST.tsv" | cut -f2)
    if echo "$src_sha  $cache/modbus.pcap" | sha256sum -c --status \
      && python3 "$root/tests/integration/gt_pcap/movedport.py" "$cache/modbus.pcap" "$work/dnp3" \
      && (cd "$work/dnp3" && sha256sum -c --quiet "$gt/modbus/modbus-moved-port.sha256"); then
      cp "$cache/modbus.pcap" "$work/dnp3/modbus.pcap"
    else
      echo "modbus-moved-port or its control did not check out; left out"
      rm -f "$work/dnp3/modbus-moved-port.pcap"
    fi
    engines "$work/dnp3" "$work/out-dnp3"
    pipes "$work/dnp3" "$work/out-dnp3-pipe"
    { header; python3 -I "$here/table.py" dnp3 "$work/out-dnp3" "$gt" "$work" "$root"; } > "$work/dnp3.md"
    fifos "$work/dnp3" "$work/out-dnp3-pipe"
    python3 -I "$here/table.py" fifo "$work/out-dnp3" "$work/out-dnp3-pipe" >> "$work/dnp3.md"
    ;;
  public)
    cache=$3
    rm -rf "$work/public"
    mkdir -p "$work/public"
    # Each MANIFEST capture is checked against its SHA-256 here, whatever
    # fetch_captures.sh left in the cache; a capture that fails is dropped,
    # and its rows read "not run" (D7 on #625).
    grep -v '^#' "$root/tests/fixtures/network/public-ot-captures/MANIFEST.tsv" | while IFS="$(printf '\t')" read -r n sha url proto label; do
      if echo "$sha  $cache/$n" | sha256sum -c --status; then
        case $n in
          *.gz) gunzip -c "$cache/$n" > "$work/public/${n%.gz}" ;;
          *) cp "$cache/$n" "$work/public/" ;;
        esac
      else
        echo "MISMATCH or missing, dropped: $n"
      fi
    done
    grep -v '^#' "$here/extra-captures.tsv" | while IFS="$(printf '\t')" read -r n sha url proto; do
      curl -fsSL --retry 5 --retry-delay 20 -o "$work/public/$n" "$url" || echo "not fetched: $n"
      echo "$sha  $work/public/$n" | sha256sum -c --status || { echo "MISMATCH or missing: $n"; rm -f "$work/public/$n"; }
    done
    engines "$work/public" "$work/out-public"
    { header; python3 -I "$here/table.py" public "$work/out-public"; } > "$work/public.md"
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
    # E-D4-02's own checker, per configuration. It exits 1 on any row that
    # failed or did not run, and every row fails while no stage discards PRP
    # duplicates (E-D4-02), so exit 1 with every row run is the measurement,
    # and the job stays green. The job says so in its summary, beside the
    # table (D4-88). It fails instead when a row did not run or the checker
    # did not finish, because those are faults of the run, not the result.
    rc=0
    header > "$work/prp.md"
    python3 -I "$root/modules/telemetry/experiments/prp-engines/compare.py" "$work/out-prp" "$work/labels" \
      zeek zeek-probe zeek-icsnpp zeek-modbus-sig suricata suricata-midstream >> "$work/prp.md" || rc=$?
    echo "compare.py exit code: $rc" >> "$work/prp.md"
    notrun=$(grep -c '| not run |$' "$work/prp.md" || true)
    case $rc in
      0) state="**The PRP comparison passed on every row.** That is not the result E-D4-02 and E-D4-03 found (every configuration counted both LAN copies), and nothing in this harness discards PRP duplicates, so read \`prp.md\` before relying on it." ;;
      1) state="**The PRP comparison failed** (\`compare.py\` exit code 1): each row whose \`pass\` column reads \`no\` is in the table above. That is the expected result while no stage discards PRP duplicates before the engine: every configuration counts both LAN copies (E-D4-02; D4-69). **This job is green because \`run.sh\` records the comparison's exit code and does not obey it:** the comparison measures the engines alone, without the duplicate-discard stage that the sensor must add, so a failed row is the measurement, not a fault of the run. The job fails instead if a row did not run or the checker did not finish." ;;
      *) state="**The PRP comparison did not finish** (\`compare.py\` exit code $rc). The job fails." ;;
    esac
    if [ "$rc" = 1 ] && [ "$notrun" != 0 ]; then
      state="**The PRP comparison did not run on every row:** $notrun row(s) read \`not run\` (an engine did not run on a capture). The job fails, because that is a fault of the run, not the measurement."
    fi
    printf '\n%s\n' "$state" >> "$work/prp.md"
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      printf '## PRP pairs (E-D4-02, E-D4-03)\n\n%s\n' "$state" >> "$GITHUB_STEP_SUMMARY"
    fi
    # P4-4-E2, in this job for its tshark (sig, above). A run in which the
    # measurement did not finish fails the job after the PRP statement.
    sigrc=0
    sig "$cache" || sigrc=$?
    grep -q '^## P4-4-E2' "$work/sig.md" 2> /dev/null || [ "$sigrc" != 0 ] || sigrc=1
    cat "$work/sig.md" >> "$work/prp.md" 2> /dev/null || true
    if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
      cat "$work/sig.md" >> "$GITHUB_STEP_SUMMARY" 2> /dev/null || true
    fi
    [ "$sigrc" = 0 ] || { echo "P4-4-E2's measurement did not finish (exit $sigrc); the job fails" >&2; cat "$work/prp.md" >&2; exit 1; }
    case $rc in
      1) [ "$notrun" = 0 ] || { cat "$work/prp.md" >&2; exit 1; }
         echo "::warning title=PRP comparison failed (expected; job green by design)::Every configuration counts both LAN copies; no stage discards PRP duplicates before the engine (E-D4-02). See the job summary and prp.md." ;;
      0) ;;
      *) cat "$work/prp.md" >&2; exit 1 ;;
    esac
    ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
cat "$work/$mode.md" "$work/versions.txt"
