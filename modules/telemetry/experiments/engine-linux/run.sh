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
#                             case, D4-87). Given HR-23's two builds,
#                             also every capture of D6's hr23_cases.py,
#                             checked against hr23.sha256, under C0, C1, C1p
#                             and C2 only (hr23_feed below)
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
#
# HR-23 (brief P4-4-HR23, stage 3; docs/phase4/D4-hr23-design.md, section
# 4.1): `zeek-probe` now carries part (a), and is C1. `zeek-probe-c0` is the
# control C0, the same image with the script as before part (a)
# (OtsecProbe::log_dir=F). When HR23_C1P_IMAGE and HR23_C2_IMAGE name the
# images zeek-patch/build.sh built, `zeek-probe-c1p` and `zeek-probe-c2` run
# too, on those images by ID. A fourth mode, `hr23-unit WORK`, runs D4's unit
# and negative tests of the patch (zeek-patch/dispatch_unit.py) on them.
#
# The script-hash check (docs/release.md section 8.4 item 3; D4-115 item 5):
# every Zeek container that has a mount is made, checked, run and removed
# by mountcheck.py (mc_run below) with the same options, image and Zeek
# command line as before, one capture per container (D1's ruling 6955678741
# on #744), so the measured run is unchanged and the rules are read before
# every Zeek process. Suricata's containers, the
# comparison, are left as they were: its image declares four VOLUMEs, which
# Docker makes writable for each container, and the check refuses any
# writable mount but /out. Each mode first shows the
# check's controls on this runner's Docker (mountcheck.py selftest), and
# stops the run when a rule fails on any container. Its record, with one
# line per container, ends the mode's table file (mc_record).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
mode=$1
work=$2
mkdir -p "$work"
work=$(cd "$work" && pwd)
. "$here/pins.env"
# The job's own stderr, kept on fd 9, so that a failed rule reaches the job
# log even from a container whose output a caller redirects.
exec 9>&2
mc=$work/containers-$mode
# A reused WORK must not carry an earlier invocation's containers into the
# record (D3's N3).
rm -rf "$mc"
# One engine container under mountcheck.py's rules: the arguments are those
# `docker run` took, less --rm. A failed rule stops the run.
mc_run() {
  mc_rc=0
  mc_counts
  MOUNTCHECK_LOG=/dev/fd/9 python3 -I "$here/mountcheck.py" run "$mc" $mc_count -- "$@" || mc_rc=$?
  mc_stop
  return $mc_rc
}
mc_stop() {
  if [ -e "$mc/FAILED" ]; then
    { echo "the script-hash check (docs/release.md section 8.4 item 3) failed; the run stops:"; cat "$mc/FAILED"; } >&9
    exit 1
  fi
}
# The check's controls, on this runner's Docker and the stock image, before
# any measured container; its table goes to WORK/mountcheck-<mode>.md.
mc_selftest() {
  python3 -I "$here/mountcheck.py" selftest "$ZEEK_IMAGE" "$here" "$work/mountcheck-selftest-$mode" > "$work/mountcheck-$mode.md" || {
    cat "$work/mountcheck-$mode.md" >&9
    echo "the script-hash check's controls did not all fail as expected; the run stops" >&9
    exit 1
  }
  cat "$work/mountcheck-$mode.md"
}
# The check's record of this mode, appended to FILE, which the workflow
# uploads (D6's N5): the controls, and mountcheck.py's summary, which reads
# every output folder again (output-unchanged) and fails on a rule failed.
# hr23-unit, and the dnp3 mode when it feeds HR-23's captures, print each
# output folder's hash without its entry count, and name only the container
# when its output folder changed or could not be hashed: the count or an
# entry's name would say which logs a held row's capture left (D4-112 item
# 1.3; #764; D1's ruling 2 on #769).
mc_counts() {
  mc_count=
  [ "$mode" != hr23-unit ] || mc_count=--no-count
  [ "$mode" != dnp3 ] || [ -z "$hr23" ] || mc_count=--no-count
}
mc_record() {
  mc_counts
  { echo; cat "$work/mountcheck-$mode.md"; python3 -I "$here/mountcheck.py" summary "$mc" $mc_count; } >> "$1" || {
    cat "$1" >&9
    echo "the script-hash check (docs/release.md section 8.4 item 3) failed; the run stops" >&9
    exit 1
  }
}

# 1. The pins, checked before anything fetched runs.
# HR-23's two builds, if given, are checked first: each must be an image ID
# present here, and report Zeek 9.0.1.
hr23=
if [ -n "${HR23_C1P_IMAGE:-}" ] || [ -n "${HR23_C2_IMAGE:-}" ]; then
  for img in "${HR23_C1P_IMAGE:-}" "${HR23_C2_IMAGE:-}"; do
    case $img in sha256:*) ;; *) echo "HR23_C1P_IMAGE and HR23_C2_IMAGE must both be image IDs (sha256:...)" >&2; exit 1 ;; esac
    v=$(docker run --rm --network none "$img" zeek --version)
    [ "$v" = "$ZEEK_VERSION" ] || { echo "HR-23 image $img is not $ZEEK_VERSION: $v" >&2; exit 1; }
  done
  hr23=1
fi
if [ "$mode" = hr23-unit ]; then
  [ -n "$hr23" ] || { echo "hr23-unit needs HR23_C1P_IMAGE and HR23_C2_IMAGE" >&2; exit 1; }
  u=$work/hr23-unit
  rm -rf "$u"
  python3 -I "$here/zeek-patch/dispatch_unit.py" write "$u/pcaps"
  mkdir -p "$u/out"
  # C0, the stock image with the script as before part (a), for D1's
  # experiment on #715 (the `*-first` cases are quoted under C0 too).
  docker pull -q "$ZEEK_IMAGE" > /dev/null
  zv=$(docker run --rm --network none "$ZEEK_IMAGE" zeek --version)
  [ "$zv" = "$ZEEK_VERSION" ] || { echo "Zeek image is not $ZEEK_VERSION: $zv" >&2; exit 1; }
  mc_selftest
  # (B')'s three controls (D1's ruling on #715, condition 4.5), when build.sh
  # built them; the check reads a missing control as not run, which fails.
  ctl=
  for m in STOCK_CATCH RAISE_RETHROW NO_VIOLATION; do
    eval "im=\${HR23_M_${m}_IMAGE:-}"
    [ -z "$im" ] || ctl="$ctl zeek-probe-m-$(echo "$m" | tr A-Z_ a-z-)=$im"
  done
  # Every configuration also loads zeek-patch/viol.zeek, which logs each
  # violation as raised (otsec_viol.log), for the check's three-state judge.
  # C1 (`zeek-probe`, the stock image with part (a)) runs for the one GT-PCAP
  # capture that dispatch_unit.py writes, dnp3-tcp-master-short (D4-116
  # item 6), whose pinned cells name C1; it runs over the d4u-* inputs too,
  # which `check` does not read under C1.
  for c in "zeek-probe-c0=$ZEEK_IMAGE=OtsecProbe::log_dir=F" "zeek-probe=$ZEEK_IMAGE" "zeek-probe-c1p=$HR23_C1P_IMAGE" "zeek-probe-c2=$HR23_C2_IMAGE" $ctl; do
    cfg=${c%%=*}
    rest=${c#*=}
    im=${rest%%=*}
    arg=
    [ "$im" = "$rest" ] || arg=${rest#*=}
    for p in "$u/pcaps"/*; do
      case $p in *.pcap|*.pcapng|*.cap) ;; *) continue ;; esac
      mc_run --network none -v "$u/pcaps:/pcaps:ro" -v "$u/out:/out" -v "$here:/exp:ro" \
        "$im" sh /exp/in-container.sh zeek "$cfg" "/pcaps/${p##*/}" /exp/probe.zeek /exp/zeek-patch/viol.zeek $arg
    done
  done
  rc=0
  { echo "# HR-23: D4's unit and negative tests of option (i)'s patch"; echo
    echo "D4's own inputs (\`d4u-*\`), and one GT-PCAP capture (dnp3-tcp-master-short, whether each configuration ran"
    echo "and its exit code only); no counted measurement reads them. Each test's"
    echo "control is C1p, the same tree without the patch. C0 (the stock image) runs for D1's experiment on #715."
    echo "(B')'s controls are C2 with one control patch each (zeek-patch/controls/)."; echo
    python3 -I "$here/zeek-patch/dispatch_unit.py" check "$u/out" || rc=$?; } > "$work/hr23-unit.md"
  mc_stop
  mc_record "$work/hr23-unit.md"
  cat "$work/hr23-unit.md"
  [ -z "${GITHUB_STEP_SUMMARY:-}" ] || cat "$work/hr23-unit.md" >> "$GITHUB_STEP_SUMMARY"
  exit $rc
fi
docker pull -q "$ZEEK_IMAGE" > /dev/null
docker pull -q "$SURICATA_IMAGE" > /dev/null
zv=$(docker run --rm --network none "$ZEEK_IMAGE" zeek --version)
sv=$(docker run --rm --network none --entrypoint suricata "$SURICATA_IMAGE" -V 2>&1 | head -1)
case "$zv" in "$ZEEK_VERSION") ;; *) echo "Zeek image is not $ZEEK_VERSION: $zv" >&2; exit 1 ;; esac
case "$sv" in *"$SURICATA_VERSION"*) ;; *) echo "Suricata image is not $SURICATA_VERSION: $sv" >&2; exit 1 ;; esac
mc_selftest
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
  if [ -n "$hr23" ]; then
    echo "HR-23 C1p image: $HR23_C1P_IMAGE"
    echo "HR-23 C2 image: $HR23_C2_IMAGE"
    # zeek-patch/build.sh's record, if this run has it: the lines that tie
    # each image to its binary and its generated parser.
    grep -E '^(## |zeek --version:|zeek binary sha256:|base image:|tarball:|signature:|patch:|configure:)' "$work/zeek-build.txt" 2> /dev/null || true
    grep -A2 '^generated parser:' "$work/zeek-build.txt" 2> /dev/null || true
  fi
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
    "- Run, for HR-23 (P4-4-HR23; \`zeek-probe-c0\`, \`zeek-probe\` as C1, \`zeek-probe-c1p\`, \`zeek-probe-c2\`): rehearsal: not the counted result (this header does not yet check the HR23_* pins in pins.env, D4-115 item 4 is open, and so are docs/release.md section 8.4 items 1, 2 and 4 to 7)" \
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
# One Zeek container per capture, in the order in-container.sh's own loop
# took them (D1's ruling 6955678741 on #744).
locked=
img=$ZEEK_IMAGE
zeek_run() {
  zr_e=$1
  zr_c=$2
  shift 2
  for zr_p in "$pcaps"/*; do
    case $zr_p in *.pcap|*.pcapng|*.cap) ;; *) continue ;; esac
    mc_run --network none $locked -v "$pcaps:/pcaps:ro" -v "$out:/out" -v "$here:/exp:ro" -v "$pkgs:/pkgs:ro" \
      "$img" sh /exp/in-container.sh "$zr_e" "$zr_c" "/pcaps/${zr_p##*/}" "$@"
  done
}
suricata_run() {
  sr_e=$1
  sr_c=$2
  shift 2
  docker run --rm --network none $locked -v "$pcaps:/pcaps:ro" -v "$out:/out" -v "$here:/exp:ro" \
    -v "$work/suricata.yaml:/cfg/suricata.yaml:ro" --entrypoint sh "$SURICATA_IMAGE" /exp/in-container.sh \
    "$sr_e" "$sr_c" all "$@" --set app-layer.protocols.dnp3.enabled=yes --set app-layer.protocols.modbus.enabled=yes
}
engines() {
  pcaps=$1
  out=$2
  mkdir -p "$out"
  zeek_run zeek zeek
  zeek_run zeek zeek-probe /exp/probe.zeek
  zeek_run zeek zeek-icsnpp /pkgs/icsnpp-dnp3/scripts /pkgs/icsnpp-modbus/scripts
  zeek_run zeek zeek-modbus-sig /exp/probe.zeek /exp/modbus-sig.zeek
  zeek_run zeek zeek-probe-c0 /exp/probe.zeek OtsecProbe::log_dir=F
  if [ -n "$hr23" ]; then
    img=$HR23_C1P_IMAGE
    zeek_run zeek zeek-probe-c1p /exp/probe.zeek
    img=$HR23_C2_IMAGE
    zeek_run zeek zeek-probe-c2 /exp/probe.zeek
    img=$ZEEK_IMAGE
  fi
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

# HR-23's feed (D4-120 item 3.7; the design's section 4.1): every capture
# D6's hr23_cases.py writes, and each capture of hr23-cases.tsv that
# dnp3_cases.py writes (hr23_feed.py extend, from WORK/dnp3, which the dnp3
# mode checked against dnp3.sha256; D1's ruling 3 on #776), left in only
# when it equals its pin in hr23.sha256 or dnp3.sha256
# (WORK/hr23-feed.sha256; hr23_feed.py pin, which removes every other file zeek_run
# would feed, by mountcheck.py's CAPTURE), under C0, C1, C1p and C2 with
# viol.zeek (its otsec_viol.log counts violations as raised; the judge reads
# analyzer.log, as hr23-conditions.tsv's mal-states says). The false-positive
# set (fp_set.py, fp.sha256) is fed the same way into its own folders.
# check judges the captures pin kept (WORK/hr23-kept.txt, WORK/fp-kept.txt). They have their
# own folders, so that no other table of this mode reads them. Some HR-23 rows
# are held from per-row publication (D4-112 item 1.3): each container's own
# output, in which in-container.sh prints the engine's warnings, goes to a
# file that is neither printed nor uploaded, and hr23_feed.py check prints only
# whether each configuration ran and its exit code, and for a held capture
# only that it is held. table.py hr23judge then judges what the brief
# P4-4-HR23-JUDGE and D1's rulings 7056743490 and 7057468942 on #776 allow
# to be printed. A held list that the check refuses (exit 1) stops the feed
# before any other table. Otherwise the first non-zero exit code is
# returned: 3 when, on refs/heads/main, a capture did not run cleanly under
# all four, or the held list or the salt is missing.
# -B: hr23_feed.py imports mountcheck.py, and without it python3 writes
# __pycache__ into $here, the folder mounted at /exp and hashed (D6's N1).
hr23_feed() {
  h=$work/hr23
  rm -rf "$h" "$work/out-hr23" "$work/fp" "$work/out-fp" "$work/ports-hr23"
  # The caller's `||` turns off set -e in here, so each step that can fail
  # returns on its own.
  python3 "$root/tests/integration/gt_pcap/hr23_cases.py" "$h" > /dev/null || return 1
  python3 -I -B "$here/hr23_feed.py" extend "$root/tests/fixtures/network/gt-pcap/hr23/hr23.sha256" \
    "$root/tests/fixtures/network/gt-pcap/dnp3/dnp3.sha256" "$root/tests/integration/gt_pcap/hr23-cases.tsv" \
    "$work/dnp3" "$h" "$work/hr23-feed.sha256" || return 1
  python3 -I -B "$here/hr23_feed.py" pin "$h" "$work/hr23-feed.sha256" "$work/hr23-kept.txt" || return 1
  # The false-positive set (D2's N2 = D6's G1 on #769), fed and pin-checked
  # the same way, into its own folders.
  python3 "$root/tests/integration/gt_pcap/fp_set.py" "$work/fp" > /dev/null || return 1
  python3 -I -B "$here/hr23_feed.py" pin "$work/fp" "$root/tests/fixtures/network/gt-pcap/fp/fp.sha256" "$work/fp-kept.txt" || return 1
  {
    for set in "$h=$work/out-hr23" "$work/fp=$work/out-fp"; do
      pcaps=${set%%=*}
      out=${set#*=}
      mkdir -p "$out"
      zeek_run zeek zeek-probe-c0 /exp/probe.zeek /exp/zeek-patch/viol.zeek OtsecProbe::log_dir=F
      zeek_run zeek zeek-probe /exp/probe.zeek /exp/zeek-patch/viol.zeek
      img=$HR23_C1P_IMAGE
      zeek_run zeek zeek-probe-c1p /exp/probe.zeek /exp/zeek-patch/viol.zeek
      img=$HR23_C2_IMAGE
      zeek_run zeek zeek-probe-c2 /exp/probe.zeek /exp/zeek-patch/viol.zeek
      img=$ZEEK_IMAGE
    done
  } > "$work/hr23-engines.txt" 2>&1
  # cfg-ports (D2's N1 on #769): likely_server_ports under each of the four
  # configurations, with its own scripts and image, from ports.zeek over one
  # kept capture of the false-positive set, which no held list can name
  # (D3's N1 on #776). Only ports.zeek's two lines are kept; the judge
  # prints them. The mount check's own lines for these containers (fd 9)
  # and its record go to WORK/ports-hr23 and WORK/containers-ports, neither
  # printed nor uploaded, so their exit codes and arguments stay off the job
  # log and dnp3.md; a rule that failed there still stops the run.
  mkdir -p "$work/ports-hr23"
  first=$(head -n 1 "$work/fp-kept.txt")
  mc_main=$mc
  mc=$work/containers-ports
  for c in "zeek-probe-c0=$ZEEK_IMAGE=OtsecProbe::log_dir=F" "zeek-probe=$ZEEK_IMAGE=" \
    "zeek-probe-c1p=$HR23_C1P_IMAGE=" "zeek-probe-c2=$HR23_C2_IMAGE="; do
    cfg=${c%%=*}
    rest=${c#*=}
    im=${rest%%=*}
    extra=${rest#*=}
    if [ -n "$first" ]; then
      # $extra is word-split on purpose: it is one Zeek argument or none.
      mc_run --network none -v "$work/fp:/pcaps:ro" -v "$here:/exp:ro" "$im" zeek -C -r "/pcaps/$first.pcap" \
        /exp/probe.zeek /exp/zeek-patch/viol.zeek $extra /exp/ports.zeek 2>&1 9>> "$work/ports-hr23/mountcheck.txt" \
        | grep '^likely_server_ports at ' > "$work/ports-hr23/$cfg.txt" || true
    fi
  done
  mc=$mc_main
  if [ -e "$work/containers-ports/FAILED" ]; then
    echo "the script-hash check (docs/release.md section 8.4 item 3) failed on the cfg-ports step; the run stops" >&2
    exit 1
  fi
  hr23_counted=
  [ "${GITHUB_REF:-local}" != refs/heads/main ] || hr23_counted=--counted
  rc=0
  python3 -I -B "$here/hr23_feed.py" check "$work/out-hr23" "$work/hr23-feed.sha256" "$work/hr23-kept.txt" \
    "$root/tests/integration/gt_pcap/hr23-cases.tsv" $hr23_counted || rc=$?
  # A refused held list (D1's ruling 1 on #776) stops here, before any other table.
  [ "$rc" != 1 ] || return 1
  python3 -I -B "$here/hr23_feed.py" check "$work/out-fp" "$root/tests/fixtures/network/gt-pcap/fp/fp.sha256" "$work/fp-kept.txt" $hr23_counted || { r=$?; [ "$rc" != 0 ] || rc=$r; }
  # HR-23's judge (brief P4-4-HR23-JUDGE): the malformed set, the
  # false-positive set and hr23-cases.tsv's rows against D6's conditions.
  # The held list and the salt (OTSEC_HR23_HELD, OTSEC_HR23_SALT) reach the
  # check and the judge from the environment at run time, never from a
  # committed file (D1's ruling 7056743490 on #776); without them neither
  # prints a per-capture row, and a counted run fails here. The list is
  # checked against the digest committed in hr23-held.hmac (D1's ruling 1).
  python3 -I -B "$here/table.py" hr23judge "$work/out-hr23" "$work/out-fp" "$work/fp-kept.txt" "$root" "$work/ports-hr23" "$h" $hr23_counted || { r=$?; [ "$rc" != 0 ] || rc=$r; }
  return "$rc"
}

# CH-53's and CH-57's requirements on the script (D4-102 item 6; D1's
# ruling 1 on #715): script_reqs.py's captures under its configurations,
# each a test or the control that undoes one requirement, on the stock
# image. Prints its table; returns non-zero on a row that did not pass.
reqs() {
  r=$work/reqs
  rm -rf "$r"
  python3 -I "$here/script_reqs.py" write "$r/pcaps"
  pcaps=$r/pcaps
  out=$r/out
  mkdir -p "$out"
  python3 -I "$here/script_reqs.py" configs > "$r/configs.txt"
  while read -r cfg args; do
    # $args is word-split on purpose: each word is one Zeek argument.
    zeek_run zeek "$cfg" /exp/probe.zeek /exp/script-reqs/reqtest.zeek $args < /dev/null
  done < "$r/configs.txt"
  python3 -I "$here/script_reqs.py" check "$out"
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
    mc_run --network none -v "$pcaps:/pcaps:ro" -v "$here:/exp:ro" "$ZEEK_IMAGE" \
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
    # Every table, count and engine line of this mode leaves out the held
    # list's captures, or, with no list accepted, every capture of
    # hr23-cases.tsv (table.py's hidden; D1's ruling 1 on #776). The
    # engines' own lines go to a file on the runner, and only held-log's
    # copy of them, without those captures, reaches the job log.
    dnp3_counted=
    [ "${GITHUB_REF:-local}" != refs/heads/main ] || dnp3_counted=--counted
    engines "$work/dnp3" "$work/out-dnp3" > "$work/dnp3-engines.txt"
    pipes "$work/dnp3" "$work/out-dnp3-pipe" >> "$work/dnp3-engines.txt"
    python3 -I -B "$here/table.py" held-log "$work/dnp3-engines.txt" "$root" $dnp3_counted
    feedrc=0
    if [ -n "$hr23" ]; then
      hr23_feed > "$work/hr23-feed.md" || feedrc=$?
    else
      printf '\n## HR-23 captures\n\nNot fed: this run has no HR-23 builds (HR23_C1P_IMAGE, HR23_C2_IMAGE), and no HR-23 result comes from it.\n' > "$work/hr23-feed.md"
    fi
    { header; python3 -I -B "$here/table.py" dnp3 "$work/out-dnp3" "$gt" "$work" "$root" $dnp3_counted
      python3 -I -B "$here/table.py" hr23 "$work/out-dnp3" "$root" $dnp3_counted; cat "$work/hr23-feed.md"; } > "$work/dnp3.md"
    if [ "$feedrc" != 0 ]; then
      cat "$work/dnp3.md" >&2
      echo "HR-23's feed: a capture did not run cleanly under C0, C1, C1p and C2 on a counted run, or the check did not finish (exit $feedrc); the job fails" >&2
      exit 1
    fi
    fifos "$work/dnp3" "$work/out-dnp3-pipe" > "$work/dnp3-fifo-engines.txt"
    python3 -I -B "$here/table.py" held-log "$work/dnp3-fifo-engines.txt" "$root" $dnp3_counted
    python3 -I -B "$here/table.py" fifo "$work/out-dnp3" "$work/out-dnp3-pipe" "$root" $dnp3_counted >> "$work/dnp3.md"
    reqrc=0
    reqs >> "$work/dnp3.md" || reqrc=$?
    if [ "$reqrc" != 0 ]; then
      cat "$work/dnp3.md" >&2
      echo "CH-53's or CH-57's requirements on the script: a row did not pass (exit $reqrc); the job fails" >&2
      exit 1
    fi
    ;;
  public)
    cache=$3
    rm -rf "$work/public"
    mkdir -p "$work/public"
    # Each MANIFEST capture is checked against its SHA-256 here, whatever
    # fetch_captures.sh left in the cache; a capture that fails is dropped,
    # and its rows read "not run (not fetched)" (D7 on #625). table.py lists
    # every capture of both lists, fetched or not; on refs/heads/main, where
    # every counted run is made, a capture not fetched fails the job after
    # public.md is written (D6's finding on #744, D4-118 item 2.5).
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
    counted=
    if [ "${GITHUB_REF:-local}" = refs/heads/main ]; then counted=--counted; fi
    pubrc=0
    { header
      python3 -I "$here/table.py" public "$work/out-public" "$work/public" \
        "$root/tests/fixtures/network/public-ot-captures/MANIFEST.tsv" "$here/extra-captures.tsv" $counted || pubrc=$?
      python3 -I -B "$here/table.py" hr23 "$work/out-public" "$root" $counted; } > "$work/public.md"
    if [ "$pubrc" != 0 ]; then
      echo "table.py public exited $pubrc (3: a listed capture was not fetched on a counted run; see public.md); the job fails" >&2
      exit 1
    fi
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
      zeek zeek-probe zeek-icsnpp zeek-modbus-sig zeek-probe-c0 ${hr23:+zeek-probe-c1p zeek-probe-c2} \
      suricata suricata-midstream >> "$work/prp.md" || rc=$?
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
mc_stop
mc_record "$work/$mode.md"
cat "$work/$mode.md" "$work/versions.txt"
