#!/bin/sh
# Runs inside a pinned engine container with no network (run.sh starts it
# with --network none): one engine configuration over every capture in
# /pcaps, each into /out/<capture>/<config>/, with the engine's exit code in
# exit-code. A failure on one capture is printed with the tail of the
# engine's stderr, and the loop goes on: that capture reads "not run".
# Usage: in-container.sh zeek|suricata CONFIG [engine arguments...]
eng=$1
cfg=$2
shift 2
for p in /pcaps/*; do
  case "$p" in *.pcap|*.pcapng|*.cap) ;; *) continue ;; esac
  n=$(basename "$p")
  n=${n%.*}
  d=/out/$n/$cfg
  mkdir -p "$d"
  cd "$d" || exit 1
  case $eng in
    zeek) zeek -C -r "$p" LogAscii::use_json=T "$@" > zeek.stderr 2>&1 ;;
    suricata) suricata -c /cfg/suricata.yaml -r "$p" -l "$d" -k none --disable-detection "$@" > suricata.stderr 2>&1 ;;
    *) echo "unknown engine $eng" >&2; exit 2 ;;
  esac
  rc=$?
  echo "$rc" > exit-code
  [ "$rc" = 0 ] || { echo "$eng failed on $n ($cfg), exit $rc:"; tail -5 "$eng.stderr"; }
done
