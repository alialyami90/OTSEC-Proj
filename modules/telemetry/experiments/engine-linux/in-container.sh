#!/bin/sh
# Runs inside a pinned engine container with no network (run.sh starts it
# with --network none): one engine configuration over every capture in
# /pcaps, each into /out/<capture>/<config>/, with the engine's exit code in
# exit-code. A failure on one capture is printed with the tail of the
# engine's stderr, and the loop goes on: that capture reads "not run".
# Usage: in-container.sh zeek|zeek-pipe|suricata|suricata-fifo CONFIG [engine arguments...]
#   zeek-pipe:     the capture reaches Zeek on stdin through a pipe,
#                  `cat FILE | zeek -r -`. run.sh records the pinned image's
#                  own `zeek --help` line for -r, which is the citation.
#   suricata-fifo: the capture reaches Suricata through a FIFO that `cat`
#                  writes, `suricata -r FIFO`: the engine under `timeout 60`,
#                  the writer under `timeout 30`, and after the first
#                  time-out every later capture is skipped, so a hang costs at
#                  most a minute and never the job (D6 on #630).
eng=$1
cfg=$2
shift 2
fifo() {
  rm -f in.fifo
  mkfifo in.fifo || return 125
  timeout 30 sh -c 'cat "$1" > in.fifo' sh "$p" &
  writer=$!
  timeout 60 suricata -c /cfg/suricata.yaml -r "$d/in.fifo" -l "$d" -k none --disable-detection "$@" > suricata-fifo.stderr 2>&1
  r=$?
  kill "$writer" 2> /dev/null
  wait "$writer" 2> /dev/null
  rm -f in.fifo
  return "$r"
}
timed_out=
for p in /pcaps/*; do
  case "$p" in *.pcap|*.pcapng|*.cap) ;; *) continue ;; esac
  n=$(basename "$p")
  n=${n%.*}
  d=/out/$n/$cfg
  mkdir -p "$d"
  cd "$d" || exit 1
  if [ -n "$timed_out" ]; then
    echo skipped > exit-code
    continue
  fi
  case $eng in
    zeek) zeek -C -r "$p" LogAscii::use_json=T "$@" > zeek.stderr 2>&1 ;;
    zeek-pipe) cat "$p" | zeek -C -r - LogAscii::use_json=T "$@" > zeek-pipe.stderr 2>&1 ;;
    suricata) suricata -c /cfg/suricata.yaml -r "$p" -l "$d" -k none --disable-detection "$@" > suricata.stderr 2>&1 ;;
    suricata-fifo) fifo "$@" ;;
    *) echo "unknown engine $eng" >&2; exit 2 ;;
  esac
  rc=$?
  echo "$rc" > exit-code
  [ "$eng" = suricata-fifo ] && [ "$rc" = 124 ] && timed_out=1
  [ "$rc" = 0 ] || { echo "$eng failed on $n ($cfg), exit $rc:"; tail -5 "$eng.stderr"; }
  # An engine that exits 0 can still warn about the capture (truncated,
  # unsupported, unreadable): print its first such lines either way.
  grep -iE '^[WE]: |warn|error|truncat|unknown file format' "$eng.stderr" 2> /dev/null | head -3 | sed "s|^|$eng $n ($cfg) says: |"
done
