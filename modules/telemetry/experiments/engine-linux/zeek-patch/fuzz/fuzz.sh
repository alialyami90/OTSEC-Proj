#!/bin/sh
# HR-23's sanitizer fuzz run (brief P4-4-HR23-FUZZ; docs/phase4/
# D4-hr23-design.md, section 4.6). D4 wrote it; D6 runs it and judges it,
# by hand, from .github/workflows/d4-zeek-dnp3-fuzz.yml on a GitHub-hosted
# runner, never on the owner's PC.
#
# Usage: fuzz.sh build WORK      checks every input (build.sh verify, then
#                                fuzz.env's pins), then builds C1p and C2's
#                                fuzz targets with ASan, UBSan and coverage,
#                                and writes WORK/fuzz/record.txt
#        fuzz.sh seeds WORK      writes the captures, converts them with
#                                seeds.py, and checks the corpus pin
#        fuzz.sh campaign WORK TARGET
#                                runs TARGET (dnp3_tcp, dnp3_udp or packet)
#                                on C1p and C2 at once, for HR23_FUZZ_SECONDS
#        fuzz.sh replay WORK     replays every input that gave a report, alone,
#                                on both builds, with the same options
#        fuzz.sh coverage WORK   replays C2's final corpus of each target on
#                                C2 for coverage, and checks the coverage
#                                condition (fuzz_judge.py coverage)
#        fuzz.sh summary WORK    prints the summary: pass or fail, and counts
#
# Disclosure (section 4.6; D4-112 item 1). Everything a fuzzer, a replay or
# a sanitizer writes goes to WORK/fuzz/private, which no step prints or
# uploads. Only `summary` prints, and it prints only what fuzz_judge.py
# writes: fixed words, counts and pinned hashes (test_hr23_fuzz.py). Every
# build, campaign and replay runs with no network (`nonet`). Nothing here
# captures traffic or contacts a device.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
patchdir=$(cd "$here/.." && pwd)
root=$(cd "$here/../../../../../.." && pwd)
mode=$1
work=$2
. "$patchdir/build.env"
. "$here/fuzz.env"
mkdir -p "$work"
work=$(cd "$work" && pwd)
f=$work/fuzz
priv=$f/private
mkdir -p "$priv"
chmod 700 "$priv"
fail() { echo "fuzz.sh: $*" >&2; exit 1; }
pin() {
  h=$(sha256sum < "$1" | cut -c1-64)
  [ "$h" = "$2" ] || fail "$(basename "$1") has SHA-256 $h, not the pin $2"
}
V=$HR23_FUZZ_CLANG
TARGETS="dnp3_tcp dnp3_udp packet"

# The command with no network: a new network namespace, as the caller's
# own user. The environment is only what the caller names after `env`.
nonet() {
  if [ "$(id -u)" = 0 ]; then
    unshare --net -- env -i HOME="$HOME" PATH="$PATH" "$@"
  else
    sudo -n unshare --net -- setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups -- \
      env -i HOME="$HOME" PATH="$PATH" "$@"
  fi
}

# The libFuzzer options of every campaign and replay (fuzz.env).
fopts="-timeout=$HR23_FUZZ_TIMEOUT -rss_limit_mb=$HR23_FUZZ_RSS_LIMIT_MB -max_len=$HR23_FUZZ_MAX_LEN -seed=$HR23_FUZZ_SEED -detect_leaks=$HR23_FUZZ_DETECT_LEAKS -report_slow_units=$HR23_FUZZ_SLOW_UNITS -print_final_stats=1"

# One build's fuzzer TARGET, with its options and its sanitizer settings,
# under nonet; the caller redirects its output into WORK/fuzz/private.
fuzzer() {
  # Its own names: sh has no local variables, and the replay loop's $b and
  # $t must survive this call.
  fz_b=$1 fz_t=$2
  shift 2
  zp=$(cat "$f/$fz_b/zeekpath")
  nonet env ZEEKPATH="$zp" ASAN_OPTIONS="$HR23_FUZZ_ASAN_OPTIONS" UBSAN_OPTIONS="$HR23_FUZZ_UBSAN_OPTIONS" \
    LLVM_PROFILE_FILE="${PROFILE:-$priv/discard-%p.profraw}" \
    "$f/$fz_b/zeek-9.0.1/build/src/fuzzers/zeek-$fz_t-fuzzer" $fopts "$@"
}

case $mode in
build)
  sh "$patchdir/build.sh" verify "$work"
  pin "$here/hr23-fuzz-harness.patch" "$HR23_FUZZ_HARNESS_SHA256"
  pin "$here/hr23-crc-mutator.cc" "$HR23_FUZZ_MUTATOR_SHA256"
  for p in clang-$V clang++-$V llvm-profdata-$V llvm-cov-$V; do
    command -v $p > /dev/null || fail "$p is not installed"
  done
  tarball=$work/zeek-src/$(basename "$ZEEK_TARBALL_URL")
  cov=$HR23_FUZZ_COVERAGE_FLAGS
  for b in c1p c2; do
    rm -rf "$f/$b"
    mkdir -p "$f/$b"
    tar xzf "$tarball" -C "$f/$b"
    s=$f/$b/zeek-9.0.1
    # Option (i)'s patch in C2 only; the harness in both.
    if [ $b = c2 ]; then patch -d "$s" -p1 --fuzz=0 --no-backup-if-mismatch < "$patchdir/hr23-fc-dispatch.patch" > /dev/null; fi
    patch -d "$s" -p1 --fuzz=0 --no-backup-if-mismatch < "$here/hr23-fuzz-harness.patch" > /dev/null
    cp "$here/hr23-crc-mutator.cc" "$s/src/fuzzers/"
    (cd "$s" && nonet env CC=clang-$V CXX=clang++-$V LIB_FUZZING_ENGINE=-fsanitize=fuzzer ZEEK_TAILORED_UB_CHECKS=1 \
      CFLAGS="$cov" CXXFLAGS="$cov" LDFLAGS="$cov -fsanitize=address,undefined" \
      ./configure --build-dir=build --generator=Ninja --build-type=debug \
        --sanitizers="$HR23_FUZZ_SANITIZERS" --enable-fuzzers \
        --enable-static-binpac \
        --disable-btest-pcaps --disable-broker-tests --disable-cpp-tests \
        --disable-zkg --disable-zeekctl --disable-javascript --disable-python \
        --disable-cluster-backend-zeromq --disable-af-packet) > "$f/$b/configure.log" 2>&1 \
      || { grep -A8 "CMake Error" "$f/$b/configure.log" | head -60 >&2; fail "$b: configure failed"; }
    # binpac is linked statically, as in Zeek's OSS-Fuzz build: with binpac
    # and Broker as shared libraries beside libzeek_fuzzer_shared.so, ASan's
    # start-up check reported an ODR violation (smoke run 44008961055) and
    # no fuzzer started. A static Broker does not configure with
    # --sanitizers in 9.0.1 (smoke run 44017063571); the duplicate left is
    # SQLite's, which fuzz.env's detect_odr_violation=1 passes (same size).
    # Spicy is on, as in the measured image (fuzz.env).
    # The build's own tools (bifcl, binpac, spicyz) link the sanitizer
    # runtimes through LDFLAGS; LSan is off for them as for the run, and
    # their ODR check is the run's (fuzz.env).
    nonet env ASAN_OPTIONS=detect_leaks=0:detect_odr_violation=1 ninja -C "$s/build" $(for t in $TARGETS; do printf 'zeek-%s-fuzzer ' "$t"; done) > "$f/$b/ninja.log" 2>&1 \
      || { grep -E 'error|FAILED' "$f/$b/ninja.log" | head -40 >&2; fail "$b: build failed"; }
    sh -c ". '$s/build/zeek-path-dev.sh' && printf '%s' \"\$ZEEKPATH\"" > "$f/$b/zeekpath"
    # Zeek 9.0.1's CMake sets no output folder for zeek_fuzzer_shared, so
    # its place in the build tree is found, and must be one file.
    (cd "$s/build" && find . -name libzeek_fuzzer_shared.so -type f) > "$f/$b/sharedlib"
    [ "$(wc -l < "$f/$b/sharedlib")" = 1 ] || fail "$b: not exactly one libzeek_fuzzer_shared.so in the build"
    # Zeek's tailored UB checks, and the flag that makes a UBSan report stop
    # the run (fuzz.env).
    grep -q -- "-fno-sanitize-recover=$HR23_FUZZ_UB_CHECKS " "$s/build/build.ninja" \
      || fail "$b: the build lines do not carry -fno-sanitize-recover=HR23_FUZZ_UB_CHECKS"
  done
  # The two builds differ in option (i)'s generated parser, so the patch is
  # in C2 and not in C1p.
  for b in c1p c2; do
    (cd "$f/$b/zeek-9.0.1/build" && sha256sum $(find . -name 'dnp3_pac.cc' -o -name 'dnp3_pac.h' | sort)) > "$f/$b/generated.sha256"
  done
  ! cmp -s "$f/c1p/generated.sha256" "$f/c2/generated.sha256" || fail "C1p and C2 have the same generated DNP3 parser"
  rec=$f/record.txt
  {
    echo "runner image: ${ImageOS:-unknown} ${ImageVersion:-unknown}"
    echo "clang: $(clang-$V --version | head -1)"
    echo "packages: $(dpkg-query -W -f '${Package}=${Version} ' clang-$V libclang-rt-$V-dev llvm-$V libpcap-dev libssl-dev flex bison cmake ninja-build 2> /dev/null)"
    echo "tarball: sha256 $ZEEK_TARBALL_SHA256 (build.sh verify: signature by subkey $ZEEK_SIGNING_SUBKEY_FPR)"
    echo "option (i)'s patch: sha256 $HR23_PATCH_SHA256 (C2 only)"
    echo "harness patch: sha256 $HR23_FUZZ_HARNESS_SHA256 (both)"
    echo "mutator: sha256 $HR23_FUZZ_MUTATOR_SHA256 (both)"
    echo "sanitizers: $HR23_FUZZ_SANITIZERS, UB checks $HR23_FUZZ_UB_CHECKS, -fno-sanitize-recover for them checked in both builds' lines"
    echo "coverage flags: $cov (both)"
    echo "configure: Spicy on, binpac static, the rest as in this file (both)"
    for b in c1p c2; do
      echo "## $b"
      echo "generated parser:"
      cat "$f/$b/generated.sha256"
      echo "binaries (sha256):"
      (cd "$f/$b/zeek-9.0.1/build" && sha256sum "$(cat "$f/$b/sharedlib")" $(for t in $TARGETS; do printf 'src/fuzzers/zeek-%s-fuzzer ' "$t"; done))
    done
  } > "$rec"
  cat "$rec"
  ;;
seeds)
  pin "$here/seeds.py" "$HR23_FUZZ_SEEDS_SHA256"
  caps=$f/caps
  rm -rf "$caps" "$f/seeds"
  mkdir -p "$caps/hr23" "$caps/d4u"
  python3 "$root/tests/integration/gt_pcap/hr23_cases.py" "$caps/hr23" > /dev/null
  python3 -I "$patchdir/dispatch_unit.py" write "$caps/d4u"
  rm -rf "$f/zeek-corpus"
  mkdir -p "$f/zeek-corpus"
  tar xzf "$work/zeek-src/$(basename "$ZEEK_TARBALL_URL")" -C "$f/zeek-corpus" zeek-9.0.1/src/fuzzers/corpora/dnp3_tcp-corpus.zip
  python3 -I "$here/seeds.py" --max-len "$HR23_FUZZ_MAX_LEN" \
    --zeek-corpus "$f/zeek-corpus/zeek-9.0.1/src/fuzzers/corpora/dnp3_tcp-corpus.zip" \
    "$f/seeds" "$caps/hr23" "$caps/d4u"
  h=$(sha256sum < "$f/seeds/manifest.sha256" | cut -c1-64)
  echo "corpus: sha256 $h, $(wc -l < "$f/seeds/manifest.sha256") seeds"
  [ "$h" = "$HR23_FUZZ_CORPUS_SHA256" ] || fail "the corpus has SHA-256 $h, not the pin $HR23_FUZZ_CORPUS_SHA256"
  ;;
campaign)
  t=$3
  case " $TARGETS " in *" $t "*) ;; *) fail "unknown target $t" ;; esac
  [ -f "$f/seeds/manifest.sha256" ] || fail "no corpus: run fuzz.sh seeds first"
  for b in c1p c2; do
    d=$priv/$b/$t
    rm -rf "$d"
    mkdir -p "$d/corpus" "$d/artifacts"
    cp "$f/seeds/$t/"* "$d/corpus/"
  done
  for b in c1p c2; do
    d=$priv/$b/$t
    (
      s0=$(date +%s)
      rc=0
      fuzzer $b $t -max_total_time="$HR23_FUZZ_SECONDS" -artifact_prefix="$d/artifacts/" "$d/corpus" > "$d/log" 2>&1 || rc=$?
      echo $rc > "$d/exit-code"
      echo $(($(date +%s) - s0)) > "$d/seconds"
    ) &
  done
  wait
  echo "fuzz.sh: campaign $t done on both builds"
  ;;
replay)
  : > "$priv/replay.tsv"
  for t in $TARGETS; do
    for b in c1p c2; do
      for a in "$priv/$b/$t/artifacts/"*; do
        [ -f "$a" ] || continue
        line="$t	$b"
        for rb in c1p c2; do
          rc=0
          fuzzer $rb $t "$a" > "$priv/replay.log" 2>&1 || rc=$?
          line="$line	$rc"
        done
        echo "$line" >> "$priv/replay.tsv"
      done
    done
  done
  rm -f "$priv/replay.log"
  echo "fuzz.sh: replay done"
  ;;
coverage)
  lib=$(cat "$f/c2/sharedlib")
  s=$f/c2/zeek-9.0.1
  for t in $TARGETS; do
    d=$priv/cov-$t
    rm -rf "$d"
    mkdir -p "$d"
    rc=0
    PROFILE=$d/%p.profraw fuzzer c2 $t -runs=0 "$priv/c2/$t/corpus" > "$d/log" 2>&1 || rc=$?
    echo $rc > "$d/exit-code"
    if ls "$d/"*.profraw > /dev/null 2>&1; then
      llvm-profdata-$V merge -sparse "$d/"*.profraw -o "$d/merged.profdata"
      llvm-cov-$V export -format=lcov -instr-profile="$d/merged.profdata" \
        "$s/build/src/fuzzers/zeek-$t-fuzzer" -object "$s/build/$lib" > "$d/lcov.info"
    fi
  done
  python3 -I "$here/fuzz_judge.py" coverage "$f" "$s/src/analyzer/protocol/dnp3/DNP3.cc"
  ;;
summary)
  python3 -I "$here/fuzz_judge.py" summary "$f"
  ;;
*)
  fail "unknown mode $mode"
  ;;
esac
