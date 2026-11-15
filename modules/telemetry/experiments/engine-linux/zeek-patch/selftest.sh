#!/bin/sh
# Negative tests of build.sh's input checks (brief P4-4-HR23, stage 3): each
# case copies this folder, changes one input, and expects `build.sh verify`
# to stop with its own message. The control is the unchanged copy, which
# must pass. Builds nothing and needs no docker.
#
# Usage: selftest.sh WORK   (fetches the tarball and its .asc once into
# WORK/cache, checked by the control run like any other run)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$1
mkdir -p "$work"
work=$(cd "$work" && pwd)
. "$here/build.env"
cache=$work/cache
mkdir -p "$cache"
for u in "$ZEEK_TARBALL_URL" "$ZEEK_ASC_URL"; do
  [ -f "$cache/$(basename "$u")" ] || curl -fsSL --retry 3 -o "$cache/$(basename "$u")" "$u"
done
tb=$(basename "$ZEEK_TARBALL_URL")
bad=0

# A copy of this folder with build.env's pins as they are.
fresh() {
  rm -rf "$work/case"
  mkdir -p "$work/case"
  cp -R "$here/." "$work/case/"
  mkdir -p "$work/case-cache"
  cp "$cache/"* "$work/case-cache/"
}
setpin() {
  sed -i "s|^$1=.*|$1=$2|" "$work/case/build.env"
}
sha() { sha256sum < "$1" | cut -c1-64; }
# expect NAME MESSAGE: build.sh verify must fail and say MESSAGE; an empty
# MESSAGE means it must pass (the control).
expect() {
  rc=0
  ZEEK_TARBALL_DIR=$work/case-cache sh "$work/case/build.sh" verify "$work/case-work" > "$work/out.txt" 2>&1 || rc=$?
  if [ -z "$2" ]; then
    if [ $rc = 0 ]; then r=pass; else r="FAIL (exit $rc)"; bad=1; fi
  elif [ $rc != 0 ] && grep -qF "$2" "$work/out.txt"; then
    r=pass
  else
    r="FAIL (exit $rc, wanted: $2)"; bad=1
  fi
  echo "| $1 | ${2:-passes} | $r |"
  [ "$r" = pass ] || sed 's/^/    /' "$work/out.txt"
  rm -rf "$work/case-work"
}

echo "| case | expected | result |"
echo "| --- | --- | --- |"
fresh
expect "control: every input as pinned" ""

fresh
printf 'x' >> "$work/case-cache/$tb"
expect "tarball changed, pin kept" "$tb has SHA-256"

fresh
printf 'x' >> "$work/case-cache/$tb"
setpin ZEEK_TARBALL_SHA256 "$(sha "$work/case-cache/$tb")"
expect "tarball changed and pinned: the signature must refuse it" "gpgv refused"

fresh
setpin ZEEK_SIGNING_SUBKEY_FPR D847AB22652D062028460D9561C716F36F9AD2A2
expect "another subkey of the same key pinned as the signer" "the signature is not by subkey"

fresh
g=$(mktemp -d)
GNUPGHOME=$g gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key 'otsec selftest <selftest@invalid>' ed25519 sign never 2> /dev/null
GNUPGHOME=$g gpg --batch --armor --export > "$work/case/zeek-release-key.asc"
rm -rf "$g"
setpin ZEEK_KEY_SHA256 "$(sha "$work/case/zeek-release-key.asc")"
expect "another key, pinned" "does not hold the primary key"

fresh
printf '\n' >> "$work/case/zeek-release-key.asc"
expect "key file changed, pin kept" "zeek-release-key.asc has SHA-256"

fresh
printf '\n' >> "$work/case/COPYING"
expect "COPYING changed, pin kept" "COPYING has SHA-256"

fresh
sed -i 's/^ # This is Binpac code for DNP3 analyzer by Hui Lin\.$/ # This is not the line Zeek 9.0.1 has./' "$work/case/hr23-fc-dispatch.patch"
expect "patch changed, pin kept" "hr23-fc-dispatch.patch has SHA-256"
setpin HR23_PATCH_SHA256 "$(sha "$work/case/hr23-fc-dispatch.patch")"
expect "patch context changed and pinned: it needs fuzz" "does not apply with no fuzz"

fresh
sed -i 's/^@@ -25,6 +25,17 @@$/@@ -20,6 +20,17 @@/' "$work/case/hr23-fc-dispatch.patch"
setpin HR23_PATCH_SHA256 "$(sha "$work/case/hr23-fc-dispatch.patch")"
expect "patch hunk moved and pinned: it applies only at an offset" "only with an offset or fuzz"

rm -rf "$work/case" "$work/case-cache"

# build.sh's record checks (D6's N4 and N5 on #715), on made-up lists:
# each case changes one list, and `build.sh record-check` must stop with
# its own message. The control is the lists as a one-tree build gives them.
r=$work/rec
rec_fresh() {
  rm -rf "$r"
  mkdir -p "$r"
  a=$(printf '%064d' 1)
  b=$(printf '%064d' 2)
  for v in c1p c2; do
    h=$a
    [ $v = c2 ] && h=$b
    { echo "$h  ./bin/zeek"
      echo "$h  ./include/zeek/analyzer/protocol/dnp3/dnp3-analyzer.pac"
      echo "$h  ./include/zeek/analyzer/protocol/dnp3/dnp3-protocol.pac"
      echo "$a  ./lib/zeek/python/zeekclient/cli.py"
      echo "$h  ./share/otsec-build/generated.sha256"
      echo "$a  ./share/zeek/base/init-bare.zeek"; } > "$r/files-$v.txt"
    printf 'Zeek::AF_Packet - Packet acquisition via AF_Packet (built-in)\nZeek::DNP3 - DNP3 analyzer (built-in)\n' > "$r/plugins-$v.txt"
  done
  printf '//BinPAC executable\nBinPAC_EXE:STRING=binpac\nBinPAC_INCLUDE_DIR:STRING=/src/zeek/tools/binpac/lib;/src/zeek/build/tools/binpac/lib\n' > "$r/binpac.txt"
}
rexpect() {
  rc=0
  sh "$here/build.sh" record-check "$r" > "$work/out.txt" 2>&1 || rc=$?
  if [ -z "$2" ]; then
    if [ $rc = 0 ]; then res=pass; else res="FAIL (exit $rc)"; bad=1; fi
  elif [ $rc != 0 ] && grep -qF "$2" "$work/out.txt"; then
    res=pass
  else
    res="FAIL (exit $rc, wanted: $2)"; bad=1
  fi
  echo "| $1 | ${2:-passes} | $res |"
  [ "$res" = pass ] || sed 's/^/    /' "$work/out.txt"
}
rec_fresh
rexpect "record control: four files differ, in-tree binpac, nothing left out present" ""
rec_fresh
sed -i "s|^$a  ./share/zeek/base/init-bare.zeek$|$b  ./share/zeek/base/init-bare.zeek|" "$r/files-c2.txt"
rexpect "record: a fifth file differs (another tree)" "not one tree"
rec_fresh
sed -i "s|^$b  ./include/zeek/analyzer/protocol/dnp3/dnp3-protocol.pac$|$a  ./include/zeek/analyzer/protocol/dnp3/dnp3-protocol.pac|" "$r/files-c2.txt"
rexpect "record: a patched file the same in both" "not one tree"
rec_fresh
sed -i 's|^BinPAC_EXE:STRING=binpac$|BinPAC_EXE:FILEPATH=/usr/bin/binpac|' "$r/binpac.txt"
rexpect "record: CMake's binpac from the PATH" "not the tarball's in-tree target"
rec_fresh
echo "$a  ./bin/zkg" >> "$r/files-c1p.txt"
echo "$a  ./bin/zkg" >> "$r/files-c2.txt"
rexpect "record: zkg installed" "installs what"
rec_fresh
echo "Zeek::Cluster_Backend_ZeroMQ - ZeroMQ cluster backend (built-in)" >> "$r/plugins-c2.txt"
rexpect "record: the ZeroMQ plugin in zeek -NN" "zeek -NN lists"
rec_fresh
rm "$r/plugins-c1p.txt"
rexpect "record: a list missing" "missing or empty"
rm -rf "$r"
exit $bad
