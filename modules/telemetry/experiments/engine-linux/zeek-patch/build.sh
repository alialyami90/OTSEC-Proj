#!/bin/sh
# HR-23 option (i): the project's Zeek 9.0.1 build (brief P4-4-HR23, stage
# 3; docs/phase4/D4-hr23-design.md, section 4.5). Builds two images from one
# tree: C1p, without the patch, and C2, with it (section 4.1).
#
# Usage: build.sh verify WORK   checks every input against build.env, the
#                               signature with gpgv, and that the patch
#                               applies with no fuzz; builds nothing
#        build.sh build WORK    the same, then both images, and writes
#                               WORK/images.env (HR23_C1P_IMAGE and
#                               HR23_C2_IMAGE, each an image ID) and
#                               WORK/zeek-build.txt (the build record),
#                               then the record checks below
#        build.sh record-check WORK   the record checks alone, on
#                               WORK/files-c1p.txt, files-c2.txt (each
#                               image's `sha256sum` list under
#                               /usr/local/zeek), plugins-c1p.txt,
#                               plugins-c2.txt (`zeek -NN`) and binpac.txt
#                               (CMakeCache's binpac lines); selftest.sh
#                               runs it on made-up lists
# ZEEK_TARBALL_DIR, if set, is read for zeek-9.0.1.tar.gz and its .asc
# instead of fetching them; they are checked the same way.
#
# Needs: sh, curl, sha256sum, tar, patch, gpg and gpgv (for the key's
# fingerprints and the signature), docker (build only). Nothing here touches
# a network other than the two release URLs and Docker Hub, and nothing
# captures or contacts a device.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
mode=$1
work=$2
. "$here/build.env"
mkdir -p "$work"
work=$(cd "$work" && pwd)
fail() { echo "build.sh: $*" >&2; exit 1; }

# The record checks (D6's N4 and N5 on #715).
# - One tree: the two images differ in exactly the four files the patch
#   changes, so a cache miss that rebuilt C2 from another tree fails here.
# - The binpac CMake used is the tarball's own target, not one on the PATH.
# - What the five effective `--disable-*` options leave out is absent: zkg,
#   ZeekControl, Broker's Python bindings, the JavaScript and ZeroMQ plugins.
#   (`--disable-af-packet` has no effect in 9.0.1; see the Dockerfile.)
record_check() {
  for f in files-c1p.txt files-c2.txt plugins-c1p.txt plugins-c2.txt binpac.txt; do
    [ -s "$work/$f" ] || fail "record check: $f is missing or empty"
  done
  awk 'NR == FNR { h[$2] = $1; next } { if (!($2 in h) || h[$2] != $1) print $2; delete h[$2] } END { for (p in h) print p }' \
    "$work/files-c1p.txt" "$work/files-c2.txt" | sort > "$work/changed.txt"
  printf '%s\n' ./bin/zeek ./include/zeek/analyzer/protocol/dnp3/dnp3-analyzer.pac \
    ./include/zeek/analyzer/protocol/dnp3/dnp3-protocol.pac ./share/otsec-build/generated.sha256 > "$work/changed-want.txt"
  cmp -s "$work/changed.txt" "$work/changed-want.txt" \
    || { cat "$work/changed.txt" >&2; fail "record check: C1p and C2 differ in other files than the patch's four, so they are not one tree"; }
  grep -qx 'BinPAC_EXE:STRING=binpac' "$work/binpac.txt" \
    && grep -q '^BinPAC_INCLUDE_DIR:STRING=/src/zeek/tools/binpac/lib' "$work/binpac.txt" \
    || { cat "$work/binpac.txt" >&2; fail "record check: CMake's binpac is not the tarball's in-tree target"; }
  for v in c1p c2; do
    if grep -E '^[0-9a-f]+  \./(bin/zkg|bin/zeekctl|lib/zeek/python/broker/)' "$work/files-$v.txt" >&2; then
      fail "record check: $v installs what --disable-zkg, --disable-zeekctl or --disable-python leave out"
    fi
    if grep -iE 'javascript|zeromq' "$work/plugins-$v.txt" >&2; then
      fail "record check: $v's zeek -NN lists what --disable-javascript or --disable-cluster-backend-zeromq leave out"
    fi
  done
  echo "build.sh: record checked: one tree (four files differ), the in-tree binpac, nothing the five options leave out"
}
if [ "$mode" = record-check ]; then
  record_check
  exit 0
fi

# 1. The committed files at their pins.
pin() {
  h=$(sha256sum < "$here/$1" | cut -c1-64)
  [ "$h" = "$2" ] || fail "$1 has SHA-256 $h, not the pin $2"
}
pin COPYING "$COPYING_SHA256"
pin zeek-release-key.asc "$ZEEK_KEY_SHA256"
pin hr23-fc-dispatch.patch "$HR23_PATCH_SHA256"

# 2. The key's fingerprints, read from the committed file in an empty home:
# no default keyring is read and no keyserver is asked.
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
gpg --batch --with-colons --show-keys "$here/zeek-release-key.asc" 2> /dev/null | awk -F: '$1 == "fpr" { print $10 }' > "$work/fprs.txt"
grep -qx "$ZEEK_KEY_FPR" "$work/fprs.txt" || fail "the key file does not hold the primary key $ZEEK_KEY_FPR"
grep -qx "$ZEEK_SIGNING_SUBKEY_FPR" "$work/fprs.txt" || fail "the key file does not hold the signing subkey $ZEEK_SIGNING_SUBKEY_FPR"
rm -f "$work/zeek-keyring.gpg"
gpg --batch --dearmor < "$here/zeek-release-key.asc" > "$work/zeek-keyring.gpg"

# 3. The tarball and its signature, by SHA-256, then the signature by gpgv
# against that keyring alone. The signing key must be the pinned subkey of
# the pinned primary key (VALIDSIG names both).
src=$work/zeek-src
mkdir -p "$src"
for f in tarball asc; do
  if [ $f = tarball ]; then url=$ZEEK_TARBALL_URL sha=$ZEEK_TARBALL_SHA256; else url=$ZEEK_ASC_URL sha=$ZEEK_ASC_SHA256; fi
  n=$(basename "$url")
  if [ -n "${ZEEK_TARBALL_DIR:-}" ]; then cp "$ZEEK_TARBALL_DIR/$n" "$src/$n"; else curl -fsSL --retry 3 -o "$src/$n" "$url"; fi
  h=$(sha256sum < "$src/$n" | cut -c1-64)
  [ "$h" = "$sha" ] || fail "$n has SHA-256 $h, not the pin $sha"
done
tarball=$src/$(basename "$ZEEK_TARBALL_URL")
gpgv --status-fd 1 --keyring "$work/zeek-keyring.gpg" "$src/$(basename "$ZEEK_ASC_URL")" "$tarball" > "$work/gpgv.txt" 2>&1 \
  || { cat "$work/gpgv.txt" >&2; fail "gpgv refused the tarball's signature"; }
grep -q "^\[GNUPG:\] VALIDSIG $ZEEK_SIGNING_SUBKEY_FPR .* $ZEEK_KEY_FPR\$" "$work/gpgv.txt" \
  || { cat "$work/gpgv.txt" >&2; fail "the signature is not by subkey $ZEEK_SIGNING_SUBKEY_FPR of $ZEEK_KEY_FPR"; }
rm -rf "$GNUPGHOME"

# 4. The patch must apply with no fuzz and no offset (D7's C1). This is
# checked on the DNP3 folder alone, unpacked apart, so that the build's
# context stays unpatched for C1p.
dry=$work/zeek-dry
rm -rf "$dry"
mkdir -p "$dry"
tar xzf "$tarball" -C "$dry" zeek-9.0.1/src/analyzer/protocol/dnp3 || fail "the tarball has no zeek-9.0.1/src/analyzer/protocol/dnp3"
patch -d "$dry/zeek-9.0.1" -p1 --fuzz=0 --no-backup-if-mismatch < "$here/hr23-fc-dispatch.patch" > "$work/patch-dry.txt" 2>&1 \
  || { cat "$work/patch-dry.txt" >&2; fail "the patch does not apply with no fuzz"; }
! grep -qiE 'fuzz|offset|hunk .* (failed|ignored)' "$work/patch-dry.txt" \
  || { cat "$work/patch-dry.txt" >&2; fail "the patch applied only with an offset or fuzz"; }
rm -rf "$dry"
echo "build.sh: inputs checked: tarball, signature (subkey $ZEEK_SIGNING_SUBKEY_FPR), key, COPYING, patch (applies with no fuzz)"
[ "$mode" = verify ] && exit 0
[ "$mode" = build ] || fail "unknown mode $mode"

# The build's context: the whole unpacked tree, the patch and COPYING.
ctx=$work/zeek-ctx
rm -rf "$ctx"
mkdir -p "$ctx"
tar xzf "$tarball" -C "$ctx"
cp "$here/hr23-fc-dispatch.patch" "$here/COPYING" "$ctx/"

# 5. Both images from one build stage, which BuildKit builds once and
# reuses for the second target.
for v in c1p c2; do
  docker build --progress=plain --target "$v" --build-arg "BASE_IMAGE=$BASE_IMAGE" -t "otsec-zeek:$v" -f "$here/Dockerfile" "$ctx"
done

# 6. The record: what was built, from what, and the hashes that tie a run to
# the binary it measured (the design's section 4.5; D7's C2).
rec=$work/zeek-build.txt
: > "$work/images.env"
{
  echo "base image: $BASE_IMAGE"
  echo "tarball: $ZEEK_TARBALL_URL sha256 $ZEEK_TARBALL_SHA256"
  echo "signature: $(grep '^\[GNUPG:\] VALIDSIG' "$work/gpgv.txt" | cut -d' ' -f3,12)"
  echo "patch: hr23-fc-dispatch.patch sha256 $HR23_PATCH_SHA256 (C2 only)"
  echo "configure: $(sed -n '/^RUN --network=none \.\/configure/,/af-packet$/p' "$here/Dockerfile" | tr -d '\\' | tr -s ' \n' '  ')"
} > "$rec"
for v in c1p c2; do
  id=$(docker image inspect -f '{{.Id}}' "otsec-zeek:$v")
  V=$(echo "$v" | tr a-z A-Z)
  echo "HR23_${V}_IMAGE=$id" >> "$work/images.env"
  docker run --rm --network none "$id" sh -c 'cd /usr/local/zeek && find . -type f | sort | xargs sha256sum' > "$work/files-$v.txt"
  docker run --rm --network none "$id" zeek -NN > "$work/plugins-$v.txt"
  docker run --rm --network none "$id" cat /usr/local/zeek/share/otsec-build/binpac.txt > "$work/binpac.txt"
  {
    echo
    echo "## $v: image $id"
    echo "zeek --version: $(docker run --rm --network none "$id" zeek --version)"
    echo "zeek binary sha256: $(docker run --rm --network none "$id" sha256sum /usr/local/zeek/bin/zeek | cut -c1-64)"
    echo "generated parser:"
    docker run --rm --network none "$id" cat /usr/local/zeek/share/otsec-build/generated.sha256
    echo "binpac (CMakeCache):"
    cat "$work/binpac.txt"
    echo "zeek -NN:"
    cat "$work/plugins-$v.txt"
    echo "ldd zeek:"
    docker run --rm --network none "$id" ldd /usr/local/zeek/bin/zeek
    echo "build packages:"
    docker run --rm --network none "$id" cat /usr/local/zeek/share/otsec-build/build-packages.txt
    echo "runtime packages:"
    docker run --rm --network none "$id" cat /usr/local/zeek/share/otsec-build/runtime-packages.txt
    echo "files under /usr/local/zeek (sha256):"
    cat "$work/files-$v.txt"
  } >> "$rec"
done
# Not in a pipe: a failed check must stop this script.
record_check >> "$rec"
tail -1 "$rec"
cat "$work/images.env"
