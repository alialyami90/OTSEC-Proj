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
#                               HR23_C2_IMAGE, each an image ID, and
#                               HR23_M_*_IMAGE for (B')'s three
#                               controls) and
#                               WORK/zeek-build.txt (the build record),
#                               then the record checks below
#        build.sh record-check WORK   the record checks alone, on
#                               WORK/files-c1p.txt, files-c2.txt (each
#                               image's `sha256sum` list under
#                               /usr/local/zeek), plugins-c1p.txt,
#                               plugins-c2.txt (`zeek -NN`) and binpac.txt
#                               (CMakeCache's binpac lines); selftest.sh
#                               runs it on made-up lists
#
# HR-25's option A, part HR25-B1 (D4-124; the design's section 4, C1): the
# same tree, after C2, with hr25-resync.patch applied after the HR-23 patch,
# in that fixed order and with no fuzz, is built as a third image, C2A
# (HR25_C2A_IMAGE), with A's mutant controls (HR25_M_<NAME>_IMAGE, one per
# build.env's HR25_CONTROLS). verify checks that both patches apply in that
# order; the record check also reads files-c2a.txt and plugins-c2a.txt.
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
  for f in files-c1p.txt files-c2.txt files-c2a.txt plugins-c1p.txt plugins-c2.txt plugins-c2a.txt binpac.txt; do
    [ -s "$work/$f" ] || fail "record check: $f is missing or empty"
  done
  awk 'NR == FNR { h[$2] = $1; next } { if (!($2 in h) || h[$2] != $1) print $2; delete h[$2] } END { for (p in h) print p }' \
    "$work/files-c1p.txt" "$work/files-c2.txt" | sort > "$work/changed.txt"
  printf '%s\n' ./bin/zeek ./include/zeek/analyzer/protocol/dnp3/dnp3-analyzer.pac \
    ./include/zeek/analyzer/protocol/dnp3/dnp3-protocol.pac ./share/otsec-build/generated.sha256 > "$work/changed-want.txt"
  cmp -s "$work/changed.txt" "$work/changed-want.txt" \
    || { cat "$work/changed.txt" >&2; fail "record check: C1p and C2 differ in other files than the patch's four, so they are not one tree"; }
  # C2 and C2A: A's patch changes DNP3.h, DNP3.cc and events.bif, so C2A's
  # bin/zeek must differ from C2's, and nothing may differ but bin/zeek,
  # the DNP3 analyzer's installed headers and its events' generated script
  # (the exact list is in the record, for D6 and D7 to pin from a build).
  awk 'NR == FNR { h[$2] = $1; next } { if (!($2 in h) || h[$2] != $1) print $2; delete h[$2] } END { for (p in h) print p }' \
    "$work/files-c2.txt" "$work/files-c2a.txt" | sort > "$work/changed-a.txt"
  grep -qx './bin/zeek' "$work/changed-a.txt" \
    || fail "record check: C2A's bin/zeek is C2's, so A's patch was not built"
  if grep -vE '^\./(bin/zeek|include/zeek/analyzer/protocol/dnp3/[^/]+|share/zeek/base/bif/plugins/Zeek_DNP3\.events\.bif\.zeek)$' "$work/changed-a.txt" >&2; then
    fail "record check: C2 and C2A differ in files A's patch does not change, so they are not one tree"
  fi
  grep -qx 'BinPAC_EXE:STRING=binpac' "$work/binpac.txt" \
    && grep -q '^BinPAC_INCLUDE_DIR:STRING=/src/zeek/tools/binpac/lib' "$work/binpac.txt" \
    || { cat "$work/binpac.txt" >&2; fail "record check: CMake's binpac is not the tarball's in-tree target"; }
  for v in c1p c2 c2a; do
    if grep -E '^[0-9a-f]+  \./(bin/zkg|bin/zeekctl|lib/zeek/python/broker/)' "$work/files-$v.txt" >&2; then
      fail "record check: $v installs what --disable-zkg, --disable-zeekctl or --disable-python leave out"
    fi
    if grep -iE 'javascript|zeromq' "$work/plugins-$v.txt" >&2; then
      fail "record check: $v's zeek -NN lists what --disable-javascript or --disable-cluster-backend-zeromq leave out"
    fi
  done
  echo "build.sh: record checked: one tree (four files differ, and C2A differs from C2 in A's files only), the in-tree binpac, nothing the five options leave out"
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
pin hr25-resync.patch "$HR25_PATCH_SHA256"

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
# context stays unpatched for C1p. A's patch is checked the same way, after
# the HR-23 patch, in that fixed order (the HR-25 design's section 4, C1).
dry=$work/zeek-dry
rm -rf "$dry"
mkdir -p "$dry"
tar xzf "$tarball" -C "$dry" zeek-9.0.1/src/analyzer/protocol/dnp3 || fail "the tarball has no zeek-9.0.1/src/analyzer/protocol/dnp3"
patch -d "$dry/zeek-9.0.1" -p1 --fuzz=0 --no-backup-if-mismatch < "$here/hr23-fc-dispatch.patch" > "$work/patch-dry.txt" 2>&1 \
  || { cat "$work/patch-dry.txt" >&2; fail "the patch does not apply with no fuzz"; }
! grep -qiE 'fuzz|offset|hunk .* (failed|ignored)' "$work/patch-dry.txt" \
  || { cat "$work/patch-dry.txt" >&2; fail "the patch applied only with an offset or fuzz"; }
patch -d "$dry/zeek-9.0.1" -p1 --fuzz=0 --no-backup-if-mismatch < "$here/hr25-resync.patch" > "$work/patch-dry-a.txt" 2>&1 \
  || { cat "$work/patch-dry-a.txt" >&2; fail "A's patch does not apply with no fuzz after the HR-23 patch"; }
! grep -qiE 'fuzz|offset|hunk .* (failed|ignored)' "$work/patch-dry-a.txt" \
  || { cat "$work/patch-dry-a.txt" >&2; fail "A's patch applied only with an offset or fuzz"; }
for m in $HR25_CONTROLS; do
  [ -f "$here/controls/hr25-$m.patch" ] || fail "control hr25-$m.patch is missing"
done
rm -rf "$dry"
echo "build.sh: inputs checked: tarball, signature (subkey $ZEEK_SIGNING_SUBKEY_FPR), key, COPYING, patches (each applies with no fuzz, A's after HR-23's)"
[ "$mode" = verify ] && exit 0
[ "$mode" = build ] || fail "unknown mode $mode"

# The build's context: the whole unpacked tree, the patch and COPYING.
ctx=$work/zeek-ctx
rm -rf "$ctx"
mkdir -p "$ctx"
tar xzf "$tarball" -C "$ctx"
cp "$here/hr23-fc-dispatch.patch" "$here/hr25-resync.patch" "$here/COPYING" "$ctx/"
cp -R "$here/controls" "$ctx/"

# 5. Both images from one build stage, which BuildKit builds once and
# reuses for the second target; then (B')'s three controls, each C2 with
# one control patch's bin/zeek (the Dockerfile's `controls` stage).
for v in c1p c2 m-stock-catch m-raise-rethrow m-no-violation c2a; do
  docker build --progress=plain --target "$v" --build-arg "BASE_IMAGE=$BASE_IMAGE" -t "otsec-zeek:$v" -f "$here/Dockerfile" "$ctx"
done
# A's mutant controls (HR25-B1): each C2A with one control's bin/zeek, from
# the Dockerfile's `controls-a` stage, which BuildKit builds once.
for m in $HR25_CONTROLS; do
  docker build --progress=plain --target m25 --build-arg "BASE_IMAGE=$BASE_IMAGE" \
    --build-arg "HR25_CONTROLS=$HR25_CONTROLS" --build-arg "MUTANT=$m" -t "otsec-zeek:m25-$m" -f "$here/Dockerfile" "$ctx"
done

# 6. The record: what was built, from what, and the hashes that tie a run to
# the binary it measured (the design's section 4.5; D7's C2).
rec=$work/zeek-build.txt
: > "$work/images.env"
{
  echo "base image: $BASE_IMAGE"
  echo "tarball: $ZEEK_TARBALL_URL sha256 $ZEEK_TARBALL_SHA256"
  echo "signature: $(grep '^\[GNUPG:\] VALIDSIG' "$work/gpgv.txt" | cut -d' ' -f3,12)"
  echo "patch: hr23-fc-dispatch.patch sha256 $HR23_PATCH_SHA256 (C2 and C2A)"
  echo "patch: hr25-resync.patch sha256 $HR25_PATCH_SHA256 (C2A only, applied after hr23-fc-dispatch.patch)"
  echo "configure: $(sed -n '/^RUN --network=none \.\/configure/,/af-packet$/p' "$here/Dockerfile" | tr -d '\\' | tr -s ' \n' '  ')"
} > "$rec"
for v in c1p c2 c2a; do
  id=$(docker image inspect -f '{{.Id}}' "otsec-zeek:$v")
  V=$(echo "$v" | tr a-z A-Z)
  if [ "$v" = c2a ]; then echo "HR25_${V}_IMAGE=$id"; else echo "HR23_${V}_IMAGE=$id"; fi >> "$work/images.env"
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
# The controls: never shipped, recorded by image, control patch and binary.
for m in stock-catch raise-rethrow no-violation; do
  id=$(docker image inspect -f '{{.Id}}' "otsec-zeek:m-$m")
  V=$(echo "$m" | tr a-z- A-Z_)
  echo "HR23_M_${V}_IMAGE=$id" >> "$work/images.env"
  {
    echo
    echo "## control m-$m (C2 with controls/$m.patch; never shipped): image $id"
    echo "control patch sha256: $(sha256sum < "$here/controls/$m.patch" | cut -c1-64)"
    echo "zeek binary sha256: $(docker run --rm --network none "$id" sha256sum /usr/local/zeek/bin/zeek | cut -c1-64)"
  } >> "$rec"
done
for m in $HR25_CONTROLS; do
  id=$(docker image inspect -f '{{.Id}}' "otsec-zeek:m25-$m")
  V=$(echo "$m" | tr a-z- A-Z_)
  echo "HR25_M_${V}_IMAGE=$id" >> "$work/images.env"
  {
    echo
    echo "## control m25-$m (C2A with controls/hr25-$m.patch; never shipped): image $id"
    echo "control patch sha256: $(sha256sum < "$here/controls/hr25-$m.patch" | cut -c1-64)"
    echo "zeek binary sha256: $(docker run --rm --network none "$id" sha256sum /usr/local/zeek/bin/zeek | cut -c1-64)"
  } >> "$rec"
done
# Not in a pipe: a failed check must stop this script.
record_check >> "$rec"
{ echo; echo "## files that differ between C2 and C2A"; cat "$work/changed-a.txt"; } >> "$rec"
tail -1 "$rec"
cat "$work/images.env"
