#!/bin/sh
# Download the public captures listed in MANIFEST.tsv into a cache directory
# outside the repository and verify each SHA-256. Captures are not vendored
# because their redistribution terms are not stated (see SOURCE.md).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
manifest="$here/../../../../tests/fixtures/network/public-ot-captures/MANIFEST.tsv"
cache=${1:-${OTSEC_CAPTURE_CACHE:-$HOME/.cache/otsec-captures}}
mkdir -p "$cache"
fail=0
list=$(mktemp)
grep -v '^#' "$manifest" > "$list"
while IFS="$(printf '\t')" read -r name sha url proto label; do
  out="$cache/$name"
  if [ ! -s "$out" ] || ! echo "$sha  $out" | sha256sum -c --status; then
    curl -fsSL --retry 3 -o "$out.part" "$url" && mv "$out.part" "$out"
  fi
  if echo "$sha  $out" | sha256sum -c --status; then
    echo "ok       $name"
  else
    echo "MISMATCH $name (expected $sha)"; fail=1
  fi
  case "$name" in *.gz) gunzip -kf "$out" ;; esac
done < "$list"
rm -f "$list"
exit $fail
