#!/bin/sh
# Reproduces every A5 Phase 0 experiment and writes results/<name>.txt.
# Requires Go 1.24+. The ENOSPC case needs root to mount a 4 MiB tmpfs;
# without root it is skipped and says so.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'umount "$work/full" 2>/dev/null || true; rm -rf "$work"' EXIT
mkdir -p "$here/results" "$work/scratch" "$work/full"

cd "$here"
go vet ./...
CGO_ENABLED=0 go build -trimpath -o "$work/p0" .

env_line() {
	echo "# $(date -u +%Y-%m-%dT%H:%M:%SZ) $(go version) $(uname -srm) cpus=$(nproc)"
	echo "# filesystem for scratch: $(df -T "$work/scratch" | awk 'NR==2 {print $2}')"
}

{ env_line; "$work/p0" crash-durability -iterations "${ITERATIONS:-100}" -dir "$work/scratch"; } \
	2>&1 | tee results/crash-durability.txt
{ env_line; "$work/p0" throughput -dir "$work/scratch"; } 2>&1 | tee results/throughput.txt

if mount -t tmpfs -o size=4m tmpfs "$work/full" 2>/dev/null; then
	{ env_line; "$work/p0" storage-limit -dir "$work/scratch" -enospc-dir "$work/full"; } \
		2>&1 | tee results/storage-limit.txt
else
	{ env_line; "$work/p0" storage-limit -dir "$work/scratch"; } 2>&1 | tee results/storage-limit.txt
fi

{ env_line; "$work/p0" syslog-loss -runs 10 -dir "$work/scratch"; } 2>&1 | tee results/syslog-loss.txt

{
	env_line
	for t in linux/amd64 linux/arm64 linux/arm windows/amd64; do
		o="$work/p0-$(echo "$t" | tr / -)"
		CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -trimpath -ldflags='-s -w' -o "$o" .
		echo "$t $(stat -c %s "$o") bytes: $(file -b "$o" | cut -d, -f1-2,4)"
	done
	echo "ldd linux/amd64: $(ldd "$work/p0-linux-amd64" 2>&1 | tr -d '\t')"
	echo "module dependencies: $(go list -m all | wc -l) (go list -m all)"
} 2>&1 | tee results/cross-build.txt
