#!/usr/bin/env bash
# Experiment E1: what an SSH bastion can and cannot enforce for engineering access.
#
# Questions (see README.md): can a stock OpenSSH bastion pin a user to one
# device:port, block shells and reverse tunnels, and revoke a live session?
# Does destination pinning constrain *operations* on the device?
#
# Everything runs on loopback against mock_ied.py. Requires root (creates a
# throwaway local user and runs sshd on 127.0.0.1:22022). Results are
# `simulated` evidence only: no real IED, no real network.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
# Not under /tmp: sshd StrictModes rejects key files below world-writable dirs.
WORK="$(mktemp -d /run/otsec-e1.XXXXXX)"
chmod 755 "$WORK"
USER_NAME="otsec-eng-e1"
SSHD_PORT=22022
APPROVED_IED="127.0.0.2"      # the one device the session is approved for
APPROVED_PORT=9100
OTHER_IED="127.0.0.3"         # a device the session is NOT approved for
OTHER_PORT_SAME_IED=2323      # another service on the approved device
PASS=0; FAIL=0
pids=()

cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  pkill -f "sshd: $USER_NAME" 2>/dev/null
  [ -f "$WORK/sshd.pid" ] && kill "$(cat "$WORK/sshd.pid")" 2>/dev/null
  userdel "$USER_NAME" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

result() { # id, expectation, observed, pass(0/1)
  if [ "$4" = 1 ]; then PASS=$((PASS+1)); s=PASS; else FAIL=$((FAIL+1)); s=FAIL; fi
  printf '%-4s %-4s expected: %s | observed: %s\n' "$1" "$s" "$2" "$3"
}
ied_lines() { grep -c "\"ied\": \"$1\".*\"event\": \"$2\"" "$WORK/ied.log" 2>/dev/null || true; }

echo "# E1 run $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "# $(ssh -V 2>&1) | kernel $(uname -r)"

# --- setup -----------------------------------------------------------------
# A real login shell on purpose: refusals in T4/T4b must come from sshd and key
# restrictions, not from a nologin shell (A1 review note on the first version).
id "$USER_NAME" >/dev/null 2>&1 || useradd -M -s /bin/bash "$USER_NAME"
# No password, but not "locked" (sshd refuses locked accounts when UsePAM=no).
usermod -p "*" "$USER_NAME"
mkdir -p /run/sshd
ssh-keygen -q -t ed25519 -N '' -f "$WORK/host_key"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/user_key"
mkdir -p "$WORK/ak"
# Per-key policy: everything off ("restrict"), then only one forwarding target.
printf 'restrict,port-forwarding,permitopen="%s:%d",command="/bin/false" %s\n' \
  "$APPROVED_IED" "$APPROVED_PORT" "$(cat "$WORK/user_key.pub")" > "$WORK/ak/$USER_NAME"
chmod 644 "$WORK/ak/$USER_NAME"

cat > "$WORK/sshd_config" <<EOF
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $WORK/host_key
PidFile $WORK/sshd.pid
AuthorizedKeysFile $WORK/ak/%u
AllowUsers $USER_NAME
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
UsePAM no
AllowTcpForwarding local
PermitListen none
AllowAgentForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
GatewayPorts no
LogLevel VERBOSE
EOF
/usr/sbin/sshd -t -f "$WORK/sshd_config" || { echo "sshd config invalid"; exit 2; }
/usr/sbin/sshd -f "$WORK/sshd_config" -E "$WORK/sshd.log"

python3 "$HERE/mock_ied.py" "$APPROVED_IED" "$APPROVED_PORT" approved "$WORK/ied.log" & pids+=($!)
python3 "$HERE/mock_ied.py" "$OTHER_IED" "$APPROVED_PORT" other "$WORK/ied.log" & pids+=($!)
python3 "$HERE/mock_ied.py" "$APPROVED_IED" "$OTHER_PORT_SAME_IED" approved-otherport "$WORK/ied.log" & pids+=($!)
sleep 1

SSH=(ssh -i "$WORK/user_key" -p "$SSHD_PORT" -o BatchMode=yes -o StrictHostKeyChecking=no
     -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ExitOnForwardFailure=yes)

tunnel() { # local_port dest_host dest_port -> starts ssh -N -L in background
  "${SSH[@]}" -N -L "127.0.0.1:$1:$2:$3" "$USER_NAME@127.0.0.1" 2>>"$WORK/client.err" &
  pids+=($!); sleep 1
}

# --- T0: precondition, the key authenticates at all ------------------------
# Without this, refusals in T2-T5 could be authentication failures, not policy.
"${SSH[@]}" -N -o ConnectTimeout=5 "$USER_NAME@127.0.0.1" 2>"$WORK/t0.err" & p=$!; sleep 2
if kill -0 "$p" 2>/dev/null; then kill "$p"; ok=1; else ok=0; fi
grep -q 'Accepted publickey' "$WORK/sshd.log" && ok=$ok || ok=0
result T0 "user key authenticates (sshd: Accepted publickey)" "$(grep -c 'Accepted publickey' "$WORK/sshd.log") accepts; client err='$(tr '\n' ' ' < "$WORK/t0.err")'" "$ok"
[ "$ok" = 1 ] || { echo "# precondition failed; sshd log:"; sed 's/^/#   /' "$WORK/sshd.log"; exit 1; }

# --- T1: forwarding to the approved device:port works ------------------------
tunnel 15001 "$APPROVED_IED" "$APPROVED_PORT"
out=$(python3 "$HERE/probe.py" 127.0.0.1 15001 "READ SER")
result T1 "approved device reachable (REPLY OK DATA)" "$out" "$([ "$out" = "REPLY OK DATA" ] && echo 1 || echo 0)"

# --- T2: another device is refused, and never sees a connection --------------
tunnel 15002 "$OTHER_IED" "$APPROVED_PORT"
out=$(python3 "$HERE/probe.py" 127.0.0.1 15002 "READ SER")
n=$(ied_lines other connect)
result T2 "unapproved device refused; 0 connects at device" "$out; device connects=$n" \
  "$([ "$out" != "REPLY OK DATA" ] && [ "$n" = 0 ] && echo 1 || echo 0)"

# --- T3: another port on the approved device is refused ----------------------
tunnel 15003 "$APPROVED_IED" "$OTHER_PORT_SAME_IED"
out=$(python3 "$HERE/probe.py" 127.0.0.1 15003 "READ SER")
n=$(ied_lines approved-otherport connect)
result T3 "other port on approved device refused; 0 connects" "$out; device connects=$n" \
  "$([ "$out" != "REPLY OK DATA" ] && [ "$n" = 0 ] && echo 1 || echo 0)"

# --- T4: shell / remote command is refused -----------------------------------
out=$("${SSH[@]}" "$USER_NAME@127.0.0.1" 'echo SHELL_OK' 2>&1); rc=$?
result T4 "authenticated, but remote command refused (no SHELL_OK)" "rc=$rc output='${out//$'\n'/ }'" \
  "$([[ "$out" != *SHELL_OK* ]] && [[ "$out" != *"Permission denied"* ]] && echo 1 || echo 0)"

# --- T4b: interactive shell with a forced TTY is refused --------------------
out=$(printf 'echo SHELL_OK\nexit\n' | timeout 10 "${SSH[@]}" -tt "$USER_NAME@127.0.0.1" 2>&1); rc=$?
result T4b "authenticated, but interactive shell refused (no SHELL_OK, no TTY)" "rc=$rc output='${out//$'\n'/ }'" \
  "$([[ "$out" != *SHELL_OK* ]] && [[ "$out" != *"Permission denied"* ]] && echo 1 || echo 0)"

# --- T5: reverse tunnel (bastion -> user) is refused -------------------------
out=$("${SSH[@]}" -N -R 127.0.0.1:16000:127.0.0.1:1 "$USER_NAME@127.0.0.1" 2>&1 & p=$!; sleep 2; kill $p 2>/dev/null; wait $p 2>/dev/null)
listening=$(ss -ltn 2>/dev/null | grep -c '127.0.0.1:16000 ' || true)
result T5 "remote forward refused; nothing listening on bastion:16000" "listeners=$listening; client='${out//$'\n'/ }'" \
  "$([ "$listening" = 0 ] && [[ "$out" != *"Permission denied"* ]] && echo 1 || echo 0)"

# --- T6: destination pinning does not constrain operations -------------------
# Expected to "pass through": this records a limitation, not a control.
out=$(python3 "$HERE/probe.py" 127.0.0.1 15001 "WRITE SETTING TRIP_DELAY=0")
w=$(grep -c '"line": "WRITE SETTING' "$WORK/ied.log" || true)
result T6 "LIMITATION CHECK: WRITE reaches device through approved tunnel" "$out; WRITE lines at device=$w" \
  "$([ "$out" = "REPLY OK WRITTEN" ] && [ "$w" -ge 1 ] && echo 1 || echo 0)"

# --- T7: device sees the bastion, not the user --------------------------------
peers=$(grep '"ied": "approved"' "$WORK/ied.log" | grep '"connect"' | sed 's/.*"peer": "\([^:]*\):.*/\1/' | sort -u | tr '\n' ' ')
result T7 "LIMITATION CHECK: device-side peer is bastion address only" "peers=$peers" \
  "$([ "$peers" = "127.0.0.1 " ] && echo 1 || echo 0)"

# --- T8: revocation of a live session -----------------------------------------
python3 - "$WORK" <<'PY' & holder=$!
import socket, sys, time
work = sys.argv[1]
s = socket.create_connection(("127.0.0.1", 15001), timeout=30)
s.sendall(b"READ SER\n"); s.recv(4096)
open(work + "/held", "w").write("ok")
s.settimeout(30)
try:
    while s.recv(4096):
        pass
    open(work + "/eof", "w").write(repr(time.time()))
except socket.timeout:
    open(work + "/eof", "w").write("TIMEOUT")
PY
for _ in $(seq 50); do [ -f "$WORK/held" ] && break; sleep 0.1; done
t_kill=$(python3 -c 'import time; print(repr(time.time()))')
pkill -f "sshd: $USER_NAME" ; wait "$holder" 2>/dev/null
eof=$(cat "$WORK/eof" 2>/dev/null || echo none)
lat=$(python3 -c "print('%.3f' % (float('$eof') - $t_kill))" 2>/dev/null || echo n/a)
after=$(python3 "$HERE/probe.py" 127.0.0.1 15001 "READ SER")
result T8 "termination: kill of session process closes held app connection" \
  "eof_after_s=$lat; new connection: $after" \
  "$([ "$lat" != n/a ] && [ "$after" != "REPLY OK DATA" ] && echo 1 || echo 0)"

# --- T9 (A6 probe): killing the session is not revocation --------------------
# Limitation check: the same key immediately re-establishes access after T8.
tunnel 15009 "$APPROVED_IED" "$APPROVED_PORT"
out=$(python3 "$HERE/probe.py" 127.0.0.1 15009 "READ SER")
result T9 "LIMITATION CHECK (A6): after kill, same key re-establishes access" "$out" \
  "$([ "$out" = "REPLY OK DATA" ] && echo 1 || echo 0)"

# --- T9r: revocation = remove the authorization, then terminate sessions ------
: > "$WORK/ak/$USER_NAME"
pkill -f "sshd: $USER_NAME"; sleep 1
held=$(python3 "$HERE/probe.py" 127.0.0.1 15009 "READ SER")
out=$("${SSH[@]}" -N -o ConnectTimeout=5 "$USER_NAME@127.0.0.1" 2>&1 & p=$!; sleep 2; kill $p 2>/dev/null; wait $p 2>/dev/null)
result T9r "revocation: key removed + sessions killed -> held tunnel dead and re-authentication denied" \
  "held tunnel: $held; reconnect: '${out//$'\n'/ }'" \
  "$([ "$held" != "REPLY OK DATA" ] && [[ "$out" == *"Permission denied"* ]] && echo 1 || echo 0)"
# Restore the key so later checks run authenticated.
printf 'restrict,port-forwarding,permitopen="%s:%d",command="/bin/false" %s\n' \
  "$APPROVED_IED" "$APPROVED_PORT" "$(cat "$WORK/user_key.pub")" > "$WORK/ak/$USER_NAME"

# --- T10 (A6 probe): stdio forwarding (-W) to an unapproved device -------------
out=$(printf 'READ SER\n' | timeout 5 "${SSH[@]}" -W "$OTHER_IED:$APPROVED_PORT" "$USER_NAME@127.0.0.1" 2>&1)
n=$(ied_lines other connect)
result T10 "-W to unapproved device refused; 0 connects" "out='${out//$'\n'/ }'; device connects=$n" \
  "$([[ "$out" != *"OK DATA"* ]] && [[ "$out" != *"Permission denied"* ]] && [ "$n" = 0 ] && echo 1 || echo 0)"

# --- T11 (A6 probe): sftp subsystem refused -----------------------------------
out=$(printf 'ls /\n' | timeout 5 sftp -b - -i "$WORK/user_key" -P "$SSHD_PORT" -o BatchMode=yes \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USER_NAME@127.0.0.1" 2>&1); rc=$?
result T11 "sftp subsystem refused" "rc=$rc out='${out//$'\n'/ }'" \
  "$([ $rc != 0 ] && [[ "$out" != *"/etc"* ]] && [[ "$out" != *"Permission denied"* ]] && echo 1 || echo 0)"

echo "# sshd evidence (refusals):"
grep -Ei 'refus|prohibit|not permitted|denied|Received request' "$WORK/sshd.log" | sed 's/^/#   /' | head -20
echo "# summary: $PASS pass, $FAIL fail"
[ "$FAIL" = 0 ]
