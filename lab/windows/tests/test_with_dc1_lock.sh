#!/usr/bin/env bash
# Offline proof of lab/windows/bin/with-dc1-lock (T-0839). Real flock, throwaway lock file; no lab needed.
# Cases: a second invocation waits and names the holder, then runs after the first exits; a timeout
# fails (exit 75) and does not run the command; the command's exit status is passed through; a wrapped
# command nested in a wrapped command does not deadlock; windows-lab test-connector and agent-verify
# take the lock. Each case must FAIL if the wrapper is broken: the sabotage run at the end proves it.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../bin"
LOCKW="${LOCKW:-$BIN/with-dc1-lock}"
T="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
export DIQ_DC1_LOCK="$T/dc1.lock"
unset DIQ_DC1_LOCK_HELD DIQ_DC1_LOCK_WHO
fails=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fails=$((fails+1)); }

# 1. first holds, second waits, names the holder, runs only after the first exits
DIQ_DC1_LOCK_WHO="holder-one" "$LOCKW" -- bash -c 'echo first-in > "$1"; sleep 3; echo first-out >> "$1"' _ "$T/order" 2>"$T/e1" &
for _ in $(seq 50); do [ -s "$T/order" ] && break; sleep 0.1; done
start=$SECONDS
DIQ_DC1_LOCK_WAIT=30 "$LOCKW" -- bash -c 'echo second >> "$1"' _ "$T/order" 2>"$T/e2"; rc2=$?
wait
[ "$rc2" = 0 ] && ok "second invocation ran (exit 0)" || bad "second invocation exit $rc2"
[ "$(tr '\n' ' ' < "$T/order")" = "first-in first-out second " ] && ok "second ran after the first exited" || bad "order was: $(tr '\n' ' ' < "$T/order")"
grep -q "dc1 is busy.*Held by: holder-one" "$T/e2" && ok "waiter printed the holder" || bad "waiter did not print the holder: $(cat "$T/e2")"
[ $((SECONDS - start)) -ge 1 ] && ok "second really waited" || bad "second did not wait"
[ ! -e "$DIQ_DC1_LOCK.holder" ] && ok "holder file removed on exit" || bad "stale holder file"

# 2. timeout: exit 75, command not run, holder named
"$LOCKW" -- sleep 4 2>/dev/null &
sleep 0.5
DIQ_DC1_LOCK_WAIT=1 "$LOCKW" -- touch "$T/should-not-exist" 2>"$T/e3"; rc3=$?
[ "$rc3" = 75 ] && ok "timeout exits 75" || bad "timeout exit $rc3"
[ ! -e "$T/should-not-exist" ] && ok "timed-out command did not run" || bad "timed-out command ran"
grep -q "gave up after 1s" "$T/e3" && ok "timeout message" || bad "timeout message: $(cat "$T/e3")"
wait

# 3. exit status of the command is passed through
"$LOCKW" -- bash -c 'exit 7' 2>/dev/null; [ "$?" = 7 ] && ok "exit status passed through" || bad "exit status lost"

# 4. nesting does not deadlock
DIQ_DC1_LOCK_WAIT=3 "$LOCKW" -- "$LOCKW" -- true 2>/dev/null; [ "$?" = 0 ] && ok "nested wrapper runs through" || bad "nested wrapper deadlocked"

# 5. a stale marker (dead holder pid) is not trusted
DIQ_DC1_LOCK_HELD=999999 DIQ_DC1_LOCK_WAIT=3 "$LOCKW" -- true 2>"$T/e5"; grep -q "holding dc1 lock" "$T/e5" && ok "stale DIQ_DC1_LOCK_HELD ignored" || bad "stale marker trusted"

# 6. a killed holder releases the lock
setsid "$LOCKW" -- sleep 60 2>/dev/null & hp=$!; disown "$hp"  # disowned: bash prints no "Killed" job notice (its pid made the CI log differ run to run)
sleep 0.5; kill -KILL -- "-$hp" 2>/dev/null; sleep 0.3
DIQ_DC1_LOCK_WAIT=3 "$LOCKW" -- true 2>/dev/null; [ "$?" = 0 ] && ok "lock free after the holder died" || bad "lock stuck after the holder died"

# 7. the real entry points take the lock (waiter times out while a holder runs; both fail fast with no hypervisor, no go, no winrm)
"$LOCKW" -- sleep 6 2>/dev/null &
sleep 0.5
for target in "agent-verify --log $T/x.log" "windows-lab test-connector"; do
  set -- $target
  WIN_LAB_MODE=external WIN_LAB_DC_ADDR=192.0.2.1 DIQ_DC1_LOCK_WAIT=1 "$BIN/$1" "${@:2}" >/dev/null 2>"$T/e7"; rc=$?
  [ "$rc" = 75 ] && grep -q "dc1 is busy" "$T/e7" && ok "$1 waits for the dc1 lock" || bad "$1 did not wait for the lock (exit $rc): $(head -c 300 "$T/e7")"
done
wait
# ... and when the lock is free agent-verify announces that it holds it before doing anything else
WIN_LAB_ENV="$T/none" "$BIN/agent-verify" --log "$T/x.log" >/dev/null 2>"$T/e8"
grep -q "holding dc1 lock" "$T/e8" && ok "agent-verify holds the lock for its run" || bad "agent-verify run did not announce the lock: $(head -c 300 "$T/e8")"

echo; [ "$fails" = 0 ] && echo "with-dc1-lock: all cases pass" || echo "with-dc1-lock: $fails case(s) FAILED"
exit $((fails > 0))
