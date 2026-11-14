#!/bin/bash
# SecureSuite.app launcher: start the bundled engine, open the console in the
# default browser, and keep the app process alive while the engine runs.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
DATA="$HOME/.securesuite"
LOG="${TMPDIR:-/tmp}/securesuite.log"
PIDFILE="$DATA/engine.pid"
mkdir -p "$DATA"

# Apps opened from Finder get no shell environment, so ports (e.g.
# SECURESUITE_PROXY_PORT=8086 when Burp has 8080) can be set in this file.
if [ -f "$DATA/env" ]; then
  set -a
  . "$DATA/env"
  set +a
fi
UI_PORT="${SECURESUITE_UI_PORT:-8081}"

alert() {
  osascript -e 'on run argv' \
    -e 'display alert "SecureSuite could not start" message (item 1 of argv) as critical' \
    -e 'end run' "$1" >/dev/null 2>&1 || true
}

# An engine left over from a launch that was force-quit still holds the ports.
if [ -f "$PIDFILE" ]; then
  OLD="$(cat "$PIDFILE")"
  if ps -p "$OLD" -o comm= 2>/dev/null | grep -q securesuite-engine; then
    kill "$OLD" 2>/dev/null
    sleep 1
  fi
fi

"$DIR/securesuite-engine" >"$LOG" 2>&1 &
ENGINE_PID=$!
echo "$ENGINE_PID" >"$PIDFILE"

stop_engine() {
  kill "$ENGINE_PID" 2>/dev/null
  rm -f "$PIDFILE"
}
trap stop_engine EXIT
trap 'exit 0' TERM INT HUP

# Wait for the UI to come up (max ~10s), then open it.
for _ in $(seq 1 40); do
  kill -0 "$ENGINE_PID" 2>/dev/null || break
  if curl -s "http://127.0.0.1:${UI_PORT}" >/dev/null 2>&1; then
    open "http://127.0.0.1:${UI_PORT}" 2>/dev/null || true
    break
  fi
  sleep 0.25
done

wait "$ENGINE_PID"
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
  alert "$(tail -n 5 "$LOG")

If a port is already in use (Burp uses 8080), put different ports in
$DATA/env, for example:
SECURESUITE_PROXY_PORT=8086
SECURESUITE_UI_PORT=8087
Full log: $LOG"
fi
exit "$STATUS"
