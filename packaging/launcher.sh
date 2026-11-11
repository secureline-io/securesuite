#!/bin/bash
# SecureSuite.app launcher: start the bundled engine, open the console in the
# default browser, and keep the app process alive while the engine runs.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
UI_PORT="${SECURESUITE_UI_PORT:-8081}"

"$DIR/securesuite-engine" >"${TMPDIR:-/tmp}/securesuite.log" 2>&1 &
ENGINE_PID=$!

# Wait for the UI to come up (max ~10s), then open it.
for _ in $(seq 1 40); do
  curl -s "http://127.0.0.1:${UI_PORT}" >/dev/null 2>&1 && break
  sleep 0.25
done
open "http://127.0.0.1:${UI_PORT}" 2>/dev/null || true

wait "$ENGINE_PID"
