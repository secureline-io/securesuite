#!/usr/bin/env bash
# Route all macOS proxy-aware traffic through SecureSuite (fully reversible).
# Usage:
#   scripts/system-proxy.sh on     [service] [host] [port]   # default Wi-Fi 127.0.0.1 8080
#   scripts/system-proxy.sh off    [service]
#   scripts/system-proxy.sh status [service]
set -euo pipefail

ACTION="${1:-status}"
SERVICE="${2:-Wi-Fi}"
HOST="${3:-127.0.0.1}"
PORT="${4:-8080}"

case "$ACTION" in
  on)
    networksetup -setwebproxy       "$SERVICE" "$HOST" "$PORT"
    networksetup -setsecurewebproxy "$SERVICE" "$HOST" "$PORT"
    networksetup -setwebproxystate       "$SERVICE" on
    networksetup -setsecurewebproxystate "$SERVICE" on
    echo "System HTTP/HTTPS proxy -> $HOST:$PORT on '$SERVICE'."
    echo "Trust ~/.securesuite/ca-cert.pem to decrypt HTTPS. Run 'off' to revert."
    ;;
  off)
    networksetup -setwebproxystate       "$SERVICE" off
    networksetup -setsecurewebproxystate "$SERVICE" off
    echo "System proxy disabled on '$SERVICE'."
    ;;
  status)
    echo "== HTTP ==";  networksetup -getwebproxy       "$SERVICE"
    echo "== HTTPS =="; networksetup -getsecurewebproxy "$SERVICE"
    ;;
  *)
    echo "usage: $0 on|off|status [service] [host] [port]"; exit 1 ;;
esac
