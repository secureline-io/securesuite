#!/usr/bin/env bash
# Build SecureSuite for Linux: release binary -> .tar.gz (+ .deb if dpkg-deb).
# Arch-agnostic: packages for whatever Linux arch it runs on (CI x86_64, or
# arm64 in a container). Honors CARGO_TARGET_DIR so container builds don't
# clobber a host macOS target/.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VER="$(grep -A8 'workspace.package' Cargo.toml | grep -m1 '^version' | sed 's/.*"\(.*\)".*/\1/')"
[ -z "$VER" ] && VER=0.0.1
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) DEBARCH=amd64 ;;
  aarch64|arm64) DEBARCH=arm64 ;;
  *) DEBARCH="$ARCH" ;;
esac

echo "==> cargo build --release -p securesuite ($ARCH)"
cargo build --release -p securesuite

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
BIN="$TARGET_DIR/release/securesuite"

STAGE="$ROOT/dist/linux/securesuite-$VER-linux-$ARCH"
rm -rf "$STAGE"; mkdir -p "$STAGE" "$ROOT/dist"
install -m755 "$BIN" "$STAGE/securesuite"
cat > "$STAGE/securesuite.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=SecureSuite
Comment=Open-source web application security testing platform
Exec=securesuite
Icon=securesuite
Terminal=true
Categories=Development;Security;Network;
EOF
cp "$ROOT/packaging/README.md" "$STAGE/README.md" 2>/dev/null || true
cp "$ROOT/packaging/brand/app-icon/app-icon-256.png" "$STAGE/securesuite.png" 2>/dev/null || true

TAR="$ROOT/dist/securesuite-$VER-linux-$ARCH.tar.gz"
tar -C "$(dirname "$STAGE")" -czf "$TAR" "$(basename "$STAGE")"
echo "==> $TAR"

if command -v dpkg-deb >/dev/null 2>&1; then
  PKG="$ROOT/dist/deb/securesuite_${VER}_${DEBARCH}"
  rm -rf "$PKG"
  mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/usr/share/applications" \
    "$PKG/usr/share/icons/hicolor/256x256/apps" \
    "$PKG/usr/share/icons/hicolor/512x512/apps" \
    "$PKG/usr/share/icons/hicolor/128x128/apps"
  install -m755 "$BIN" "$PKG/usr/bin/securesuite"
  cp "$STAGE/securesuite.desktop" "$PKG/usr/share/applications/securesuite.desktop"
  install -m644 "$ROOT/packaging/brand/app-icon/app-icon-256.png" "$PKG/usr/share/icons/hicolor/256x256/apps/securesuite.png"
  install -m644 "$ROOT/packaging/brand/app-icon/app-icon-512.png" "$PKG/usr/share/icons/hicolor/512x512/apps/securesuite.png"
  install -m644 "$ROOT/packaging/brand/app-icon/app-icon-128.png" "$PKG/usr/share/icons/hicolor/128x128/apps/securesuite.png"
  cat > "$PKG/DEBIAN/control" <<EOF
Package: securesuite
Version: $VER
Section: utils
Priority: optional
Architecture: $DEBARCH
Maintainer: SecureSuite <noreply@securesuite.in>
Description: Open-source web application security testing platform
 A clean-room, AGPL-licensed Burp-Suite-equivalent: intercepting proxy,
 repeater, intruder, scanner, and more. Authorized testing only.
EOF
  dpkg-deb --build --root-owner-group "$PKG" "$ROOT/dist/securesuite_${VER}_${DEBARCH}.deb" >/dev/null
  echo "==> $ROOT/dist/securesuite_${VER}_${DEBARCH}.deb"
else
  echo "(dpkg-deb not found — skipped .deb; tarball still produced)"
fi
echo "done"
