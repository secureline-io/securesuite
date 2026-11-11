#!/usr/bin/env bash
# Build SecureSuite.app (and a .dmg) around the release engine binary (macOS).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "==> cargo build --release -p securesuite"
cargo build --release -p securesuite

APP="$ROOT/dist/SecureSuite.app"
echo "==> assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$ROOT/target/release/securesuite" "$APP/Contents/MacOS/securesuite-engine"
cp "$ROOT/packaging/launcher.sh"      "$APP/Contents/MacOS/SecureSuite"
cp "$ROOT/packaging/Info.plist"       "$APP/Contents/Info.plist"
cp "$ROOT/packaging/SecureSuite.icns" "$APP/Contents/Resources/SecureSuite.icns"
chmod +x "$APP/Contents/MacOS/SecureSuite" "$APP/Contents/MacOS/securesuite-engine"

# Mark the directory as a bundle package and (re)register it so Finder shows the
# app icon immediately instead of a generic folder.
/usr/bin/SetFile -a B "$APP" 2>/dev/null || true
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$APP" 2>/dev/null || true

DMG="$ROOT/dist/SecureSuite.dmg"
echo "==> building $DMG"
# Stage the app next to an /Applications symlink so the mounted DMG is a
# standard drag-to-install image.
STAGE_DMG="$ROOT/dist/dmg-stage"
rm -rf "$STAGE_DMG"; mkdir -p "$STAGE_DMG"
cp -R "$APP" "$STAGE_DMG/"
ln -s /Applications "$STAGE_DMG/Applications"
rm -f "$DMG"
hdiutil create -volname SecureSuite -srcfolder "$STAGE_DMG" -ov -format UDZO "$DMG" >/dev/null
rm -rf "$STAGE_DMG"

echo "==> done"
echo "    app: $APP"
echo "    dmg: $DMG"
