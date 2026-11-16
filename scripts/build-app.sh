#!/bin/bash
# Local ad-hoc development bundle only; no Developer ID signature or notarization.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${1:-debug}"
case "$CONFIGURATION" in
    debug|release) ;;
    *) printf 'Usage: bash scripts/build-app.sh [debug|release]\n' >&2; exit 2 ;;
esac

swift build --package-path "$ROOT" --configuration "$CONFIGURATION"
BIN_DIR="$(swift build --package-path "$ROOT" --configuration "$CONFIGURATION" --show-bin-path)"
APP="$ROOT/dist/Russian Armour.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$ROOT/Support/Info.plist" "$APP/Contents/Info.plist"
# Replace the executable atomically; do not truncate a binary mapped by a running app.
STAGED_BINARY="$(mktemp "$APP/Contents/MacOS/.RussianArmour.XXXXXX")"
trap 'rm -f "$STAGED_BINARY"' EXIT
cp "$BIN_DIR/RussianArmour" "$STAGED_BINARY"
chmod 755 "$STAGED_BINARY"
mv -f "$STAGED_BINARY" "$APP/Contents/MacOS/RussianArmour"
/usr/bin/plutil -lint "$APP/Contents/Info.plist"
# The standalone SPM executable's signature does not seal this assembled bundle.
/usr/bin/codesign --force --sign - "$APP"
/usr/bin/codesign --verify --strict "$APP"
printf '\nBuilt: %s\nLaunch: open "%s"\n' "$APP" "$APP"
