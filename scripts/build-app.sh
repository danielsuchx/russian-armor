#!/bin/bash
# Local ad-hoc development bundle only; no Developer ID signature or notarization.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${1:-release}"
ARCHITECTURE="${2:-native}"
case "$CONFIGURATION" in
    debug|release) ;;
    *) printf 'Usage: bash scripts/build-app.sh [debug|release] [native|universal]\n' >&2; exit 2 ;;
esac

BUILD_OPTIONS=(--package-path "$ROOT" --configuration "$CONFIGURATION")
case "$ARCHITECTURE" in
    native) ;;
    universal) BUILD_OPTIONS+=(--arch arm64 --arch x86_64 --scratch-path "$ROOT/.build/universal") ;;
    *) printf 'Unknown architecture: use native or universal.\n' >&2; exit 2 ;;
esac
swift build "${BUILD_OPTIONS[@]}" --product RussianArmor
swift build "${BUILD_OPTIONS[@]}" --product ArmorClashReader
swift build "${BUILD_OPTIONS[@]}" --product ArmorFirewall
bash "$ROOT/scripts/build-wireguard.sh"
bash "$ROOT/scripts/build-engine.sh" "$CONFIGURATION" "$ARCHITECTURE"
if [[ -n "${ARMOR_FILTER_TEAM_ID:-}" ]]; then
    bash "$ROOT/scripts/build-claude-filter.sh"
fi
BIN_DIR="$(swift build "${BUILD_OPTIONS[@]}" --show-bin-path)"
APP="$ROOT/dist/Russian Armor.app"
mkdir -p "$ROOT/dist"
STAGING_DIRECTORY="$(mktemp -d "$ROOT/dist/.RussianArmor.XXXXXX")"
trap 'rm -rf "$STAGING_DIRECTORY"' EXIT
STAGED_APP="$STAGING_DIRECTORY/Russian Armor.app"
# Assemble only these files; stale or user-added files in the old app cannot leak.
mkdir -p "$STAGED_APP/Contents/MacOS" "$STAGED_APP/Contents/Resources"
cp -X "$ROOT/Support/Info.plist" "$STAGED_APP/Contents/Info.plist"
cp -X "$ROOT/Sources/RussianArmor/Resources/AppIcon.icns" "$STAGED_APP/Contents/Resources/AppIcon.icns"
mkdir -p "$STAGED_APP/Contents/Helpers"
/usr/bin/ditto "$ROOT/.build/network-engine/ArmorNetworkEngine.app" "$STAGED_APP/Contents/Helpers/ArmorNetworkEngine.app"
cp -X "$ROOT/NetworkEngine/LICENSE" "$STAGED_APP/Contents/Resources/NetworkEngine-LICENSE.txt"
cp -X "$ROOT/THIRD_PARTY_NOTICES.md" "$STAGED_APP/Contents/Resources/THIRD_PARTY_NOTICES.md"
cp -X "$ROOT/Support/UpdatePublicKey.txt" "$STAGED_APP/Contents/Resources/UpdatePublicKey.txt"
cp -X "$BIN_DIR/RussianArmor" "$STAGED_APP/Contents/MacOS/RussianArmor"
cp -X "$BIN_DIR/ArmorFirewall" "$STAGED_APP/Contents/MacOS/ArmorFirewall"
cp -X "$ROOT/.build/wireguard/wireguard-go" "$STAGED_APP/Contents/MacOS/ArmorWireGuard"
cp -X "$ROOT/.build/wireguard/WireGuard-LICENSE.txt" "$STAGED_APP/Contents/Resources/WireGuard-LICENSE.txt"
/usr/bin/codesign --force --identifier app.russian-armor.firewall --sign - "$STAGED_APP/Contents/MacOS/ArmorFirewall"
/usr/bin/codesign --force --identifier app.russian-armor.wireguard --sign - "$STAGED_APP/Contents/MacOS/ArmorWireGuard"
mkdir -p "$STAGED_APP/Contents/Library/LaunchDaemons"
cp -X "$ROOT/Support/app.russian-armor.clash-reader.plist" "$STAGED_APP/Contents/Library/LaunchDaemons/"
cp -X "$BIN_DIR/ArmorClashReader" "$STAGED_APP/Contents/MacOS/"
if [[ "$CONFIGURATION" == release ]]; then
    /usr/bin/strip -S -x "$STAGED_APP/Contents/MacOS/ArmorClashReader"
fi
/usr/bin/codesign --force --identifier app.russian-armor.clash-reader --sign - "$STAGED_APP/Contents/MacOS/ArmorClashReader"
chmod 755 "$STAGED_APP/Contents/MacOS/RussianArmor"
if [[ "$ARCHITECTURE" == universal ]]; then
    # Xcode 27's lipo accepts one architecture per -verify_arch invocation.
    /usr/bin/lipo -verify_arch arm64 "$STAGED_APP/Contents/MacOS/RussianArmor"
    /usr/bin/lipo -verify_arch x86_64 "$STAGED_APP/Contents/MacOS/RussianArmor"
fi
if [[ "$CONFIGURATION" == release ]]; then
    # SwiftPM release binaries retain debug/linker metadata containing source paths.
    /usr/bin/strip -S -x "$STAGED_APP/Contents/MacOS/RussianArmor"
    /usr/bin/strings -a "$STAGED_APP/Contents/MacOS/RussianArmor" > "$STAGING_DIRECTORY/binary-strings.txt"
    if /usr/bin/grep -Fq "$ROOT/" "$STAGING_DIRECTORY/binary-strings.txt" \
        || /usr/bin/grep -Eq '/Users/[^/]+/|/home/[^/]+/' "$STAGING_DIRECTORY/binary-strings.txt"; then
        printf 'Release verification failed: local build paths remain in the executable.\n' >&2
        exit 1
    fi
fi
/usr/bin/plutil -lint "$STAGED_APP/Contents/Info.plist"
# The standalone SPM executable's signature does not seal this assembled bundle.
if [[ -n "${ARMOR_FILTER_TEAM_ID:-}" ]]; then
    ARMOR_FILTER_HOST="$ROOT/.build/claude-filter/Build/Products/Release/ArmorFilterHost.app"
    mkdir -p "$STAGED_APP/Contents/Library/SystemExtensions"
    /usr/bin/ditto "$ARMOR_FILTER_HOST/Contents/Library/SystemExtensions/ArmorClaudeFilter.systemextension" \
        "$STAGED_APP/Contents/Library/SystemExtensions/app.russian-armor.claude-filter.systemextension"
    cp -X "$ARMOR_FILTER_HOST/Contents/embedded.provisionprofile" "$STAGED_APP/Contents/embedded.provisionprofile"
    /usr/bin/codesign --force --options runtime --entitlements "$ROOT/Support/ClaudeFilter/Host.entitlements" \
        --sign "${ARMOR_SIGNING_IDENTITY:-Apple Development}" "$STAGED_APP"
else
    /usr/bin/codesign --force --sign - "$STAGED_APP"
fi
/usr/bin/codesign --verify --strict --all-architectures "$STAGED_APP"
# Swap complete bundles atomically. A running app keeps its mapped executable;
# the old bundle moves into our staging directory and is removed by the trap.
swift - "$STAGED_APP" "$APP" <<'SWIFT'
import Darwin
import Foundation
let staged = CommandLine.arguments[1]
let destination = CommandLine.arguments[2]
let exists = FileManager.default.fileExists(atPath: destination)
let result = exists ? renamex_np(staged, destination, UInt32(RENAME_SWAP)) : rename(staged, destination)
guard result == 0 else {
    perror("Cannot install app bundle")
    exit(1)
}
SWIFT
printf '\nBuilt: %s\nLaunch: open "%s"\n' "$APP" "$APP"
