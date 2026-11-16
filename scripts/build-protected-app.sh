#!/bin/bash
# Explicitly provisioned local development bundle. Does not install or activate it.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${1:-debug}"
case "$CONFIGURATION" in
    debug|release) ;;
    *) printf 'Usage: bash scripts/build-protected-app.sh [debug|release]\n' >&2; exit 2 ;;
esac

MISSING=0
for INPUT_NAME in ARMOUR_SIGNING_IDENTITY ARMOUR_APP_PROFILE ARMOUR_PROXY_PROFILE; do
    if [ -z "${!INPUT_NAME:-}" ]; then
        printf 'Missing: %s\n' "$INPUT_NAME" >&2
        MISSING=1
    fi
done
if [ "$MISSING" -ne 0 ]; then
    printf '%s\n' \
        'Нужны Apple signing identity и два provisioning profile с Network Extension:' \
        '  ARMOUR_SIGNING_IDENTITY — полная SHA-1 или полное имя сертификата в Связке ключей;' \
        '  ARMOUR_APP_PROFILE — profile для app.russian-armour.desktop с System Extension install;' \
        '  ARMOUR_PROXY_PROFILE — profile для app.russian-armour.desktop.proxy.' \
        'Оба profile должны разрешать Network Extension и общую keychain group TEAM.app.russian-armour.shared.' \
        'Ad-hoc подпись и отключение SIP не используются.' >&2
    exit 2
fi

mkdir -p "$ROOT/dist"
BUILD_STAGE="$(mktemp -d "$ROOT/dist/.protected-build.XXXXXX")"
trap 'rm -rf "$BUILD_STAGE"' EXIT
xcrun swiftc "$ROOT/scripts/verify-provisioning-profile.swift" -o "$BUILD_STAGE/verify-provisioning-profile"
python3 "$ROOT/scripts/protection_signing.py" prepare \
    --identity "$ARMOUR_SIGNING_IDENTITY" \
    --app-profile "$ARMOUR_APP_PROFILE" \
    --proxy-profile "$ARMOUR_PROXY_PROFILE" \
    --configuration "$CONFIGURATION" \
    --profile-verifier "$BUILD_STAGE/verify-provisioning-profile" \
    --base-info "$ROOT/Support/Info.plist" \
    --support "$ROOT/Support/Protection" \
    --output "$BUILD_STAGE"
SIGNING_IDENTITY="$(cat "$BUILD_STAGE/identity.sha1")"

swift build --package-path "$ROOT" --configuration "$CONFIGURATION" --product RussianArmour
swift build --package-path "$ROOT" --configuration "$CONFIGURATION" --product ArmourProxyExtension
BIN_DIR="$(swift build --package-path "$ROOT" --configuration "$CONFIGURATION" --show-bin-path)"
STAGED_APP="$BUILD_STAGE/Russian Armour Protected.app"
STAGED_PROXY="$STAGED_APP/Contents/Library/SystemExtensions/app.russian-armour.desktop.proxy.systemextension"
mkdir -p "$STAGED_APP/Contents/MacOS" "$STAGED_APP/Contents/Resources" "$STAGED_PROXY/Contents/MacOS"
cp "$BUILD_STAGE/AppInfo.plist" "$STAGED_APP/Contents/Info.plist"
cp "$BUILD_STAGE/ProxyInfo.plist" "$STAGED_PROXY/Contents/Info.plist"
cp "$BUILD_STAGE/App.provisionprofile" "$STAGED_APP/Contents/embedded.provisionprofile"
cp "$BUILD_STAGE/Proxy.provisionprofile" "$STAGED_PROXY/Contents/embedded.provisionprofile"
/usr/bin/find "$STAGED_APP" -type d -exec chmod 755 {} +
chmod 644 "$STAGED_APP/Contents/Info.plist" "$STAGED_PROXY/Contents/Info.plist" \
    "$STAGED_APP/Contents/embedded.provisionprofile" "$STAGED_PROXY/Contents/embedded.provisionprofile"

# Publish executable files by rename, never by truncating a mapped binary.
cp "$BIN_DIR/RussianArmour" "$STAGED_APP/Contents/MacOS/.RussianArmour.staged"
chmod 755 "$STAGED_APP/Contents/MacOS/.RussianArmour.staged"
mv "$STAGED_APP/Contents/MacOS/.RussianArmour.staged" "$STAGED_APP/Contents/MacOS/RussianArmour"
cp "$BIN_DIR/ArmourProxyExtension" "$STAGED_PROXY/Contents/MacOS/.ArmourProxyExtension.staged"
chmod 755 "$STAGED_PROXY/Contents/MacOS/.ArmourProxyExtension.staged"
mv "$STAGED_PROXY/Contents/MacOS/.ArmourProxyExtension.staged" "$STAGED_PROXY/Contents/MacOS/ArmourProxyExtension"
/usr/bin/plutil -lint "$STAGED_APP/Contents/Info.plist" "$STAGED_PROXY/Contents/Info.plist"
/usr/bin/codesign --force --options runtime --timestamp=none --sign "$SIGNING_IDENTITY" \
    --entitlements "$BUILD_STAGE/Proxy.entitlements" "$STAGED_PROXY"
/usr/bin/codesign --force --options runtime --timestamp=none --sign "$SIGNING_IDENTITY" \
    --entitlements "$BUILD_STAGE/App.entitlements" "$STAGED_APP"
/usr/bin/codesign --verify --deep --strict "$STAGED_APP"

APP="$ROOT/dist/Russian Armour Protected.app"
python3 "$ROOT/scripts/protection_signing.py" publish --source "$STAGED_APP" --destination "$APP"
printf '\nBuilt: %s\n' "$APP"
printf '%s\n' 'Сборка подписана и проверена. Установка расширения и включение защиты не выполнялись.'
printf '%s\n' 'Для публичного выпуска дополнительно нужны secure timestamp, notarization и stapling; этот локальный скрипт не обращается к сервисам Apple.'
