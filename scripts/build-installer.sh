#!/bin/bash
# Universal drag-and-drop image; no privileged package scripts or bundled user data.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/scripts/build-app.sh" release universal

APP="$ROOT/dist/Russian Armor.app"
VERSION="$(/usr/bin/plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")"
IMAGE="$ROOT/dist/Russian-Armor.dmg"
STAGING_DIRECTORY="$(mktemp -d "$ROOT/dist/.Installer.XXXXXX")"
trap 'rm -rf "$STAGING_DIRECTORY"' EXIT
PAYLOAD="$STAGING_DIRECTORY/payload"
mkdir -p "$PAYLOAD"
/usr/bin/ditto --norsrc --noextattr "$APP" "$PAYLOAD/Russian Armor.app"
/usr/bin/codesign --verify --deep --strict --all-architectures "$PAYLOAD/Russian Armor.app"
ln -s /Applications "$PAYLOAD/Applications"
cat > "$PAYLOAD/Установка.txt" <<EOF
Russian Armor $VERSION
macOS 13 и новее · Apple Silicon и Intel

1. Перетащите Russian Armor.app в папку Applications («Программы»).
2. Извлеките образ диска.
3. Включите свой VPN и откройте Russian Armor из «Программ».
4. Нажмите на щит в строке меню и настройте разрешённую страну в «Настройки → Защита».

При обновлении сначала выйдите из работающего Russian Armor через его меню.

Сборка имеет локальную подпись и не заверена Apple для распространения.
macOS может предупредить о неизвестном разработчике или заблокировать запуск.
Инструкция Apple: https://support.apple.com/ru-ru/102445
Не отключайте защиту macOS. Открывайте приложение, только если доверяете источнику.

Настройки и история создаются в профиле запускающего пользователя.
В приложение входит служба чтения туннелей Hiddify и Clash, включаемая в настройках.

Исходный код: https://github.com/danielsuchx/russian-armor
EOF

# A new source folder and read-only image exclude stale files and volume writes.
/usr/bin/hdiutil create -volname "Russian Armor $VERSION" -srcfolder "$PAYLOAD" \
    -fs HFS+ -format UDZO -nospotlight "$STAGING_DIRECTORY/Russian-Armor.dmg"
/usr/bin/hdiutil verify "$STAGING_DIRECTORY/Russian-Armor.dmg"
mv -f "$STAGING_DIRECTORY/Russian-Armor.dmg" "$IMAGE"
(cd "$ROOT/dist" && /usr/bin/shasum -a 256 Russian-Armor.dmg > SHA256SUMS.txt)
printf '\nInstaller: %s\nChecksum: %s\n' "$IMAGE" "$ROOT/dist/SHA256SUMS.txt"
