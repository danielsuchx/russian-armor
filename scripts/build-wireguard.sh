#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE="$ROOT/.build/dependencies/wireguard-go"
REVISION=b3bc704ef0ee21a36298601a9e1e5ff90377ac52
if [[ ! -d "$SOURCE/.git" ]]; then
    git clone https://git.zx2c4.com/wireguard-go "$SOURCE"
fi
[[ "$(git -C "$SOURCE" rev-parse HEAD)" == "$REVISION" ]] || { printf 'Unexpected WireGuard source revision\n' >&2; exit 1; }
ARMOR_GO="$(command -v go || true)"
[[ -n "$ARMOR_GO" ]] || ARMOR_GO=/opt/homebrew/bin/go
mkdir -p "$ROOT/.build/wireguard"
for ARCH in arm64 amd64; do
    (cd "$SOURCE" && CGO_ENABLED=0 GOOS=darwin GOARCH="$ARCH" "$ARMOR_GO" build -trimpath -ldflags="-s -w" -o "$ROOT/.build/wireguard/core-$ARCH" .)
done
/usr/bin/lipo -create "$ROOT/.build/wireguard/core-arm64" "$ROOT/.build/wireguard/core-amd64" -output "$ROOT/.build/wireguard/wireguard-go"
/usr/bin/codesign --force --identifier app.russian-armor.wireguard --sign - "$ROOT/.build/wireguard/wireguard-go"
cp "$SOURCE/LICENSE" "$ROOT/.build/wireguard/WireGuard-LICENSE.txt"
(cd "$SOURCE" && "$ARMOR_GO" version -m "$ROOT/.build/wireguard/wireguard-go") > "$ROOT/.build/wireguard/build-info.txt" 2>/dev/null || true
