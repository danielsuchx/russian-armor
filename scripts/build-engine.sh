#!/bin/bash
# Build the MIT network engine as a private helper; never run it during a build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIGURATION="${1:-release}"
ARCHITECTURE="${2:-native}"
if command -v cargo >/dev/null 2>&1; then
    ARMOR_CARGO="$(command -v cargo)"
    ARMOR_RUSTUP="$(command -v rustup || true)"
    if [[ -z "$ARMOR_RUSTUP" ]]; then
        printf 'rustup is required to install the selected macOS target. Install the minimal Rust toolchain and retry.\n' >&2
        exit 1
    fi
elif [[ -x "$ROOT/.build/toolchains/cargo/bin/cargo" ]]; then
    ARMOR_CARGO="$ROOT/.build/toolchains/cargo/bin/cargo"
    ARMOR_RUSTUP="$ROOT/.build/toolchains/cargo/bin/rustup"
    export CARGO_HOME="$ROOT/.build/toolchains/cargo"
    export RUSTUP_HOME="$ROOT/.build/toolchains/rustup"
else
    printf 'Rust is required. Install the minimal toolchain from https://rustup.rs/ and retry.\n' >&2
    exit 1
fi
case "$CONFIGURATION" in
    release|debug) ;;
    *) exit 2;;
esac
case "$ARCHITECTURE" in
    universal) ARMOR_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin);;
    native) if [[ "$(uname -m)" == arm64 ]]; then ARMOR_TARGETS=(aarch64-apple-darwin); else ARMOR_TARGETS=(x86_64-apple-darwin); fi;;
    *) exit 2;;
esac
python3 "$ROOT/scripts/generate-engine-bridge.py"
python3 "$ROOT/scripts/engine-license-notices.py" "$ARMOR_CARGO"
export MACOSX_DEPLOYMENT_TARGET=13.0
export RUSTFLAGS="--remap-path-prefix=$ROOT=/src/russian-armor ${RUSTFLAGS:-}"
ARMOR_EXECUTABLES=()
for ARMOR_TARGET in "${ARMOR_TARGETS[@]}"; do
    "$ARMOR_RUSTUP" target add "$ARMOR_TARGET"
    if [[ "$CONFIGURATION" == release ]]; then
        "$ARMOR_CARGO" build --locked --manifest-path "$ROOT/NetworkEngine/src-tauri/Cargo.toml" --bin zastava --target "$ARMOR_TARGET" --release
    else
        "$ARMOR_CARGO" build --locked --manifest-path "$ROOT/NetworkEngine/src-tauri/Cargo.toml" --bin zastava --target "$ARMOR_TARGET"
    fi
    ARMOR_EXECUTABLES+=("$ROOT/NetworkEngine/src-tauri/target/$ARMOR_TARGET/$CONFIGURATION/zastava")
done
ARMOR_HELPER="$ROOT/.build/network-engine/ArmorNetworkEngine.app"
mkdir -p "$ARMOR_HELPER/Contents/MacOS" "$ARMOR_HELPER/Contents/Resources"
if [[ ${#ARMOR_EXECUTABLES[@]} == 2 ]]; then
    /usr/bin/lipo -create "${ARMOR_EXECUTABLES[@]}" -output "$ARMOR_HELPER/Contents/MacOS/ArmorNetworkEngine"
else
    cp -X "${ARMOR_EXECUTABLES[0]}" "$ARMOR_HELPER/Contents/MacOS/ArmorNetworkEngine"
fi
cp -X "$ROOT/Support/NetworkEngine-Info.plist" "$ARMOR_HELPER/Contents/Info.plist"
cp -X "$ROOT/NetworkEngine/LICENSE" "$ARMOR_HELPER/Contents/Resources/NetworkEngine-LICENSE.txt"
cp -X "$ROOT/.build/network-engine/ThirdPartyLicenses.txt" "$ARMOR_HELPER/Contents/Resources/ThirdPartyLicenses.txt"
chmod 755 "$ARMOR_HELPER/Contents/MacOS/ArmorNetworkEngine"
/usr/bin/codesign --force --sign - "$ARMOR_HELPER"
/usr/bin/codesign --verify --strict --all-architectures "$ARMOR_HELPER"
printf 'Built network helper: %s\n' "$ARMOR_HELPER"
