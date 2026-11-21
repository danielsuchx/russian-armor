#!/bin/bash
# A real Network Extension profile is mandatory; ad-hoc signing cannot install it.
set -euo pipefail
ARMOR_FILTER_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
command -v xcodegen >/dev/null || { printf 'Install xcodegen to build the Claude filter.\n' >&2; exit 1; }
xcodegen generate --spec "$ARMOR_FILTER_ROOT/Support/ClaudeFilter/project.yml"
ARMOR_FILTER_OPTIONS=(-project "$ARMOR_FILTER_ROOT/Support/ClaudeFilter/ArmorClaudeFilter.xcodeproj" -configuration Release -derivedDataPath "$ARMOR_FILTER_ROOT/.build/claude-filter")
if [[ "${1:-}" == --unsigned ]]; then
    xcodebuild "${ARMOR_FILTER_OPTIONS[@]}" -scheme ArmorClaudeFilter CODE_SIGNING_ALLOWED=NO build
else
    : "${ARMOR_FILTER_TEAM_ID:?Set ARMOR_FILTER_TEAM_ID after signing in to Xcode Settings Accounts}"
    xcodebuild "${ARMOR_FILTER_OPTIONS[@]}" -scheme ArmorFilterHost -allowProvisioningUpdates \
        "DEVELOPMENT_TEAM=$ARMOR_FILTER_TEAM_ID" build
    /usr/bin/codesign --verify --deep --strict "$ARMOR_FILTER_ROOT/.build/claude-filter/Build/Products/Release/ArmorFilterHost.app"
fi
