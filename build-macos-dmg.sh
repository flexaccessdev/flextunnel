#!/usr/bin/env bash
#
# Build the desktop app's drag-to-Applications disk image into dist/macos:
# cargo-packager makes flextunnel.app, then create-dmg wraps it. cargo-packager's
# own dmg format is not used because it always takes the app icon as the mounted
# volume's icon; here the volume gets icons/dmg-volume.icns instead — a white
# drive with the app icon on it, the usual installer-volume look (regenerate it
# with icons/make-dmg-volume-icon.py after changing the app icon).
#
# Requires cargo-packager and create-dmg (`brew install create-dmg`). The Finder
# window layout is applied through AppleScript, so run it from a GUI session;
# with CI=true it is skipped (as cargo-packager does), leaving the default view.
#
# Usage:
#   ./build-macos-dmg.sh                         # host target
#   ./build-macos-dmg.sh aarch64-apple-darwin    # explicit target
set -euo pipefail

TARGET="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

command -v create-dmg >/dev/null || { echo "create-dmg not found (brew install create-dmg)" >&2; exit 1; }

TARGET_ARGS=()
RELEASE_DIR="target/release"
if [[ -n "$TARGET" ]]; then
  TARGET_ARGS=(--target "$TARGET")
  RELEASE_DIR="target/$TARGET/release"
fi
case "${TARGET:-$(uname -m)}" in
  aarch64*|arm64) ARCH="arm64" ;;
  x86_64*)        ARCH="amd64" ;;
  *) echo "unsupported target '${TARGET:-$(uname -m)}'" >&2; exit 1 ;;
esac

cargo build --release -p flextunnel-desktop ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"}
cargo packager --release -p flextunnel-desktop --formats app ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"}

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp -R "$RELEASE_DIR/flextunnel.app" "$STAGE/"

OUT_DIR="dist/macos"
DMG="$OUT_DIR/flextunnel-desktop-macos-$ARCH.dmg"
mkdir -p "$OUT_DIR"
rm -f "$DMG"

# Same window layout as cargo-packager's dmg defaults.
DMG_ARGS=(
  --volname flextunnel
  --volicon crates/flextunnel-desktop/icons/dmg-volume.icns
  --window-size 600 400
  --icon flextunnel.app 180 170
  --hide-extension flextunnel.app
  --app-drop-link 480 170
)
[[ "${CI:-}" == "true" ]] && DMG_ARGS+=(--skip-jenkins)

create-dmg "${DMG_ARGS[@]}" "$DMG" "$STAGE"
echo "built $DMG"
