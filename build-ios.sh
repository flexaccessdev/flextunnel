#!/usr/bin/env bash
#
# Build libflextunnel.a for a real iOS device (aarch64-apple-ios) and stage it
# with the C header for the separate Xcode project (../flextunnel-ios).
#
# Unlike a Packet Tunnel Provider, the flextunnel POC app has no Network
# Extension, so the static lib also links and runs in the iOS Simulator — but
# this script builds the device slice only (matching the ezvpn convention). Add
# an aarch64-apple-ios-sim slice if you need the Simulator.
#
# Usage:
#   ./build-ios.sh            # release build (default)
#   ./build-ios.sh debug      # debug build (faster compile, huge .a)
set -euo pipefail

PROFILE="${1:-release}"
TARGET="aarch64-apple-ios"
# Minimum iOS version. WKWebsiteDataStore.proxyConfigurations needs iOS 17.
# Must be <= the Xcode project's deployment target. Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-17.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

if ! rustup target list --installed | grep -q "^${TARGET}$"; then
  echo "Installing Rust target ${TARGET}..."
  rustup target add "$TARGET"
fi

echo "Building libflextunnel.a [$PROFILE] for $TARGET ..."
cargo build --lib -p flextunnel-ffi ${CARGO_FLAGS} --target "$TARGET"

DIST="$SCRIPT_DIR/dist/ios"
mkdir -p "$DIST"
cp "target/${TARGET}/${OUT_SUBDIR}/libflextunnel.a" "$DIST/libflextunnel.a"
cp "ios/flextunnel.h" "$DIST/flextunnel.h"
echo "Staged: $DIST/libflextunnel.a"
echo "        $DIST/flextunnel.h"

# If the sibling Xcode project exists, sync the artifacts into its vendor dir so
# a rebuild there picks them up with no manual copy.
SIBLING_VENDOR="$SCRIPT_DIR/../flextunnel-ios/vendor"
if [ -d "$SIBLING_VENDOR" ]; then
  cp "$DIST/libflextunnel.a" "$SIBLING_VENDOR/libflextunnel.a"
  cp "$DIST/flextunnel.h"    "$SIBLING_VENDOR/flextunnel.h"
  echo "Synced into:  $SIBLING_VENDOR/"
fi

echo "Done."
