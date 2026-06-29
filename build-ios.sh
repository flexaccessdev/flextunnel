#!/usr/bin/env bash
#
# Build libflextunnel for iOS — both the device (aarch64-apple-ios) and the
# Simulator (aarch64-apple-ios-sim) slices — and bundle them into
# libflextunnel.xcframework, staged with the C header for the separate Xcode
# project (../flextunnel-ios).
#
# An XCFramework is required (not a lipo "fat" .a): the device and Simulator
# slices are both arm64 on Apple Silicon, and lipo refuses to combine two slices
# of the same architecture. The .xcframework lets one Xcode project link the
# right slice for whichever destination (device or Simulator) is selected.
#
# Unlike a Packet Tunnel Provider, the flextunnel POC app has no Network
# Extension, so the static lib links and runs in the iOS Simulator too.
#
# Usage:
#   ./build-ios.sh            # release build (default)
#   ./build-ios.sh debug      # debug build (faster compile, huge .a)
set -euo pipefail

PROFILE="${1:-release}"
DEVICE_TARGET="aarch64-apple-ios"
SIM_TARGET="aarch64-apple-ios-sim"
# Minimum iOS version. The SwiftUI WebView/WebPage proxy path needs iOS 26.
# Must be <= the Xcode project's deployment target. Override via env.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-26.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release"; OUT_SUBDIR="release" ;;
  debug)   CARGO_FLAGS="";          OUT_SUBDIR="debug"   ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

for target in "$DEVICE_TARGET" "$SIM_TARGET"; do
  if ! rustup target list --installed | grep -q "^${target}$"; then
    echo "Installing Rust target ${target}..."
    rustup target add "$target"
  fi
done

for target in "$DEVICE_TARGET" "$SIM_TARGET"; do
  echo "Building libflextunnel.a [$PROFILE] for $target ..."
  cargo build --lib -p flextunnel-ffi ${CARGO_FLAGS} --target "$target"
done

DIST="$SCRIPT_DIR/dist/ios"
XCFRAMEWORK="$DIST/libflextunnel.xcframework"
mkdir -p "$DIST"
cp "ios/flextunnel.h" "$DIST/flextunnel.h"

echo "Creating libflextunnel.xcframework ..."
rm -rf "$XCFRAMEWORK"
xcodebuild -create-xcframework \
  -library "target/${DEVICE_TARGET}/${OUT_SUBDIR}/libflextunnel.a" -headers "ios" \
  -library "target/${SIM_TARGET}/${OUT_SUBDIR}/libflextunnel.a"    -headers "ios" \
  -output "$XCFRAMEWORK"

echo "Staged: $XCFRAMEWORK"
echo "        $DIST/flextunnel.h"

# If the sibling Xcode project exists, sync the artifacts into its vendor dir so
# a rebuild there picks them up with no manual copy.
SIBLING_VENDOR="$SCRIPT_DIR/../flextunnel-ios/vendor"
if [ -d "$SIBLING_VENDOR" ]; then
  rm -rf "$SIBLING_VENDOR/libflextunnel.xcframework"
  cp -R "$XCFRAMEWORK" "$SIBLING_VENDOR/libflextunnel.xcframework"
  cp "$DIST/flextunnel.h" "$SIBLING_VENDOR/flextunnel.h"
  # Drop the obsolete single-arch lib from earlier device-only builds.
  rm -f "$SIBLING_VENDOR/libflextunnel.a"
  echo "Synced into:  $SIBLING_VENDOR/"
fi

echo "Done."
