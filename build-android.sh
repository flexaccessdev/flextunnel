#!/usr/bin/env bash
#
# Build libflextunnel.so for Android and stage it in the jniLibs layout the
# Android app (../flextunnel-android) consumes:
#
#   dist/android/jniLibs/<abi>/libflextunnel.so
#
# The app loads it through the JNI surface in crates/flextunnel-ffi/src/android.rs.
# It downloads the pinned release's libflextunnel-android.zip by default, and
# links this dist/android tree instead when FLEXTUNNEL_LOCAL_JNILIBS is exactly
# 1 (see that repo's README). This script only produces dist/android; it does
# not write into ../flextunnel-android.
#
# Each ABI is built on a host with the same CPU: arm64-v8a on an arm64 host
# (macvm, an Apple-silicon Mac, CI's macos-latest), x86_64 on an x86_64 one
# (the Linux workstation, CI's ubuntu-latest). The default is the host's own
# ABI, and a different one is refused. Building on another machine's working
# tree goes through ci/unix/remote.sh, e.g. the arm64 .so from here:
#
#   ci/unix/remote.sh -H macvm run ./build-android.sh release
#   ci/unix/remote.sh -H macvm fetch dist/android/jniLibs/arm64-v8a dist/android/jniLibs/arm64-v8a
#
# Only the ABI being built is replaced under dist/android/jniLibs, so the two
# can be staged side by side. The release workflow builds each on its own
# runner and zips the merged tree as libflextunnel-android.zip.
#
# Requires the Android NDK — ANDROID_NDK_HOME / ANDROID_NDK_ROOT, else the
# newest under $ANDROID_HOME/ndk (default ~/Android/Sdk, or
# ~/Library/Android/sdk on a Mac), else Homebrew's android-ndk cask — and
# `cargo ndk` (cargo install cargo-ndk). The Rust target is added on demand.
#
# Usage:
#   ./build-android.sh            # release build of the host's ABI (default)
#   ./build-android.sh debug      # debug build (faster compile, huge .so)
#
set -euo pipefail

PROFILE="${1:-release}"
# Minimum Android API level the .so links against: the app's minSdk, 34
# (Android 14).
ANDROID_API=34
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

case "$PROFILE" in
  release) CARGO_FLAGS="--release" ;;
  debug)   CARGO_FLAGS="" ;;
  *) echo "unknown profile '$PROFILE' (use 'release' or 'debug')" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  arm64|aarch64) HOST_ABI=arm64-v8a TARGET=aarch64-linux-android ;;
  x86_64|amd64)  HOST_ABI=x86_64    TARGET=x86_64-linux-android ;;
  *) echo "no Android ABI builds on a $(uname -m) host" >&2; exit 1 ;;
esac
ABI="${ABIS:-$HOST_ABI}"
if [ "$ABI" != "$HOST_ABI" ]; then
  echo "this $(uname -m) host builds $HOST_ABI only, not '$ABI': each ABI is built on a host with its own CPU (see the top of this script)" >&2
  exit 1
fi

command -v cargo-ndk >/dev/null 2>&1 ||
  { echo "cargo-ndk not found: install it with 'cargo install cargo-ndk'" >&2; exit 1; }
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
  if [ "$(uname -s)" = Darwin ]; then sdk_default="$HOME/Library/Android/sdk"; else sdk_default="$HOME/Android/Sdk"; fi
  SDK="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$sdk_default}}"
  if [ -d "$SDK/ndk" ] && [ -n "$(ls -A "$SDK/ndk")" ]; then
    ANDROID_NDK_HOME="$(ls -d "$SDK"/ndk/* | sort -V | tail -1)"
  elif [ -d /opt/homebrew/share/android-ndk ]; then
    ANDROID_NDK_HOME=/opt/homebrew/share/android-ndk
  else
    echo "no Android NDK found: set ANDROID_NDK_HOME, or install one under $SDK/ndk" >&2
    exit 1
  fi
  export ANDROID_NDK_HOME
fi
echo "NDK: ${ANDROID_NDK_HOME:-$ANDROID_NDK_ROOT}"

rustup target list --installed | grep -qx "$TARGET" || rustup target add "$TARGET"

JNILIBS="$SCRIPT_DIR/dist/android/jniLibs"
rm -rf "${JNILIBS:?}/$ABI"
mkdir -p "$JNILIBS"

echo "Building libflextunnel.so [$PROFILE] for $ABI ..."
# shellcheck disable=SC2086
cargo ndk -t "$ABI" --platform "$ANDROID_API" -o "$JNILIBS" \
  build -p flextunnel-ffi --lib $CARGO_FLAGS
# cargo-ndk stages every shared library it finds; only libflextunnel.so is wanted.
find "$JNILIBS/$ABI" -type f ! -name libflextunnel.so -delete

ls -la "$JNILIBS/$ABI/libflextunnel.so"
echo
echo "For local Android FFI dev, build the app against this tree with:"
echo "    cd ../flextunnel-android"
echo "    FLEXTUNNEL_LOCAL_JNILIBS=1 ./gradlew :app:installDebug"
