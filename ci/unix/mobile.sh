#!/usr/bin/env bash
# The mobile libraries' CI jobs from .github/workflows/ci.yml, on request:
# `verify-ios-xcframework` (macOS with Xcode) and `android` (the ABI of this
# host's CPU — build-android.sh builds no other). They are kept out of
# ci/unix/ci.sh (and so out of ci/all.sh): they are only needed when working on
# ../flextunnel-ios or ../flextunnel-android, those apps pin a release of
# their own rather than tracking this tree, and they need Xcode or an Android
# NDK, which a CI host does not always have.
#
#   ci/unix/mobile.sh [ios] [android]        # natively; no argument: both
#   ci/unix/remote.sh -H macvm run ci/unix/mobile.sh   # on macvm: iOS + arm64-v8a
#   ci/unix/mobile.sh android                # here on x86_64 Linux: x86_64
#
# A job this host cannot run (iOS off a Mac, Android without cargo-ndk or an
# NDK, arm64 Linux, which has no NDK) fails rather than skips: it was asked for.
set -euo pipefail

cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

jobs=("$@")
[ ${#jobs[@]} -gt 0 ] || jobs=(ios android)
for job in "${jobs[@]}"; do
    case $job in ios|android) ;; *) echo "usage: $0 [ios] [android]" >&2; exit 2 ;; esac
done

ios() {
    echo ''
    echo '== iOS xcframework (debug) =='
    [ "$(uname -s)" = Darwin ] && command -v xcodebuild >/dev/null ||
        { echo 'the iOS build needs a Mac with Xcode' >&2; return 1; }
    echo '   ./build-ios.sh debug'
    ./build-ios.sh debug
}

android() {
    local abi ndk=
    case "$(uname -m)" in
        arm64|aarch64) abi=arm64-v8a ;;
        x86_64|amd64) abi=x86_64 ;;
        *) echo "no Android ABI builds on a $(uname -m) host" >&2; return 1 ;;
    esac
    echo ''
    echo "== Android $abi (clippy + debug .so) =="
    if [ "$(uname -s)" = Linux ] && [ "$abi" = arm64-v8a ]; then
        echo 'no Android NDK runs on arm64 Linux: build arm64-v8a on a Mac' >&2
        return 1
    fi
    command -v cargo-ndk >/dev/null || { echo 'cargo-ndk is not installed (cargo install cargo-ndk)' >&2; return 1; }
    # The NDK the way build-android.sh finds it (an SDK's newest over
    # Homebrew's); clippy needs it too.
    ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
    if [ -z "$ndk" ]; then
        for d in /opt/homebrew/share/android-ndk "$HOME"/Library/Android/sdk/ndk/* "$HOME"/Android/Sdk/ndk/*; do
            [ -d "$d" ] && ndk=$d
        done
    fi
    [ -n "$ndk" ] || { echo 'no Android NDK on this machine' >&2; return 1; }
    echo "   cargo ndk -t $abi --platform 34 clippy -p flextunnel-ffi --lib -- -D warnings"
    ANDROID_NDK_HOME=$ndk cargo ndk -t "$abi" --platform 34 clippy -p flextunnel-ffi --lib -- -D warnings
    echo '   ./build-android.sh debug'
    ANDROID_NDK_HOME=$ndk ./build-android.sh debug
}

for job in "${jobs[@]}"; do "$job"; done
echo ''
echo 'mobile steps passed'
