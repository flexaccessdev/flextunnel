#!/usr/bin/env bash
# The steps from .github/workflows/ci.yml, in the same order, with the same
# flags — the `linux` + `miri` + x86_64 `android` jobs on Linux, the `macos` +
# `miri` + `verify-ios-xcframework` + arm64-v8a `android` jobs on macOS. When this file and that workflow
# disagree, the workflow is right and this is stale; it exists to say what CI
# will say before CI is asked.
#
# This runs natively on whatever Unix machine it is invoked on: a CI box (see
# ci/unix/remote.sh) or a dev machine. It installs nothing beyond what
# scripts/miri.sh does (its pinned nightly with Miri), so running it locally is
# safe.
#
# Not covered here, on purpose: release-profile builds, .dmg/.msi packaging and
# the Docker images, all of which belong to release.yml.
set -euo pipefail

# Invoked over ssh the working directory is the login user's home, not the
# checkout, so anchor to the repo root this script sits in. A non-interactive
# ssh shell also skips the profile that puts rustup's bin dir on PATH.
cd "$(dirname "$0")/../.."
export PATH="$HOME/.cargo/bin:$PATH"

step() {
    local name=$1; shift
    echo ''
    echo "== $name =="
    echo "   cargo $*"
    cargo "$@"
}

# The miri job (scripts/miri-tests.txt under Miri). The script installs its
# pinned nightly with Miri if missing.
miri() {
    echo ''
    echo '== Miri =='
    echo '   scripts/miri.sh'
    ./scripts/miri.sh
}

# The android job, for the ABI with this host's CPU (build-android.sh builds no
# other): clippy on the FFI for that target, then a debug .so. Skipped loudly
# where cargo-ndk or an NDK is missing — an arm64 Linux box has no NDK at all
# (Google ships none for it), and its ABI is the Mac's job.
android() {
    local abi ndk
    case "$(uname -m)" in
        arm64|aarch64) abi=arm64-v8a ;;
        x86_64|amd64) abi=x86_64 ;;
        *) abi= ;;
    esac
    echo ''
    echo "== Android ${abi:-?} (clippy + debug .so) =="
    if [ -z "$abi" ] || { [ "$(uname -s)" = Linux ] && [ "$abi" = arm64-v8a ]; }; then
        echo '   SKIPPED: no Android NDK runs on this host (arm64-v8a is built on the Mac)'
        return
    fi
    if ! command -v cargo-ndk >/dev/null; then
        echo '   SKIPPED: cargo-ndk is not installed (cargo install cargo-ndk)'
        return
    fi
    # The NDK the way build-android.sh finds it (an SDK's newest over
    # Homebrew's); clippy needs it too. A glob loop, not ls: under pipefail an
    # ls of a path that doesn't exist would end the script.
    ndk=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}
    if [ -z "$ndk" ]; then
        for d in /opt/homebrew/share/android-ndk "$HOME"/Library/Android/sdk/ndk/* "$HOME"/Android/Sdk/ndk/*; do
            [ -d "$d" ] && ndk=$d
        done
    fi
    if [ -z "$ndk" ]; then
        echo '   SKIPPED: no Android NDK on this machine'
        return
    fi
    echo "   cargo ndk -t $abi --platform 34 clippy -p flextunnel-ffi --lib -- -D warnings"
    ANDROID_NDK_HOME=$ndk cargo ndk -t "$abi" --platform 34 clippy -p flextunnel-ffi --lib -- -D warnings
    echo '   ./build-android.sh debug'
    ANDROID_NDK_HOME=$ndk ./build-android.sh debug
}

echo '== toolchain =='
uname -sm
rustc --version
cargo --version
cargo clippy --version
[ -n "${CARGO_TARGET_DIR:-}" ] && echo "   CARGO_TARGET_DIR=$CARGO_TARGET_DIR"

if [ "$(uname -s)" = Darwin ]; then
    # The macos job: the host clippy is what type-checks flextunnel-desktop's
    # macOS backend (tray + keychain), which the Linux job never sees.
    step 'Clippy' clippy --workspace --all-targets -- -D warnings
    step 'Test' test -p flextunnel-core -p flextunnel-cli -p flextunnel-desktop
    miri

    # The verify-ios-xcframework job. Needs Xcode (xcodebuild) and the two iOS
    # Rust targets — build-ios.sh adds the targets itself, but nothing here can
    # conjure up Xcode, so a machine without it skips loudly rather than failing.
    # FLEXTUNNEL_CI_SKIP_IOS=1 skips it on a machine that does have Xcode.
    if [ -n "${FLEXTUNNEL_CI_SKIP_IOS:-}" ]; then
        echo ''
        echo '== iOS xcframework (debug) =='
        echo '   SKIPPED: FLEXTUNNEL_CI_SKIP_IOS is set'
    elif ! command -v xcodebuild >/dev/null; then
        echo ''
        echo '== iOS xcframework (debug) =='
        echo '   SKIPPED: no xcodebuild on this machine'
    else
        echo ''
        echo '== iOS xcframework (debug) =='
        echo '   ./build-ios.sh debug'
        # build-ios.sh builds into ./target and stages ./dist/ios by relative
        # path; CARGO_TARGET_DIR (set by remote.sh) still redirects the former.
        ./build-ios.sh debug
    fi
    android
else
    # The linux job: flextunnel-desktop is macOS/Windows only (tray + keychain
    # backends) and is excluded; flextunnel-ffi still type-checks here.
    step 'Clippy' clippy --workspace --exclude flextunnel-desktop --all-targets -- -D warnings
    step 'Test' test -p flextunnel-core -p flextunnel-cli
    miri
    android
fi

echo ''
echo 'all steps passed'
