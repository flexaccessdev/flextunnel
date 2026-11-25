#!/usr/bin/env bash
# The steps from .github/workflows/ci.yml, in the same order, with the same
# flags — the `linux` + `miri` jobs on Linux, the `macos` + `miri` jobs on
# macOS. When this file and that workflow disagree, the workflow is right and
# this is stale; it exists to say what CI will say before CI is asked.
#
# The mobile libraries' jobs (`verify-ios-xcframework`, `android`) are not
# here: they are only needed when working on ../flextunnel-ios or
# ../flextunnel-android, and need Xcode or an Android NDK. ci/unix/mobile.sh
# runs them, on request.
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
else
    # The linux job: flextunnel-desktop is macOS/Windows only (tray + keychain
    # backends) and is excluded; flextunnel-ffi still type-checks here.
    step 'Clippy' clippy --workspace --exclude flextunnel-desktop --all-targets -- -D warnings
    step 'Test' test -p flextunnel-core -p flextunnel-cli
    miri
fi

echo ''
echo 'all steps passed'
