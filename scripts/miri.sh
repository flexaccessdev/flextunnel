#!/usr/bin/env bash
# Run the flextunnel-ffi tests in scripts/miri-tests.txt under Miri on this
# host (Linux or macOS): the C surface the iOS app links, whose unsafe is the
# handle it boxes and frees, the C strings it reads and the caller buffers it
# writes. Run it on Linux and on macvm, the nearest host to the app's
# aarch64-apple-ios.
#
# Isolation is off for the real clock (a new key's timestamp, the session's
# runtime). Miri builds go to target/miri, so the RUSTFLAGS below never touch
# normal builds.
#
#   scripts/miri.sh            # MIRI_TOOLCHAIN overrides the pinned nightly
set -euo pipefail
cd "$(dirname "$0")/.."

toolchain="${MIRI_TOOLCHAIN:-nightly-2026-10-31}"
rustup toolchain install "$toolchain" --profile minimal --component miri,rust-src >/dev/null
export MIRIFLAGS="${MIRIFLAGS:--Zmiri-disable-isolation}"
# sha2 picks the CPU's SHA instructions at runtime, whose intrinsics Miri does
# not implement on aarch64; its portable backend computes the same digests.
export RUSTFLAGS="${RUSTFLAGS:-} --cfg sha2_backend=\"soft\""

host=$(uname -s | tr '[:upper:]' '[:lower:]')
# A read loop rather than mapfile, which macOS' bash 3.2 lacks.
filters=()
while read -r os filter; do
    case "$os" in
        any) filters+=("$filter") ;;
        "$host") filters+=("$filter") ;;
    esac
done <scripts/miri-tests.txt

cargo "+$toolchain" miri test -p flextunnel-ffi -- "${filters[@]}"
