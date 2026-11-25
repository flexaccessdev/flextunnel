# Running CI locally

`ci/all.sh` runs the clippy and test steps from
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) against the working
tree, including uncommitted changes. macOS and Windows checks compile the
desktop backends that Linux excludes.

```sh
ci/all.sh                  # macOS, Linux and Windows concurrently
ci/all.sh linux windows    # selected platforms
ci/unix/ci.sh              # this host's Unix checks, with live output
pwsh -File ci/windows/ci.ps1   # on a Windows dev box, with live output
```

On Linux, the Linux job runs on the current host; on macOS, the macOS job does.
The other jobs use SSH. `ci/all.sh` captures each job's output and prints the
logs and exit codes after all jobs finish.

When a `ci.*` script and the workflow disagree, the workflow is right and the
script is stale. Nothing enforces this; keep them in step by hand.

## Hosts and prerequisites

| Platform | Default SSH alias | Host override |
| --- | --- | --- |
| macOS | `macvm` | `FLEXTUNNEL_MACCI_HOST` |
| Linux | `workstation-wsl` | `FLEXTUNNEL_UNIXCI_HOST` |
| Windows | `windows-ci-build` | `FLEXTUNNEL_WINCI_HOST` |

Hosts need Rust, clippy and a native C toolchain.
Windows remoting needs PowerShell 7 on both ends and an SSH PowerShell
subsystem on the remote host.

The remote wrappers use the sibling `../devtools` checkout, or `DEVTOOLS_DIR`,
with this repo's [`.devtools.conf`](../.devtools.conf). They copy the working
tree over SSH and invoke `ci/unix/ci.sh` or `ci/windows/ci.ps1` remotely.
The shared drivers document transport details.

The Windows VM is provisioned as described in
[`../wrustic/docs/windows-vm-ci.md`](https://github.com/andrewtheguy/wrustic/blob/main/docs/windows-vm-ci.md),
with rustup installed machine-wide so it is visible over SSH. Two failures there
look like a broken toolchain: sshd captures its environment when the service
starts, so a machine-scoped `PATH` or `CARGO_*` change needs
`Restart-Service sshd`; and without a page file, parallel `rustc` processes
exhaust the commit limit.

```sh
ci/unix/remote.sh doctor
ci/unix/remote.sh -H another-host ci
ci/unix/remote.sh shell
ci/unix/remote.sh clean

pwsh -File ci/windows/remote.ps1 doctor
pwsh -File ci/windows/remote.ps1 ci
```

Both remote drivers accept `ci` (the default), `shell`, `doctor` and `clean`.
`clean` deletes the Cargo build cache: the remote target directory, and for
Windows also this repo's snapshots in the build cache's restic repository.

## Checks

| Platform | Clippy | Tests | Additional check |
| --- | --- | --- | --- |
| Linux | `cargo clippy --workspace --exclude flextunnel-desktop --all-targets -- -D warnings` | `cargo test -p flextunnel-core -p flextunnel-cli` | `scripts/miri.sh` |
| macOS | `cargo clippy --workspace --all-targets -- -D warnings` | `cargo test -p flextunnel-core -p flextunnel-cli -p flextunnel-desktop` | `scripts/miri.sh` |
| Windows | Same as macOS | Same as macOS | — |

`scripts/miri.sh` runs the iOS FFI tests listed in
[`scripts/miri-tests.txt`](../scripts/miri-tests.txt) under Miri, installing
its pinned nightly with Miri if missing. The session test runs on Linux only:
its tokio runtime needs epoll, which Miri emulates, and not kqueue. Windows has
no Miri leg: its only unsafe is the Win32 calls in the CLI's pipe security,
which Miri cannot run.

## Mobile libraries (on request)

The iOS xcframework and the Android `libflextunnel.so` are not part of
`ci/unix/ci.sh` or `ci/all.sh`, so a local run for a CLI or desktop change never
needs the hosts and tools they do (Xcode, an Android NDK, macvm for arm64-v8a).
They are only needed when working on `../flextunnel-ios` or
`../flextunnel-android`, and those apps pin a flextunnel release of their own
instead of following this tree.
`ci/unix/mobile.sh` runs their CI jobs (`verify-ios-xcframework`, `android`)
when asked:

```sh
ci/unix/remote.sh -H macvm run ci/unix/mobile.sh   # iOS + Android arm64-v8a, on macvm
ci/unix/mobile.sh android                          # Android x86_64, here on x86_64 Linux
```

Android builds each ABI on a host with its own CPU only (see `build-android.sh`).
A job the host cannot run fails rather than skips, since it was asked for. On
GitHub nothing changes: `ci.yml` runs the same jobs, and `release.yml` builds
both mobile assets for every release.

The xcframework check builds the Rust library for iOS; it does not build or run
the Swift app. For app integration, run `ci/ci.sh ffi` in `../flextunnel-ios`;
see [the app's CI guide](https://github.com/flexaccessdev/flextunnel-ios/blob/main/docs/local-ci.md). That job builds
and links against the sibling Rust working tree. Simulator tests and device
runs are separate app-side checks.

## Remote workspaces

Each run replaces the remote source workspace. Build caches live outside it.

| | Unix remotes | Windows |
| --- | --- | --- |
| Workspace | `~/codes/staging-area/flextunnel` | `C:\ci-workspaces\flextunnel` |
| Build cache | `~/codes/staging-area/flextunnel-cargo-target` | `C:\ci-workspaces\flextunnel-target`, for the run only; snapshots in the restic repository `rest:https://ci-cache.home.in.kuvi.fyi/main`, tagged `repo:flextunnel` |
| Lock | `~/codes/staging-area/flextunnel.lock` | `C:\ci-workspaces\flextunnel.lock` |
| Overrides | `FLEXTUNNEL_UNIXCI_STAGING` | `FLEXTUNNEL_WINCI_STAGING`, `FLEXTUNNEL_WINCI_CACHE_DIR` |

A Unix remote keeps its target directory between runs. The Windows VM keeps
none, like GitHub Actions' cache: the driver restores the run's target
directory from this repo's newest matching restic snapshot, keyed on the lock
and toolchain files and the VM's `rustc -vV`, and after a passing run whose key
missed it saves one pruned to third-party dependencies, keeping the repo's
three newest. restic runs on the driving machine, which needs restic, zstd and
bash; without them the Windows run builds cold. Drivers lock the
workspace during CI and cache cleanup; if a terminated run leaves a lock,
confirm it has stopped before using the removal command printed by the driver.

## Coverage limits

Local hosts use their installed Rust/Xcode versions and OS environments, which
can differ from GitHub runners. Use `doctor` to inspect a remote host.

Release builds, installer packaging, release uploads and Docker images are not
checked here. They have additional build and packaging failure modes and are
covered by the release workflows.
