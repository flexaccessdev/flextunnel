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
| macOS | `macwork` | `FLEXTUNNEL_MACCI_HOST` |
| Linux | `workstation-wsl` | `FLEXTUNNEL_UNIXCI_HOST` |
| Windows | `windows-ci-build` | `FLEXTUNNEL_WINCI_HOST` |

Hosts need Rust, clippy and a native C toolchain. The macOS xcframework check
also needs Xcode; `build-ios.sh` installs the required Rust targets if missing.
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
`clean` deletes the remote Cargo build cache.

## Checks

| Platform | Clippy | Tests | Additional check |
| --- | --- | --- | --- |
| Linux | `cargo clippy --workspace --exclude flextunnel-desktop --all-targets -- -D warnings` | `cargo test -p flextunnel-core -p flextunnel-cli` | — |
| macOS | `cargo clippy --workspace --all-targets -- -D warnings` | `cargo test -p flextunnel-core -p flextunnel-cli -p flextunnel-desktop` | `./build-ios.sh debug` |
| Windows | Same as macOS | Same as macOS | — |

The macOS script reports the xcframework check as skipped if `xcodebuild` is
missing or `FLEXTUNNEL_CI_SKIP_IOS` is set. A green run with that skip does not
verify the iOS build.

The xcframework check builds the Rust library for iOS; it does not build or run
the Swift app. For app integration, run `ci/ci.sh ffi` in `../flextunnel-ios`;
see [the app's CI guide](https://github.com/flexaccessdev/flextunnel-ios/blob/main/docs/local-ci.md). That job builds
and links against the sibling Rust working tree. Simulator tests and device
runs are separate app-side checks.

## Remote workspaces

Each run replaces the remote source workspace. Build caches live outside it
and survive subsequent runs.

| | Unix remotes | Windows |
| --- | --- | --- |
| Workspace | `~/codes/staging-area/flextunnel` | `C:\ci-workspaces\flextunnel` |
| Build cache | `~/codes/staging-area/flextunnel-cargo-target` | `C:\ci-workspaces\cargo-target` |
| Lock | `~/codes/staging-area/flextunnel.lock` | `C:\ci-workspaces\flextunnel.lock` |
| Overrides | `FLEXTUNNEL_UNIXCI_STAGING` | `FLEXTUNNEL_WINCI_STAGING`, `FLEXTUNNEL_WINCI_CACHE_DIR` |

The Windows cache is shared across Rust repos on that VM. Drivers lock the
workspace during CI and cache cleanup; if a terminated run leaves a lock,
confirm it has stopped before using the removal command printed by the driver.

## Coverage limits

Local hosts use their installed Rust/Xcode versions and OS environments, which
can differ from GitHub runners. Use `doctor` to inspect a remote host.

Release builds, installer packaging, release uploads and Docker images are not
checked here. They have additional build and packaging failure modes and are
covered by the release workflows.
