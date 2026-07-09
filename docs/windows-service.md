# Running flextunnel-agent as a Windows service

`flextunnel-agent` is a plain console binary (see [`main.rs`](../crates/flextunnel-agent/src/main.rs))
— it doesn't call the Windows Service Control API, so `sc create` can't launch
it directly (you'd get error 1053, "the service did not respond in a timely
fashion"). To have it start **at boot, before any interactive logon** — the
scenario where the agent is what unblocks remote desktop access to the
machine — wrap it with [NSSM](https://nssm.cc/), which implements the Service
Control Protocol on the binary's behalf.

A per-user autostart (Task Scheduler "at logon", the Startup folder) does
**not** cover this case: those only run once a user has already logged in
interactively.

## Why not just `sc create` pointed at the exe, or rely on PATH/env vars as-is

- flextunnel-agent never shells out to another process, so PATH resolution
  for *its own* execution isn't a concern — NSSM is given the exe's full
  path directly.
- It calls `dirs::home_dir()` for `--default-config` and for `~` expansion in
  config paths. Under a service this resolves to the **service account's**
  profile, not yours (e.g. `LocalSystem` maps to
  `C:\Windows\System32\config\systemprofile`), so **don't use
  `--default-config`** — pass explicit absolute paths instead.
- `RUST_LOG` (via `env_logger`) only takes effect if it's set on the service
  process itself — it does not inherit from your interactive shell's
  environment.
- The service's working directory defaults to `C:\Windows\System32`, which
  only matters if you pass relative paths — use absolute paths for
  `--config` / `--auth-token-file` and this is moot.

## Automated setup

[`install-agent-service.ps1`](../install-agent-service.ps1) wraps the steps
below, enforces absolute paths, and refuses `--default-config`. From an
**elevated** PowerShell session:

```powershell
# One-time: install the agent binary (system-wide, C:\Program Files\flextunnel)
# and NSSM if you don't have it.
.\install-agent.ps1
winget install NSSM.NSSM

# Install and start the service. -BinaryPath defaults to
# C:\Program Files\flextunnel\flextunnel-agent.exe, so it's omitted here.
.\install-agent-service.ps1 -ConfigPath C:\ProgramData\flextunnel\agent.toml
```

Copy [`agent.toml.example`](../agent.toml.example) to
`C:\ProgramData\flextunnel\agent.toml` and fill in `server_node_id` and
`auth_token` (or `auth_token_file`, as an absolute path) first. The binary
lives in `C:\Program Files\flextunnel` (read-only program files); config and
logs live in `C:\ProgramData\flextunnel` (mutable machine-wide state) —
the standard Windows split.

## Updating to a new release

The running service holds a lock on `flextunnel-agent.exe`, so you must stop
it before overwriting the binary — otherwise `install-agent.ps1` fails to
replace the file. From an **elevated** PowerShell session:

```powershell
# 1. Stop the service so the binary is no longer locked.
nssm stop flextunnel-agent

# 2. Install the new binary (checksum-verified) over the old one. Replace
#    vX.Y.Z with the release tag from GitHub releases.
.\install-agent.ps1 vX.Y.Z

# 3. Reinstall and start the service. This removes the stopped service and
#    recreates it with the same config — pass the same -ConfigPath (and any
#    -AgentArgs) you used originally.
.\install-agent-service.ps1 -ConfigPath C:\ProgramData\flextunnel\agent.toml
```

`install-agent-service.ps1` removes any existing service before recreating it,
so step 3 both applies the new binary and restarts cleanly. Confirm the
upgrade with `flextunnel-agent --version` and by checking the log for the
`flextunnel-agent v<version>` and `Authenticated.` lines.

To remove the service:

```powershell
.\install-agent-service.ps1 -Uninstall
```

Logs land in `C:\ProgramData\flextunnel\logs\flextunnel-agent.{out,err}.log`
by default (rotated at 10 MB). Check for the `Agent network id: ftm1…` and
connection lines there to confirm it's running the same as it would
interactively.

## Manual setup (what the script does)

```powershell
$svc = "flextunnel-agent"
nssm install $svc "C:\Program Files\flextunnel\flextunnel-agent.exe"
nssm set $svc AppParameters 'run --config "C:\ProgramData\flextunnel\agent.toml"'
nssm set $svc AppDirectory C:\ProgramData\flextunnel
nssm set $svc AppStdout C:\ProgramData\flextunnel\logs\flextunnel-agent.out.log
nssm set $svc AppStderr C:\ProgramData\flextunnel\logs\flextunnel-agent.err.log
nssm set $svc AppRotateFiles 1
nssm set $svc AppRotateOnline 1
nssm set $svc AppRotateBytes 10485760
nssm set $svc AppEnvironmentExtra "RUST_LOG=info,iroh=warn,tracing=warn"
nssm set $svc Start SERVICE_AUTO_START
nssm set $svc AppExit Default Restart
nssm set $svc AppRestartDelay 5000
nssm start $svc
```

By default this runs as `LocalSystem`, which starts before logon and needs
no separate credentials — appropriate for the agent since it only reaches
`127.0.0.1` on its own machine and holds no long-lived secret beyond the
`fta` token on disk. If you'd rather run it under a dedicated service
account, use `nssm set <svc> ObjectName <domain\user> <password>`; that
account's profile is what `--default-config` would resolve against, which
is exactly why this setup avoids that flag and uses explicit paths instead.

WinSW is a viable alternative to NSSM (XML-configured, `<env>` /
`<workingdirectory>` elements cover the same env-var and path gotchas) if
you'd rather avoid an NSSM dependency; the script here only automates NSSM.
