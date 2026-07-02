#!/usr/bin/env pwsh

# Installs flextunnel-agent as a native Windows service via NSSM (https://nssm.cc/),
# so it starts at boot before any interactive logon. See docs/windows-service.md.
#
# Usage:
#   .\install-agent-service.ps1 -ConfigPath <path> [-BinaryPath <path>] [-AgentArgs <args>]
#   .\install-agent-service.ps1 -Uninstall [-ServiceName <name>]
#
# -BinaryPath defaults to C:\Program Files\flextunnel\flextunnel-agent.exe, i.e.
# wherever install-agent.ps1 installs it.
#
# Requires: NSSM on PATH (winget install NSSM.NSSM), and an elevated PowerShell session.

param(
    [string]$ServiceName = "flextunnel-agent",
    [string]$BinaryPath = "$env:ProgramFiles\flextunnel\flextunnel-agent.exe",
    [string]$ConfigPath,
    [string[]]$AgentArgs = @(),
    [string]$LogLevel = "info",
    [string]$DataDir = "$env:ProgramData\flextunnel",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

function Print-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Green }
function Print-Warn { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Print-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

function Test-AdminPrivileges {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Print-Error "This script must be run from an elevated (Administrator) PowerShell session."
        Print-Error "Installing or removing a Windows service requires admin rights."
        exit 1
    }
}

function Get-Nssm {
    $cmd = Get-Command nssm -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Print-Error "nssm was not found on PATH."
        Print-Error "Install it first, e.g.:"
        Print-Error "  winget install NSSM.NSSM"
        Print-Error "or download from https://nssm.cc/download"
        exit 1
    }
    return $cmd.Source
}

function Remove-ServiceIfExists {
    param([string]$Nssm, [string]$Name)

    & $Nssm status $Name *> $null
    if ($LASTEXITCODE -eq 0) {
        Print-Warn "Service '$Name' already exists; removing it first."
        & $Nssm stop $Name *> $null
        & $Nssm remove $Name confirm | Out-Null
    }
}

function Format-NssmArgString {
    param([string[]]$Arguments)

    ($Arguments | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    }) -join ' '
}

Test-AdminPrivileges
$nssm = Get-Nssm

if ($Uninstall) {
    Print-Info "Stopping and removing service '$ServiceName'..."
    & $nssm stop $ServiceName *> $null
    & $nssm remove $ServiceName confirm
    Print-Info "Service '$ServiceName' removed."
    exit 0
}

$BinaryPath = [System.IO.Path]::GetFullPath($BinaryPath)
if (-not (Test-Path $BinaryPath)) {
    Print-Error "Binary not found at $BinaryPath"
    Print-Error "Install it first (.\install-agent.ps1) or pass -BinaryPath explicitly."
    exit 1
}

if ($AgentArgs -contains "--default-config") {
    Print-Error "Do not use --default-config with a service: it resolves against the service"
    Print-Error "account's profile (e.g. LocalSystem's), not yours. Pass -ConfigPath instead,"
    Print-Error "or absolute --auth-token-file / --server-node-id values in -AgentArgs."
    exit 1
}

$runArgs = @("run")
if ($ConfigPath) {
    if (-not [System.IO.Path]::IsPathRooted($ConfigPath)) {
        Print-Error "-ConfigPath must be an absolute path — the service does not run from your"
        Print-Error "current directory or your user profile."
        exit 1
    }
    $runArgs += @("--config", $ConfigPath)
}
$runArgs += $AgentArgs

$DataDir = [System.IO.Path]::GetFullPath($DataDir)
$logDir = Join-Path $DataDir "logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$stdoutLog = Join-Path $logDir "$ServiceName.out.log"
$stderrLog = Join-Path $logDir "$ServiceName.err.log"
$paramString = Format-NssmArgString -Arguments $runArgs

Print-Info "Installing service '$ServiceName'..."
Print-Info "  Binary:    $BinaryPath"
Print-Info "  Arguments: $paramString"
Print-Info "  Directory: $DataDir"
Print-Info "  Log level: $LogLevel (RUST_LOG)"
Print-Info "  Stdout:    $stdoutLog"
Print-Info "  Stderr:    $stderrLog"

Remove-ServiceIfExists -Nssm $nssm -Name $ServiceName

& $nssm install $ServiceName $BinaryPath
& $nssm set $ServiceName AppParameters $paramString
& $nssm set $ServiceName AppDirectory $DataDir
& $nssm set $ServiceName AppStdout $stdoutLog
& $nssm set $ServiceName AppStderr $stderrLog
& $nssm set $ServiceName AppRotateFiles 1
& $nssm set $ServiceName AppRotateOnline 1
& $nssm set $ServiceName AppRotateBytes 10485760
& $nssm set $ServiceName AppEnvironmentExtra "RUST_LOG=$LogLevel"
& $nssm set $ServiceName Start SERVICE_AUTO_START
& $nssm set $ServiceName AppExit Default Restart
& $nssm set $ServiceName AppRestartDelay 5000
& $nssm set $ServiceName DisplayName "flextunnel reverse-routing agent"
& $nssm set $ServiceName Description "Runs flextunnel-agent so this machine is reachable via reverse routing, starting at boot before any interactive logon."

Print-Info "Starting service..."
& $nssm start $ServiceName
Start-Sleep -Seconds 2
& $nssm status $ServiceName

Print-Info "Done."
Print-Info "Logs: $stdoutLog"
Print-Info "      $stderrLog"
Print-Info "Uninstall with: .\install-agent-service.ps1 -Uninstall -ServiceName $ServiceName"
