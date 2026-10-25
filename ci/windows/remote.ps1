# Thin wrapper: the logic lives in the sibling devtools repo, parameterized by
# this repo's .devtools.conf.
#Requires -Version 7
$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..')).Path
$DevTools = if ($env:DEVTOOLS_DIR) { $env:DEVTOOLS_DIR } else { Join-Path (Split-Path -Parent $RepoRoot) 'devtools' }
$SharedScript = Join-Path $DevTools 'ci' 'windows' 'remote.ps1'
if (-not (Test-Path $SharedScript)) {
    throw "devtools not found at $DevTools — git clone git@github.com:andrewtheguy/devtools.git there (or set DEVTOOLS_DIR)"
}
$env:DEVTOOLS_REPO_ROOT = $RepoRoot
# `@args`, not a param block: splatting the automatic `$args` keeps `-Name` tokens as
# parameter names, where a captured string array would hand them on as plain values.
& $SharedScript @args
# A script that ends without `exit` exits 0 whatever the last command did.
exit $LASTEXITCODE
