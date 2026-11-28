# wb.ps1 VARIANT DIR FLOWS [SECS]: one benchmark run on the Windows client, printed as one JSON line.
# VARIANT is a version staged as flextunnel-VARIANT.exe or "none" (no tunnel). Runs remotely
# through Invoke-Command -FilePath; hosts.json (written by bench/stage.py) gives the server address.
param([string]$Version, [string]$Dir, [int]$Flows = 1, [int]$Secs = 6)
$ErrorActionPreference = 'Stop'
$B = 'C:\ci-workspaces\flextunnel-bench'
$iperf = "$B\iperf3\iperf3.exe"
$server4 = (Get-Content "$B\hosts.json" | ConvertFrom-Json).server4

function Run-Iperf([string]$TargetHost, [int]$Port) {
  $a = @('-J', '-t', "$Secs", '-O', '1', '-P', "$Flows", '-c', $TargetHost, '-p', "$Port")
  if ($Dir -eq 'down') { $a += '-R' }
  foreach ($attempt in 1..3) {
    $out = (& $iperf @a 2>&1 | Out-String)
    if ($out -match '"sum_received"') { return ($out | ConvertFrom-Json) }
    Start-Sleep -Seconds 2
  }
  throw "iperf3 failed: $out"
}

function Last-Path {
  $l = Get-Content "$B\client.log", "$B\client.out" -ErrorAction SilentlyContinue | Select-String -Pattern 'Connection: (.*)$' | Select-Object -Last 1
  if ($l) { $l.Matches[0].Groups[1].Value } else { '' }
}

function Add-Result($res, $j) {
  $res.mbps = [math]::Round($j.end.sum_received.bits_per_second / 1e6, 1)
  # iperf3 on Windows does not report a sender's retransmits; a download's come from the Linux server.
  $res.retr = $j.end.sum_sent.retransmits
}

$res = [ordered]@{ variant = $Version; dir = $Dir; flows = $Flows }
if ($Version -eq 'none') {
  Add-Result $res (Run-Iperf $server4 5201)
} else {
  Get-Process | Where-Object { $_.Name -like 'flextunnel-*' } | Stop-Process -Force
  Remove-Item "$B\client.log", "$B\client.out" -ErrorAction SilentlyContinue
  $env:RUST_LOG = 'info,iroh=warn,tracing=warn,flextunnel_core::transport::paths=debug'
  $p = Start-Process -FilePath "$B\flextunnel-$Version.exe" -ArgumentList 'client', 'start', '-c', "$B\client.toml" `
    -RedirectStandardError "$B\client.log" -RedirectStandardOutput "$B\client.out" -PassThru -WindowStyle Hidden
  try {
    $deadline = (Get-Date).AddSeconds(20)
    while (-not (Select-String -Path "$B\client.log", "$B\client.out" -Pattern 'listening on 127.0.0.1:5301' -Quiet -ErrorAction SilentlyContinue)) {
      if ((Get-Date) -gt $deadline) { throw 'client not up' }
      Start-Sleep -Milliseconds 100
    }
    # Connect the destination without sending bulk: read sshd's banner through a second forward.
    $c = [System.Net.Sockets.TcpClient]::new('127.0.0.1', 5322)
    $c.ReceiveTimeout = 15000
    $buf = [byte[]]::new(4); [void]$c.GetStream().Read($buf, 0, 4); $c.Close()
    $deadline = (Get-Date).AddSeconds(20)
    while (-not ((Last-Path) -like 'Direct*')) {
      if ((Get-Date) -gt $deadline) { throw "no direct path: $(Last-Path)" }
      Start-Sleep -Milliseconds 200
    }
    Start-Sleep -Seconds 1
    $res.path = Last-Path
    $p.Refresh(); $c0 = $p.TotalProcessorTime.TotalSeconds; $t0 = Get-Date
    $j = Run-Iperf '127.0.0.1' 5301
    $p.Refresh(); $c1 = $p.TotalProcessorTime.TotalSeconds; $t1 = Get-Date
    Add-Result $res $j
    $res.cpu_client = [math]::Round(($c1 - $c0) / ($t1 - $t0).TotalSeconds, 2)
    $res.path_after = Last-Path
    $res.version = (Get-Content "$B\client.log", "$B\client.out" | Select-String -Pattern 'flextunnel-cli v[0-9.]+' | Select-Object -First 1).Matches[0].Value
  } finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
}
$res | ConvertTo-Json -Compress
