$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$serverScript = Join-Path $scriptDir "showcase_server.ps1"
$port = 48317
$powershellExe = (Get-Process -Id $PID).Path
$serverUrl = "http://127.0.0.1:{0}" -f $port
$argumentList = @(
  "-NoProfile",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  $serverScript
)

$process = Start-Process -FilePath $powershellExe `
  -ArgumentList $argumentList `
  -WorkingDirectory $scriptDir `
  -PassThru

Start-Sleep -Seconds 2
Start-Process $serverUrl

Write-Host "Zero Trust Showcase started"
Write-Host "PID: $($process.Id)"
Write-Host "URL: $serverUrl"
