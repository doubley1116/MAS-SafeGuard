$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$serverScript = Join-Path $scriptDir "showcase_server.ps1"
$nodeServer = Join-Path $scriptDir "server.js"
$port = 48317
$powershellExe = (Get-Process -Id $PID).Path
$serverUrl = "http://127.0.0.1:{0}" -f $port

$nodeCandidates = @()
$bundledNode = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\node\bin\node.exe"
if (Test-Path -LiteralPath $bundledNode) {
  $nodeCandidates += $bundledNode
}
$pathNode = Get-Command node.exe -ErrorAction SilentlyContinue
if ($pathNode) {
  $nodeCandidates += $pathNode.Source
}

$bundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if (Test-Path -LiteralPath $bundledPython) {
  $env:ZERO_TRUST_PYTHON = $bundledPython
}

$nodeExe = $nodeCandidates | Select-Object -First 1

if ($nodeExe) {
  $process = Start-Process -FilePath $nodeExe `
    -ArgumentList @($nodeServer) `
    -WorkingDirectory $scriptDir `
    -WindowStyle Hidden `
    -PassThru
  $runtime = "Node"
} else {
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
    -WindowStyle Hidden `
    -PassThru
  $runtime = "PowerShell fallback"
}

Start-Sleep -Seconds 2
Start-Process $serverUrl

Write-Host "Zero Trust Showcase started"
Write-Host "Runtime: $runtime"
Write-Host "PID: $($process.Id)"
Write-Host "URL: $serverUrl"
