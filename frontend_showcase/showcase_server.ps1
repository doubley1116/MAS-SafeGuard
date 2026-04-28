$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Web

$frontendRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $frontendRoot
$port = 48317
$encoding = [System.Text.Encoding]::UTF8

function Get-Discovery {
  $policyFiles = @(
    Get-ChildItem -Path $repoRoot -Recurse -File -Filter policy.yaml -ErrorAction SilentlyContinue |
      Select-Object -ExpandProperty FullName
  ) | Sort-Object -Unique

  $workflowDirs = @(
    Get-ChildItem -Path $repoRoot -Recurse -Directory -Filter workflows -ErrorAction SilentlyContinue |
      Where-Object { $_.FullName -match '[\\/]+audit_logs[\\/]+workflows$' } |
      Select-Object -ExpandProperty FullName
  ) | Sort-Object -Unique

  $defaultPolicyPath = $policyFiles | Where-Object { $_ -match '[\\/]AutoGenAuditor[\\/]' } | Select-Object -First 1
  if (-not $defaultPolicyPath) {
    $defaultPolicyPath = $policyFiles | Select-Object -First 1
  }

  $defaultWorkflowDir = $workflowDirs | Select-Object -First 1

  [pscustomobject]@{
    repoRoot = [string]$repoRoot
    policyFiles = @($policyFiles | ForEach-Object { [string]$_ })
    workflowDirs = @($workflowDirs | ForEach-Object { [string]$_ })
    defaultPolicyPath = if ($defaultPolicyPath) { [string]$defaultPolicyPath } else { "" }
    defaultWorkflowDir = if ($defaultWorkflowDir) { [string]$defaultWorkflowDir } else { "" }
  }
}

function Normalize-WorkflowPayload {
  param([string] $WorkflowPath)

  try {
    $raw = Get-Content -Path $WorkflowPath -Raw -Encoding UTF8 | ConvertFrom-Json
    [pscustomobject]@{
      filePath = $WorkflowPath
      name = [System.IO.Path]::GetFileNameWithoutExtension($WorkflowPath)
      data = $raw
    }
  } catch {
    [pscustomobject]@{
      filePath = $WorkflowPath
      name = [System.IO.Path]::GetFileNameWithoutExtension($WorkflowPath)
      error = $_.Exception.Message
    }
  }
}

function Get-WorkflowWatchSummary {
  param([string] $WorkflowDir)

  $exists = $WorkflowDir -and (Test-Path -LiteralPath $WorkflowDir)
  $workflowFiles = @()

  if ($exists) {
    $workflowFiles = @(
      Get-ChildItem -Path $WorkflowDir -File -Filter *.json -ErrorAction SilentlyContinue |
        Sort-Object Name
    )
  }

  $fileSummaries = @(
    $workflowFiles | ForEach-Object {
      [pscustomobject]@{
        name = $_.Name
        fullPath = $_.FullName
        length = $_.Length
        lastModified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        lastWriteUtcTicks = $_.LastWriteTimeUtc.Ticks
      }
    }
  )

  $latestFile = $workflowFiles | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
  $fingerprintSeed = if (-not $WorkflowDir) {
    "missing::workflowDir"
  } elseif (-not $exists) {
    "missing::$WorkflowDir"
  } elseif (-not $fileSummaries.Count) {
    "empty::$WorkflowDir"
  } else {
    ($fileSummaries | ForEach-Object {
      "$($_.name)|$($_.length)|$($_.lastWriteUtcTicks)"
    }) -join ";"
  }

  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    $fingerprintBytes = $sha256.ComputeHash($encoding.GetBytes($fingerprintSeed))
  } finally {
    $sha256.Dispose()
  }

  [pscustomobject]@{
    workflowDir = $WorkflowDir
    exists = [bool]$exists
    workflowCount = $workflowFiles.Count
    latestModified = if ($latestFile) { $latestFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
    fingerprint = ([System.BitConverter]::ToString($fingerprintBytes)).Replace("-", "").ToLowerInvariant()
    files = $fileSummaries
    scannedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
  }
}

function Get-ApiPayload {
  param([string] $RequestTarget)

  $requestUri = [System.Uri]("http://127.0.0.1:$port$RequestTarget")
  $path = $requestUri.AbsolutePath

  if ($path -eq "/api/discover") {
    return @{
      StatusCode = 200
      ContentType = "application/json; charset=utf-8"
      Headers = @{
        "Access-Control-Allow-Origin" = "*"
        "Cache-Control" = "no-store"
      }
      Body = (Get-Discovery | ConvertTo-Json -Depth 100)
    }
  }

  if ($path -eq "/api/filesystem") {
    $discovery = Get-Discovery
    $query = [System.Web.HttpUtility]::ParseQueryString($requestUri.Query)
    $policyPath = $query["policyPath"]
    $workflowDir = $query["workflowDir"]

    if (-not $policyPath) {
      $policyPath = $discovery.defaultPolicyPath
    }
    if (-not $workflowDir) {
      $workflowDir = $discovery.defaultWorkflowDir
    }

    $policyPath = [string]$policyPath
    $workflowDir = [string]$workflowDir

    $policyText = ""
    if ($policyPath -and (Test-Path -LiteralPath $policyPath)) {
      $policyText = [string](Get-Content -Path $policyPath -Raw -Encoding UTF8)
    }

    $workflowFiles = @()
    if ($workflowDir -and (Test-Path -LiteralPath $workflowDir)) {
      $workflowFiles = @(
        Get-ChildItem -Path $workflowDir -File -Filter *.json -ErrorAction SilentlyContinue |
          Sort-Object Name |
          Select-Object -ExpandProperty FullName
      )
    }

    $rawWorkflows = @($workflowFiles | ForEach-Object { Normalize-WorkflowPayload -WorkflowPath $_ })
    $watchSummary = Get-WorkflowWatchSummary -WorkflowDir $workflowDir

    return @{
      StatusCode = 200
      ContentType = "application/json; charset=utf-8"
      Headers = @{
        "Access-Control-Allow-Origin" = "*"
        "Cache-Control" = "no-store"
      }
      Body = ([pscustomobject]@{
        repoRoot = $repoRoot
        policyPath = $policyPath
        workflowDir = $workflowDir
        workflowFiles = $workflowFiles
        policyText = $policyText
        rawWorkflows = $rawWorkflows
        watchSummary = $watchSummary
        loadedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
      } | ConvertTo-Json -Depth 100)
    }
  }

  if ($path -eq "/api/workflow-watch") {
    $discovery = Get-Discovery
    $query = [System.Web.HttpUtility]::ParseQueryString($requestUri.Query)
    $workflowDir = $query["workflowDir"]

    if (-not $workflowDir) {
      $workflowDir = $discovery.defaultWorkflowDir
    }

    $workflowDir = [string]$workflowDir

    return @{
      StatusCode = 200
      ContentType = "application/json; charset=utf-8"
      Headers = @{
        "Access-Control-Allow-Origin" = "*"
        "Cache-Control" = "no-store"
      }
      Body = ((Get-WorkflowWatchSummary -WorkflowDir $workflowDir) | ConvertTo-Json -Depth 100)
    }
  }

  return @{
    StatusCode = 404
    ContentType = "application/json; charset=utf-8"
    Headers = @{
      "Access-Control-Allow-Origin" = "*"
      "Cache-Control" = "no-store"
    }
    Body = (@{ error = "Not found" } | ConvertTo-Json -Depth 10)
  }
}

function Get-StaticPayload {
  param([string] $RequestTarget)

  $pathPart = $RequestTarget.Split("?")[0]
  $relativePath = if ([string]::IsNullOrWhiteSpace($pathPart) -or $pathPart -eq "/") {
    "index.html"
  } else {
    $pathPart.TrimStart("/") -replace "/", "\"
  }

  $fullPath = [System.IO.Path]::GetFullPath((Join-Path $frontendRoot $relativePath))
  $normalizedFrontendRoot = [System.IO.Path]::GetFullPath($frontendRoot)

  if (-not $fullPath.StartsWith($normalizedFrontendRoot) -or -not (Test-Path -LiteralPath $fullPath)) {
    return @{
      StatusCode = 404
      ContentType = "text/plain; charset=utf-8"
      Headers = @{}
      BodyBytes = $encoding.GetBytes("Not found")
    }
  }

  $item = Get-Item -LiteralPath $fullPath
  if ($item.PSIsContainer) {
    return @{
      StatusCode = 404
      ContentType = "text/plain; charset=utf-8"
      Headers = @{}
      BodyBytes = $encoding.GetBytes("Not found")
    }
  }

  $contentType = switch ([System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()) {
    ".html" { "text/html; charset=utf-8" }
    ".css" { "text/css; charset=utf-8" }
    ".js" { "application/javascript; charset=utf-8" }
    ".json" { "application/json; charset=utf-8" }
    default { "application/octet-stream" }
  }

  return @{
    StatusCode = 200
    ContentType = $contentType
    Headers = @{}
    BodyBytes = [System.IO.File]::ReadAllBytes($fullPath)
  }
}

function Write-Response {
  param(
    [System.Net.Sockets.TcpClient] $Client,
    [int] $StatusCode,
    [string] $ContentType,
    [byte[]] $BodyBytes,
    [hashtable] $Headers
  )

  $statusText = switch ($StatusCode) {
    200 { "OK" }
    404 { "Not Found" }
    500 { "Internal Server Error" }
    default { "OK" }
  }

  $headerLines = @(
    "HTTP/1.1 $StatusCode $statusText",
    "Content-Type: $ContentType",
    "Content-Length: $($BodyBytes.Length)",
    "Connection: close"
  )

  foreach ($key in $Headers.Keys) {
    $headerLines += "${key}: $($Headers[$key])"
  }

  $headerBytes = $encoding.GetBytes(($headerLines -join "`r`n") + "`r`n`r`n")
  $stream = $Client.GetStream()
  $stream.Write($headerBytes, 0, $headerBytes.Length)
  if ($BodyBytes.Length -gt 0) {
    $stream.Write($BodyBytes, 0, $BodyBytes.Length)
  }
  $stream.Flush()
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse("127.0.0.1"), $port)
$listener.Start()

Write-Host "Zero Trust Showcase listening on http://127.0.0.1:$port"

try {
  while ($true) {
    $client = $listener.AcceptTcpClient()
    try {
      $stream = $client.GetStream()
      $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::ASCII, $false, 8192, $true)
      $requestLine = $reader.ReadLine()
      if ([string]::IsNullOrWhiteSpace($requestLine)) {
        $client.Close()
        continue
      }

      while ($true) {
        $headerLine = $reader.ReadLine()
        if ([string]::IsNullOrEmpty($headerLine)) {
          break
        }
      }

      $parts = $requestLine.Split(" ")
      $method = if ($parts.Count -ge 1) { $parts[0] } else { "GET" }
      $target = if ($parts.Count -ge 2) { $parts[1] } else { "/" }

      if ($method -ne "GET") {
        Write-Response -Client $client -StatusCode 404 -ContentType "text/plain; charset=utf-8" -BodyBytes $encoding.GetBytes("Only GET is supported") -Headers @{}
        $client.Close()
        continue
      }

      if ($target -like "/api/*") {
        $payload = Get-ApiPayload -RequestTarget $target
        $bodyBytes = $encoding.GetBytes([string]$payload.Body)
        Write-Response -Client $client -StatusCode $payload.StatusCode -ContentType $payload.ContentType -BodyBytes $bodyBytes -Headers $payload.Headers
      } else {
        $payload = Get-StaticPayload -RequestTarget $target
        Write-Response -Client $client -StatusCode $payload.StatusCode -ContentType $payload.ContentType -BodyBytes $payload.BodyBytes -Headers $payload.Headers
      }
    } catch {
      $bodyBytes = $encoding.GetBytes($_.Exception.Message)
      Write-Response -Client $client -StatusCode 500 -ContentType "text/plain; charset=utf-8" -BodyBytes $bodyBytes -Headers @{}
    } finally {
      $client.Close()
    }
  }
} finally {
  $listener.Stop()
}
