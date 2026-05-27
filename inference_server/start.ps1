# SFT 模型推理服务 — Windows 启动脚本
# 用法:
#   .\start.ps1                  # FP16 (需 ~16 GB 显存)
#   .\start.ps1 -Quantize int4   # 4-bit 量化 (需 ~8 GB 显存)
#   .\start.ps1 -Port 8000       # 指定端口

param(
    [string]$Port = "8000",
    [string]$HostAddr = "127.0.0.1",
    [string]$Device = "auto",
    [string]$Quantize = "",
    [string]$BaseModel = "Qwen/Qwen2.5-7B-Instruct"
)

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $repoRoot
$adapterPath = Join-Path $repoRoot "AuditDataGen\SFT\qwen-sft-output\final_model"

$pythonArgs = @(
    (Join-Path $PSScriptRoot "server.py"),
    "--port", $Port,
    "--host", $HostAddr,
    "--device", $Device,
    "--base-model", $BaseModel,
    "--adapter-path", $adapterPath
)

if ($Quantize) {
    $pythonArgs += "--quantize"
    $pythonArgs += $Quantize
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " SFT Model Inference Server" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Base Model : $BaseModel"
Write-Host "  Adapter    : $adapterPath"
Write-Host "  Device     : $Device"
Write-Host "  Quantize   : $(if ($Quantize) { $Quantize } else { 'FP16 (none)' })"
Write-Host "  Endpoint   : http://${HostAddr}:${Port}"
Write-Host "========================================" -ForegroundColor Cyan

python $pythonArgs
