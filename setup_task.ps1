# -*- coding: utf-8 -*-
<#
.SYNOPSIS
  注册 AIAutomator 独立计划任务（每天 08:00，任务名 AIAutomatorDaily）
  与旧版 LoomyAICheckin 完全独立，互不影响。

.DESCRIPTION
  用途说明：本脚本仅向当前用户注册一个 Windows 计划任务，
  定时以本机 Python 执行 `python -m automator run daily`（每日签到任务）。
  - -ExecutionPolicy Bypass 仅作用于本次脚本调用，不修改系统策略；
  - 脚本只执行本仓库内的 automator 模块，不下载、不执行任何远程代码；
  - 支持睡眠唤醒（WakeToRun）、电池供电运行，任务执行超时 10 分钟。

  用法：
    powershell -ExecutionPolicy Bypass -File .\setup_task.ps1
    powershell -ExecutionPolicy Bypass -File .\setup_task.ps1 -Time "09:30"
    powershell -ExecutionPolicy Bypass -File .\setup_task.ps1 -Remove
#>
param(
    [string]$Time = "08:00",
    [switch]$Remove
)

$ErrorActionPreference = "Stop"
$TaskName = "AIAutomatorDaily"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# 定位 Python（优先 PATH 中的 python，其次常见安装位置）
$pythonCandidates = @(
    (Get-Command python.exe -ErrorAction SilentlyContinue).Source,
    (Get-Command py.exe -ErrorAction SilentlyContinue).Source,
    "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
    "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

if (-not $pythonCandidates) {
    Write-Error "未找到 python.exe，请先安装 Python 3.11+"
    exit 1
}
$PythonExe = $pythonCandidates[0]
Write-Host "使用 Python: $PythonExe"

if ($Remove) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "已删除计划任务: $TaskName"
    exit 0
}

$action = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-m automator run daily" `
    -WorkingDirectory $ScriptDir

$trigger = New-ScheduledTaskTrigger -Daily -At $Time

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew `
    -WakeToRun

$task = Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Description "AIAutomator 通用任务框架每日执行（独立于旧版签到）" `
    -Force

# 允许电池供电时运行
$task.Settings.DisallowStartIfOnBatteries = $false
$task.Settings.StopIfGoingOnBatteries = $false
Set-ScheduledTask -TaskName $TaskName -Settings $task.Settings | Out-Null

Write-Host "✅ 独立计划任务已注册: $TaskName，每天 $Time 自动执行"
Write-Host "   工作目录: $ScriptDir"
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State | Format-Table -AutoSize
