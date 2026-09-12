# -*- coding: utf-8 -*-
<#
.SYNOPSIS
  注册 AIAutomator 独立计划任务（每天 08:00，任务名 AIAutomatorDaily）
  与旧版 LoomyAICheckin 完全独立，互不影响。

.DESCRIPTION
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

# 定位 Python
$pythonCandidates = @(
    "C:\Users\USER\AppData\Local\Programs\Python\Python312\python.exe",
    "C:\Users\USER\AppData\Local\Programs\Python\Python311\python.exe",
    (Get-Command python.exe -ErrorAction SilentlyContinue).Source
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
