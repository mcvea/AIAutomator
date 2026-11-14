$ErrorActionPreference = 'Continue'
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'
# 关键：PowerShell 按 [Console]::OutputEncoding 解码本地命令输出（中文系统默认 GBK），
# 不设为 UTF-8 会导致 Python 的 UTF-8 输出被二次转码成乱码写入日志
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
if (-not (Test-Path 'logs')) { New-Item -ItemType Directory -Path 'logs' | Out-Null }
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
"[$stamp] daily run start" | Out-File 'logs\task-run.log' -Append -Encoding UTF8
& '.\.venv\Scripts\python.exe' -m automator run daily 2>&1 | Out-File 'logs\task-run.log' -Append -Encoding UTF8
"exit=$LASTEXITCODE" | Out-File 'logs\task-run.log' -Append -Encoding UTF8
