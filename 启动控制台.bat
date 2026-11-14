@echo off
chcp 65001 >nul 2>&1
title AIAutomator Console
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" ui_server.py
) else (
    python ui_server.py
)
pause
