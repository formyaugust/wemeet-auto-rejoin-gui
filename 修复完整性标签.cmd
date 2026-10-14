@echo off
rem ============================================================
rem  Fix the "Low integrity label" problem.
rem  ASCII only. Chinese text lives in fix-integrity.ps1 (UTF-8).
rem  Run this by double-clicking from Explorer.
rem ============================================================
setlocal
set "PS1=%~dp0fix-integrity.ps1"
if not exist "%PS1%" (
    echo [ERROR] fix-integrity.ps1 not found next to this file.
    pause
    exit /b 1
)
where pwsh >nul 2>nul
if %errorlevel%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
)
endlocal
