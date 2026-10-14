@echo off
rem ============================================================
rem  Rebuild the exe from WeMeetAutoRejoin.cs
rem  ASCII only. Chinese text lives in build.ps1 (UTF-8).
rem ============================================================
setlocal
set "PS1=%~dp0build.ps1"
if not exist "%PS1%" (
    echo [ERROR] build.ps1 not found next to this file.
    pause
    exit /b 1
)
where pwsh >nul 2>nul
if %errorlevel%==0 (
    pwsh -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%PS1%"
)
echo.
pause
endlocal
