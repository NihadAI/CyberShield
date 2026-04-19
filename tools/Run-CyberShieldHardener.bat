@echo off
REM CyberShield Hardener launcher
REM Runs the PowerShell script with ExecutionPolicy Bypass so users don't have to
REM fight with policy warnings. No Admin is required to launch, but some checks
REM need Admin — use the "Help -> Relaunch as Administrator" menu item inside
REM the app if you want full coverage.

setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%CyberShieldHardener.ps1"
endlocal
