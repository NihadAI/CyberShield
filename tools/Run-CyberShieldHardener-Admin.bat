@echo off
REM CyberShield Hardener — Admin launcher
REM Re-launches the .ps1 elevated via a UAC prompt so all checks (BitLocker,
REM scheduled tasks, some firewall queries) have the privileges they need.

setlocal
set "SCRIPT_DIR=%~dp0"
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','%SCRIPT_DIR%CyberShieldHardener.ps1'"
endlocal
