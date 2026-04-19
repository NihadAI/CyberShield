<#
.SYNOPSIS
  Compiles CyberShieldHardener.ps1 into a real .exe using PS2EXE.

.DESCRIPTION
  Run this script ONCE on any Windows machine to turn the PowerShell source
  into a double-clickable CyberShieldHardener.exe. After the first run, you
  can distribute the .exe on its own — end users no longer need PowerShell
  execution-policy knowledge, the .bat launcher, or the .ps1 file.

.NOTES
  - Requires internet on first run (to install the PS2EXE module from the
    PowerShell Gallery).
  - The produced .exe is NOT code-signed. For distribution you should sign
    it with a code-signing certificate (use Signtool).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Build-Exe.ps1
#>

[CmdletBinding()]
param(
    [string]$Source = (Join-Path $PSScriptRoot 'CyberShieldHardener.ps1'),
    [string]$Output = (Join-Path $PSScriptRoot 'CyberShieldHardener.exe')
)

if (-not (Test-Path $Source)) {
    Write-Error "Source file not found: $Source"
    exit 1
}

Write-Host "CyberShield Hardener — Build-Exe" -ForegroundColor Cyan
Write-Host "Source: $Source"
Write-Host "Output: $Output"
Write-Host ""

# Install PS2EXE for the current user if not already present.
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "PS2EXE module not found. Installing for current user..." -ForegroundColor Yellow
    try {
        Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
    } catch {
        Write-Error "Could not install PS2EXE: $($_.Exception.Message)"
        Write-Host "You may need to run: Set-PSRepository -Name PSGallery -InstallationPolicy Trusted"
        exit 1
    }
}

Import-Module ps2exe -ErrorAction Stop

Invoke-ps2exe `
    -inputFile   $Source `
    -outputFile  $Output `
    -title       'CyberShield Hardener' `
    -description 'NGO security diagnostic tool — part of the CyberShield toolkit.' `
    -company     'CyberShield Project' `
    -product     'CyberShield Hardener' `
    -copyright   '(c) CyberShield Project — free for humanitarian use.' `
    -version     '0.1.0.0' `
    -noConsole `
    -requireAdmin:$false

if (Test-Path $Output) {
    Write-Host "`nBuild succeeded: $Output" -ForegroundColor Green
    Write-Host "File size: $([math]::Round((Get-Item $Output).Length / 1KB, 1)) KB"
} else {
    Write-Error "Build failed — no .exe produced."
    exit 1
}
