<#
.SYNOPSIS
  CyberShield Hardener — a free Windows diagnostic GUI for NGOs.

.DESCRIPTION
  Runs a curated set of READ-ONLY PowerShell security checks (Defender,
  firewall, BitLocker, updates, accounts, startup, DNS/hosts, scheduled tasks,
  browser/proxy) and writes the output to a log folder. Users can export the
  results as a single .zip "evidence bundle" to share with an incident-response
  helpline (e.g. Access Now, Front Line Defenders, CERT).

  The tool does NOT change any system settings. Every action is read-only.

.NOTES
  Part of the CyberShield NGO Incident Response Toolkit.
  Target: Windows 10 / 11  (Windows PowerShell 5.1, included by default).
  License: free to use and adapt for humanitarian purposes.
#>

[CmdletBinding()]
param()

# ---------- Assemblies ----------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- Globals ----------
$ErrorActionPreference = 'Continue'
$script:AppName     = 'CyberShield Hardener'
$script:AppVersion  = '0.1.0'
$script:LogFolder   = Join-Path $env:TEMP ("CyberShield-Logs-{0:yyyyMMdd-HHmmss}" -f (Get-Date))
$script:SessionLog  = Join-Path $script:LogFolder 'session.log'
New-Item -ItemType Directory -Path $script:LogFolder -Force | Out-Null

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$script:IsAdmin = Test-Admin

# ---------- Check definitions ----------
# Every Action MUST be read-only. Return a string (multi-line OK).
$script:Checks = @(
    @{
        Key = 'defender'
        Name = 'Windows Defender status'
        Description = 'Real-time protection, signature freshness, recent scans.'
        Action = {
            $s = Get-MpComputerStatus -ErrorAction Stop
            @(
                "Antivirus enabled            : $($s.AntivirusEnabled)"
                "Real-time protection         : $($s.RealTimeProtectionEnabled)"
                "Behavior monitor             : $($s.BehaviorMonitorEnabled)"
                "Tamper protection            : $($s.IsTamperProtected)"
                "Signature version            : $($s.AntivirusSignatureVersion)"
                "Signature last updated       : $($s.AntivirusSignatureLastUpdated)"
                "Quick scan last run          : $($s.QuickScanStartTime)"
                "Full scan last run           : $($s.FullScanStartTime)"
            ) -join "`r`n"
        }
    },
    @{
        Key = 'firewall'
        Name = 'Firewall profiles'
        Description = 'Domain / Private / Public profiles and default actions.'
        Action = {
            Get-NetFirewallProfile |
                Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
                Format-Table -AutoSize | Out-String
        }
    },
    @{
        Key = 'bitlocker'
        Name = 'BitLocker drive encryption'
        Description = 'Encryption status per volume. Read-only — does not enable anything.'
        Action = {
            try {
                Get-BitLockerVolume -ErrorAction Stop |
                    Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionPercentage, VolumeType |
                    Format-Table -AutoSize | Out-String
            } catch {
                "BitLocker cmdlets are not available on this edition of Windows (Home editions don't include them)."
            }
        }
    },
    @{
        Key = 'updates'
        Name = 'Recent Windows updates'
        Description = 'Last 15 installed hotfixes and their dates.'
        Action = {
            Get-HotFix | Sort-Object InstalledOn -Descending |
                Select-Object -First 15 HotFixID, Description, InstalledOn, InstalledBy |
                Format-Table -AutoSize | Out-String
        }
    },
    @{
        Key = 'accounts'
        Name = 'Local user accounts & admins'
        Description = 'Enabled local users and current members of the Administrators group.'
        Action = {
            $out = New-Object System.Text.StringBuilder
            [void]$out.AppendLine('== Enabled local users ==')
            [void]$out.AppendLine((Get-LocalUser | Where-Object Enabled |
                Select-Object Name, Enabled, LastLogon, PasswordRequired, PasswordLastSet |
                Format-Table -AutoSize | Out-String))
            [void]$out.AppendLine('== Members of Administrators group ==')
            try {
                [void]$out.AppendLine((Get-LocalGroupMember -Group 'Administrators' |
                    Select-Object Name, PrincipalSource, ObjectClass |
                    Format-Table -AutoSize | Out-String))
            } catch {
                [void]$out.AppendLine("Could not enumerate admins: $($_.Exception.Message)")
            }
            $out.ToString()
        }
    },
    @{
        Key = 'startup'
        Name = 'Startup programs'
        Description = 'Programs configured to launch at login.'
        Action = {
            Get-CimInstance Win32_StartupCommand |
                Select-Object Name, Command, Location, User |
                Format-Table -AutoSize -Wrap | Out-String
        }
    },
    @{
        Key = 'schedtasks'
        Name = 'Suspicious scheduled tasks'
        Description = 'Enabled non-Microsoft tasks — often the first place persistence hides.'
        Action = {
            Get-ScheduledTask | Where-Object {
                $_.State -eq 'Ready' -and $_.TaskPath -notmatch '^\\Microsoft\\'
            } | Select-Object TaskName, TaskPath, Author, State |
              Format-Table -AutoSize | Out-String
        }
    },
    @{
        Key = 'network'
        Name = 'DNS, hosts file & network'
        Description = 'DNS servers, IP config, and hosts-file tampering check.'
        Action = {
            $out = New-Object System.Text.StringBuilder
            [void]$out.AppendLine('== DNS client server addresses ==')
            [void]$out.AppendLine((Get-DnsClientServerAddress -AddressFamily IPv4 |
                Select-Object InterfaceAlias, ServerAddresses |
                Format-Table -AutoSize | Out-String))
            [void]$out.AppendLine('== IP configuration ==')
            [void]$out.AppendLine((Get-NetIPConfiguration |
                Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, DNSServer |
                Format-Table -AutoSize | Out-String))
            [void]$out.AppendLine('== hosts file (non-comment, non-localhost lines) ==')
            $hosts = "$env:windir\System32\drivers\etc\hosts"
            if (Test-Path $hosts) {
                $lines = Get-Content $hosts | Where-Object {
                    $_ -and ($_ -notmatch '^\s*#') -and ($_ -notmatch '(127\.0\.0\.1|::1)\s+localhost')
                }
                if ($lines) { [void]$out.AppendLine(($lines -join "`r`n")) }
                else        { [void]$out.AppendLine('(no suspicious entries)') }
            }
            $out.ToString()
        }
    },
    @{
        Key = 'proxy'
        Name = 'Proxy & browser overrides'
        Description = 'Checks Internet Settings proxy — attackers often add one to MITM traffic.'
        Action = {
            $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
            $r = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
            @(
                "ProxyEnable  : $($r.ProxyEnable)"
                "ProxyServer  : $($r.ProxyServer)"
                "ProxyOverride: $($r.ProxyOverride)"
                "AutoConfigURL: $($r.AutoConfigURL)"
            ) -join "`r`n"
        }
    }
)

# ---------- Runner ----------
function Invoke-CyberShieldCheck {
    param([hashtable]$Check, [System.Windows.Forms.RichTextBox]$Output)
    $header = "`r`n=== [{0:HH:mm:ss}] {1} ===`r`n" -f (Get-Date), $Check.Name
    $Output.AppendText($header)
    Add-Content -Path $script:SessionLog -Value $header
    try {
        $result = & $Check.Action
        if ($null -eq $result -or $result -eq '') { $result = '(no data)' }
        $Output.AppendText("$result`r`n")
        $fileSafe = $Check.Key -replace '[^a-zA-Z0-9]', '_'
        $perFile = Join-Path $script:LogFolder ("{0}.txt" -f $fileSafe)
        Set-Content -Path $perFile -Value $result -Encoding UTF8
        Add-Content -Path $script:SessionLog -Value $result
    } catch {
        $err = "ERROR: $($_.Exception.Message)"
        $Output.AppendText("$err`r`n")
        Add-Content -Path $script:SessionLog -Value $err
    }
}

function Export-EvidenceBundle {
    param([System.Windows.Forms.Form]$Parent)
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'ZIP archive (*.zip)|*.zip'
    $dlg.FileName = ("CyberShield-Evidence-{0:yyyyMMdd-HHmmss}.zip" -f (Get-Date))
    $dlg.InitialDirectory = [Environment]::GetFolderPath('Desktop')
    if ($dlg.ShowDialog($Parent) -ne 'OK') { return $null }
    $zipPath = $dlg.FileName
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $script:LogFolder '*') -DestinationPath $zipPath
    return $zipPath
}

# ---------- GUI ----------
function Show-MainForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$script:AppName  v$script:AppVersion"
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(960, 640)
    $form.MinimumSize = New-Object System.Drawing.Size(820, 520)
    $form.BackColor = [System.Drawing.Color]::FromArgb(20, 26, 53)
    $form.ForeColor = [System.Drawing.Color]::White
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    # Title banner
    $banner = New-Object System.Windows.Forms.Panel
    $banner.Dock = 'Top'
    $banner.Height = 64
    $banner.BackColor = [System.Drawing.Color]::FromArgb(15, 21, 48)
    $titleLbl = New-Object System.Windows.Forms.Label
    $titleLbl.Text = "🛡  CyberShield Hardener"
    $titleLbl.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 14)
    $titleLbl.ForeColor = [System.Drawing.Color]::White
    $titleLbl.AutoSize = $true
    $titleLbl.Location = New-Object System.Drawing.Point(18, 10)
    $subLbl = New-Object System.Windows.Forms.Label
    $subLbl.Text = "Read-only security diagnostics for NGO-owned Windows PCs. Every action is logged locally."
    $subLbl.ForeColor = [System.Drawing.Color]::FromArgb(154, 163, 199)
    $subLbl.AutoSize = $true
    $subLbl.Location = New-Object System.Drawing.Point(20, 36)
    $adminLbl = New-Object System.Windows.Forms.Label
    $adminLbl.AutoSize = $true
    $adminLbl.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
    if ($script:IsAdmin) {
        $adminLbl.Text = "● Running as Administrator"
        $adminLbl.ForeColor = [System.Drawing.Color]::FromArgb(134, 239, 172)
    } else {
        $adminLbl.Text = "● Limited mode — some checks require Admin"
        $adminLbl.ForeColor = [System.Drawing.Color]::FromArgb(253, 224, 71)
    }
    $adminLbl.Anchor = 'Top, Right'
    $adminLbl.Location = New-Object System.Drawing.Point(680, 22)
    $banner.Controls.AddRange(@($titleLbl, $subLbl, $adminLbl))

    # Split container: left = checks list, right = output
    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = 'Fill'
    $split.Orientation = 'Vertical'
    $split.SplitterDistance = 340
    $split.Panel1.BackColor = [System.Drawing.Color]::FromArgb(27, 35, 72)
    $split.Panel2.BackColor = [System.Drawing.Color]::FromArgb(14, 20, 48)

    # Left: checklist
    $leftLbl = New-Object System.Windows.Forms.Label
    $leftLbl.Text = "Select checks to run"
    $leftLbl.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
    $leftLbl.AutoSize = $true
    $leftLbl.Location = New-Object System.Drawing.Point(12, 8)
    $split.Panel1.Controls.Add($leftLbl)

    $checkList = New-Object System.Windows.Forms.CheckedListBox
    $checkList.Location = New-Object System.Drawing.Point(12, 32)
    $checkList.Size = New-Object System.Drawing.Size(316, 420)
    $checkList.Anchor = 'Top, Left, Right, Bottom'
    $checkList.BackColor = [System.Drawing.Color]::FromArgb(14, 20, 48)
    $checkList.ForeColor = [System.Drawing.Color]::White
    $checkList.BorderStyle = 'FixedSingle'
    $checkList.CheckOnClick = $true
    $checkList.IntegralHeight = $false
    foreach ($c in $script:Checks) {
        [void]$checkList.Items.Add($c.Name, $true)
    }
    $split.Panel1.Controls.Add($checkList)

    $descLbl = New-Object System.Windows.Forms.Label
    $descLbl.Text = 'Click a check to see a short description.'
    $descLbl.ForeColor = [System.Drawing.Color]::FromArgb(154, 163, 199)
    $descLbl.Location = New-Object System.Drawing.Point(12, 458)
    $descLbl.Size = New-Object System.Drawing.Size(316, 60)
    $descLbl.Anchor = 'Left, Right, Bottom'
    $split.Panel1.Controls.Add($descLbl)

    $checkList.Add_SelectedIndexChanged({
        if ($checkList.SelectedIndex -ge 0) {
            $descLbl.Text = $script:Checks[$checkList.SelectedIndex].Description
        }
    })

    # Select/Clear buttons
    $btnAll = New-Object System.Windows.Forms.Button
    $btnAll.Text = 'Select all'
    $btnAll.Location = New-Object System.Drawing.Point(12, 528)
    $btnAll.Size = New-Object System.Drawing.Size(100, 28)
    $btnAll.Anchor = 'Left, Bottom'
    $btnAll.FlatStyle = 'Flat'
    $btnAll.BackColor = [System.Drawing.Color]::FromArgb(45, 55, 110)
    $btnAll.ForeColor = [System.Drawing.Color]::White
    $btnAll.Add_Click({ for ($i=0; $i -lt $checkList.Items.Count; $i++) { $checkList.SetItemChecked($i, $true) } })
    $split.Panel1.Controls.Add($btnAll)

    $btnNone = New-Object System.Windows.Forms.Button
    $btnNone.Text = 'Clear'
    $btnNone.Location = New-Object System.Drawing.Point(120, 528)
    $btnNone.Size = New-Object System.Drawing.Size(80, 28)
    $btnNone.Anchor = 'Left, Bottom'
    $btnNone.FlatStyle = 'Flat'
    $btnNone.BackColor = [System.Drawing.Color]::FromArgb(45, 55, 110)
    $btnNone.ForeColor = [System.Drawing.Color]::White
    $btnNone.Add_Click({ for ($i=0; $i -lt $checkList.Items.Count; $i++) { $checkList.SetItemChecked($i, $false) } })
    $split.Panel1.Controls.Add($btnNone)

    # Right: output
    $outLbl = New-Object System.Windows.Forms.Label
    $outLbl.Text = "Output"
    $outLbl.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
    $outLbl.AutoSize = $true
    $outLbl.Location = New-Object System.Drawing.Point(12, 8)
    $split.Panel2.Controls.Add($outLbl)

    $output = New-Object System.Windows.Forms.RichTextBox
    $output.Location = New-Object System.Drawing.Point(12, 32)
    $output.Size = New-Object System.Drawing.Size(560, 488)
    $output.Anchor = 'Top, Left, Right, Bottom'
    $output.Font = New-Object System.Drawing.Font('Consolas', 9)
    $output.BackColor = [System.Drawing.Color]::FromArgb(11, 16, 32)
    $output.ForeColor = [System.Drawing.Color]::FromArgb(207, 214, 255)
    $output.ReadOnly = $true
    $output.WordWrap = $false
    $output.DetectUrls = $false
    $split.Panel2.Controls.Add($output)

    $output.AppendText("$script:AppName v$script:AppVersion`r`n")
    $output.AppendText("Session log folder: $script:LogFolder`r`n")
    $output.AppendText("Select the checks you want and click 'Run selected checks'.`r`n")

    # Bottom buttons
    $btnRun = New-Object System.Windows.Forms.Button
    $btnRun.Text = '▶  Run selected checks'
    $btnRun.Size = New-Object System.Drawing.Size(180, 34)
    $btnRun.Location = New-Object System.Drawing.Point(12, 528)
    $btnRun.Anchor = 'Left, Bottom'
    $btnRun.FlatStyle = 'Flat'
    $btnRun.BackColor = [System.Drawing.Color]::FromArgb(34, 197, 94)
    $btnRun.ForeColor = [System.Drawing.Color]::White
    $btnRun.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
    $btnRun.Add_Click({
        $btnRun.Enabled = $false
        $output.AppendText("`r`n----- Run started at {0:HH:mm:ss} -----`r`n" -f (Get-Date))
        for ($i=0; $i -lt $checkList.Items.Count; $i++) {
            if ($checkList.GetItemChecked($i)) {
                Invoke-CyberShieldCheck -Check $script:Checks[$i] -Output $output
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        $output.AppendText("`r`n----- Run finished at {0:HH:mm:ss} -----`r`n" -f (Get-Date))
        $btnRun.Enabled = $true
    })
    $split.Panel2.Controls.Add($btnRun)

    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Text = '📦  Export evidence bundle'
    $btnExport.Size = New-Object System.Drawing.Size(200, 34)
    $btnExport.Location = New-Object System.Drawing.Point(202, 528)
    $btnExport.Anchor = 'Left, Bottom'
    $btnExport.FlatStyle = 'Flat'
    $btnExport.BackColor = [System.Drawing.Color]::FromArgb(124, 92, 255)
    $btnExport.ForeColor = [System.Drawing.Color]::White
    $btnExport.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
    $btnExport.Add_Click({
        $p = Export-EvidenceBundle -Parent $form
        if ($p) {
            [System.Windows.Forms.MessageBox]::Show("Evidence bundle saved to:`r`n$p", $script:AppName, 'OK', 'Information') | Out-Null
        }
    })
    $split.Panel2.Controls.Add($btnExport)

    $btnOpenLog = New-Object System.Windows.Forms.Button
    $btnOpenLog.Text = '📁  Open log folder'
    $btnOpenLog.Size = New-Object System.Drawing.Size(150, 34)
    $btnOpenLog.Location = New-Object System.Drawing.Point(412, 528)
    $btnOpenLog.Anchor = 'Left, Bottom'
    $btnOpenLog.FlatStyle = 'Flat'
    $btnOpenLog.BackColor = [System.Drawing.Color]::FromArgb(45, 55, 110)
    $btnOpenLog.ForeColor = [System.Drawing.Color]::White
    $btnOpenLog.Add_Click({ Start-Process explorer.exe $script:LogFolder })
    $split.Panel2.Controls.Add($btnOpenLog)

    $form.Controls.Add($split)
    $form.Controls.Add($banner)

    # About / menu
    $menu = New-Object System.Windows.Forms.MenuStrip
    $menu.BackColor = [System.Drawing.Color]::FromArgb(15, 21, 48)
    $menu.ForeColor = [System.Drawing.Color]::White
    $mHelp = New-Object System.Windows.Forms.ToolStripMenuItem('Help')
    $mAbout = New-Object System.Windows.Forms.ToolStripMenuItem('About')
    $mAbout.Add_Click({
        [System.Windows.Forms.MessageBox]::Show(
            "$script:AppName v$script:AppVersion`r`n`r`nPart of the CyberShield NGO Incident Response Toolkit.`r`nEvery check is read-only. Logs are stored only on this computer.`r`n`r`nNeed expert help? Contact help@accessnow.org (24/7 free for civil society).",
            "About", 'OK', 'Information') | Out-Null
    })
    $mRelaunch = New-Object System.Windows.Forms.ToolStripMenuItem('Relaunch as Administrator')
    $mRelaunch.Add_Click({
        if ($script:IsAdmin) {
            [System.Windows.Forms.MessageBox]::Show('Already running as Administrator.', $script:AppName, 'OK', 'Information') | Out-Null
            return
        }
        Start-Process powershell.exe -Verb RunAs -ArgumentList @('-ExecutionPolicy','Bypass','-File',$PSCommandPath)
        $form.Close()
    })
    [void]$mHelp.DropDownItems.Add($mRelaunch)
    [void]$mHelp.DropDownItems.Add($mAbout)
    [void]$menu.Items.Add($mHelp)
    $form.MainMenuStrip = $menu
    $form.Controls.Add($menu)

    [void]$form.ShowDialog()
}

Show-MainForm
