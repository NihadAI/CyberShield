# CyberShield Hardener — Windows tool

A small Windows-only diagnostic GUI that runs a curated set of **read-only**
PowerShell security checks and lets the user export the results as a single
`.zip` "evidence bundle" they can share with an incident-response helpline.

> **This tool never modifies your system.** Every check is strictly read-only.
> It is a recon tool, not a fixer — by design, so NGOs without a sysadmin can
> run it safely.

## What's in this folder

| File | What it does |
|------|--------------|
| `CyberShieldHardener.ps1` | The actual app. Pure PowerShell + WinForms. Runs on any Windows 10/11. |
| `Run-CyberShieldHardener.bat` | Double-click launcher (bypasses ExecutionPolicy noise). |
| `Run-CyberShieldHardener-Admin.bat` | Same, but relaunches with a UAC prompt so all checks work. |
| `Build-Exe.ps1` | Optional — compiles the `.ps1` into a real double-clickable `.exe` using PS2EXE. Run this on Windows once if you want to ship a single `.exe`. |

## How to use (end user)

1. Download this folder (`tools/`).
2. Double-click **`Run-CyberShieldHardener-Admin.bat`** — Windows will ask for
   UAC elevation. Click "Yes".
3. In the app, leave all checkboxes ticked and click **▶ Run selected checks**.
4. When it finishes, click **📦 Export evidence bundle** and save the `.zip`
   somewhere safe (USB stick, personal cloud).
5. If you need expert help, email the bundle to **help@accessnow.org** — the
   free 24/7 Access Now Digital Security Helpline for civil society.

If SmartScreen warns you ("Windows protected your PC"), click *More info* →
*Run anyway*. This is normal for unsigned scripts distributed outside the
Microsoft Store. For production you should have the file signed.

## Checks included

| # | Check | What it reads |
|---|-------|---------------|
| 1 | Windows Defender status | Real-time protection, signature freshness, recent scans. |
| 2 | Firewall profiles       | Domain / Private / Public on/off + default actions. |
| 3 | BitLocker encryption    | Per-volume encryption status (Pro/Enterprise editions only). |
| 4 | Recent Windows updates  | Last 15 installed hotfixes. |
| 5 | Local user accounts     | Enabled users + members of the Administrators group. |
| 6 | Startup programs        | `Win32_StartupCommand` — classic persistence location. |
| 7 | Suspicious scheduled tasks | Enabled, non-`\Microsoft\` tasks. |
| 8 | DNS, hosts & network    | DNS servers, IP config, hosts-file tampering. |
| 9 | Proxy & browser overrides | Internet Settings proxy — attackers often add one to MITM. |

## Building a real .exe (optional, one-time)

The `.ps1` + `.bat` combo is already a fully working Windows tool. If you
want to ship a single double-clickable `.exe` instead — which is easier for
non-technical end users and also needed if you want to code-sign it — run
`Build-Exe.ps1` on any Windows PC:

```powershell
# In a regular PowerShell window inside this folder
powershell -ExecutionPolicy Bypass -File .\Build-Exe.ps1
```

This will:

1. Install the [`PS2EXE`](https://github.com/MScholtes/PS2EXE) module for
   the current user (one-time, from the PowerShell Gallery).
2. Compile `CyberShieldHardener.ps1` into `CyberShieldHardener.exe` in the
   same folder.

The produced `.exe` is **not code-signed**. For public distribution you
should sign it with your code-signing certificate using `signtool.exe`.

## Why the tool is only read-only

NGOs are usually the **worst possible environment to auto-remediate**: shared
laptops, irregular backups, staff without admin training, field workers in
low-connectivity places. A fixer tool that silently flips a registry key
could easily make a situation worse. This tool therefore:

- reads state,
- shows you exactly what it ran,
- lets you hand the log to someone qualified.

If you want a hardening pass with confirmations (enable BitLocker, enforce
account lockout, harden SMB…), open an issue — that will be version 0.2 and
will land as separate, opt-in "Fix" buttons with a full undo log.

## Threat model & privacy

- Runs entirely on the user's machine. **Nothing is uploaded anywhere.**
- Log folder lives under `%TEMP%\CyberShield-Logs-YYYYMMDD-HHMMSS\`.
- The evidence bundle is a local `.zip` — only sent to a helpline if the user
  chooses to attach it.
- Source is open: audit it, fork it, adapt it for your org.

## Not a replacement for expert help

If your NGO is under active attack, stop fiddling with diagnostics and
contact a helpline:

- **Access Now Digital Security Helpline** — <help@accessnow.org> (24/7, free)
- **Front Line Defenders** — <https://www.frontlinedefenders.org/en/emergency-contact>
- **Citizen Lab** (for suspected mercenary spyware) — <https://citizenlab.ca/contact/>
