#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SMB File Share Hardening Script — Blue Team Competition
    Team: Delta Echo | System: svc-smb-01 (Windows 11)

.DESCRIPTION
    Hardens the Windows 11 SMB file share service for CCDC-style competition.
    Mirrors the structure of the AD/DNS hardening script for consistency.
    Covers:
      - Grey Team scoring/monitoring IP whitelist (runs unconditionally, always first)
      - RDP access rule (unconditional — primary competition access method)
      - Local account password rotation (secure display, no disk writes)
      - Unauthorized account enumeration & disabling
      - SMB protocol hardening (SMBv1 guard, signing required, NTLMv2)
      - Share permission lockdown (delete/recreate without -NoAccess to avoid Deny entries)
      - Windows Firewall configuration
      - Auditing & enhanced logging
      - Unnecessary service disabling
      - Scheduled task audit

.NOTES
    Run as local Administrator on svc-smb-01.
    All actions logged to $env:USERPROFILE\BlueTeam\hardening_log.txt

    BEFORE RUNNING:
      - Add all authorized Amazonian accounts to $SafeAccounts below
      - Confirm $GreyTeamScoring and $GreyTeamMonitoring IPs match the packet

    CONFIRMED FROM DAY 0 RECON:
      - Scored share name : CTFShare  (path C:\CTFShare)
      - Local accounts    : Administrator, cloudbase-init, cyberrange (OpenStack default),
                            readuserw1, readuserw2, WDAGUtilityAccount, DefaultAccount, Guest
      - Admins group      : Administrator, cloudbase-init, cyberrange
      - SMBv1             : Already disabled/uninstalled on this Windows 11 build
      - RequireSecuritySignature : False (needs to be flipped — done in Section 4)

    KNOWN BEHAVIOR ON THIS BUILD:
      - New-SmbShare -NoAccess "Everyone" creates an explicit Deny rule instead of
        simply omitting Everyone. Deny entries block ALL access including scoring.
        Fix: omit -NoAccess entirely, then clean up any residual Everyone entries
        using the Grant-then-Revoke pattern in Section 5.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# =============================================================================
#  CONFIGURATION — Confirm before running
# =============================================================================

# Scored share name — confirmed from Day 0 recon
$ShareName = "CTFShare"

# Grey Team IPs — must NEVER be blocked (packet: 10.10.10.4 / 10.10.10.5)
$GreyTeamScoring    = "10.10.10.11"
$GreyTeamMonitoring = "10.10.10.10"

# Accounts that should NEVER be disabled
# Confirmed from Day 0 recon + competition rules
$SafeAccounts = @(
    "Administrator",        # Primary admin account — password rotated in Section 2
    "cloudbase-init",       # OpenStack provisioning agent — confirmed Day 0
    "GREYTEAM",             # Competition rule — off limits, do not touch
    "ANSIBLE",              # Competition rule — off limits, do not touch
    "SCORING",              # Competition rule — off limits, do not touch
    "WDAGUtilityAccount",   # Windows Defender App Guard — system managed
    "DefaultAccount"        # System managed account
    # Add authorized Amazonian usernames here once list is provided on Day 1
)

# Services required for SMB file share function — excluded from disable prompts
$RequiredServices = @(
    "LanmanServer",       # SMB Server — the scored service itself
    "LanmanWorkstation",  # SMB Client
    "MpsSvc",             # Windows Firewall
    "EventLog",           # Windows Event Log — needed for auditing
    "CryptSvc",           # Cryptographic Services
    "DcomLaunch",         # DCOM / RPC foundation
    "RpcEptMapper",       # RPC Endpoint Mapper
    "RpcSs",              # Remote Procedure Call
    "SamSs",              # Security Account Manager
    "Schedule",           # Task Scheduler
    "PlugPlay",           # Hardware baseline
    "SystemEventsBroker", # Core OS broker
    "TimeBrokerSvc",      # Time broker
    "W32Time",            # Windows Time — Kerberos clock sync with AD
    "Netlogon",           # Domain auth (needed if domain-joined)
    "WinDefend",          # Windows Defender
    "TermService"         # Remote Desktop Services — kept, RDP is primary access method
)

# =============================================================================
#  LOGGING SETUP
# =============================================================================

$LogDir  = "$env:USERPROFILE\BlueTeam"
$LogFile = "$LogDir\hardening_log.txt"

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line }
    }
}

function Write-Banner {
    param([string]$Title)
    $line = "=" * 70
    Write-Host "`n$line" -ForegroundColor Magenta
    Write-Host "  $Title" -ForegroundColor Magenta
    Write-Host "$line`n" -ForegroundColor Magenta
    Write-Log "=== $Title ==="
}

function Prompt-YesNo {
    param([string]$Question)
    do { $ans = Read-Host "$Question [Y/N]" } while ($ans -notmatch '^[YyNn]$')
    return ($ans -match '^[Yy]$')
}

# Transcript helpers — suspends transcript around password display so passwords
# never appear in log files, mirroring the AD/DNS script pattern
$TranscriptPath = "$LogDir\PSTranscripts\transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$txDir = "$LogDir\PSTranscripts"
if (-not (Test-Path $txDir)) { New-Item -ItemType Directory $txDir | Out-Null }

function Stop-TranscriptSafe {
    try { Stop-Transcript | Out-Null; return $true } catch { return $false }
}
function Start-TranscriptSafe {
    param([string]$Path)
    try { Start-Transcript -Append -Path $Path | Out-Null } catch {}
}

function New-StrongPassword {
    # 24-character random password — same generator as AD/DNS script for consistency
    $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = [char[]]'abcdefghjkmnpqrstuvwxyz'
    $digits  = [char[]]'23456789'
    $special = [char[]]'!@#$%^&*()-_=+[]'
    $all     = $upper + $lower + $digits + $special
    $rng     = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes   = New-Object byte[] 32

    $pwd = @(
        $upper[$bytes[0] % $upper.Count],
        $upper[$bytes[1] % $upper.Count],
        $lower[$bytes[2] % $lower.Count],
        $lower[$bytes[3] % $lower.Count],
        $digits[$bytes[4] % $digits.Count],
        $digits[$bytes[5] % $digits.Count],
        $special[$bytes[6] % $special.Count],
        $special[$bytes[7] % $special.Count]
    )
    $rng.GetBytes($bytes)
    for ($i = $pwd.Count; $i -lt 24; $i++) {
        $rng.GetBytes($bytes)
        $pwd += $all[$bytes[0] % $all.Count]
    }
    $rng.GetBytes($bytes)
    for ($i = $pwd.Count - 1; $i -gt 0; $i--) {
        $j = $bytes[$i % $bytes.Count] % ($i + 1)
        $tmp = $pwd[$i]; $pwd[$i] = $pwd[$j]; $pwd[$j] = $tmp
    }
    return ($pwd -join '')
}

Write-Banner "SMB COMPETITION HARDENING SCRIPT — svc-smb-01"
Write-Log "Script started by: $env:USERNAME on $env:COMPUTERNAME"
Write-Log "Scored share: $ShareName"
Write-Log "Grey Team Scoring IP: $GreyTeamScoring"
Write-Log "Grey Team Monitoring IP: $GreyTeamMonitoring"

# =============================================================================
#  SECTION 0 — GREY TEAM WHITELIST + RDP ACCESS  (unconditional, always runs)
# =============================================================================
# These rules run before ANY other firewall logic and are never wrapped in a
# prompt. Blocking Grey Team IPs = zero points for uptime AND functionality.
# RDP is hardcoded because it is the only way to access this box during
# competition — accidentally blocking it mid-script locks you out permanently.

Write-Banner "SECTION 0: Grey Team Whitelist + RDP Access (Unconditional)"

# ── Grey Team scoring and monitoring whitelist ────────────────────────────────
foreach ($entry in @(
    @{ IP = $GreyTeamScoring;    Label = "Scoring"    },
    @{ IP = $GreyTeamMonitoring; Label = "Monitoring" }
)) {
    $ruleName = "GREYTEAM Allow $($entry.Label) $($entry.IP)"
    try {
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        New-NetFirewallRule `
            -DisplayName   $ruleName `
            -Direction     Inbound `
            -RemoteAddress $entry.IP `
            -Action        Allow `
            -Profile       Any `
            -Enabled       True | Out-Null
        Write-Log "Whitelist rule created: $ruleName" "SUCCESS"
    } catch {
        Write-Log "CRITICAL: Failed to create whitelist rule for $($entry.IP) — $_" "ERROR"
        Write-Host "  [!!] Grey Team whitelist rule FAILED. Investigate before continuing." -ForegroundColor Red
    }
}

# Whitelist the entire Grey Team management subnet 10.10.10.1-10.10.10.11
Remove-NetFirewallRule -DisplayName "GREYTEAM Allow Management Subnet" -ErrorAction SilentlyContinue
New-NetFirewallRule `
    -DisplayName   "GREYTEAM Allow Management Subnet" `
    -Direction     Inbound `
    -RemoteAddress "10.10.10.1-10.10.10.11" `
    -Action        Allow `
    -Profile       Any `
    -Enabled       True | Out-Null
Write-Log "Whitelist rule created: GREYTEAM Allow Management Subnet 10.10.10.1-10.10.10.11" "SUCCESS"

# ── RDP — unconditional allow (primary competition access method) ─────────────
# NOT wrapped in a prompt — answering No would permanently lock you out mid-script
try {
    Remove-NetFirewallRule -DisplayName "Allow RDP Competition" -ErrorAction SilentlyContinue
    New-NetFirewallRule `
        -DisplayName "Allow RDP Competition" `
        -Direction   Inbound `
        -Protocol    TCP `
        -LocalPort   3389 `
        -Action      Allow `
        -Profile     Any `
        -Enabled     True | Out-Null
    Write-Log "RDP inbound allowed unconditionally (primary access method)." "SUCCESS"
} catch {
    Write-Log "CRITICAL: Failed to create RDP allow rule — $_" "ERROR"
    Write-Host "  [!!] RDP rule FAILED. You may lose access to this box." -ForegroundColor Red
}

Write-Log "Section 0 complete." "SUCCESS"
Write-Host "`n  [OK] Grey Team IPs whitelisted. RDP secured. Safe to proceed.`n" -ForegroundColor Green

# =============================================================================
#  SECTION 1 — SCORED SERVICE VERIFICATION
# =============================================================================
# Confirm the service and share are up before doing anything else.
# If either is down, points are already bleeding — fix immediately.

Write-Banner "SECTION 1: Scored Service Verification"

# ── LanmanServer ─────────────────────────────────────────────────────────────
Write-Log "Checking LanmanServer (SMB Server service) status..."
try {
    $svc = Get-Service -Name LanmanServer -ErrorAction Stop
    Write-Log "LanmanServer status: $($svc.Status)"

    if ($svc.Status -ne "Running") {
        Write-Host "  [!!] LanmanServer is NOT running — attempting start..." -ForegroundColor Red
        Start-Service -Name LanmanServer -ErrorAction Stop
        Start-Sleep -Seconds 3
        $svc.Refresh()
        if ($svc.Status -eq "Running") {
            Write-Log "LanmanServer started successfully." "SUCCESS"
        } else {
            Write-Log "LanmanServer FAILED to start. Investigate immediately." "ERROR"
        }
    } else {
        Write-Log "LanmanServer is Running." "SUCCESS"
        Write-Host "  [OK] LanmanServer is Running." -ForegroundColor Green
    }
} catch {
    Write-Log "Could not query LanmanServer — $_" "ERROR"
}

# ── CTFShare ──────────────────────────────────────────────────────────────────
Write-Log "Verifying scored share '$ShareName' exists..."
try {
    $share = Get-SmbShare -Name $ShareName -ErrorAction Stop
    Write-Log "Share '$ShareName' found at path: $($share.Path)" "SUCCESS"
    Write-Host "  [OK] Share '$ShareName' present at $($share.Path)." -ForegroundColor Green
} catch {
    Write-Log "Share '$ShareName' NOT FOUND." "ERROR"
    Write-Host "  [!!] Share '$ShareName' not found. Run 'net share' to see all current shares." -ForegroundColor Red
    net share
}

Write-Log "Section 1 complete." "SUCCESS"

# =============================================================================
#  SECTION 2 — PASSWORD ROTATION
# =============================================================================
# Mirrors the AD/DNS script's secure display pattern exactly:
# passwords shown once on screen, transcript suspended during display,
# nothing written to disk. Administrator is always rotated first.

Write-Banner "SECTION 2: Local Account Password Rotation"

$LocalUsers = Get-LocalUser | Where-Object {
    $_.Name -notin $SafeAccounts -and
    $_.Enabled -eq $true
} | Sort-Object Name

Write-Host "`nAccounts eligible for password rotation (excludes SafeAccounts):" -ForegroundColor Yellow
$LocalUsers | Format-Table Name, Enabled, LastLogon -AutoSize

# Always rotate Administrator first — highest value account on this box
$adminAcct  = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue
$otherUsers = $LocalUsers | Where-Object { $_.Name -ne "Administrator" }
$rotationOrder = @($adminAcct) + @($otherUsers) | Where-Object { $_ -ne $null }

$RotateAll = Prompt-YesNo "Rotate passwords for ALL eligible local accounts automatically?"

Write-Host "`n[!] Passwords displayed ONCE on screen — never written to disk." -ForegroundColor Yellow
Write-Host "    Record each password before pressing ENTER.`n" -ForegroundColor Yellow

foreach ($user in $rotationOrder) {
    $doRotate = $false
    if ($RotateAll) {
        $doRotate = $true
    } else {
        $doRotate = Prompt-YesNo "Rotate password for '$($user.Name)'?"
    }

    if ($doRotate) {
        try {
            $newPwd    = New-StrongPassword
            $securePwd = ConvertTo-SecureString $newPwd -AsPlainText -Force

            $wasTranscribing = Stop-TranscriptSafe

            Write-Host "`n  ┌──────────────────────────────────────────────────┐" -ForegroundColor Yellow
            Write-Host "  │  ACCOUNT  : $($user.Name)" -ForegroundColor Yellow
            Write-Host "  │  PASSWORD : $newPwd" -ForegroundColor Green
            Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Yellow
            Write-Host "  Record this now — it will not be shown again or written to disk." -ForegroundColor Red
            Read-Host "  Press ENTER when recorded"

            $newPwd = $null
            [System.GC]::Collect()

            if ($wasTranscribing) { Start-TranscriptSafe $TranscriptPath }

            $user | Set-LocalUser -Password $securePwd
            $securePwd.Dispose()

            Write-Log "Password rotated for local account: $($user.Name)" "SUCCESS"
        } catch {
            if ($wasTranscribing) { Start-TranscriptSafe $TranscriptPath }
            Write-Log "FAILED to rotate password for $($user.Name) — $_" "ERROR"
        }
    }
}

Write-Log "Password rotation complete. No passwords written to disk." "SUCCESS"

# =============================================================================
#  SECTION 3 — ACCOUNT ENUMERATION & DISABLING
# =============================================================================
# Cross-reference every enabled account against SafeAccounts.
# Anything not on the authorized list gets flagged for disabling.
# readuserw1 and readuserw2 (Day 0 read accounts) should appear here
# and be disabled — their passwords are known to everyone in the room.

Write-Banner "SECTION 3: Account Enumeration & Disabling"

$AllLocal = Get-LocalUser | Sort-Object Name

Write-Host "`nAll local accounts ($($AllLocal.Count) total):`n"
$AllLocal | Format-Table Name, Enabled, LastLogon, Description -AutoSize

Write-Host "  Safe accounts (will not be touched):" -ForegroundColor DarkGray
$SafeAccounts | ForEach-Object { Write-Host "    - $_" -ForegroundColor DarkGray }
Write-Host ""

$DisableList = @()

foreach ($user in $AllLocal) {
    if ($SafeAccounts -contains $user.Name) {
        Write-Host "  [SAFE] $($user.Name) — skipping" -ForegroundColor DarkGray
        continue
    }
    if (-not $user.Enabled) {
        Write-Host "  [ALREADY DISABLED] $($user.Name)" -ForegroundColor DarkGray
        continue
    }

    Write-Host "`n  Account   : $($user.Name)" -ForegroundColor White
    Write-Host "  Enabled   : $($user.Enabled)"
    Write-Host "  Last Logon: $($user.LastLogon)"
    Write-Host "  Desc      : $($user.Description)"

    # Flag Day 0 read accounts explicitly — passwords are known to all participants
    if ($user.Name -in @("readuserw1", "readuserw2")) {
        Write-Host "  [!!] Day 0 read account — password known to all competition participants." -ForegroundColor Red
        Write-Host "       Strongly recommended to disable." -ForegroundColor Red
    }

    if (Prompt-YesNo "  >> Disable '$($user.Name)'?") {
        $DisableList += $user.Name
    }
}

# Guest — disable without prompting if somehow enabled
try {
    $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($guest -and $guest.Enabled) {
        Disable-LocalUser -Name "Guest"
        Write-Log "Guest account disabled." "SUCCESS"
    }
} catch {}

if ($DisableList.Count -gt 0) {
    Write-Host "`nAccounts queued for disabling:" -ForegroundColor Yellow
    $DisableList | ForEach-Object { Write-Host "  - $_" }

    if (Prompt-YesNo "Confirm — disable all $($DisableList.Count) listed account(s)?") {
        foreach ($name in $DisableList) {
            try {
                Disable-LocalUser -Name $name
                Write-Log "Disabled local account: $name" "SUCCESS"
            } catch {
                Write-Log "Failed to disable $name — $_" "ERROR"
            }
        }
    }
} else {
    Write-Log "No accounts selected for disabling."
}

Write-Log "Section 3 complete." "SUCCESS"

# =============================================================================
#  SECTION 4 — SMB PROTOCOL HARDENING
# =============================================================================
# Day 0 recon confirmed:
#   - SMBv1 already disabled/uninstalled — guarded below, no error thrown
#   - RequireSecuritySignature = False — must be flipped (relay attack risk)
#   - EnableSMB2Protocol = True — correct, leave alone

Write-Banner "SECTION 4: SMB Protocol Hardening"

if (Prompt-YesNo "Apply SMB protocol hardening (signing, NTLMv2, WDigest, null sessions)?") {

    # ── SMBv1 — guard against uninstalled feature before calling cmdlet ───────
    # Day 0 confirmed SMBv1 is already uninstalled on this build.
    # Guard prevents "service does not exist" error when feature is missing.
    Write-Log "Checking SMBv1 status..."
    try {
        $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
        if ($smb1Feature -and $smb1Feature.State -eq "Enabled") {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
            Set-ItemProperty `
                -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                -Name "SMB1" -Value 0 -Type DWord
            Write-Log "SMBv1 was enabled — now disabled." "SUCCESS"
        } elseif ($smb1Feature) {
            Write-Log "SMBv1 already disabled/uninstalled (State: $($smb1Feature.State)). No action needed." "SUCCESS"
            Write-Host "  [OK] SMBv1 already disabled/uninstalled on this build." -ForegroundColor Green
        } else {
            Write-Log "SMBv1 feature not found — fully removed from this system." "SUCCESS"
            Write-Host "  [OK] SMBv1 not present on this system." -ForegroundColor Green
        }
    } catch {
        Write-Log "SMBv1 check failed — $_" "WARN"
    }

    # ── SMB signing — Day 0 confirmed this is False, flip it ─────────────────
    # Prevents NTLM relay attacks where Red Team intercepts SMB auth
    # and relays it to the DC to gain elevated access
    Write-Log "Enabling required SMB signing on server and client..."
    try {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
        $sigCheck = (Get-SmbServerConfiguration).RequireSecuritySignature
        Write-Log "SMB signing required. RequireSecuritySignature = $sigCheck" "SUCCESS"
    } catch {
        Write-Log "SMB signing failed — $_" "ERROR"
    }

    # ── NTLMv2 only — refuse LM and NTLMv1 ───────────────────────────────────
    # Value 5 = Send NTLMv2 response only, refuse LM & NTLM
    Write-Log "Setting LAN Manager authentication level to NTLMv2 only..."
    try {
        Set-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
            -Name "LmCompatibilityLevel" -Value 5 -Type DWord
        Write-Log "LmCompatibilityLevel set to 5 (NTLMv2 only)." "SUCCESS"
    } catch {
        Write-Log "LmCompatibilityLevel change failed — $_" "ERROR"
    }

    # ── WDigest — disable cleartext credential caching in LSASS ──────────────
    Write-Log "Disabling WDigest credential caching..."
    try {
        $wdPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        if (-not (Test-Path $wdPath)) { New-Item -Path $wdPath -Force | Out-Null }
        Set-ItemProperty -Path $wdPath -Name "UseLogonCredential" -Value 0 -Type DWord
        Write-Log "WDigest disabled." "SUCCESS"
    } catch {
        Write-Log "WDigest disable failed — $_" "ERROR"
    }

    # ── Null/anonymous session restrictions ───────────────────────────────────
    Write-Log "Restricting anonymous/null sessions..."
    try {
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous"         -Value 1 -Type DWord
        Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM"      -Value 1 -Type DWord
        Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
        Write-Log "Anonymous/null session restrictions applied." "SUCCESS"
    } catch {
        Write-Log "Null session restriction failed — $_" "ERROR"
    }

    Write-Log "SMB protocol hardening complete." "SUCCESS"

} else {
    Write-Log "SMB protocol hardening skipped by operator."
}

# =============================================================================
#  SECTION 5 — SHARE PERMISSION LOCKDOWN
# =============================================================================
# Day 0 confirmed CTFShare has Everyone - Allow - Full at the share level.
#
# IMPORTANT: On this build, New-SmbShare -NoAccess "Everyone" creates an
# explicit Deny rule rather than simply omitting Everyone. An explicit Deny
# overrides ALL Allow rules and blocks the scoring engine.
# Fix: omit -NoAccess entirely so Everyone has no entry at all, then use the
# Grant-then-Revoke pattern to clean up any residual Everyone entries.
# Revoke-SmbShareAccess can only remove Allow entries — it cannot remove a
# Deny. Granting Allow first converts the Deny to Allow, then Revoke removes it.

Write-Banner "SECTION 5: Share Permission Lockdown — $ShareName"

if (Prompt-YesNo "Harden share permissions on '$ShareName'?") {

    try {
        # Capture path before touching the share
        $sharePath = (Get-SmbShare -Name $ShareName -ErrorAction Stop).Path

        Write-Log "Current share ACL for '$ShareName':"
        Get-SmbShareAccess -Name $ShareName | ForEach-Object {
            Write-Log "  $($_.AccountName) — $($_.AccessControlType) — $($_.AccessRight)"
        }

        # Remove and recreate cleanly
        # -NoAccess is intentionally omitted — it creates an explicit Deny on this build
        # which blocks the scoring engine. Omitting Everyone is cleaner and safer.
        Write-Log "Removing share '$ShareName'..."
        Remove-SmbShare -Name $ShareName -Force -ErrorAction Stop
        Start-Sleep -Seconds 1

        Write-Log "Recreating share '$ShareName' at $sharePath..."
        New-SmbShare `
            -Name       $ShareName `
            -Path       $sharePath `
            -FullAccess "BUILTIN\Administrators" `
            -ErrorAction Stop

        Write-Log "Share '$ShareName' recreated." "SUCCESS"

        # Clean up any residual Everyone entry using Grant-then-Revoke pattern.
        # Revoke-SmbShareAccess only works on Allow entries — if a Deny survived
        # from a previous run, Grant converts it to Allow first, then Revoke removes it.
        $everyoneEntry = Get-SmbShareAccess -Name $ShareName |
            Where-Object { $_.AccountName -eq "Everyone" }

        if ($everyoneEntry) {
            Write-Log "Residual Everyone entry found ($($everyoneEntry.AccessControlType)) — cleaning up..." "WARN"
            Grant-SmbShareAccess -Name $ShareName -AccountName "Everyone" -AccessRight Full -Force
            Revoke-SmbShareAccess -Name $ShareName -AccountName "Everyone" -Force
            Write-Log "Grant-then-Revoke cleanup applied to Everyone entry." "SUCCESS"
        }

        # Final verification — Everyone must be completely absent
        $finalAcl     = Get-SmbShareAccess -Name $ShareName
        $everyoneGone = -not ($finalAcl | Where-Object { $_.AccountName -eq "Everyone" })

        Write-Log "Final share ACL for '$ShareName':"
        $finalAcl | ForEach-Object {
            Write-Log "  $($_.AccountName) — $($_.AccessControlType) — $($_.AccessRight)"
        }

        if ($everyoneGone) {
            Write-Log "Confirmed: Everyone fully absent from share ACL." "SUCCESS"
            Write-Host "  [OK] Everyone removed. Share ACL is clean." -ForegroundColor Green
        } else {
            Write-Log "WARNING: Everyone still present after cleanup — manual intervention required." "WARN"
            Write-Host "  [!!] Everyone entry persists. Run manually:" -ForegroundColor Red
            Write-Host "       Grant-SmbShareAccess -Name '$ShareName' -AccountName 'Everyone' -AccessRight Full -Force" -ForegroundColor Yellow
            Write-Host "       Revoke-SmbShareAccess -Name '$ShareName' -AccountName 'Everyone' -Force" -ForegroundColor Yellow
        }

        # Remind operator to verify scoring account access
        Write-Host "`n  [NOTE] Confirm the Grey Team scoring account can still reach '$ShareName'." -ForegroundColor Yellow
        Write-Host "         If the scoring engine uses an account not in Administrators, grant it:" -ForegroundColor Yellow
        Write-Host "         Grant-SmbShareAccess -Name '$ShareName' -AccountName 'DOMAIN\ScoringAcct' -AccessRight Read -Force" -ForegroundColor White

    } catch {
        Write-Log "Share permission hardening failed — $_" "ERROR"
        Write-Host "  [!!] Share recreation failed. Manual fix:" -ForegroundColor Red
        Write-Host "       Remove-SmbShare -Name '$ShareName' -Force" -ForegroundColor Yellow
        Write-Host "       New-SmbShare -Name '$ShareName' -Path 'C:\$ShareName' -FullAccess 'BUILTIN\Administrators'" -ForegroundColor Yellow
    }

} else {
    Write-Log "Share permission lockdown skipped by operator."
}

Write-Log "Section 5 complete." "SUCCESS"

# =============================================================================
#  SECTION 6 — FIREWALL CONFIGURATION
# =============================================================================
# Grey Team whitelist and RDP rules were already created unconditionally in
# Section 0. This section adds service-specific rules and sets default-deny.
# Skipping this section is safe — Section 0 rules always exist regardless.

Write-Banner "SECTION 6: Firewall Configuration"

if (Prompt-YesNo "Configure Windows Firewall rules for SMB service?") {

    # Enable firewall on all profiles
    Write-Log "Enabling Windows Firewall on all profiles..."
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    Write-Log "Firewall enabled on Domain, Public, Private." "SUCCESS"

    # Default-deny inbound on all profiles
    # Section 0 allow rules already exist and take precedence over default-deny
    Write-Log "Setting default inbound policy to Block on all profiles..."
    Set-NetFirewallProfile -Profile Public `
        -DefaultInboundAction Block -DefaultOutboundAction Allow -AllowInboundRules True
    Set-NetFirewallProfile -Profile Domain, Private `
        -DefaultInboundAction Block -DefaultOutboundAction Allow
    Write-Log "Default inbound = Block on all profiles." "SUCCESS"

    # SMB (445) — allowed on Domain/Private, blocked on Public
    Write-Log "Creating SMB firewall rules..."
    try {
        Remove-NetFirewallRule -DisplayName "Allow SMB Domain Private" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Allow SMB Domain Private" `
            -Direction Inbound -Protocol TCP -LocalPort 445 `
            -Action Allow -Profile Domain, Private | Out-Null
        Write-Log "SMB (445) allowed on Domain/Private." "SUCCESS"

        Remove-NetFirewallRule -DisplayName "Block SMB Public" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Block SMB Public" `
            -Direction Inbound -Protocol TCP -LocalPort 445 `
            -Action Block -Profile Public | Out-Null
        Write-Log "SMB (445) blocked on Public profile." "SUCCESS"
    } catch {
        Write-Log "SMB firewall rule creation failed — $_" "ERROR"
    }

    # WinRM — prompt (useful for remote PowerShell but not required if using RDP)
    if (Prompt-YesNo "Allow WinRM (5985/5986) inbound on Domain/Private?") {
        try {
            foreach ($port in @(5985, 5986)) {
                Remove-NetFirewallRule -DisplayName "Allow WinRM $port" -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "Allow WinRM $port" `
                    -Direction Inbound -Protocol TCP -LocalPort $port `
                    -Action Allow -Profile Domain, Private | Out-Null
            }
            Write-Log "WinRM inbound allowed on Domain/Private." "SUCCESS"
        } catch { Write-Log "WinRM allow rule failed — $_" "ERROR" }
    } else {
        try {
            foreach ($port in @(5985, 5986)) {
                Remove-NetFirewallRule -DisplayName "Block WinRM $port" -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "Block WinRM $port" `
                    -Direction Inbound -Protocol TCP -LocalPort $port `
                    -Action Block | Out-Null
            }
            Write-Log "WinRM inbound blocked." "SUCCESS"
        } catch { Write-Log "WinRM block rule failed — $_" "ERROR" }
    }

    # Firewall logging
    Write-Log "Enabling firewall logging..."
    Set-NetFirewallProfile -Profile Domain, Private, Public `
        -LogBlocked True -LogAllowed True `
        -LogFileName "$LogDir\firewall_log.txt" `
        -LogMaxSizeKilobytes 32767
    Write-Log "Firewall logging enabled." "SUCCESS"

    Write-Log "Firewall configuration complete." "SUCCESS"

} else {
    Write-Log "Firewall configuration skipped by operator."
}

# =============================================================================
#  SECTION 7 — AUDITING & ENHANCED LOGGING
# =============================================================================

Write-Banner "SECTION 7: Auditing & Enhanced Logging"

if (Prompt-YesNo "Enable comprehensive audit policies and enhanced logging?") {

    Write-Log "Applying audit policies..."

    $AuditPolicies = @{
        "Account Management" = @(
            "User Account Management",
            "Security Group Management",
            "Other Account Management Events"
        )
        "Logon/Logoff" = @(
            "Logon",
            "Logoff",
            "Account Lockout",
            "Other Logon/Logoff Events",
            "Special Logon"
        )
        "Object Access" = @(
            "File Share",
            "Detailed File Share",
            "File System",
            "Other Object Access Events"
        )
        "Detailed Tracking" = @(
            "Process Creation",
            "Process Termination"
        )
        "Policy Change" = @(
            "Audit Policy Change",
            "Authentication Policy Change",
            "Other Policy Change Events"
        )
        "Privilege Use" = @(
            "Sensitive Privilege Use",
            "Other Privilege Use Events"
        )
        "System" = @(
            "Security State Change",
            "Security System Extension",
            "System Integrity"
        )
    }

    foreach ($category in $AuditPolicies.Keys) {
        foreach ($sub in $AuditPolicies[$category]) {
            $result = & auditpol /set /subcategory:"$sub" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Audit enabled — [$category] $sub" "SUCCESS"
            } else {
                Write-Log "Audit WARN — [$category] $sub : $result" "WARN"
            }
        }
    }

    # Expand Security event log to 512 MB
    Write-Log "Expanding event log sizes..."
    & wevtutil sl Security    /ms:536870912
    & wevtutil sl System      /ms:268435456
    & wevtutil sl Application /ms:268435456
    Write-Log "Event log sizes expanded." "SUCCESS"

    # PowerShell Script Block + Module Logging
    Write-Log "Enabling PowerShell Script Block + Module Logging..."
    $PSLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $PSModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $PSTxPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    foreach ($path in @($PSLogPath, $PSModPath, $PSTxPath)) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    }
    Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockLogging"           -Value 1 -Type DWord
    Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
    Set-ItemProperty -Path $PSModPath -Name "EnableModuleLogging"                -Value 1 -Type DWord
    if (-not (Test-Path "$PSModPath\ModuleNames")) {
        New-Item -Path "$PSModPath\ModuleNames" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PSModPath\ModuleNames" -Name "*" -Value "*" -Type String

    Set-ItemProperty -Path $PSTxPath -Name "EnableTranscripting"   -Value 1 -Type DWord
    Set-ItemProperty -Path $PSTxPath -Name "OutputDirectory"        -Value $txDir -Type String
    Set-ItemProperty -Path $PSTxPath -Name "EnableInvocationHeader" -Value 1 -Type DWord

    # Command-line auditing in process creation events (4688)
    $ProcAuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $ProcAuditPath)) { New-Item -Path $ProcAuditPath -Force | Out-Null }
    Set-ItemProperty -Path $ProcAuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

    Write-Log "Auditing & enhanced logging configured." "SUCCESS"

} else {
    Write-Log "Auditing section skipped by operator."
}

# =============================================================================
#  SECTION 8 — SERVICE ENUMERATION & DISABLING
# =============================================================================

Write-Banner "SECTION 8: Service Enumeration & Disabling"

$CandidateServices = Get-Service |
    Where-Object { $_.StartType -ne 'Disabled' -and $RequiredServices -notcontains $_.Name } |
    Sort-Object DisplayName

Write-Host "`nServices eligible for review: $($CandidateServices.Count)" -ForegroundColor Yellow
Write-Host "(Required SMB/RDP services pre-filtered — will not appear)`n"

$i = 0
foreach ($svc in $CandidateServices) {
    $i++
    $color = if ($svc.Status -eq 'Running') { 'Red' } else { 'DarkGray' }
    Write-Host ("{0,4}. {1,-48} {2,-12} {3}" -f $i, $svc.DisplayName, $svc.Status, $svc.StartType) -ForegroundColor $color
}

Write-Host "`nRunning services in red. Stopped/non-disabled in gray." -ForegroundColor Yellow
Write-Host "High-confidence candidates to disable on an SMB-only box:" -ForegroundColor Yellow
Write-Host "  Spooler (Print Spooler — PrintNightmare), Fax, XboxGipSvc," -ForegroundColor Yellow
Write-Host "  DiagTrack (Connected User Experiences/Telemetry), WSearch, RemoteRegistry`n" -ForegroundColor Yellow
Write-Host "Enter numbers to stop & disable, comma-separated (e.g. 1,3,7)" -ForegroundColor Cyan
Write-Host "Press ENTER with no input to skip.`n" -ForegroundColor Cyan

$raw = Read-Host "Services to disable"
$StopList = @()

if ($raw.Trim() -ne '') {
    $selections = $raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    foreach ($sel in $selections) {
        $idx = [int]$sel - 1
        if ($idx -ge 0 -and $idx -lt $CandidateServices.Count) {
            $StopList += $CandidateServices[$idx]
        } else {
            Write-Log "Selection '$sel' out of range — skipped." "WARN"
        }
    }
}

if ($StopList.Count -gt 0) {
    Write-Host "`nQueued for disabling:" -ForegroundColor Yellow
    $StopList | ForEach-Object { Write-Host "  - $($_.Name)  ($($_.DisplayName))" }

    if (Prompt-YesNo "Confirm — stop & disable these $($StopList.Count) service(s)?") {
        foreach ($svc in $StopList) {
            try {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Log "Stopped: $($svc.Name)" "SUCCESS"
                }
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled: $($svc.Name)" "SUCCESS"
            } catch {
                Write-Log "Failed to stop/disable $($svc.Name) — $_" "ERROR"
            }
        }
    }
} else {
    Write-Log "No services selected for disabling."
}

Write-Log "Section 8 complete." "SUCCESS"

# =============================================================================
#  SECTION 9 — SCHEDULED TASK AUDIT
# =============================================================================

Write-Banner "SECTION 9: Scheduled Task Audit"

Write-Log "Enumerating Ready scheduled tasks..."
$tasks = Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } |
         Select-Object TaskName, TaskPath, State |
         Sort-Object TaskPath, TaskName

Write-Host "`nAll 'Ready' scheduled tasks:" -ForegroundColor Yellow
$tasks | Format-Table -AutoSize

# Flag anything outside standard Microsoft paths — Red Team persistence lands here
$suspiciousTasks = $tasks | Where-Object {
    $_.TaskPath -notlike "\Microsoft\*" -and $_.TaskPath -ne "\"
}

if ($suspiciousTasks) {
    Write-Host "`n  [!!] Non-standard task paths found — review immediately:" -ForegroundColor Red
    $suspiciousTasks | Format-Table -AutoSize
    Write-Log "WARNING: Non-standard scheduled tasks detected:" "WARN"
    $suspiciousTasks | ForEach-Object {
        Write-Log "  $($_.TaskPath)$($_.TaskName)" "WARN"
    }
} else {
    Write-Log "No non-standard scheduled tasks found." "SUCCESS"
    Write-Host "  [OK] All tasks are under standard Microsoft paths." -ForegroundColor Green
}

Write-Host "`n  To disable a suspicious task:" -ForegroundColor Cyan
Write-Host "    Disable-ScheduledTask -TaskName '<n>' -TaskPath '<path>'" -ForegroundColor White

Write-Log "Section 9 complete." "SUCCESS"

# =============================================================================
#  FINAL VERIFICATION
# =============================================================================

Write-Banner "FINAL VERIFICATION"

Write-Host "Running post-hardening checks...`n" -ForegroundColor Cyan

# LanmanServer
$finalSvc = Get-Service -Name LanmanServer
$svcOk    = $finalSvc.Status -eq "Running"
Write-Log "LanmanServer: $($finalSvc.Status)" $(if ($svcOk) { "SUCCESS" } else { "ERROR" })
Write-Host ("  LanmanServer        : {0}" -f $finalSvc.Status) `
    -ForegroundColor $(if ($svcOk) { "Green" } else { "Red" })

# CTFShare present
try {
    $finalShare = Get-SmbShare -Name $ShareName -ErrorAction Stop
    Write-Log "CTFShare present at: $($finalShare.Path)" "SUCCESS"
    Write-Host "  CTFShare            : Present at $($finalShare.Path)" -ForegroundColor Green
} catch {
    Write-Log "CTFShare NOT FOUND after hardening." "ERROR"
    Write-Host "  CTFShare            : NOT FOUND [!!]" -ForegroundColor Red
}

# Share ACL — Everyone must be completely absent
try {
    $finalAcl     = Get-SmbShareAccess -Name $ShareName
    $everyoneGone = -not ($finalAcl | Where-Object { $_.AccountName -eq "Everyone" })
    Write-Log "Everyone absent from share ACL: $everyoneGone" $(if ($everyoneGone) { "SUCCESS" } else { "WARN" })
    Write-Host ("  Everyone in ACL     : {0}" -f $(if ($everyoneGone) { "Absent [OK]" } else { "PRESENT [!!]" })) `
        -ForegroundColor $(if ($everyoneGone) { "Green" } else { "Red" })
} catch {}

# SMB signing
$sigStatus = (Get-SmbServerConfiguration).RequireSecuritySignature
Write-Log "RequireSecuritySignature: $sigStatus" $(if ($sigStatus) { "SUCCESS" } else { "WARN" })
Write-Host ("  SMB Signing Required: {0}" -f $sigStatus) `
    -ForegroundColor $(if ($sigStatus) { "Green" } else { "Yellow" })

# Grey Team whitelist rules
$gtRules = Get-NetFirewallRule | Where-Object {
    $_.DisplayName -like "GREYTEAM*" -and $_.Enabled -eq "True"
}
$gtOk = $gtRules.Count -eq 3
Write-Log "Grey Team firewall rules: $($gtRules.Count)/2" $(if ($gtOk) { "SUCCESS" } else { "ERROR" })
Write-Host ("  Grey Team FW Rules  : {0}/2 present" -f $gtRules.Count) `
    -ForegroundColor $(if ($gtOk) { "Green" } else { "Red" })

# RDP rule
$rdpRule = Get-NetFirewallRule -DisplayName "Allow RDP Competition" -ErrorAction SilentlyContinue
$rdpOk   = $rdpRule -and $rdpRule.Enabled -eq "True"
Write-Log "RDP allow rule present: $rdpOk" $(if ($rdpOk) { "SUCCESS" } else { "ERROR" })
Write-Host ("  RDP Allow Rule      : {0}" -f $(if ($rdpOk) { "Present [OK]" } else { "MISSING [!!]" })) `
    -ForegroundColor $(if ($rdpOk) { "Green" } else { "Red" })

# =============================================================================
#  DONE
# =============================================================================

Write-Banner "HARDENING COMPLETE — svc-smb-01"
Write-Log "All sections complete. Review log at: $LogFile"

Write-Host "`n  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  NEXT STEPS:                                                     ║" -ForegroundColor Green
Write-Host "  ║  1. Verify Grey Team scoring can reach CTFShare                  ║" -ForegroundColor Green
Write-Host "  ║  2. Post status to #delta-echo Discord                           ║" -ForegroundColor Green
Write-Host "  ║  3. Watch Security log: filter EID 4625, 4624, 5140, 5145        ║" -ForegroundColor Green
Write-Host "  ║  4. Assist Teammate A with workstations if SMB is stable         ║" -ForegroundColor Green
Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  LOG FILES:                                                      ║" -ForegroundColor Green
Write-Host "  ║  Hardening  : $LogFile" -ForegroundColor Green
Write-Host "  ║  Transcripts: $LogDir\PSTranscripts\" -ForegroundColor Green
Write-Host "  ║  Firewall   : $LogDir\firewall_log.txt" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Green
