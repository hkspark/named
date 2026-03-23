#Requires -RunAsAdministrator
<#
Author: Jack O'Donnell
.SYNOPSIS
    AD/DNS Server Hardening Script for Attack/Defend Competitions

.DESCRIPTION
    Interactively hardens an Active Directory / DNS Windows Server for use in
    blue-team competition scenarios. Covers:
      - Admin & privileged account password rotation
      - Kerberos vulnerability audit (AS-REP roasting, Kerberoasting,
        unconstrained delegation, DCSync rights)
      - Account enumeration & selective disabling
      - Firewall configuration (DC/DNS rules + RPC dynamic ports)
      - Login auditing & enhanced event logging
      - Service enumeration & scheduled task audit
      - LSASS protection, protocol hardening, DNS zone security,
        LLMNR/NBT-NS poisoning prevention, account lockout policy

.NOTES
    Run as Domain Admin on the DC/DNS server.
    All actions are logged to $env:USERPROFILE\BlueTeam\hardening_log.txt
    Populate $SafeAccounts below before running.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIGURATION  –  Edit before running
# ─────────────────────────────────────────────────────────────────────────────

# Accounts that should NEVER be disabled (blue team + scoring engine accounts).
# Guest is handled separately regardless of this list.
$SafeAccounts = @(
    "Administrator",
    "SYSTEM"
    # Add scoring engine / inject service accounts here before running
)

# Services genuinely required for DC/DNS function – everything else gets prompted.
# Intentionally excludes: WinRM, Spooler, RDP stack, Themes, SysMain, TrkWks,
# WinHttpAutoProxySvc, wuauserv, WerSvc – those are operator decisions.
$RequiredServices = @(
    "ADWS",               # Active Directory Web Services
    "CryptSvc",           # Cryptographic Services – cert chain validation
    "DcomLaunch",         # DCOM process launcher – RPC foundation
    "DNS",                # DNS Server role
    "EventLog",           # Windows Event Log – cannot audit without it
    "gpsvc",              # Group Policy – core DC function
    "kdc",                # Kerberos Key Distribution Center
    "LanmanServer",       # SMB server – SYSVOL/NETLOGON shares
    "LanmanWorkstation",  # SMB client – needed for DC replication
    "MpsSvc",             # Windows Firewall
    "Netlogon",           # Domain authentication / DC locator
    "NTDS",               # AD Domain Services core
    "NtFrs",              # File Replication (SYSVOL, legacy)
    "PlugPlay",           # Hardware/driver baseline
    "RpcEptMapper",       # RPC Endpoint Mapper
    "RpcSs",              # Remote Procedure Call
    "SamSs",              # Security Account Manager
    "Schedule",           # Task Scheduler – GPO processing, replication
    "SENS",               # System Event Notification – needed by many core svcs
    "SystemEventsBroker", # Coordinates WinRT/background tasks for core OS
    "TimeBrokerSvc",      # Time broker (feeds W32Time)
    "W32Time",            # Windows Time – Kerberos requires clock sync
    "WinDefend"           # Windows Defender – keep unless replaced by another AV
)

# ─────────────────────────────────────────────────────────────────────────────
#  LOGGING & HELPERS
# ─────────────────────────────────────────────────────────────────────────────

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
    $sep = "=" * 70
    Write-Host "`n$sep" -ForegroundColor Magenta
    Write-Host "  $Title" -ForegroundColor Magenta
    Write-Host "$sep`n" -ForegroundColor Magenta
    Write-Log "=== $Title ==="
}

function Prompt-YesNo {
    param([string]$Question)
    do { $ans = Read-Host "$Question [Y/N]" } while ($ans -notmatch '^[YyNn]$')
    return ($ans -match '^[Yy]$')
}

# Transcript helpers defined here because Section 1 (password rotation) uses them.
$TranscriptPath = "$LogDir\PSTranscripts\transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function Stop-TranscriptSafe {
    try { Stop-Transcript | Out-Null; return $true } catch { return $false }
}
function Start-TranscriptSafe {
    param([string]$Path)
    try { Start-Transcript -Append -Path $Path | Out-Null } catch {}
}

Write-Banner "AD/DNS COMPETITION HARDENING SCRIPT"
Write-Log "Script started by: $env:USERNAME on $env:COMPUTERNAME"

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 1 – PASSWORD ROTATION
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 1: Password Rotation"

function New-StrongPassword {
    # Generates a 24-character random password satisfying complexity requirements.
    $upper   = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZ'
    $lower   = [char[]]'abcdefghjkmnpqrstuvwxyz'
    $digits  = [char[]]'23456789'
    $special = [char[]]'!@#$%^&*()-_=+[]'
    $all     = $upper + $lower + $digits + $special
    $rng     = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes   = New-Object byte[] 32

    # Fill bytes BEFORE building the initial character set so none are zero.
    $rng.GetBytes($bytes)

    # Guarantee at least two characters from each class.
    $passChars = @(
        $upper[$bytes[0]  % $upper.Count],
        $upper[$bytes[1]  % $upper.Count],
        $lower[$bytes[2]  % $lower.Count],
        $lower[$bytes[3]  % $lower.Count],
        $digits[$bytes[4] % $digits.Count],
        $digits[$bytes[5] % $digits.Count],
        $special[$bytes[6] % $special.Count],
        $special[$bytes[7] % $special.Count]
    )

    # Fill remaining characters to reach length 24.
    for ($i = $passChars.Count; $i -lt 24; $i++) {
        $rng.GetBytes($bytes)
        $passChars += $all[$bytes[0] % $all.Count]
    }

    # Fisher-Yates shuffle.
    $rng.GetBytes($bytes)
    for ($i = $passChars.Count - 1; $i -gt 0; $i--) {
        $j = $bytes[$i % $bytes.Count] % ($i + 1)
        $tmp = $passChars[$i]; $passChars[$i] = $passChars[$j]; $passChars[$j] = $tmp
    }
    return ($passChars -join '')
}

# ── krbtgt: verify disabled state + double password rotation ─────────────────

Write-Host "`n-- krbtgt Account --" -ForegroundColor Cyan

try {
    $krbtgt = Get-ADUser -Identity "krbtgt" -Properties Enabled, PasswordLastSet

    if ($krbtgt.Enabled) {
        Write-Log "krbtgt is ENABLED - this should never be the case. Investigate immediately." "WARN"
        Write-Host "  [!!] krbtgt is enabled. Disabling now..." -ForegroundColor Red
        Disable-ADAccount -Identity "krbtgt"
        Write-Log "krbtgt forcibly disabled." "SUCCESS"
    } else {
        Write-Log "krbtgt is correctly disabled." "SUCCESS"
        Write-Host "  [OK] krbtgt is disabled (correct)." -ForegroundColor Green
    }

    Write-Host "  Last password set: $($krbtgt.PasswordLastSet)" -ForegroundColor Yellow

} catch {
    Write-Log "Failed to query krbtgt account - $_" "ERROR"
}

if (Prompt-YesNo "Rotate krbtgt password? (Recommended - invalidates any forged Golden Tickets)") {

    Write-Host "`n  [!] krbtgt requires TWO rotations due to AD password history caching." -ForegroundColor Yellow
    Write-Host "      Wait ~10 minutes between rounds for replication to fully propagate." -ForegroundColor Yellow
    Write-Host "      You will be prompted between rounds.`n" -ForegroundColor Yellow

    foreach ($round in 1..2) {
        $wasTranscribing = $false
        try {
            $newPwd    = New-StrongPassword
            $securePwd = ConvertTo-SecureString $newPwd -AsPlainText -Force

            $wasTranscribing = Stop-TranscriptSafe

            Write-Host "`n  ┌──────────────────────────────────────────────────┐" -ForegroundColor Yellow
            Write-Host "  │  krbtgt PASSWORD ROTATION – Round $round of 2          │" -ForegroundColor Yellow
            Write-Host "  │  PASSWORD : $newPwd" -ForegroundColor Green
            Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Yellow
            Write-Host "  Record this now — it will not be shown again or written to disk." -ForegroundColor Red
            Read-Host "  Press ENTER when recorded"

            $newPwd = $null
            [System.GC]::Collect()

            if ($wasTranscribing) { Start-TranscriptSafe $TranscriptPath }

            Set-ADAccountPassword -Identity "krbtgt" -NewPassword $securePwd -Reset
            $securePwd.Dispose()

            Write-Log "krbtgt password rotation round $round complete." "SUCCESS"

            if ($round -eq 1) {
                Write-Host "`n  Round 1 complete. Wait ~10 minutes before round 2 to flush the old hash." -ForegroundColor Yellow
                Read-Host "  Press ENTER when ready for round 2"
            }

        } catch {
            if ($wasTranscribing) { Start-TranscriptSafe $TranscriptPath }
            Write-Log "Failed krbtgt rotation round $round – $_" "ERROR"
        }
    }

    Write-Log "krbtgt double rotation complete." "SUCCESS"
}

# ── Privileged domain accounts ────────────────────────────────────────────────

$PrivGroups = @(
    "Domain Admins", "Administrators", "Schema Admins",
    "Enterprise Admins", "Group Policy Creator Owners", "Account Operators"
)

$PrivAccounts = @()
foreach ($grp in $PrivGroups) {
    try {
        $members = Get-ADGroupMember -Identity $grp -Recursive -ErrorAction SilentlyContinue |
                   Where-Object { $_.objectClass -eq 'user' }
        $PrivAccounts += $members
    } catch {}
}
$PrivAccounts = $PrivAccounts | Select-Object -ExpandProperty SamAccountName -Unique | Sort-Object

Write-Log "Privileged accounts found: $($PrivAccounts -join ', ')"
Write-Host "`nPrivileged accounts discovered across admin groups:" -ForegroundColor Yellow
$PrivAccounts | ForEach-Object { Write-Host "  - $_" }

# Warn if the current operator's account is in the list.
if ($PrivAccounts -contains $env:USERNAME) {
    Write-Host "`n  [!] Your current account ($env:USERNAME) is in the privileged list." -ForegroundColor Yellow
    Write-Host "      Rotating it will not terminate this session, but you must record the" -ForegroundColor Yellow
    Write-Host "      new password — you will need it for any new auth (RDP, runas, etc.)." -ForegroundColor Yellow
}

$RotateAll = Prompt-YesNo "`nRotate passwords for ALL privileged accounts automatically?"

Write-Host "`n[!] Passwords will be displayed ONCE on screen and never written to disk." -ForegroundColor Yellow
Write-Host "    Record each password before pressing ENTER to continue.`n" -ForegroundColor Yellow

foreach ($acct in $PrivAccounts) {
    $doRotate = $RotateAll -or (Prompt-YesNo "Rotate password for '$acct'?")

    if ($doRotate) {
        $wasTranscribing = $false
        try {
            $newPwd    = New-StrongPassword
            $securePwd = ConvertTo-SecureString $newPwd -AsPlainText -Force

            $wasTranscribing = Stop-TranscriptSafe

            Write-Host "`n  ┌──────────────────────────────────────────────────┐" -ForegroundColor Yellow
            Write-Host "  │  ACCOUNT  : $acct" -ForegroundColor Yellow
            Write-Host "  │  PASSWORD : $newPwd" -ForegroundColor Green
            Write-Host "  └──────────────────────────────────────────────────┘" -ForegroundColor Yellow
            Write-Host "  Record this now — it will not be shown again or written to disk." -ForegroundColor Red
            Read-Host "  Press ENTER when recorded"

            $newPwd = $null
            [System.GC]::Collect()

            if ($wasTranscribing) { Start-TranscriptSafe $TranscriptPath }

            Set-ADAccountPassword -Identity $acct -NewPassword $securePwd -Reset
            Set-ADUser -Identity $acct -ChangePasswordAtLogon $false
            $securePwd.Dispose()

            Write-Log "Password rotated for: $acct" "SUCCESS"
        } catch {
            if ($wasTranscribing) { Start-TranscriptSafe $TranscriptPath }
            Write-Log "FAILED to rotate password for $acct – $_" "ERROR"
        }
    }
}

Write-Log "Password rotation complete. No passwords were written to disk."

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 2 – ACCOUNT ENUMERATION & DISABLING
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 2: Account Enumeration & Disabling"

$AllUsers = Get-ADUser -Filter * -Properties Enabled, LastLogonDate, Description, MemberOf |
            Sort-Object SamAccountName

Write-Host "`nAll AD accounts ($(($AllUsers).Count) total):`n"
$AllUsers | Format-Table SamAccountName, Enabled, LastLogonDate, Description -AutoSize

$DisableList = @()

foreach ($user in $AllUsers) {
    $sam = $user.SamAccountName

    if ($SafeAccounts -contains $sam) {
        Write-Host "  [SAFE] $sam - skipping" -ForegroundColor DarkGray
        continue
    }
    if ($sam -eq 'krbtgt') {
        Write-Host "  [SKIP] krbtgt - handled in Section 1" -ForegroundColor DarkGray
        continue
    }
    if ($sam.EndsWith('$')) {
        Write-Host "  [SKIP] $sam - computer account" -ForegroundColor DarkGray
        continue
    }
    if (-not $user.Enabled) {
        Write-Host "  [ALREADY DISABLED] $sam" -ForegroundColor DarkGray
        continue
    }

    Write-Host "`n  Account   : $sam" -ForegroundColor White
    Write-Host "  Last Logon: $($user.LastLogonDate)"
    Write-Host "  Desc      : $($user.Description)"

    if (Prompt-YesNo "  >> Disable '$sam'?") {
        $DisableList += $sam
    }
}

if ($DisableList.Count -gt 0) {
    Write-Host "`nAccounts queued for disabling:" -ForegroundColor Yellow
    $DisableList | ForEach-Object { Write-Host "  - $_" }

    if (Prompt-YesNo "Confirm - disable all $($DisableList.Count) listed accounts?") {
        foreach ($sam in $DisableList) {
            try {
                Disable-ADAccount -Identity $sam
                Write-Log "Disabled account: $sam" "SUCCESS"
            } catch {
                Write-Log "Failed to disable $sam - $_" "ERROR"
            }
        }
    }
} else {
    Write-Log "No accounts selected for disabling."
}

# Disable Guest explicitly regardless of $SafeAccounts.
try {
    $guest = Get-ADUser -Identity "Guest" -Properties Enabled
    if ($guest.Enabled) {
        Disable-ADAccount -Identity "Guest"
        Write-Log "Guest account disabled." "SUCCESS"
    } else {
        Write-Log "Guest account already disabled." "INFO"
    }
} catch {
    Write-Log "Could not check Guest account - $_" "WARN"
}

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 3 – KERBEROS & DELEGATION AUDIT
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 3: Kerberos & Delegation Audit"

Write-Host "Scanning for high-risk Kerberos and delegation configurations...`n" -ForegroundColor Cyan

# ── AS-REP roastable accounts ─────────────────────────────────────────────────
$AsRepAccounts = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
    -Properties DoesNotRequirePreAuth |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }

if ($AsRepAccounts) {
    Write-Log "AS-REP roastable accounts: $($AsRepAccounts.SamAccountName -join ', ')" "WARN"
    Write-Host "  [!] AS-REP Roastable (no Kerberos pre-auth required):" -ForegroundColor Red
    $AsRepAccounts | ForEach-Object { Write-Host "      - $($_.SamAccountName)" -ForegroundColor Red }

    if (Prompt-YesNo "  Enable Kerberos pre-authentication on all listed accounts?") {
        foreach ($u in $AsRepAccounts) {
            try {
                Set-ADAccountControl -Identity $u.SamAccountName -DoesNotRequirePreAuth $false
                Write-Log "Pre-auth enabled for: $($u.SamAccountName)" "SUCCESS"
            } catch {
                Write-Log "Failed to enable pre-auth for $($u.SamAccountName) – $_" "ERROR"
            }
        }
    }
} else {
    Write-Log "No AS-REP roastable accounts found." "SUCCESS"
    Write-Host "  [OK] No AS-REP roastable accounts." -ForegroundColor Green
}

# ── Kerberoastable accounts (user accounts with SPNs) ────────────────────────
$KerberoastAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
    -Properties ServicePrincipalName |
    Where-Object { $_.SamAccountName -ne 'krbtgt' }

if ($KerberoastAccounts) {
    Write-Log "Kerberoastable user accounts: $($KerberoastAccounts.SamAccountName -join ', ')" "WARN"
    Write-Host "`n  [!] Kerberoastable user accounts (have SPNs - hashes crackable offline):" -ForegroundColor Yellow
    $KerberoastAccounts | ForEach-Object {
        Write-Host "      - $($_.SamAccountName): $($_.ServicePrincipalName -join ', ')" -ForegroundColor Yellow
    }
    Write-Host "      Ensure their passwords were rotated in Section 1." -ForegroundColor Yellow
    Write-Log "Kerberoastable accounts listed - verify passwords rotated." "WARN"
} else {
    Write-Log "No Kerberoastable user accounts found." "SUCCESS"
    Write-Host "`n  [OK] No Kerberoastable user accounts." -ForegroundColor Green
}

# ── Unconstrained delegation ──────────────────────────────────────────────────
$DomainDCs = (Get-ADDomainController -Filter *).Name

$UnconstrainedComps = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
    -Properties TrustedForDelegation |
    Where-Object { $DomainDCs -notcontains $_.Name }

if ($UnconstrainedComps) {
    Write-Log "Non-DC computers with unconstrained delegation: $($UnconstrainedComps.Name -join ', ')" "WARN"
    Write-Host "`n  [!!] Non-DC machines with unconstrained delegation (high risk):" -ForegroundColor Red
    $UnconstrainedComps | ForEach-Object { Write-Host "       - $($_.Name)" -ForegroundColor Red }

    if (Prompt-YesNo "  Disable unconstrained delegation on these computers?") {
        foreach ($comp in $UnconstrainedComps) {
            try {
                Set-ADComputer -Identity $comp.Name -TrustedForDelegation $false
                Write-Log "Unconstrained delegation disabled on: $($comp.Name)" "SUCCESS"
            } catch {
                Write-Log "Failed to modify delegation for $($comp.Name) – $_" "ERROR"
            }
        }
    }
} else {
    Write-Log "No non-DC computers with unconstrained delegation." "SUCCESS"
    Write-Host "`n  [OK] No non-DC unconstrained delegation found." -ForegroundColor Green
}

# ── DCSync rights (non-DC principals with replication rights) ─────────────────
Write-Host "`n  Checking for non-DC principals with DCSync rights..." -ForegroundColor Cyan

try {
    $DomainDN  = (Get-ADDomain).DistinguishedName
    $DomainSID = (Get-ADDomain).DomainSID.Value

    $ReplChangesGUID    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    $ReplChangesAllGUID = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"

    $acl       = Get-Acl -Path "AD:\$DomainDN"
    $syncRights = $acl.Access | Where-Object {
        ($_.ObjectType -eq $ReplChangesGUID -or $_.ObjectType -eq $ReplChangesAllGUID) -and
        $_.AccessControlType -eq 'Allow'
    }

    $legitimateSIDs = @(
        "$DomainSID-516",  # Domain Controllers
        "$DomainSID-498",  # Enterprise Read-Only Domain Controllers
        "S-1-5-32-544"     # Builtin\Administrators
    )

    $suspectSync = $syncRights | Where-Object {
        $sid = $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $legitimateSIDs -notcontains $sid
    }

    if ($suspectSync) {
        Write-Log "Suspicious DCSync rights detected!" "WARN"
        Write-Host "  [!!] Non-standard principals with DCSync rights:" -ForegroundColor Red
        $suspectSync | ForEach-Object {
            Write-Host "       - $($_.IdentityReference)" -ForegroundColor Red
            Write-Log "DCSync right holder: $($_.IdentityReference) (ObjectType: $($_.ObjectType))" "WARN"
        }
        Write-Host "       Remove these manually via ADSI Edit or Set-Acl." -ForegroundColor Red
    } else {
        Write-Log "DCSync rights appear clean – no unexpected principals." "SUCCESS"
        Write-Host "  [OK] No unexpected DCSync rights found." -ForegroundColor Green
    }
} catch {
    Write-Log "DCSync rights check failed – $_" "WARN"
    Write-Host "  [WARN] Could not complete DCSync rights check: $_" -ForegroundColor Yellow
}

# ── Add admin accounts to Protected Users ─────────────────────────────────────
Write-Host ""
if (Prompt-YesNo "Add privileged accounts to the 'Protected Users' security group? (disables NTLM, DES, RC4, unconstrained delegation for those accounts)") {
    foreach ($acct in $PrivAccounts) {
        try {
            Add-ADGroupMember -Identity "Protected Users" -Members $acct -ErrorAction Stop
            Write-Log "Added $acct to Protected Users." "SUCCESS"
        } catch {
            Write-Log "Could not add $acct to Protected Users – $_" "WARN"
        }
    }
}

Write-Log "Kerberos & delegation audit complete." "SUCCESS"

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 4 – FIREWALL CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 4: Firewall Configuration"

if (Prompt-YesNo "Enable and configure Windows Firewall for all profiles?") {

    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    netsh advfirewall set allprofiles state on | Out-Null
    Write-Log "Firewall enabled on all profiles." "SUCCESS"

    # Public profile – block all unsolicited inbound.
    Set-NetFirewallProfile -Profile Public `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow `
        -AllowInboundRules False
    Write-Log "Public profile hardened (block all inbound)." "SUCCESS"

    # Domain profile – default block, rely on explicit rules below.
    Set-NetFirewallProfile -Profile Domain `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow
    Write-Log "Domain profile inbound default set to Block." "SUCCESS"

    # ── Core DC/DNS inbound rules ─────────────────────────────────────────────
    # RPC dynamic ports (49152-65535) are required alongside port 135 for DC
    # replication and many AD operations. Without them, domain functions break.
    Write-Log "Creating core DC/DNS inbound allow rules..."

    $CoreRules = @(
        @{ Name = "Allow LDAP";                Port = 389;           Protocol = "TCP" },
        @{ Name = "Allow LDAP UDP";            Port = 389;           Protocol = "UDP" },
        @{ Name = "Allow Secure LDAP";         Port = 636;           Protocol = "TCP" },
        @{ Name = "Allow Kerberos TCP";        Port = 88;            Protocol = "TCP" },
        @{ Name = "Allow Kerberos UDP";        Port = 88;            Protocol = "UDP" },
        @{ Name = "Allow DNS TCP";             Port = 53;            Protocol = "TCP" },
        @{ Name = "Allow DNS UDP";             Port = 53;            Protocol = "UDP" },
        @{ Name = "Allow SMB";                 Port = 445;           Protocol = "TCP" },
        @{ Name = "Allow RPC Endpoint Mapper"; Port = 135;           Protocol = "TCP" },
        @{ Name = "Allow RPC Dynamic Ports";   Port = "49152-65535"; Protocol = "TCP" },
        @{ Name = "Allow Global Catalog";      Port = 3268;          Protocol = "TCP" },
        @{ Name = "Allow Global Catalog SSL";  Port = 3269;          Protocol = "TCP" },
        @{ Name = "Allow NTP";                 Port = 123;           Protocol = "UDP" },
        @{ Name = "Allow Netlogon";            Port = 138;           Protocol = "UDP" }
    )

    foreach ($rule in $CoreRules) {
        try {
            Remove-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName $rule.Name `
                -Direction Inbound `
                -Protocol $rule.Protocol `
                -LocalPort $rule.Port `
                -Action Allow `
                -Profile Domain,Private | Out-Null
            Write-Log "Rule created: $($rule.Name) ($($rule.Protocol)/$($rule.Port))" "SUCCESS"
        } catch {
            Write-Log "Failed to create rule '$($rule.Name)' – $_" "ERROR"
        }
    }

    # ── RDP ───────────────────────────────────────────────────────────────────
    if (Prompt-YesNo "Allow RDP (3389) inbound?") {
        try {
            Remove-NetFirewallRule -DisplayName "Allow RDP" -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Allow RDP" `
                -Direction Inbound -Protocol TCP -LocalPort 3389 `
                -Action Allow -Profile Domain,Private | Out-Null
            Write-Log "RDP inbound allowed on Domain/Private." "SUCCESS"
        } catch {
            Write-Log "Failed to create RDP allow rule – $_" "ERROR"
        }
    } else {
        try {
            Remove-NetFirewallRule -DisplayName "Block RDP Inbound" -ErrorAction SilentlyContinue
            New-NetFirewallRule -DisplayName "Block RDP Inbound" `
                -Direction Inbound -Protocol TCP -LocalPort 3389 `
                -Action Block -Profile Any | Out-Null
            Write-Log "RDP inbound blocked on all profiles." "SUCCESS"
        } catch {
            Write-Log "Failed to create RDP block rule – $_" "ERROR"
        }
    }

    # ── WinRM ─────────────────────────────────────────────────────────────────
    if (Prompt-YesNo "Allow WinRM (5985/5986) inbound?") {
        try {
            foreach ($port in @(5985, 5986)) {
                Remove-NetFirewallRule -DisplayName "Allow WinRM $port" -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "Allow WinRM $port" `
                    -Direction Inbound -Protocol TCP -LocalPort $port `
                    -Action Allow -Profile Domain,Private | Out-Null
            }
            Write-Log "WinRM inbound allowed on Domain/Private." "SUCCESS"
        } catch {
            Write-Log "Failed to create WinRM allow rules – $_" "ERROR"
        }
    } else {
        try {
            foreach ($port in @(5985, 5986)) {
                Remove-NetFirewallRule -DisplayName "Block WinRM $port" -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName "Block WinRM $port" `
                    -Direction Inbound -Protocol TCP -LocalPort $port `
                    -Action Block -Profile Any | Out-Null
            }
            Write-Log "WinRM inbound blocked on all profiles." "SUCCESS"
        } catch {
            Write-Log "Failed to create WinRM block rules – $_" "ERROR"
        }
    }

    Write-Log "Firewall configuration complete." "SUCCESS"

} else {
    Write-Log "Firewall configuration section skipped by operator."
}

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 5 – AUDITING & ENHANCED LOGGING
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 5: Login Auditing & Enhanced Logging"

if (Prompt-YesNo "Enable comprehensive audit policies and enhanced logging?") {

    Write-Log "Applying Advanced Audit Policies..."

    $AuditPolicies = @{
        "Account Logon"      = @("Credential Validation","Kerberos Authentication Service","Kerberos Service Ticket Operations")
        "Account Management" = @("Computer Account Management","Distribution Group Management","Other Account Management Events","Security Group Management","User Account Management")
        "Detailed Tracking"  = @("DPAPI Activity","Process Creation","Process Termination","RPC Events")
        "DS Access"          = @("Directory Service Access","Directory Service Changes","Directory Service Replication")
        "Logon/Logoff"       = @("Account Lockout","Logoff","Logon","Other Logon/Logoff Events","Special Logon")
        "Object Access"      = @("File Share","Kernel Object","Other Object Access Events","Registry","SAM","File System")
        "Policy Change"      = @("Audit Policy Change","Authentication Policy Change","Authorization Policy Change","MPSSVC Rule-Level Policy Change","Other Policy Change Events")
        "Privilege Use"      = @("Non Sensitive Privilege Use","Other Privilege Use Events","Sensitive Privilege Use")
        "System"             = @("IPsec Driver","Other System Events","Security State Change","Security System Extension","System Integrity")
    }

    foreach ($category in $AuditPolicies.Keys) {
        foreach ($sub in $AuditPolicies[$category]) {
            $result = & auditpol /set /subcategory:"$sub" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Log "Audit enabled – [$category] $sub" "SUCCESS"
            } else {
                Write-Log "Audit WARN – [$category] $sub : $result" "WARN"
            }
        }
    }

    # Expand event log sizes.
    & wevtutil sl Security    /ms:536870912
    & wevtutil sl System      /ms:268435456
    & wevtutil sl Application /ms:268435456
    Write-Log "Event log sizes expanded (Security: 512 MB, System/Application: 256 MB)." "SUCCESS"

    # PowerShell Script Block + Module + Transcription logging.
    Write-Log "Enabling PowerShell Script Block, Module, and Transcription logging..."
    $PSLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $PSModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    $PSTxPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    foreach ($path in @($PSLogPath, $PSModPath, $PSTxPath)) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    }

    Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockLogging"          -Value 1 -Type DWord
    Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
    Set-ItemProperty -Path $PSModPath -Name "EnableModuleLogging"                -Value 1 -Type DWord

    if (-not (Test-Path "$PSModPath\ModuleNames")) {
        New-Item -Path "$PSModPath\ModuleNames" -Force | Out-Null
    }
    Set-ItemProperty -Path "$PSModPath\ModuleNames" -Name "*" -Value "*" -Type String

    $txDir = "$LogDir\PSTranscripts"
    if (-not (Test-Path $txDir)) { New-Item -ItemType Directory $txDir | Out-Null }
    Set-ItemProperty -Path $PSTxPath -Name "EnableTranscripting"   -Value 1      -Type DWord
    Set-ItemProperty -Path $PSTxPath -Name "OutputDirectory"        -Value $txDir -Type String
    Set-ItemProperty -Path $PSTxPath -Name "EnableInvocationHeader" -Value 1      -Type DWord

    # Command-line auditing in process creation events (Event 4688).
    $ProcAuditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $ProcAuditPath)) { New-Item -Path $ProcAuditPath -Force | Out-Null }
    Set-ItemProperty -Path $ProcAuditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    Write-Log "Command-line auditing in process creation events enabled." "SUCCESS"

    # DNS diagnostic logging.
    try {
        Set-DnsServerDiagnostics -All $true -ErrorAction SilentlyContinue
        Write-Log "DNS diagnostics logging enabled." "SUCCESS"
    } catch {
        Write-Log "DNS diagnostic logging not applied (may not be a DNS server role): $_" "WARN"
    }

    # Firewall connection logging.
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -LogBlocked True -LogAllowed True `
        -LogFileName "$LogDir\firewall_log.txt" `
        -LogMaxSizeKilobytes 32767
    Write-Log "Firewall connection logging enabled." "SUCCESS"

    Write-Log "Auditing & enhanced logging configured." "SUCCESS"
} else {
    Write-Log "Auditing section skipped by operator."
}

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 6 – SERVICE ENUMERATION & SCHEDULED TASK AUDIT
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 6: Service Enumeration & Scheduled Task Audit"

$CandidateServices = Get-Service |
    Where-Object { $_.StartType -ne 'Disabled' -and $RequiredServices -notcontains $_.Name } |
    Sort-Object DisplayName

Write-Host "`nServices eligible for review: $($CandidateServices.Count)" -ForegroundColor Yellow
Write-Host "(Required DC/DNS services are pre-filtered and will not appear)`n"

# Print numbered table – running services in red, stopped in gray.
$i = 0
foreach ($svc in $CandidateServices) {
    $i++
    $color = if ($svc.Status -eq 'Running') { 'Red' } else { 'DarkGray' }
    Write-Host ("{0,4}. {1,-48} {2,-12} {3}" -f $i, $svc.DisplayName, $svc.Status, $svc.StartType) -ForegroundColor $color
}

Write-Host "`nRunning services highlighted in red." -ForegroundColor Yellow
Write-Host "Enter the numbers of services to stop & disable, comma-separated (e.g. 1,4,7)." -ForegroundColor Cyan
Write-Host "Press ENTER with no input to skip.`n" -ForegroundColor Cyan

$raw      = Read-Host "Services to disable"
$StopList = @()

if ($raw.Trim() -ne '') {
    $selections = $raw -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }

    foreach ($sel in $selections) {
        $idx = [int]$sel - 1
        if ($idx -ge 0 -and $idx -lt $CandidateServices.Count) {
            $StopList += $CandidateServices[$idx]
        } else {
            Write-Log "Selection '$sel' out of range – skipped." "WARN"
        }
    }
}

if ($StopList.Count -gt 0) {
    Write-Host "`nQueued for disabling:" -ForegroundColor Yellow
    $StopList | ForEach-Object { Write-Host "  - $($_.Name)  ($($_.DisplayName))" }

    if (Prompt-YesNo "`nConfirm – stop & disable these $($StopList.Count) services?") {
        foreach ($svc in $StopList) {
            try {
                if ($svc.Status -eq 'Running') {
                    Stop-Service -Name $svc.Name -Force -ErrorAction Stop
                    Write-Log "Stopped service: $($svc.Name)" "SUCCESS"
                }
                Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                Write-Log "Disabled service: $($svc.Name)" "SUCCESS"
            } catch {
                Write-Log "Failed to stop/disable $($svc.Name) – $_" "ERROR"
            }
        }
    }
} else {
    Write-Log "No services selected for disabling."
}

# ── Scheduled task audit ──────────────────────────────────────────────────────
Write-Host "`n-- Scheduled Task Audit --" -ForegroundColor Cyan
Write-Host "  Listing non-Microsoft scheduled tasks (common attacker persistence location):`n" -ForegroundColor Yellow

$SuspectTasks = Get-ScheduledTask |
    Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Sort-Object TaskPath, TaskName

if ($SuspectTasks) {
    $SuspectTasks | Format-Table TaskName, TaskPath, State -AutoSize
    Write-Log "Non-Microsoft scheduled tasks found: $($SuspectTasks.Count) – review manually." "WARN"
    Write-Host "  Review the tasks above. To disable a suspicious one:" -ForegroundColor Yellow
    Write-Host "  Disable-ScheduledTask -TaskName '<name>' -TaskPath '<path>'" -ForegroundColor Cyan
} else {
    Write-Log "No non-Microsoft scheduled tasks found." "SUCCESS"
    Write-Host "  [OK] No non-Microsoft scheduled tasks found." -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 7 – ADDITIONAL HARDENING
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "SECTION 7: Additional Hardening"

if (Prompt-YesNo "Apply additional hardening? (SMBv1, NTLMv2, LDAP signing, null sessions, WDigest, LSASS RunAsPPL, LLMNR/NBT-NS, account lockout, DNS zone transfers)") {

    # Disable SMBv1.
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -Name "SMB1" -Value 0 -Type DWord
    Write-Log "SMBv1 disabled." "SUCCESS"

    # Require NTLMv2 – refuse LM & NTLMv1.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" -Value 5 -Type DWord
    Write-Log "LmCompatibilityLevel set to 5 (NTLMv2 only)." "SUCCESS"

    # Require LDAP server signing.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
        -Name "LDAPServerIntegrity" -Value 2 -Type DWord
    Write-Log "LDAP server signing required." "SUCCESS"

    # Block anonymous/null session enumeration.
    $LsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymous"        -Value 1 -Type DWord
    Set-ItemProperty -Path $LsaPath -Name "RestrictAnonymousSAM"     -Value 1 -Type DWord
    Set-ItemProperty -Path $LsaPath -Name "EveryoneIncludesAnonymous" -Value 0 -Type DWord
    Write-Log "Anonymous/null session restrictions applied." "SUCCESS"

    # Disable WDigest cleartext credential caching.
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
        -Name "UseLogonCredential" -Value 0 -Type DWord
    Write-Log "WDigest disabled (prevents cleartext creds in LSASS)." "SUCCESS"

    # LSA RunAsPPL – protects LSASS from credential dumping tools (e.g. mimikatz).
    # Takes effect after reboot.
    Set-ItemProperty -Path $LsaPath -Name "RunAsPPL" -Value 1 -Type DWord
    Write-Log "LSA RunAsPPL enabled – LSASS process protection active after reboot." "SUCCESS"
    Write-Host "  [NOTE] RunAsPPL takes effect after a reboot." -ForegroundColor Yellow

    # Disable LLMNR – prevents LLMNR poisoning / Responder attacks.
    $LLMNRPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $LLMNRPath)) { New-Item -Path $LLMNRPath -Force | Out-Null }
    Set-ItemProperty -Path $LLMNRPath -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Log "LLMNR disabled." "SUCCESS"

    # Disable NBT-NS on all adapters – prevents NetBIOS poisoning attacks.
    $adapterIndices = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled }).Index
    foreach ($idx in $adapterIndices) {
        Invoke-WmiMethod -Path "Win32_NetworkAdapterConfiguration.Index=$idx" -Name SetTcpipNetbios -ArgumentList 2 | Out-Null
    }
    Write-Log "NBT-NS disabled on all IP-enabled network adapters." "SUCCESS"

    # Account lockout policy – prevents password spray and brute-force.
    & net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null
    Write-Log "Account lockout policy set: 5 failed attempts → 30-minute lockout." "SUCCESS"

    # DNS zone transfer restriction – prevents full zone enumeration via AXFR.
    Write-Log "Restricting DNS zone transfers to authoritative servers only..."
    try {
        $zones = Get-DnsServerZone |
            Where-Object { -not $_.IsReverseLookupZone -and $_.ZoneType -eq 'Primary' }
        foreach ($zone in $zones) {
            Set-DnsServerPrimaryZone -Name $zone.ZoneName `
                -SecureSecondaries TransferToZoneNameServer -ErrorAction Stop
            Write-Log "Zone transfer restricted: $($zone.ZoneName)" "SUCCESS"
        }
    } catch {
        Write-Log "DNS zone transfer restriction failed – $_" "WARN"
    }

    Write-Log "Additional hardening complete." "SUCCESS"

} else {
    Write-Log "Additional hardening section skipped."
}

# ─────────────────────────────────────────────────────────────────────────────
#  DONE
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner "HARDENING COMPLETE"
Write-Log "All sections complete. Review log at: $LogFile"

Write-Host "`n  ╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║  NEXT STEPS:                                                     ║" -ForegroundColor Green
Write-Host "  ║  1. Verify scoring/inject accounts are still accessible          ║" -ForegroundColor Green
Write-Host "  ║  2. Reboot to activate LSA RunAsPPL (LSASS protection)           ║" -ForegroundColor Green
Write-Host "  ║  3. Review flagged scheduled tasks from Section 6                ║" -ForegroundColor Green
Write-Host "  ║  4. Use Event Viewer → Security (filter 4624/4625/4648/4688)     ║" -ForegroundColor Green
Write-Host "  ╠══════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "  ║  LOG FILES:                                                      ║" -ForegroundColor Green
Write-Host "  ║  Hardening  : $LogFile" -ForegroundColor Green
Write-Host "  ║  Transcripts: $LogDir\PSTranscripts\" -ForegroundColor Green
Write-Host "  ║  Firewall   : $LogDir\firewall_log.txt" -ForegroundColor Green
Write-Host "  ╚══════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Green
