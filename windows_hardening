#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue Team Workstation Hardening Script
.DESCRIPTION
    Hardens Windows 10/11 workstations against common Red Team attack vectors.
    Run as Administrator on the Windows 11 SMB box or any domain workstation.
#>

$LogFile = "C:\BlueTeam\hardening_log.txt"
New-Item -Path "C:\BlueTeam" -ItemType Directory -Force | Out-Null

function Log {
    param([string]$msg, [string]$color = "White")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] $msg"
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $LogFile -Value $line
}

function Section {
    param([string]$title)
    Log "========================================" "Cyan"
    Log "  $title" "Cyan"
    Log "========================================" "Cyan"
}

Log "Blue Team Hardening Script Started" "Green"
Log "Running as: $($env:USERNAME) on $($env:COMPUTERNAME)" "Green"

# ============================================================
# SECTION 1 — SMB HARDENING
# ============================================================
Section "SMB Hardening"

# Disable SMBv1 — most exploited protocol version (EternalBlue etc.)
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
Set-SmbClientConfiguration -EnableBandwidthThrottling $false -Force
Log "SMBv1 disabled" "Green"

# Enable SMB2 instead
Set-SMBServerConfiguration -EnableSMB2Protocol $true -Force
Log "SMBv2 Enabled" "Green"

# Enable SMB signing — prevents NTLM relay attacks
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
Log "SMB signing enforced" "Green"

# Disable SMB compression (CVE-2020-0796 SMBGhost mitigation)
Set-SmbServerConfiguration -DisableCompression $true -Force
Log "SMB compression disabled" "Green"

# Restrict anonymous SMB enumeration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 1
Log "Anonymous SMB enumeration restricted" "Green"

# Disable admin shares (C$, ADMIN$) — common lateral movement targets
# NOTE: Comment these out if injects require admin share access
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
    -Name "AutoShareWks" -Value 0
Log "Admin shares (C$, ADMIN$) disabled" "Yellow"

# ============================================================
# SECTION 2 — WINDOWS FIREWALL
# ============================================================
Section "Windows Firewall Hardening"

# Enable firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
Log "Firewall enabled on all profiles" "Green"

# Set default inbound policy to block
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block
Log "Default inbound action set to Block" "Green"

# Allow only necessary inbound ports — adjust to your competition needs
$allowedPorts = @(
    @{Port=445;  Proto="TCP"; Name="SMB"},
    @{Port=135;  Proto="TCP"; Name="RPC"},
    @{Port=3389; Proto="TCP"; Name="RDP"},
    @{Port=5985; Proto="TCP"; Name="WinRM-HTTP"},
    @{Port=5986; Proto="TCP"; Name="WinRM-HTTPS"},
    @{Port=80;   Proto="TCP"; Name="HTTP"},
    @{Port=443;  Proto="TCP"; Name="HTTPS"}
)

foreach ($rule in $allowedPorts) {
    New-NetFirewallRule `
        -DisplayName "BT-ALLOW-$($rule.Name)" `
        -Direction Inbound `
        -Protocol $rule.Proto `
        -LocalPort $rule.Port `
        -Action Allow `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null
    Log "Allowed inbound $($rule.Name) ($($rule.Proto)/$($rule.Port))" "Green"
}

# Block common attacker tools/ports inbound
$blockPorts = @(
    @{Port=4444;  Name="Metasploit-Default"},
    @{Port=1234;  Name="Common-Backdoor"},
    @{Port=8888;  Name="Common-C2"},
    @{Port=9999;  Name="Common-C2-Alt"},
    @{Port=6666;  Name="Common-Backdoor-Alt"},
    @{Port=31337; Name="Elite-Backdoor"}
)

foreach ($rule in $blockPorts) {
    New-NetFirewallRule `
        -DisplayName "BT-BLOCK-$($rule.Name)" `
        -Direction Outbound `
        -Protocol TCP `
        -RemotePort $rule.Port `
        -Action Block `
        -Profile Any `
        -ErrorAction SilentlyContinue | Out-Null
    Log "Blocked outbound port $($rule.Port) ($($rule.Name))" "Green"
}

# Block LLMNR (used in NTLM relay/poisoning attacks)
New-NetFirewallRule -DisplayName "BT-BLOCK-LLMNR" `
    -Direction Inbound -Protocol UDP -LocalPort 5355 -Action Block -Profile Any `
    -ErrorAction SilentlyContinue | Out-Null
Log "LLMNR inbound blocked via firewall" "Green"

# ============================================================
# SECTION 3 — CREDENTIAL PROTECTION
# ============================================================
Section "Credential Protection"

# Enable Credential Guard (Windows 11 / Server 2019+)
# Protects LSASS from credential dumping (Mimikatz etc.)
$cgPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
New-Item -Path $cgPath -Force | Out-Null
Set-ItemProperty -Path $cgPath -Name "EnableVirtualizationBasedSecurity" -Value 1
Set-ItemProperty -Path $cgPath -Name "RequirePlatformSecurityFeatures" -Value 1
Set-ItemProperty -Path $cgPath -Name "HypervisorEnforcedCodeIntegrity" -Value 1

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1
Log "Credential Guard enabled" "Green"

# Enable LSA Protection (RunAsPPL) — prevents Mimikatz from reading LSASS
Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1
Log "LSA Protection (PPL) enabled" "Green"

# Disable WDigest — forces LSASS to NOT store plaintext passwords in memory
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" `
    -Name "UseLogonCredential" -Value 0
Log "WDigest plaintext credential caching disabled" "Green"

# Disable NTLM where possible (use Kerberos instead)
# Note: Setting to 0 disables outgoing NTLM — may break some legacy apps
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
    -Name "RestrictSendingNTLMTraffic" -Value 2  # 2 = Deny all
Log "Outgoing NTLM restricted (Kerberos preferred)" "Green"

# Restrict who can access LSASS remotely
Set-ItemProperty -Path $lsaPath -Name "RestrictRemoteSAM" `
    -Value "O:BAG:BAD:(A;;RC;;;BA)"  # Only local admins
Log "Remote SAM access restricted to local admins" "Green"

# Prevent cached credential count (limit domain creds cached locally)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -Name "CachedLogonsCount" -Value "2"
Log "Cached logon count limited to 2" "Green"

# ============================================================
# SECTION 4 — POWERSHELL SECURITY
# ============================================================
Section "PowerShell Hardening"

# Set execution policy to restrict unsigned scripts
Set-ExecutionPolicy RemoteSigned -Force -Scope LocalMachine
Log "PowerShell execution policy set to RemoteSigned" "Green"

# Enable PowerShell Script Block Logging (logs all PS execution — great for detection)
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $psLogPath -Force | Out-Null
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1
Log "PowerShell Script Block Logging enabled" "Green"

# Enable PowerShell Module Logging
$psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
New-Item -Path $psModPath -Force | Out-Null
Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 1
New-Item -Path "$psModPath\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$psModPath\ModuleNames" -Name "*" -Value "*"
Log "PowerShell Module Logging enabled" "Green"

# Enable PowerShell Transcription (full session logs)
$psTranPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
New-Item -Path $psTranPath -Force | Out-Null
Set-ItemProperty -Path $psTranPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $psTranPath -Name "EnableInvocationHeader" -Value 1
Set-ItemProperty -Path $psTranPath -Name "OutputDirectory" -Value "C:\BlueTeam\PSLogs"
New-Item -Path "C:\BlueTeam\PSLogs" -ItemType Directory -Force | Out-Null
Log "PowerShell Transcription logging enabled -> C:\BlueTeam\PSLogs" "Green"

# Disable PowerShell v2 — bypasses all modern logging if available
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root `
    -NoRestart -ErrorAction SilentlyContinue | Out-Null
Log "PowerShell v2 disabled (logging bypass prevention)" "Green"

# Constrained Language Mode via WDAC/AppLocker — registry hint
# Full CLM requires WDAC policy, but this registry key signals intent
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" `
    -Name "__PSLockdownPolicy" -Value "4"
Log "PowerShell Constrained Language Mode hint set" "Yellow"

# ============================================================
# SECTION 5 — AUDIT POLICY & EVENT LOGGING
# ============================================================
Section "Audit Policy & Logging"

# Expand Security event log size (default is tiny)
wevtutil sl Security /ms:1073741824  # 1GB
wevtutil sl System /ms:524288000     # 500MB
wevtutil sl Application /ms:524288000
Log "Event log sizes expanded" "Green"

# Enable comprehensive audit policies
$auditPolicies = @(
    "Account Logon",
    "Account Management",
    "DS Access",
    "Logon/Logoff",
    "Object Access",
    "Policy Change",
    "Privilege Use",
    "Process Tracking",
    "System"
)

foreach ($cat in $auditPolicies) {
    auditpol /set /category:"$cat" /success:enable /failure:enable 2>$null
    Log "Audit policy enabled: $cat" "Green"
}

# Enable Sysmon if available (place sysmon64.exe in C:\BlueTeam\tools)
$sysmonPath = "C:\BlueTeam\tools\sysmon64.exe"
if (Test-Path $sysmonPath) {
    & $sysmonPath -accepteula -i -n 2>$null
    Log "Sysmon installed and running" "Green"
} else {
    Log "Sysmon not found at $sysmonPath — download and install manually" "Yellow"
}

# Process creation auditing (catches LOLBins, lateral movement tools)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
Log "Command line process creation logging enabled" "Green"

# ============================================================
# SECTION 6 — DISABLE UNNECESSARY SERVICES & FEATURES
# ============================================================
Section "Disable Unnecessary Services"

$disableServices = @(
    @{Name="RemoteRegistry";    Desc="Remote Registry — allows remote reg edits"},
    @{Name="Spooler";           Desc="Print Spooler — PrintNightmare vector (disable if no printing)"},
    @{Name="TapiSrv";           Desc="Telephony service — rarely needed"},
    @{Name="lltdsvc";           Desc="Link-Layer Topology Discovery"},
    @{Name="MSiSCSI";           Desc="iSCSI Initiator — not needed on workstations"},
    @{Name="RasMan";            Desc="Remote Access Connection Manager — if no VPN needed"},
    @{Name="SSDPSRV";           Desc="SSDP Discovery — UPnP attack surface"},
    @{Name="upnphost";          Desc="UPnP Device Host"},
    @{Name="WMPNetworkSvc";     Desc="Windows Media Player Network Sharing"}
)

foreach ($svc in $disableServices) {
    try {
        Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction SilentlyContinue
        Log "Disabled service: $($svc.Name) ($($svc.Desc))" "Green"
    } catch {
        Log "Could not disable $($svc.Name): $_" "Yellow"
    }
}

# Disable LLMNR (NetBIOS poisoning attack vector — Responder)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord -Force
Log "LLMNR disabled via registry" "Green"

# Disable NetBIOS over TCP/IP on all adapters
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS
}
Log "NetBIOS over TCP/IP disabled on all adapters" "Green"

# Disable WPAD (Web Proxy Auto-Discovery — used in MitM attacks)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" `
    -Name "AutoDetect" -Value 0
Log "WPAD auto-detection disabled" "Green"

# ============================================================
# SECTION 7 — USER ACCOUNT & LOCAL ADMIN HARDENING
# ============================================================
Section "Local Account Hardening"

# Rename the built-in Administrator account
$builtinAdmin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
if ($builtinAdmin.Name -eq "Administrator") {
    Rename-LocalUser -Name "Administrator" -NewName "BlueAdmin_Local"
    Log "Built-in Administrator renamed to BlueAdmin_Local" "Green"
} else {
    Log "Built-in Administrator already renamed: $($builtinAdmin.Name)" "Yellow"
}

# Disable the built-in Guest account
Disable-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
Log "Guest account disabled" "Green"

# Disable built-in Administrator account (use your own admin account)
# Disable-LocalUser -SID $builtinAdmin.SID  # Uncomment if you have another admin account

# Set a strong local admin password
$localAdminPass = ConvertTo-SecureString "B1u3T3@m$(Get-Random -Max 9999)!" -AsPlainText -Force
Set-LocalUser -Name $builtinAdmin.Name -Password $localAdminPass
Log "Local admin password randomized" "Green"

# Prevent local admin accounts from logging in over network (blocks PtH laterally)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "LocalAccountTokenFilterPolicy" -Value 0
Log "LocalAccountTokenFilterPolicy set to 0 (blocks remote local admin logon)" "Green"

# Account lockout policy (via secedit — applies locally)
$secCfg = @"
[System Access]
LockoutBadCount = 5
ResetLockoutCount = 30
LockoutDuration = 30
"@
$secCfg | Out-File "C:\BlueTeam\lockout.cfg" -Encoding ASCII
secedit /configure /db secedit.sdb /cfg "C:\BlueTeam\lockout.cfg" /quiet
Log "Account lockout policy applied (5 attempts, 30min lockout)" "Green"

# ============================================================
# SECTION 8 — ATTACK TOOL MITIGATION (LOLBins)
# ============================================================
Section "LOLBin / Attack Tool Mitigation"

# LOLBins (Living off the Land Binaries) commonly abused by Red Team:
# Block via AppLocker or rename/restrict access to high-risk binaries

$lolbins = @(
    "C:\Windows\System32\certutil.exe",      # file download, base64 encode/decode
    "C:\Windows\System32\mshta.exe",         # HTA execution
    "C:\Windows\System32\wscript.exe",       # script execution
    "C:\Windows\System32\cscript.exe",       # script execution
    "C:\Windows\System32\regsvr32.exe",      # Squiblydoo bypass
    "C:\Windows\System32\rundll32.exe",      # DLL execution
    "C:\Windows\System32\msiexec.exe",       # remote MSI install
    "C:\Windows\System32\bitsadmin.exe",     # file download
    "C:\Windows\System32\installutil.exe"    # AppLocker bypass
)

foreach ($bin in $lolbins) {
    if (Test-Path $bin) {
        # Restrict execution to Administrators only via ACL
        try {
            $acl = Get-Acl $bin
            $acl.SetAccessRuleProtection($true, $false)
            # Remove all existing rules and add admin-only
            $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "BUILTIN\Administrators", "FullControl", "Allow")
            $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                "NT AUTHORITY\SYSTEM", "FullControl", "Allow")
            $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
            $acl.AddAccessRule($adminRule)
            $acl.AddAccessRule($systemRule)
            Set-Acl -Path $bin -AclObject $acl
            Log "Restricted access: $(Split-Path $bin -Leaf)" "Green"
        } catch {
            Log "Could not restrict $(Split-Path $bin -Leaf): $_" "Yellow"
        }
    }
}

# ============================================================
# SECTION 9 — WINDOWS DEFENDER HARDENING
# ============================================================
Section "Windows Defender / AV Hardening"

# Enable all Defender features
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisablePrivacyMode $false
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableIntrusionPreventionSystem $false
Log "Windows Defender real-time protections enabled" "Green"

# Enable Attack Surface Reduction (ASR) rules
# These block specific attack techniques used by malware and Red Team
$asrRules = @{
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email/webmail"
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block Office apps from creating child processes"
    "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office apps from creating executable content"
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office apps from injecting into processes"
    "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JS/VBS from launching downloaded executable"
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files unless they meet prevalence criteria"
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from LSASS"
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted/unsigned USB processes"
    "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication apps from creating child processes"
    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
}

foreach ($rule in $asrRules.GetEnumerator()) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key `
        -AttackSurfaceReductionRules_Actions Enabled
    Log "ASR enabled: $($rule.Value)" "Green"
}

# Enable Network Protection (blocks malicious domains/IPs)
Set-MpPreference -EnableNetworkProtection Enabled
Log "Network Protection enabled" "Green"

# Enable Controlled Folder Access (ransomware protection)
Set-MpPreference -EnableControlledFolderAccess Enabled
Log "Controlled Folder Access enabled" "Green"

# Force signature update
Update-MpSignature -ErrorAction SilentlyContinue
Log "Defender signatures updated" "Green"

# ============================================================
# SECTION 10 — MISCELLANEOUS HARDENING
# ============================================================
Section "Miscellaneous Hardening"

# Disable autorun/autoplay — prevents USB-based attacks
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 255
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoAutorun" -Value 1
Log "AutoRun/AutoPlay disabled" "Green"

# Disable Remote Desktop if not needed (comment out if RDP is required)
# Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
#     -Name "fDenyTSConnections" -Value 1
# Log "RDP disabled" "Green"

# Require NLA for RDP (prevents unauthenticated connection attempts)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 1
Log "RDP NLA (Network Level Authentication) required" "Green"

# Disable anonymous enumeration of shares and SAM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "EveryoneIncludesAnonymous" -Value 0
Log "Anonymous enumeration of shares/SAM disabled" "Green"

# Enable UAC at maximum level
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "EnableLUA" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "ConsentPromptBehaviorAdmin" -Value 2  # Prompt for credentials
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name "PromptOnSecureDesktop" -Value 1
Log "UAC set to maximum" "Green"

# Disable storing of LM hashes (very weak, crackable instantly)
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "NoLMHash" -Value 1
Log "LM hash storage disabled" "Green"

# Prevent Mimikatz SeDebugPrivilege abuse
# Remove SeDebugPrivilege from local admins (breaks some legit tools but stops Mimikatz)
# This is aggressive — uncomment only if willing to accept the trade-off
# secedit /export /cfg C:\BlueTeam\secpol.cfg /quiet
# (Get-Content C:\BlueTeam\secpol.cfg) -replace 'SeDebugPrivilege.*', '' |
#     Set-Content C:\BlueTeam\secpol.cfg
# secedit /configure /db secedit.sdb /cfg C:\BlueTeam\secpol.cfg /quiet
# Log "SeDebugPrivilege removed" "Yellow"

# ============================================================
# FINAL SUMMARY
# ============================================================
Section "Hardening Complete"
Log "All hardening steps applied. Review warnings above." "Green"
Log "Log file saved to: $LogFile" "Green"
Log "IMPORTANT: Some settings require a REBOOT to fully take effect." "Yellow"
Log "Reboot when operationally safe to do so." "Yellow"

$reboot = Read-Host "`nReboot now to apply all settings? (y/n)"
if ($reboot -eq "y") {
    Restart-Computer -Force
}
