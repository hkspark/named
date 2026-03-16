# Author: Andrew Xie
# Date: 03/15/2026
# ad_monitor.ps1 — Run on Domain Controller
# This script records the time, records failed logins and newly made accounts in the past hour, and privileged group changes. Also logs SMB sessions.
$LogPath = "C:\BlueTeam\ad_monitor.log"

function Log($msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  "$ts $msg" | Tee-Object -FilePath $LogPath -Append
}

# --- Recent failed logins (Event 4625) ---
Log "=== Failed Logins (last 1hr) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4625
  StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
  $xml = [xml]$_.ToXml()
  $user = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -Expand '#text'
  $ip   = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'}      | Select-Object -Expand '#text'
  Log "  FAIL: User=$user IP=$ip"
}

# --- New user accounts created (Event 4720) ---
Log "=== New Accounts Created (last 1hr) ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4720
  StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
  Log "  NEW USER: $($_.Message -replace '\s+',' ')"
}

# --- Privileged group changes (Event 4728/4732/4756) ---
Log "=== Privileged Group Changes ==="
Get-WinEvent -FilterHashtable @{
  LogName='Security'; Id=4728,4732,4756
  StartTime=(Get-Date).AddHours(-1)
} -ErrorAction SilentlyContinue | ForEach-Object {
  Log "  GROUP CHANGE: $($_.Message -replace '\s+',' ')"
}

# --- SMB share access ---
Log "=== SMB Sessions ==="
Get-SmbSession | Select-Object ClientComputerName, ClientUserName, NumOpens | ForEach-Object {
  Log "  SMB: $($_.ClientUserName) from $($_.ClientComputerName) opens=$($_.NumOpens)"
}

Log "=== Monitor Run Complete ==="
