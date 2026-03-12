# Author: Andrew Xie
# Date: 03/12/2026
# Create and share folders with permissions, change already existing NTFS Permissions, and switch SMB protocols (if needed)

# Create and share a folder (change folder name from newFolder to whatever), and change permissions based on inject
New-Item -Path "C:\Shares\newFolder" -ItemType Directory
New-SmbShare -Name "newFolder" -Path "C:\Shares\newFolder" -FullAccess "LAB\BlueTeamAdmins" -ReadAccess "LAB\Domain Users"

# Set NTFS Permissions, change newFolder to possible already existing share folder or not
$acl = Get-Acl "C:\Shares\newFolder"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("LAB\Domain Users", "ReadAndExecute", "Allow")
$acl.SetAccessRule($rule)
Set-Acl "C:\Shares\newFolder" $acl

# Switch SMB Protocol (VERY UNLIKELY WILL BE NEEDED FOR THIS COMPETITION)
# Set-SMBServerConfiguration -EnableSMB1Protocol $false -Force
# Set-SMBServerConfiguration -EnableSMB2Protocol $true -Force
