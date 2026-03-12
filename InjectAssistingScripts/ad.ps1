# Author: Andrew Xie
# Date: 03/12/2026
# Helps Add AD Users and OU's, sets Default Password Policy, and creates a new GPO

# Create new ADUser, change the names, path (if needed), and the PASSWORD
New-ADUser -Name "Joe Doe" -GivenName "Joe" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@lab.local" -Path "OU=Users,DC=lab,DC=local" -AccountPassword (ConvertTo-SecureString "password" -AsPlainText -Force) -Enabled $true

# Create OU, change name and path (if needed)
New-ADOrganizationalUnit -Name "BlueTeam" -Path "DC=lab,DC=local"

# Set Domain Default password Policy
Set-ADDefaultDomainPasswordPolicy -Identity "lab.local" -MinPasswordLength 12 -PasswordHistoryCount 24 -MaxPasswordAge "90.00:00:00" -LockoutThreshold 3 -LockoutDuration "00:30:00"

# Create new GPO and Link
New-GPO -Name "BlueTeam-Inject" | NewGPLink -Target "OU=Workstations,DC=lab,DC=local"
