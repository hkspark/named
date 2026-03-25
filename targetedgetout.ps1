foreach ($user in @("kthomas", "mbrown", "lwilson", "jbesos", "bins", "Aidan", "Jean")) {

    # 1. Randomize password — even if re-enabled, they can't log in
    Set-ADAccountPassword -Identity $user -NewPassword (
        ConvertTo-SecureString "$(New-Guid)$(New-Guid)" -AsPlainText -Force
    ) -Reset

    # 2. Expire the account in the past — separate check from Enabled flag
    Set-ADAccountExpiration -Identity $user -DateTime "01/01/2020"

    # 3. Zero out logon hours — AD refuses auth at all times
    Set-ADUser -Identity $user -LogonHours (New-Object byte[] 21)

    # 4. Restrict to NULL workstation
    Set-ADUser -Identity $user -LogonWorkstations "NULL"

    # 5. Strip every group membership
    Get-ADPrincipalGroupMembership -Identity $user |
        Where {$_.Name -ne 'Domain Users'} |
        ForEach { Remove-ADGroupMember -Identity $_ -Members $user -Confirm:$false }

    # 6. They can re-enable all they want now, I simply do not care
    Disable-ADAccount -Identity $user
}
