Import-Module ActiveDirectory

# Create a new Fine-Grained Password Policy (PSO)
$PSO = New-ADFineGrainedPasswordPolicy `
    -Name "Weak-Lab-PSO" `
    -Precedence 100 `
    -ComplexityEnabled $false `
    -MinPasswordLength 7 `
    -PasswordHistoryCount 1 `
    -LockoutThreshold 0 `
    -LockoutDuration "00:00:00" `
    -LockoutObservationWindow "00:00:00" `
    -ReversibleEncryptionEnabled $true `
    -ProtectedFromAccidentalDeletion $false

Write-Host "[+] Created super weak Fine-Grained Password Policy: Weak-Lab-PSO" -ForegroundColor Red

# Apply it to our three vulnerable service accounts
Add-ADFineGrainedPasswordPolicySubject "Weak-Lab-PSO" -Subjects "svc-sql","svc-app","svc-generic"

Write-Host "[+] Applied Weak-Lab-PSO to svc-sql, svc-app, svc-generic" -ForegroundColor Yellow

# Also apply to regular users
Add-ADFineGrainedPasswordPolicySubject "Weak-Lab-PSO" -Subjects "Domain Users"

Write-Host "[+] Applied Weak-Lab-PSO to all Domain Users (because legacy apps, bro)" -ForegroundColor Yellow

Write-Host "`nPassword Policy now:" -ForegroundColor Cyan
Write-Host "Min length: 7 chars" -ForegroundColor Cyan
Write-Host "Complexity: OFF" -ForegroundColor Cyan
Write-Host "Lockout: Never" -ForegroundColor Cyan
Write-Host "History: 1 password remembered" -ForegroundColor Cyan
Write-Host "Reversible encryption: ENABLED (cleartext in LSASS!)" -ForegroundColor Red