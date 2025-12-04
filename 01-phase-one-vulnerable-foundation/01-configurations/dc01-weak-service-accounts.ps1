Import-Module ActiveDirectory

# svc-sql
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -UserPrincipalName "svc-sql@cjcs.local" -Description "SQL Service - over-privileged" -AccountPassword (ConvertTo-SecureString "ServicePassword123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember "Domain Admins" "svc-sql"
Set-ADAccountControl "svc-sql" -DoesNotRequirePreAuth $true
setspn -A "MSSQLSvc/app01.cjcs.local:1433" "svc-sql"

# svc-app
New-ADUser -Name "svc-app" -SamAccountName "svc-app" -UserPrincipalName "svc-app@cjcs.local" -Description "Web App Service - excessive rights" -AccountPassword (ConvertTo-SecureString "ServicePassword123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember "Domain Admins" "svc-app"
Set-ADAccountControl "svc-app" -DoesNotRequirePreAuth $true
setspn -A "HTTP/app01.cjcs.local:80" "svc-app"

# svc-generic (no Domain Admin)
New-ADUser -Name "svc-generic" -SamAccountName "svc-generic" -UserPrincipalName "svc-generic@cjcs.local" -Description "Generic test account - no DA" -AccountPassword (ConvertTo-SecureString "ServicePassword123!" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
Set-ADAccountControl "svc-generic" -DoesNotRequirePreAuth $true
setspn -A "CIFS/dc01.cjcs.local" "svc-generic"