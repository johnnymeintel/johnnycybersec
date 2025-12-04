## Weak Service Accounts

```powershell
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

Write-Host "`nPhase 1 vulnerable service accounts created!" -ForegroundColor Green
Write-Host "svc-sql and svc-app = Domain Admins + Kerberoastable + AS-REP roastable" -ForegroundColor Yellow
Write-Host "svc-generic = Kerberoastable + AS-REP roastable (no DA)" -ForegroundColor Yellow
```

## **MITRE ATT&CK Mapping**

- **T1558.003** - Kerberoasting
- **T1558.004** - AS-REP Roasting
- **T1078.002** - Valid Accounts: Domain Accounts
- **T1098** - Account Manipulation

## **Detection Opportunities**

These misconfigurations create detectable events:

- **SPN registration** for user accounts (Event ID 4738)
- **Service account creation** with Domain Admin membership (Event ID 4720, 4728)
- **DoesNotRequirePreAuth enabled** (Event ID 4738)
- **TGS-REQ with RC4 encryption** = Kerberoasting (Event ID 4769)
- **AS-REQ without pre-auth** = AS-REP Roasting (Event ID 4768)


---

### Service Accounts with Domain Admin

**Verify on DC01:**

```powershell
# List service accounts with SPNs
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, MemberOf, DoesNotRequirePreAuth | 
    Select-Object Name, ServicePrincipalName, MemberOf, DoesNotRequirePreAuth

# Check specific accounts
Get-ADUser svc-sql -Properties * | Select-Object Name, MemberOf, ServicePrincipalName, DoesNotRequirePreAuth
Get-ADUser svc-app -Properties * | Select-Object Name, MemberOf, ServicePrincipalName, DoesNotRequirePreAuth
Get-ADUser svc-generic -Properties * | Select-Object Name, MemberOf, ServicePrincipalName, DoesNotRequirePreAuth

# Expected vulnerabilities:
# - svc-sql and svc-app = Domain Admins
# - All three have SPNs (Kerberoastable)
# - All three have DoesNotRequirePreAuth = True (AS-REP Roastable)
```

![DC01-Weak-Service-1](assets/DC01-Weak-Service-1.png)


---

## **Impact**

- **Kerberoasting** = offline password cracking
- **AS-REP Roasting** = offline password cracking without credentials
- **Domain Admin service accounts** = complete domain compromise
- **Weak passwords** = ServicePassword123! cracks in seconds
- **DCSync capability** = all domain password hashes