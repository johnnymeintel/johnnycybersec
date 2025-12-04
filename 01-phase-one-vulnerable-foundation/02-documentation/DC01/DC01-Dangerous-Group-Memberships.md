## Dangerous Group Memberships

```powershell
Import-Module ActiveDirectory

# 1. Service accounts → Domain Admins

Add-ADGroupMember "Domain Admins" -Members "svc-sql","svc-app","svc-generic"

# 2. Create IT Support group if missing

New-ADGroup -Name "IT Support" -GroupScope Global -ErrorAction SilentlyContinue

# 3. Give IT Support DCSync rights

dsacls "DC=cjcs,DC=local" /g "cjcs\IT Support:CA;Replicating Directory Changes"
dsacls "DC=cjcs,DC=local" /g "cjcs\IT Support:CA;Replicating Directory Changes All"

# 4. Backup Operators → Domain Admins

Add-ADGroupMember "Domain Admins" -Members "Backup Operators"

# 5. Create Legacy App Admins group and make it Domain Admin

New-ADGroup -Name "Legacy App Admins" -GroupScope Global -ErrorAction SilentlyContinue

Add-ADGroupMember "Domain Admins" -Members "Legacy App Admins"
```

## **MITRE ATT&CK Mapping**

- **T1069.002** - Permission Groups Discovery: Domain Groups
- **T1003.006** - OS Credential Dumping: DCSync
- **T1098.001** - Account Manipulation: Additional Cloud Credentials
- **T1484.001** - Domain Policy Modification: Group Policy Modification

## **Detection Opportunities**

These misconfigurations create detectable events:

- **Service accounts added to Domain Admins** (Event ID 4728)
- **DCSync rights granted** (Event ID 5136 - AD object permission change)
- **Backup Operators added to Domain Admins** (Event ID 4728)
- **New privileged group creation** (Event ID 4731)
- **Unusual accounts in privileged groups** via regular audits


---

### Excessive Domain Admins

**Verify on DC01:**

```powershell
# Check Domain Admins membership
Get-ADGroupMember "Domain Admins" | Select-Object Name, SamAccountName

# Check IT Support DCSync rights
dsacls "DC=cjcs,DC=local" | Select-String "IT Support"

# Check all privileged groups
Get-ADGroup -Filter {Name -like "*Admin*" -or Name -like "*Operator*"} | 
    ForEach-Object {
        Write-Host "`n$($_.Name):" -ForegroundColor Cyan
        Get-ADGroupMember $_.Name | Select-Object Name
    }

# Check Legacy App Admins
Get-ADGroupMember "Legacy App Admins" | Select-Object Name, MemberOf

# Expected issues:
# - svc-sql, svc-app, svc-generic in Domain Admins
# - IT Support has DCSync rights
# - Backup Operators in Domain Admins
# - Legacy App Admins in Domain Admins
```

![DC01-Excessive-Domain-1](assets/DC01-Excessive-Domain-1.png)

![DC01-Excessive-Domain-2](assets/DC01-Excessive-Domain-2.png)


---

## **Impact**

- **Service accounts as Domain Admins** = single compromise = full domain
- **DCSync rights to non-admins** = steal all credentials without admin
- **Backup Operators as Domain Admins** = all backup staff are god-mode
- **Legacy groups with DA** = forgotten accounts with full access
- **Attack path amplification** = multiple routes to Domain Admin