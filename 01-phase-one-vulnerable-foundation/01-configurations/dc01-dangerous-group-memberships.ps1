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