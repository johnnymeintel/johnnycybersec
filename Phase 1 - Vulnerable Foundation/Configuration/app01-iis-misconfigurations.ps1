Import-Module WebAdministration

# Directory browsing + detailed errors
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/directoryBrowse" -name "enabled" -value $true
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/httpErrors" -name "errorMode" -value "Detailed"

# App pool running as Domain Admin
Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel.identityType -Value 3
Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel.userName -Value "cjcs\marcus_chen"
Set-ItemProperty IIS:\AppPools\DefaultAppPool -Name processModel.password -Value "Executive2024!"

# Weak permissions on wwwroot
icacls "C:\inetpub\wwwroot" /grant "Everyone:(OI)(CI)F" /T

# .bak files served
Add-WebConfiguration -Filter "system.webServer/staticContent" -Value @{fileExtension=".bak"; mimeType="application/octet-stream"}