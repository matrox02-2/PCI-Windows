# This Script is used to gather information for the purpose of PCI Compliance
# Author: Matthew Hanson
# Script will drop information into seperate txt Files respective
# of their PCI Requirement section
write-host "Getting Information: Please wait" 
# System Information
systeminfo |Out-File $env:COMPUTERNAME-SystemInfo.txt -Append
write-host "System Info: Done"
# Active Directory Status R1.4
Echo "|-------------Active Directory Status R1.4-----------|" >> $env:COMPUTERNAME-Requirement-1.txt
Get-WmiObject -class win32_computersystem |Select Domain |Out-File $env:COMPUTERNAME-Requirement-1.txt -append
# Firewall Service Status R1.4
echo "|------------Firewall Status R1.4-------------|" >> $env:COMPUTERNAME-Requirement-1.txt
Get-Service -DisplayName "*firewall*" |Select DisplayName,Name,Status |out-file $env:COMPUTERNAME-Requirement-1.txt -Append
# Firewall Configuration R1.4
echo "|-------------Firewall Configuration R1.4-----------|" >> $env:COMPUTERNAME-Requirement-1.txt -append
Get-NetFirewallProfile -All | Out-File $env:COMPUTERNAME-Requirement-1.txt -Append
Get-NetFirewallSetting -All | Out-File $env:COMPUTERNAME-Requirement-1.txt -Append
echo "|-------------Firewall Rules R1.4----------------|" >> $env:COMPUTERNAME-Requirement-1.txt
Get-NetFirewallRule -All |Out-File $env:COMPUTERNAME-Requirement-1.txt -Append
write-host "Requirement 1: Done"
# User Accounts R2.1
echo "|---------------User Accounts R2.1---------------|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject -class win32_useraccount |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Installed Software R2.2.2
echo "|---------------Installed Software R2.2.2--------------|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
# Services Running R2.2.2
Echo "|----------------Running Services R2.2.2---------------|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-Service |Where-Object {$_.Status -EQ "running"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
Echo "|----------------Stopped Services R2.2.2---------------|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-Service |Where-Object {$_.Status -EQ "Stopped"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Processes Running R2.2.2
echo "|----------------Running Processes R2.2.2--------------|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-Process |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Network Connections R2.2.2
Echo "|----------------Network Connections R2.2.2---------------|" >> $env:COMPUTERNAME-Requirement-2.txt
netstat -na |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# IPV6 Support R2.2.2
echo "|----------------IPv6 Support R2.2.2-----------------|" >> $env:COMPUTERNAME-Requirement-2.txt
$IPV6 = $false
$arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress

foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains(":")} 

Echo "--------------------"$arrInterfaces `n"IPv6 Enabled="$IPV6 `n"--------------------"`n |Out-File $env:COMPUTERNAME-Requirement-2.txt -append

# MISC Security Settings R2.2.4
Echo "|---------------------Misc Security Settings R2.2.4------------------|" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "`nAccounts: Administrator Account Status:" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject -class win32_useraccount |select Name,Disabled,Status |Where-Object {$_.Name -eq "Administrator"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
Echo "`nAccounts: Guest Account Status:" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject -class win32_useraccount |select Name,Disabled,Status |Where-Object {$_.Name -eq "Guest"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
#-- List New Admin Names--
Echo "Current Administrators:" >> $env:COMPUTERNAME-Requirement-2.txt
$group=Get-WmiObject win32_group -Filter "name='Administrators'"
$group.getrelated("win32_useraccount") |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
Echo "Current Guest Accounts:" >> $env:COMPUTERNAME-Requirement-2.txt
$group=Get-WmiObject win32_group -Filter "name='Guests'"
$group.getrelated("win32_useraccount") |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
#
secedit /export /cfg sec.tmp /quiet
Echo "|----------Accounts: Limit local account use of blank passwords to console logon only----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$LimitBlankPasswordUse= Get-Content sec.tmp |Select-String LimitBlankPasswordUse
if (!$LimitBlankPasswordUse) {echo "LimitBlankPasswordUse is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$LimitBlankPasswordUse |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Devices: Allowed to format and eject removable media----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$AllocateDASD= Get-Content sec.tmp |Select-String AllocateDASD
if (!$AllocateDASD) {echo "AllocateDASD is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$AllocateDASD |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Devices: Prevent users from installing printer drivers----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$AddPrinterDrivers= Get-Content sec.tmp |Select-String AddPrinterDrivers
if (!$AddPrinterDrivers) {echo "AddPrinterDrivers is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$AddPrinterDrivers |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Devices: Restrict CD-ROM access to locally logged-on user only----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$AllocateCDRoms= Get-Content sec.tmp |Select-String AllocateCDRoms
if (!$AllocateCDRoms) {echo "AllocateCDRoms is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$AllocateCDRoms |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Devices: Restrict floppy access to locally logged-on user only----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$AllocateFloppies= Get-Content sec.tmp |Select-String AllocateFloppies
if (!$AllocateFloppies) {echo "AllocateFloppiese is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$AllocateFloppies |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Domain member: Digitally encrypt or sign secure channel data (always)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$requiresignorseal= Get-Content sec.tmp |Select-String requiresignorseal
if (!$requiresignorseal) {echo "requiresignorseal is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$requiresignorseal |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Domain member: Digitally encrypt secure channel data (when possible)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$sealsecurechannel= Get-Content sec.tmp |Select-String sealsecurechannel
if (!$sealsecurechannel) {echo "sealsecurechannel is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$sealsecurechannel |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Domain member: Disable machine account password changes----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$disablepasswordchange= Get-Content sec.tmp |Select-String disablepasswordchange
if (!$disablepasswordchange) {echo "disablepasswordchange is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$disablepasswordchange |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Domain member: Maximum machine account password age----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$maximumpasswordage= Get-Content sec.tmp |Select-String -SimpleMatch Parameters\maximumpasswordage
if (!$maximumpasswordage) {echo "Parameters\maximumpasswordage is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$maximumpasswordage |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Domain member: Require strong (Windows 2000 or later) session key----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$requirestrongkey= Get-Content sec.tmp |Select-String requirestrongkey
if (!$requirestrongkey) {echo "requirestrongkey is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$requirestrongkey |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
echo "|----------Interactive logon: Do not display last user name----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$DontDisplayLastUserName= Get-Content sec.tmp |Select-String DontDisplayLastUserName
if (!$DontDisplayLastUserName) {echo "DontDisplayLastUserName is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$DontDisplayLastUserName |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Interactive logon: Number of previous logons to cache (in case domain controller is not available)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$cachedlogonscount= Get-Content sec.tmp |Select-String cachedlogonscount
if (!$cachedlogonscount) {echo "cachedlogonscount is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$cachedlogonscount |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Interactive logon: Prompt user to change password before expiration----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$passwordexpirywarning= Get-Content sec.tmp |Select-String passwordexpirywarning
if (!$passwordexpirywarning) {echo "passwordexpirywarning is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$passwordexpirywarning |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Interactive logon: Require Domain Controller authentication to unlock workstation----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$ForceUnlockLogon= Get-Content sec.tmp |Select-String ForceUnlockLogon
if (!$ForceUnlockLogon) {echo "ForceUnlockLogon is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$ForceUnlockLogon |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Interactive logon: Message title for users attempting to log on----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$LegalNoticeCaption= Get-Content sec.tmp |Select-String LegalNoticeCaption
if (!$LegalNoticeCaption) {echo "LegalNoticeCaption is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$LegalNoticeCaption |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Interactive logon: Message text for users attempting to log on----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$LegalNoticeText= Get-Content sec.tmp |Select-String LegalNoticeText
if (!$LegalNoticeText) {echo "LegalNoticeText is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$LegalNoticeText |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network client: Digitally sign communications (always)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$RequireSecuritySignature= Get-Content sec.tmp |Select-String -simplematch LanmanWorkstation\Parameters\RequireSecuritySignature
if (!$RequireSecuritySignature) {echo "LanmanWorkstation\Parameters\RequireSecuritySignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$RequireSecuritySignature |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network client: Digitally sign communications (if server agrees)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$EnableSecuritySignature= Get-Content sec.tmp |Select-String -SimpleMatch LanmanWorkstation\Parameters\EnableSecuritySignature
if (!$EnableSecuritySignature) {echo "LanmanWorkstation\Parameters\EnableSecuritySignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$EnableSecuritySignature |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network client: Send unencrypted password to third-party SMB servers----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$EnablePlainTextPassword= Get-Content sec.tmp |Select-String -simplematch LanmanWorkstation\Parameters\EnablePlainTextPassword
if (!$EnablePlainTextPassword) {echo "LanmanWorkstation\Parameters\EnablePlainTextPassword is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$EnablePlainTextPassword |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network server: Amount of idle time required before suspending session----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$autodisconnect= Get-Content sec.tmp |Select-String -simplematch LanManServer\Parameters\autodisconnect
if (!$autodisconnect) {echo "LanManServer\Parameters\autodisconnect is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$autodisconnect |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network server: Digitally sign communications (always)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$requiresecuritysignature= Get-Content sec.tmp |Select-String -simplematch LanManServer\Parameters\requiresecuritysignature
if (!$requiresecuritysignature) {echo "LanManServer\Parameters\requiresecuritysignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$requiresecuritysignature |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network server: Digitally sign communications (if client agrees)----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$enablesecuritysignature= Get-Content sec.tmp |Select-String -SimpleMatch LanManServer\Parameters\enablesecuritysignature
if (!$enablesecuritysignature) {echo "LanManServer\Parameters\enablesecuritysignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$enablesecuritysignature |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Microsoft network server: Disconnect clients when logon hours expire----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$enableforcedlogoff= Get-Content sec.tmp |Select-String -SimpleMatch LanManServer\Parameters\enableforcedlogoff
if (!$enableforcedlogoff) {echo "LanManServer\Parameters\enableforcedlogoff is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$enableforcedlogoff |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network Access: Allow Anonymous SID\Name Translation----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$LSAAnonymousNameLookup= Get-Content sec.tmp |Select-String LSAAnonymousNameLookup
if (!$LSAAnonymousNameLookup) {echo "LSAAnonymousNameLookup is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$LSAAnonymousNameLookup |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network Access: Do not allow Anonymous Enumeration of SAM Accounts----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$RestrictAnonymousSAM= Get-Content sec.tmp |Select-String RestrictAnonymousSAM
if (!$RestrictAnonymousSAM) {echo "RestrictAnonymousSAM is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$RestrictAnonymousSAM |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network Access: Do not allow Anonymous Enumeration of SAM Accounts and shares----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$RestrictAnonymous= Get-Content sec.tmp |Select-String RestrictAnonymous
if (!$RestrictAnonymous) {echo "RestrictAnonymous is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$RestrictAnonymous |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network access: Let Everyone permissions apply to anonymous users----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$EveryoneIncludesAnonymous= Get-Content sec.tmp |Select-String EveryoneIncludesAnonymous
if (!$EveryoneIncludesAnonymous) {echo "EveryoneIncludesAnonymous is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$EveryoneIncludesAnonymous |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network access: Named Pipes that can be accessed anonymously----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$NullSessionPipes= Get-Content sec.tmp |Select-String NullSessionPipes
if (!$NullSessionPipes) {echo "NullSessionPipes is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$NullSessionPipes |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network access: Remotely accessible registry paths----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$AllowedExactPaths= Get-Content sec.tmp |Select-String AllowedExactPaths
if (!$AllowedExactPaths) {echo "AllowedExactPaths is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$AllowedExactPaths |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network access: Restrict anonymous access to Named Pipes and Shares----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$restrictnullsessaccess= Get-Content sec.tmp |Select-String restrictnullsessaccess
if (!$restrictnullsessaccess) {echo "restrictnullsessaccess is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$restrictnullsessaccess |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network access: Shares that can be accessed anonymously----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$NullSessionShares= Get-Content sec.tmp |Select-String NullSessionShares
if (!$NullSessionShares) {echo "NullSessionShares is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$NullSessionShares |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network security: Do not store LAN Manager hash value on next password change----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$NoLMHash= Get-Content sec.tmp |Select-String NoLMHash
if (!$NoLMHash) {echo "NoLMHash is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$NoLMHash |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network security: LAN Manager authentication level----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$LmCompatibilityLevel= Get-Content sec.tmp |Select-String LmCompatibilityLevel
if (!$LmCompatibilityLevel) {echo "LmCompatibilityLevel is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$LmCompatibilityLevel |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network security: LDAP client signing requirements----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$LDAPClientIntegrity= Get-Content sec.tmp |Select-String LDAPClientIntegrity
if (!$LDAPClientIntegrity) {echo "LDAPClientIntegrity is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$LDAPClientIntegrity |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Network security: Minimum session security for NTLM SSP based (including secure RPC) clients----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$NTLMMinClientSec= Get-Content sec.tmp |Select-String NTLMMinClientSec
if (!$NTLMMinClientSec) {echo "NTLMMinClientSec is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$NTLMMinClientSec |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Recovery console: Allow automatic administrative logon----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$securitylevel= Get-Content sec.tmp |Select-String securitylevel
if (!$securitylevel) {echo "securitylevel is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$securitylevel |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Recovery console: Allow floppy copy and access to all drives and all folders----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$setcommand= Get-Content sec.tmp |Select-String setcommand
if (!$setcommand) {echo "setcommand is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$setcommand |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Shutdown: Allow system to be shut down without having to log on----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$ShutdownWithoutLogon= Get-Content sec.tmp |Select-String ShutdownWithoutLogon
if (!$ShutdownWithoutLogon) {echo "ShutdownWithoutLogon is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$ShutdownWithoutLogon |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$FIPSAlgorithmPolicy= Get-Content sec.tmp |Select-String FIPSAlgorithmPolicy
if (!$FIPSAlgorithmPolicy) {echo "FIPSAlgorithmPolicy is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$FIPSAlgorithmPolicy |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------System cryptography: Force strong key protection for user keys stored on the computer----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$ForceKeyProtection= Get-Content sec.tmp |Select-String ForceKeyProtection
if (!$ForceKeyProtection) {echo "ForceKeyProtection is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$ForceKeyProtection |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Interactive logon: Do not require CTRL+ALT+DEL----------|" >> $env:COMPUTERNAME-Requirement-2.txt
$DisableCAD= Get-Content sec.tmp |Select-String DisableCAD
if (!$DisableCAD) {echo "DisableCAD is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {$DisableCAD |Out-File $env:COMPUTERNAME-Requirement-2.txt -append}

# Local Drives R2.2.5
Echo "|-----Local Drives R2.2.5:-----|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject win32_logicaldisk |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append

# Shared Folders R2.2.5
Echo "|-----Shared Folders R2.2.5:-----|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-SmbShare |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Packages Installed R2.2.5
Echo "|-----Packages Installed R2.2.5:-----|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-AppxPackage -AllUsers |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Features Installed R2.2.5
Echo "|-----Installed Features R2.2.5:-----|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WindowsFeature |Where-Object {$_.Installstate -eq 'Installed'} |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Drivers Installed R2.2.5
Echo "|-----Drivers Installed R2.2.5:-----|" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WindowsDriver -online -all |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
write-host "Requirement 2: Done"

# SSL,TLS and Cipher Registery Values R4
#************************************************
# DetectCiphersConfig.ps1
# Version 1.0.2
# Date: 9/25/2012
# Author: Tim Springston [MSFT]
# This script checks the local computers registry to see what is configured
#  for cipher and Schannel use. It has been tested with most scenarios and
#  OS versions as of 2014.
# Updates 2/2015 for Windows 8x/2012x compatibility thanks to James Noyce (MSFT).
# Registry items detailed in http://support2.microsoft.com/kb/245030/en-us
#************************************************
Trap [Exception]
		{# Handle exception and throw it to the stdout log file. Then continue with function and script.
		$Script:ExceptionMessage = $_
		Write-Host $ExceptionMessage
		$Error.Clear()
		continue
		}
$global:FormatEnumerationLimit = -1

#Define output file.
$OutputFileName = ("$env:COMPUTERNAME-Requirement-4.txt")

$InformationCollected = new-object PSObject
$OSVersion = Get-WmiObject -Class Win32_OperatingSystem

Function GetPKICipherReg
{	
	$ReturnValues = new-object PSObject
	$Time = Get-Date
	#Do Registry data collection.

	#Ciphers
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128")
		{$RC4128128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128")
		{$AES128128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256")
		{$AES256256Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168")
		{$TripleDES168Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128")
		{$RC456128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56")
		{$DES5656Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128")
		{$RC440128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128")
		{$AES128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256")
		{$AES256Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56")
		{$DES56Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL")
		{$NULLReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"}
	if (Test-path -path Registry::"HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002")
		{$NCRYPTSChannelReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"}
	if (Test-path -path Registry::"HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003")
		{$NCRYPTSChannelSigReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003"}	
	#items below are problematic if enabled or disabled.
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128")
		{$RC240128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128")
		{$RC2128128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"}

	#hashes
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5")
		{$MD5HashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA")
		{$SHAHashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA}

	#Disabling RSA use in KeyExchange PKCS 
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS")
		{$PKCSKeyXReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS}

	#SSL
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client")
			{$PCT1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server")
			{$PCT1ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client")
		{$SSL2ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server")
		{$SSL2ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client")
		{$SSL3ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server")
		{$SSL3ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server"}
	
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client")
		{$TLS1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server")
		{$TLS1ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"}
	
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client")
		{$TLS11ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server")
		{$TLS11ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"}
	
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client")
		{$TLS12ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"}
	if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server")
		{$TLS12ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"}
	


#problem condition equals <regvalname>.enabled -eq 0

	#Begin adding data to PSObject.
	add-member -inputobject $ReturnValues -membertype noteproperty -name "Time" -value $Time
	#If registry values below are populated with specific values then alert the engineer and customer since this will effect SSL/TLS and perhaps other cipher uses.

	if (($FIPSReg.Enabled -ne $null) -or ($PCT1ClientReg.Enabled -eq 0 ) -or ($PCT1ServerReg.Enabled -eq 0 ) -or ($SSL2ClientReg.Enabled -eq 0) -or ($SSL2ServerReg.Enabled -eq 0) -or `
	($SSL3ClientReg.Enabled -eq 0) -or ($SSL3ClientReg.Enabled -eq 0) -or ($SSL3ServerReg.Enabled -eq 0) -or ($MD5HashReg.Enabled -eq 0) -or ($SHAHashReg.Enabled -eq 0) -or ($PKCSKeyXReg.Enabled -eq 0)`
	 -or ($RC4128128Reg.Enabled -eq 0) -or ($AES128128Reg.Enabled -eq 0) -or ($AES256256Reg.Enabled -eq 0) -or ($TripleDES168Reg.Enabled -eq 0) -or ($RC456128Reg.Enabled -eq 0) -or ($DES5656Reg.Enabled -eq 0) `
	 -or ($RC440128Reg.Enabled -eq 0) -or ($AES128Reg.Enabled -eq 0) -or ($AES256Reg.Enabled -eq 0) -or ($NULLReg.Enabled -eq 0) -or ($RC240128Reg.Enabled -ne $null) -or ($DES56Reg.Enabled -eq 0)`
	  -or ($RC2128128Reg.Enabled -ne $null) )
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Customized Settings" -value $true}
			else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Customized Settings" -value $false}
	
	add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL Certificate Etypes Allowed" -value $NCRYPTSChannelReg.Functions
	add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL Certificate Signature Etypes Allowed" -value $NCRYPTSChannelSigReg.Functions
    if ($OSVersion.BuildNumber -eq 3790)
    {
	if (($PCT1ClientReg.Enabled -eq 1) -or ($PCT1ClientReg.Enabled -eq $null))
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Client Setting" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Client Setting" -value "Disabled (NOT default)"}
    if (($PCT1ServerReg.Enabled -eq 1) -or ($PCT1ServerReg.Enabled -eq $null))
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Server Setting" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Server Setting" -value "Disabled (NOT default)"}
    }

    if ($OSVersion.BuildNumber -ge 3790)
    {
	if (($PCT1ClientReg.Enabled -eq 0) -or ($PCT1ClientReg.Enabled -eq $null))
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Client Setting" -value "Disabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Client Setting" -value "Enabled (NOT default)"}
    if (($PCT1ServerReg.Enabled -eq 0) -or ($PCT1ServerReg.Enabled -eq $null))
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Server Setting" -value "Disabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "PCT1 Server Setting" -value "Enabled (NOT default)"}
    }




    if (($SSL2ClientReg.Enabled -eq 1) -or ($SSL2ClientReg.Enabled -eq $null))
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL2 Client Setting" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL2 Client Setting" -value "Disabled (NOT default)"}
    if (($SSL2ServerReg.Enabled -eq 1) -or ($SSL2ServerReg.Enabled -eq $null))
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL2 Server Setting" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL2 Server Setting" -value "Disabled (NOT default)"}
	 if (($SSL3ClientReg.Enabled -eq 1) -or ($SSL3ClientReg.Enabled -eq $null))	
		 {add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL3 Client Setting" -value "Enabled (default)"}
		else
			 {add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL3 Client Setting" -value "Disabled (NOT default) for POODLE"}
	 if (($SSL3ServerReg.Enabled -eq 1) -or ($SSL3ServerReg.Enabled -eq $null))	
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL3 Server Setting" -value "Enabled (default) - POODLE still possible"}
		else
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "SSL3 Server Setting" -value "Disabled (NOT Default) for POODLE"}
	 
    if (($TLS1ClientReg.Enabled -eq 1) -or ($TLS1ClientReg.Enabled -eq $null))	
		 {add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.0 Client Setting" -value "Enabled (default)"}
		else
			 {add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.0 Client Setting" -value "Disabled (NOT default)"}
	 if (($TLS1ServerReg.Enabled -eq 1) -or ($TLS1ServerReg.Enabled -eq $null))	
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.0 Server Setting" -value "Enabled (default)"}
		else
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.0 Server Setting" -value "Disabled (NOT Default)"}
	 
    if (($TLS11ClientReg.Enabled -eq 1) -or ($TLS11ClientReg.Enabled -eq $null))	
		 {add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.1 Client Setting" -value "Enabled (default)"}
		else
			 {add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.1 Client Setting" -value "Disabled (NOT default)"}
	 if (($TLS11ServerReg.Enabled -eq 1) -or ($TLS11ServerReg.Enabled -eq $null))	
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.1 Server Setting" -value "Enabled (default)"}
		else
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.1 Server Setting" -value "Disabled (NOT Default)"}
	 
    if (($TLS12ClientReg.Enabled -eq 1) -or ($TLS12ClientReg.Enabled -eq $null))	
		 {add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.2 Client Setting" -value "Enabled (default)"}
		else
			 {add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.2 Client Setting" -value "Disabled (NOT default)"}
	 if (($TLS12ServerReg.Enabled -eq 1) -or ($TLS12ServerReg.Enabled -eq $null))	
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.2 Server Setting" -value "Enabled (default)"}
		else
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "TLS 1.2 Server Setting" -value "Disabled (NOT Default)"}
    if ($FIPSReg.Enabled -eq 1)	
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "FIPS Setting" -value "Enabled (default)"}
		else
			 {add-member -inputobject $ReturnValues -membertype noteproperty -name "FIPS Setting" -value "Not Enabled (default)"}
	 if (($RC4128128Reg.Enabled -eq 1) -or ($RC4128128Reg.Enabled -eq $null))	
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: RC4 128/128 " -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: RC4 128/128 " -value "Disabled (NOT default)"}

	if (($RC456128Reg.Enabled -eq 1) -or ($RC456128Reg.Enabled -eq $null))		
	{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: RC4 56/128" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: RC4 56/128" -value "Disabled (NOT default)"}

	if (($RC440128Reg.Enabled -eq 1) -or ($RC440128Reg.Enabled -eq $null))		
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: RC4 40/128" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: RC4 40/128" -value "Disabled (NOT default)"}
	
	if ($OSVersion.BuildNumber -ge 6002)
	{
		if (($DES56Reg.Enabled -eq 1) -or ($DES56Reg.Enabled -eq $null))		
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: DES 56" -value "Enabled (default)"}
			else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: DES 56" -value "Disabled (NOT default)"}
		if (($TripleDES168Reg.Enabled -eq 1) -or ($TripleDES168Reg.Enabled -eq $null))	
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: Triple DES 168" -value "Enabled (default)"}
			else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: Triple DES 168" -value "Disabled (NOT default)"}
		if (($AES128Reg.Enabled -eq 1) -or ($AES128Reg.Enabled -eq $null))	
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 128" -value "Enabled (default)"}
			else
				{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 128" -value "Disabled (NOT default)"}
		if (($AES256Reg.Enabled -eq 1) -or ($AES256Reg.Enabled -eq $null))	
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 256" -value "Enabled (default)"}
			else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 256" -value "Disabled (NOT default)"}
		}
	if ($OSVersion.BuildNumber -eq 3790)
	{
	  if (($AES128128Reg.Enabled -eq 1) -or ($AES128128Reg.Enabled -eq $null))		
	  {add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 128/128" -value "Enabled (default)"}
		else
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 128/128" -value "Disabled (NOT default)"}
	  if (($AES256256Reg.Enabled -eq 1) -or ($AES256256Reg.Enabled -eq $null))		
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 256/256" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: AES 256/256" -value "Disabled (NOT default)"}

		if (($DES5656Reg.Enabled -eq 1) -or ($DES5656Reg.Enabled -eq $null))		
		{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: DES 56/56" -value "Enabled (default)"}
			else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Cipher Setting: DES 56/56" -value "Disabled (NOT default)"}
		}
	 
	 #HashReg Values
	 if (($SHAHashReg.Enabled -eq 1) -or ($SHAHashReg.Enabled -eq $null))	
	 	{add-member -inputobject $ReturnValues -membertype noteproperty -name "Secure Hash Algorithm (SHA-1) Use" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "Secure Hash Algorithm (SHA-1) Use" -value "Disabled (NOT default)"}
	 if (($MD5HashReg.Enabled -eq 1) -or ($MD5HashReg.Enabled -eq $null))	
	 	{add-member -inputobject $ReturnValues -membertype noteproperty -name "MD5 Hash Algorithm Use" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "MD5 Hash Algorithm Use" -value "Disabled (NOT default)"}
	 #PKCS Key Exchange use.
	 if (($PKCSKeyXReg.Enabled -eq 1) -or ($PKCSKeyXReg.Enabled -eq $null))	
	 	{add-member -inputobject $ReturnValues -membertype noteproperty -name "RSA Key Exchange Use" -value "Enabled (default)"}
		else
			{add-member -inputobject $ReturnValues -membertype noteproperty -name "RSA Key Exchange Use" -value "Disabled (NOT default)"}

	 return $ReturnValues

}


#Add your logic here to specify on which environments this rule will appy
if ($OSVersion.BuildNumber -ge 3790)
	{
	#Check to see if rule is applicable to this computer
	$InformationCollected = GetPKICipherReg
	}	
	

"SSL, TLS and Cipher Registry Values" | Out-File -Encoding UTF8 -FilePath $OutputFileName -Append
"***************************************" | Out-File -Encoding UTF8 -FilePath $OutputFileName -append
$InformationCollected | Out-File -Encoding UTF8 -FilePath $OutputFileName -append
write-host "Requirement 4: Done"

# OS Version R6.1
echo "|--------------Operating System Version R6.1---------------|" >> $env:COMPUTERNAME-Requirement-6.txt
Get-WmiObject -class win32_operatingsystem |select caption,OSArchitecture |Out-File $env:COMPUTERNAME-Requirement-6.txt -Append
# OS Updates - Service Status R6.2
echo "|--------------OS Updates - Service Status R6.2--------------|" >> $env:COMPUTERNAME-Requirement-6.txt
get-service -DisplayName "windows update" |select DisplayName,Name,Status | Out-File $env:COMPUTERNAME-Requirement-6.txt
# OS Updates - Sources R6.2
echo "|--------------OS Updates - Sources R6.2--------------|" >> $env:COMPUTERNAME-Requirement-6.txt
if (get-childitem -ErrorAction 'silentlycontinue' 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') {get-childitem "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"|Out-File $env:COMPUTERNAME-Requirement-6.txt -append}
else {echo "No Windows Update Server Configured" >> $env:COMPUTERNAME-Requirement-6.txt}
# OS Updates - Patch Status R6.2
echo "|--------------OS Updates - Patch Status R6.2--------------|" >> $env:COMPUTERNAME-Requirement-6.txt
Get-WmiObject -Class win32_quickfixengineering |out-file $env:COMPUTERNAME-Requirement-6.txt -Append
# Last update Success R6.2
echo "|--------------Last update Success R6.2--------------|" >> $env:COMPUTERNAME-Requirement-6.txt
(New-Object -com "Microsoft.Update.AutoUpdate"). Results | fl |out-file $env:COMPUTERNAME-Requirement-6.txt -Append
write-host "Requirement 6: Done"

# Current User Privilege Rights R7.1-7.2
echo "|--------------Current User Priviledge Rights R7.1-7.2--------------|" >> $env:COMPUTERNAME-Requirement-7.txt
whoami /all /fo list | Out-File $env:COMPUTERNAME-Requirement-7.txt -append
# Security Identifiers R7.1-7.2
echo "|--------------Security Identifiers R7.1-7.2--------------|" >> $env:COMPUTERNAME-Requirement-7.txt
Get-WmiObject -class win32_useraccount |select name,sid | Out-File $env:COMPUTERNAME-Requirement-7.txt -append
# Global Privilege Rights R7.1-7.2
echo "|--------------Global Priviledge Rights R7.1-7.2--------------|" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeBatchLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Required for an account to log on using the batch logon type" >> $env:COMPUTERNAME-Requirement-7.txt 
secedit /export /areas USER_RIGHTS /cfg OUTFILE.tmp
$SeBatchLogonRight = Get-Content OUTFILE.tmp |Select-String SeBatchLogonRight
if (!$SeBatchLogonRight) { echo "SeBatchLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeBatchLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeDenyBatchLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Explicitly denies an account the right to log on using the batch logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeDenyBatchLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyBatchLogonRight
if (!$SeDenyBatchLogonRight) { echo "SeDenyBatchLogonRight is not set`n" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeDenyBatchLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeDenyInteractiveLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "Explicitly denies an account the right to log on using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeDenyInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyInteractiveLogonRight
if (!$SeDenyInteractiveLogonRight) { echo "SeDenyInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeDenyInteractiveLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeDenyNetworkLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Explicitly denies an account the right to log on using the network logon type" >> $env:COMPUTERNAME-Requirement-7.txt 
$SeDenyNetworkLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyNetworkLogonRight
if (!$SeDenyNetworkLogonRight) { echo "SeDenyNetworkLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeDenyNetworkLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeDenyRemoteInteractiveLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "Explicitly denies an account the right to log on remotely using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt 
$SeDenyRemoteInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyRemoteInteractiveLogonRight
if (!$SeDenyRemoteInteractiveLogonRight) { echo "SeDenyRemoteInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeDenyRemoteInteractiveLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeDenyServiceLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Explicitly denies an account the right to log on using the service logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeDenyServiceLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyServiceLogonRight
if (!$SeDenyServiceLogonRight) { echo "SeDenyServiceLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeDenyServiceLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeInteractiveLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Required for an account to log on using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeInteractiveLogonRight
if (!$SeInteractiveLogonRight) { echo "SeInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeInteractiveLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeNetworkLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Required for an account to log on using the network logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeNetworkLogonRight = Get-Content OUTFILE.tmp |Select-String SeNetworkLogonRight
if (!$SeNetworkLogonRight) { echo "SeNetworkLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeNetworkLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeRemoteInteractiveLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Required for an account to log on remotely using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeRemoteInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeRemoteInteractiveLogonRight
if (!$SeRemoteInteractiveLogonRight) { echo "SeRemoteInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeRemoteInteractiveLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeServiceLogonRight----------" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Required for an account to log on using the service logon type" >> $env:COMPUTERNAME-Requirement-7.txt
$SeServiceLogonRight = Get-Content OUTFILE.tmp |Select-String SeServiceLogonRight
if (!$SeServiceLogonRight) { echo "SeServiceLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeServiceLogonRight |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt


ECHO "----------------------"  >> $env:COMPUTERNAME-Requirement-7.txt
ECHO "|= Privilege Constants"  >> $env:COMPUTERNAME-Requirement-7.txt
ECHO "----------------------"  >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Replace a process-level token----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeAssignPrimaryTokenPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeAssignPrimaryTokenPrivilege = Get-Content OUTFILE.tmp |Select-String SeAssignPrimaryTokenPrivilege
if (!$SeAssignPrimaryTokenPrivilege) { echo "SeAssignPrimaryTokenPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeAssignPrimaryTokenPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Generate security audits----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeAuditPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeAuditPrivilege = Get-Content OUTFILE.tmp |Select-String SeAuditPrivilege
if (!$SeAuditPrivilege) { echo "SeAuditPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeAuditPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Back up files and directories----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeBackupPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeBackupPrivilege = Get-Content OUTFILE.tmp |Select-String SeBackupPrivilege
if (!$SeBackupPrivilege) { echo "SeBackupPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeBackupPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Bypass traverse checking----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeChangeNotifyPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeChangeNotifyPrivilege = Get-Content OUTFILE.tmp |Select-String SeChangeNotifyPrivilege
if (!$SeChangeNotifyPrivilege) { echo "SeChangeNotifyPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeChangeNotifyPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Create global objects----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeCreateGlobalPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeCreateGlobalPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreateGlobalPrivilege
if (!$SeCreateGlobalPrivilege) { echo "SeCreateGlobalPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeCreateGlobalPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Create a pagefile----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeCreatePagefilePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeCreatePagefilePrivilege = Get-Content OUTFILE.tmp |Select-String SeCreatePagefilePrivilege
if (!$SeCreatePagefilePrivilege) { echo "SeCreatePagefilePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeCreatePagefilePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Create permanent shared objects----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeCreatePermanentPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeCreatePermanentPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreatePermanentPrivilege
if (!$SeCreatePermanentPrivilege) { echo "SeCreatePermanentPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeCreatePermanentPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Create symbolic links----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeCreateSymbolicLinkPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeCreateSymbolicLinkPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreateSymbolicLinkPrivilege
if (!$SeCreateSymbolicLinkPrivilege) { echo "SeCreateSymbolicLinkPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeCreateSymbolicLinkPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Create a token object----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeCreateTokenPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeCreateTokenPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreateTokenPrivilege
if (!$SeCreateTokenPrivilege) { echo "SeCreateTokenPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeCreateTokenPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Debug programs----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeDebugPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeDebugPrivilege = Get-Content OUTFILE.tmp |Select-String SeDebugPrivilege
if (!$SeDebugPrivilege) { echo "SeDebugPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeDebugPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Enable computer and user accounts to be trusted for delegation----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeEnableDelegationPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeEnableDelegationPrivilege = Get-Content OUTFILE.tmp |Select-String SeEnableDelegationPrivilege
if (!$SeEnableDelegationPrivilege) { echo "SeEnableDelegationPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeEnableDelegationPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Impersonate a client after authentication----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeImpersonatePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeImpersonatePrivilege = Get-Content OUTFILE.tmp |Select-String SeImpersonatePrivilege
if (!$SeImpersonatePrivilege) { echo "SeImpersonatePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeImpersonatePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Increase scheduling priority----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeIncreaseBasePriorityPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeIncreaseBasePriorityPrivilege = Get-Content OUTFILE.tmp |Select-String SeIncreaseBasePriorityPrivilege
if (!$SeIncreaseBasePriorityPrivilege) { echo "SeIncreaseBasePriorityPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeIncreaseBasePriorityPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Adjust memory quotas for a process----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeIncreaseQuotaPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeIncreaseQuotaPrivilege = Get-Content OUTFILE.tmp |Select-String SeIncreaseQuotaPrivilege
if (!$SeIncreaseQuotaPrivilege) { echo "SeIncreaseQuotaPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeIncreaseQuotaPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Increase a process working set----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeIncreaseWorkingSetPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeIncreaseWorkingSetPrivilege = Get-Content OUTFILE.tmp |Select-String SeIncreaseWorkingSetPrivilege
if (!$SeIncreaseWorkingSetPrivilege) { echo "SeIncreaseWorkingSetPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeIncreaseWorkingSetPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Load and unload device drivers----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeLoadDriverPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeLoadDriverPrivilege = Get-Content OUTFILE.tmp |Select-String SeLoadDriverPrivilege
if (!$SeLoadDriverPrivilege) { echo "SeLoadDriverPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeLoadDriverPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Lock pages in memory----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeLockMemoryPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeLockMemoryPrivilege = Get-Content OUTFILE.tmp |Select-String SeLockMemoryPrivilege
if (!$SeLockMemoryPrivilege) { echo "SeLockMemoryPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeLockMemoryPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Add workstations to domain----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeMachineAccountPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeMachineAccountPrivilege = Get-Content OUTFILE.tmp |Select-String SeMachineAccountPrivilege
if (!$SeMachineAccountPrivilege) { echo "SeMachineAccountPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeMachineAccountPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Manage the files on a volume----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeManageVolumePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeManageVolumePrivilege = Get-Content OUTFILE.tmp |Select-String SeManageVolumePrivilege
if (!$SeManageVolumePrivilege) { echo "SeManageVolumePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeManageVolumePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Profile single process----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeProfileSingleProcessPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeProfileSingleProcessPrivilege = Get-Content OUTFILE.tmp |Select-String SeProfileSingleProcessPrivilege
if (!$SeProfileSingleProcessPrivilege) { echo "SeProfileSingleProcessPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeProfileSingleProcessPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Modify an object label----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeRelabelPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeRelabelPrivilege = Get-Content OUTFILE.tmp |Select-String SeRelabelPrivilege
if (!$SeRelabelPrivilege) { echo "SeRelabelPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeRelabelPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Force shutdown from a remote system----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeRemoteShutdownPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeRemoteShutdownPrivilege = Get-Content OUTFILE.tmp |Select-String SeRemoteShutdownPrivilege
if (!$SeRemoteShutdownPrivilege) { echo "SeRemoteShutdownPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeRemoteShutdownPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Restore files and directories----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeRestorePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeRestorePrivilege = Get-Content OUTFILE.tmp |Select-String SeRestorePrivilege
if (!$SeRestorePrivilege) { echo "SeRestorePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeRestorePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Manage auditing and security log----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeSecurityPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeSecurityPrivilege = Get-Content OUTFILE.tmp |Select-String SeSecurityPrivilege
if (!$SeSecurityPrivilege) { echo "SeSecurityPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeSecurityPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Shut down the system----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeShutdownPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeShutdownPrivilege = Get-Content OUTFILE.tmp |Select-String SeShutdownPrivilege
if (!$SeShutdownPrivilege) { echo "SeShutdownPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeShutdownPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Synchronize directory service data----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeSyncAgentPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeSyncAgentPrivilege = Get-Content OUTFILE.tmp |Select-String SeSyncAgentPrivilege
if (!$SeSyncAgentPrivilege) { echo "SeSyncAgentPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeSyncAgentPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Modify firmware environment values----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeSystemEnvironmentPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeSystemEnvironmentPrivilege = Get-Content OUTFILE.tmp |Select-String SeSystemEnvironmentPrivilege
if (!$SeSystemEnvironmentPrivilege) { echo "SeSystemEnvironmentPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeSystemEnvironmentPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Profile system performance----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeSystemProfilePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeSystemProfilePrivilege = Get-Content OUTFILE.tmp |Select-String SeSystemProfilePrivilege
if (!$SeSystemProfilePrivilege) { echo "SeSystemProfilePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeSystemProfilePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Change the system time----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeSystemtimePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeSystemtimePrivilege = Get-Content OUTFILE.tmp |Select-String SeSystemtimePrivilege
if (!$SeSystemtimePrivilege) { echo "SeSystemtimePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeSystemtimePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Take ownership of files or other objects----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeTakeOwnershipPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeTakeOwnershipPrivilege = Get-Content OUTFILE.tmp |Select-String SeTakeOwnershipPrivilege
if (!$SeTakeOwnershipPrivilege) { echo "SeTakeOwnershipPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeTakeOwnershipPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Act as part of the operating system----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeTcbPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeTcbPrivilege = Get-Content OUTFILE.tmp |Select-String SeTcbPrivilege
if (!$SeTcbPrivilege) { echo "SeTcbPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeTcbPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Change the time zone----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeTimeZonePrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeTimeZonePrivilege = Get-Content OUTFILE.tmp |Select-String SeTimeZonePrivilege
if (!$SeTimeZonePrivilege) { echo "SeTimeZonePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeTimeZonePrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Access Credential Manager as a trusted caller----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeTrustedCredManAccessPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeTrustedCredManAccessPrivilege = Get-Content OUTFILE.tmp |Select-String SeTrustedCredManAccessPrivilege
if (!$SeTrustedCredManAccessPrivilege) { echo "SeTrustedCredManAccessPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeTrustedCredManAccessPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Remove computer from docking station----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeUndockPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeUndockPrivilege = Get-Content OUTFILE.tmp |Select-String SeUndockPrivilege
if (!$SeUndockPrivilege) { echo "SeUndockPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeUndockPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

Echo "----------Required to read unsolicited input from a terminal device----------"  >> $env:COMPUTERNAME-Requirement-7.txt
Echo "----------SeUnsolicitedInputPrivilege----------" >> $env:COMPUTERNAME-Requirement-7.txt
$SeUnsolicitedInputPrivilege = Get-Content OUTFILE.tmp |Select-String SeUnsolicitedInputPrivilege
if (!$SeUnsolicitedInputPrivilege) { echo "SeUnsolicitedInputPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {Get-Content OUTFILE.tmp |Select-String SeUnsolicitedInputPrivilege |out-file $env:COMPUTERNAME-Requirement-7.txt -append }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

write-host "Requirement 7: Done"

# Enabled Local Accounts R8.1.4
Echo "----------Enabled Local Accounts R8.1.4----------" >> $env:COMPUTERNAME-Requirement-8.txt
Get-WmiObject -class win32_useraccount -filter "disabled='false'" |Select Name |Out-File $env:COMPUTERNAME-Requirement-8.txt -append
# Disabled Local accounts R8.1.4
Echo "----------Disabled Local Accounts R8.1.4----------" >> $env:COMPUTERNAME-Requirement-8.txt
Get-WmiObject -class win32_useraccount -filter "disabled='True'" |Select Name |Out-File $env:COMPUTERNAME-Requirement-8.txt -append
# Account Lockout R8.1.6
Echo "----------Account Lockout Threshold R8.1.6----------" >> $env:COMPUTERNAME-Requirement-8.txt
net accounts >>accounts.tmp
Get-Content accounts.tmp |Select-String "lockout threshold:" |Out-File $env:COMPUTERNAME-Requirement-8.txt -append
# Account Lockout Duration R8.1.7
Echo "----------Account Lockout Duration R8.1.7----------" >> $env:COMPUTERNAME-Requirement-8.txt
Get-Content accounts.tmp |Select-String "lockout duration" |Out-File $env:COMPUTERNAME-Requirement-8.txt -append

# Session Timeout R8.1.8
echo "----------Session timeout R8.1.8----------" >> $env:COMPUTERNAME-Requirement-8.txt
REG export "HKCU\Control Panel\Desktop" screen.tmp
Echo "ScreenSaveActive Check:" >> $env:COMPUTERNAME-Requirement-8.txt
$Screensaveactive= Get-Content screen.tmp |Select-String ScreenSaveActive
if (!$Screensaveactive) {Echo "ScreenSaveActive is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string ScreenSaveActive |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
Echo "ScreenSaveTimeout Check:" >> $env:COMPUTERNAME-Requirement-8.txt

$screensavetimeout= Get-Content screen.tmp |Select-String screensavetimeout
if (!$screensavetimeout) {Echo "screensavetimeout is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string screensavetimeout |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
Echo "ScreenSaveSecure Check:" >> $env:COMPUTERNAME-Requirement-8.txt

$screensavesecure= Get-Content screen.tmp |Select-String screensavesecure
if (!$screensavesecure) {Echo "screensavesecure is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string screensavesecure |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
Echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Password Store Configuration R8.2.1
echo "----------Password Store Configuration R8.2.1----------" >> $env:COMPUTERNAME-Requirement-8.txt
echo "ClearTextPassword Check:" >> $env:COMPUTERNAME-Requirement-8.txt
$ClearTextPassword= Get-Content screen.tmp |Select-String ClearTextPassword
if (!$ClearTextPassword) {Echo "ClearTextPassword is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string ClearTextPassword |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Password Length R8.2.3
echo "----------Password Length R8.2.3----------" >> $env:COMPUTERNAME-Requirement-8.txt
echo "MinimumPasswordLength Check:" >> $env:COMPUTERNAME-Requirement-8.txt
$MinimumPasswordLength= Get-Content screen.tmp |Select-String MinimumPasswordLength
if (!$MinimumPasswordLength) {Echo "MinimumPasswordLength is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string MinimumPasswordLength |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Password Complexity R8.2.3
echo "----------Password Complexity R8.2.3----------" >> $env:COMPUTERNAME-Requirement-8.txt
echo "PasswordComplexity Check:" >> $env:COMPUTERNAME-Requirement-8.txt
$PasswordComplexity= Get-Content screen.tmp |Select-String PasswordComplexity
if (!$PasswordComplexity) {Echo "PasswordComplexity is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string PasswordComplexity |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Password Change Threshold R8.2.4
echo "----------Password Change Threshold R8.2.4----------" >> $env:COMPUTERNAME-Requirement-8.txt
echo "MaximumPasswordAge Check:" >> $env:COMPUTERNAME-Requirement-8.txt
$MaximumPasswordAge= Get-Content screen.tmp |Select-String MaximumPasswordAge
if (!$MaximumPasswordAge) {Echo "MaximumPasswordAge is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string MaximumPasswordAge |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Password History R8.2.5
echo "----------Password History R8.2.5----------" >> $env:COMPUTERNAME-Requirement-8.txt
echo "PasswordHistorySize Check:" >> $env:COMPUTERNAME-Requirement-8.txt
$PasswordHistorySize= Get-Content screen.tmp |Select-String PasswordHistorySize
if (!$PasswordHistorySize) {Echo "PasswordHistorySize is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {Get-Content screen.tmp |select-string PasswordHistorySize |out-file $env:COMPUTERNAME-Requirement-8.txt -append}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Local Accounts R8.5
echo "----------Local Accounts R8.5----------" >> $env:COMPUTERNAME-Requirement-8.txt
Get-wmiobject -Class win32_useraccount |select name | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Local Administrators R8.5
echo "----------Local Administrators R8.5----------" >> $env:COMPUTERNAME-Requirement-8.txt
$group=Get-WmiObject win32_group -Filter "name='Administrators'"
$group.getrelated("win32_useraccount") |select Name | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Local Administrator Status R8.5
echo "----------Local Administrator Status R8.5----------" >> $env:COMPUTERNAME-Requirement-8.txt
$group=Get-WmiObject win32_group -Filter "name='Administrators'"
$group.getrelated("win32_useraccount") |select name,status | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
echo "" >> $env:COMPUTERNAME-Requirement-8.txt

# Local Groups R8.5
echo "----------Local Groups R8.5----------" >> $env:COMPUTERNAME-Requirement-8.txt
Get-WmiObject -Class win32_group |select name | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append

write-host "Requirement 8: Done"

Echo "|----------Event Log - Service Status  R10.2-10.3----------|" >> $env:COMPUTERNAME-Requirement-10.txt
Get-Service -Name EventLog |Out-File $env:COMPUTERNAME-Requirement-10.txt -append

Echo "|----------Log Configuration R10.2-10.3----------|" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "|-----Audit System Events-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditSystemEvents= Get-Content sec.tmp |Select-String AuditSystemEvents
if (!$AuditSystemEvents) {Echo "AuditSystemEvents is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditSystemEvents -ne 3) {$AuditSystemEvents |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditSystemEvents' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditSystemEvents |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditSystemEvents' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Logon Events-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditLogonEvents= Get-Content sec.tmp |Select-String AuditLogonEvents
if (!$AuditLogonEvents) {Echo "AuditLogonEvents is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditLogonEvents -ne 3) {$AuditLogonEvents |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditLogonEvents' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditLogonEvents |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditLogonEvents' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Object Status-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditObjectAccess= Get-Content sec.tmp |Select-String AuditObjectAccess
if (!$AuditObjectAccess) {Echo "AuditObjectAccess is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditObjectAccess -ne 3) {$AuditObjectAccess |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditObjectAccess' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditObjectAccess |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditObjectAccess' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Priviledge use-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditPrivilegeUse= Get-Content sec.tmp |Select-String AuditPrivilegeUse
if (!$AuditPrivilegeUse) {Echo "AuditPrivilegeUse is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditPrivilegeUse -ne 3) {$AuditPrivilegeUse |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditPrivilegeUse' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditPrivilegeUse |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditPrivilegeUse' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Policy Change-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditPolicyChange= Get-Content sec.tmp |Select-String AuditPolicyChange
if (!$AuditPolicyChange) {Echo "AuditPolicyChange is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditPolicyChange -ne 3) {$AuditPolicyChange |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditPolicyChange' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditPolicyChange |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditPolicyChange' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Account Manage-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditAccountManage= Get-Content sec.tmp |Select-String AuditAccountManage
if (!$AuditAccountManage) {Echo "AuditAccountManages is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditAccountManage -ne 3) {$AuditAccountManage |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditAccountManage' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditAccountManage |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditAccountManage' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Process Tracking-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditProcessTracking= Get-Content sec.tmp |Select-String AuditProcessTracking
if (!$AuditProcessTracking) {Echo "AuditProcessTracking is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditProcessTracking -ne 3) {$AuditProcessTracking |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditProcessTracking' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditProcessTracking |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditProcessTracking' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit DS Access-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditDSAccess= Get-Content sec.tmp |Select-String AuditDSAccess
if (!$AuditDSAccess) {Echo "AuditDSAccess is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditDSAccess -ne 3) {$AuditDSAccess |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditDSAccess' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditDSAccess |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditDSAccess' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "|-----Audit Account Logon-----|" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditAccountLogon= Get-Content sec.tmp |Select-String AuditAccountLogon
if (!$AuditAccountLogon) {Echo "AuditAccountLogon is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditAccountLogon -ne 3) {$AuditAccountLogon |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditAccountLogon' does not meet with Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt
        } else {$AuditAccountLogon |out-file $env:COMPUTERNAME-Requirement-10.txt -append; echo "Variable 'AuditAccountLogon' complies with PCI DSS Req. 10.2 - 10.3" >> $env:COMPUTERNAME-Requirement-10.txt}
}
Echo ""
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "|----------Log Policies R10.2-10.3----------|" >> $env:COMPUTERNAME-Requirement-10.txt
auditpol /get /category:* >> $env:COMPUTERNAME-Requirement-10.txt

Echo "|----------NTP - Service Status R10.4----------|" >> $env:COMPUTERNAME-Requirement-10.txt
Get-Service -name W32Time | Out-File $env:COMPUTERNAME-Requirement-10.txt -append

Echo "|----------NTP Configuration R10.4.3----------|" >> $env:COMPUTERNAME-Requirement-10.txt
$timestatus=get-service -Name w32time 
if ($timestatus.status -eq "Stopped") {Echo "WARNING!: W32Time Service is Not running" >> $env:COMPUTERNAME-Requirement-10.txt
} else {echo "w32tm Status" >> $env:COMPUTERNAME-Requirement-10.txt; w32tm /query /status |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append;echo "w32tm configuration" >> $env:COMPUTERNAME-Requirement-10.txt;w32tm /query /Configuration|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append }

Echo "|----------Log DACL Permissions R10.5.1-10.5.2----------|" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "|-----Application Event Log DACL-----|:" >> $env:COMPUTERNAME-Requirement-10.txt
get-acl $env:systemroot\system32\winevt\logs\Application.evtx |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
get-acl $env:systemroot\system32\winevt\logs\Application.evtx |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
Echo "|-----Security Event Log DACL-----|:" >> $env:COMPUTERNAME-Requirement-10.txt
get-acl $env:systemroot\System32\Config\SecEvent.Evt |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
get-acl $env:systemroot\system32\winevt\logs\Security.evtx |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
Echo "|-----System Event Log DACL-----|:" >> $env:COMPUTERNAME-Requirement-10.txt
get-acl $env:systemroot\System32\Config\SysEvent.Evt |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
get-acl $env:systemroot\system32\winevt\logs\System.evtx |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append


del sec.tmp
del OUTFILE.tmp
del accounts.tmp
del screen.tmp
write-host "Requirement 10: Done"
Write-Host "Finished"