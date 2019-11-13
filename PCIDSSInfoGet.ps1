# This Script is used to gather information for the purpose of PCI Compliance
# Author: Matthew Hanson
# Script will drop information into separate txt Files respective
# of their PCI Requirement section
$ErrorActionPreference= 'silentlycontinue'
write-host "Getting Information: Please wait" 
# System Information
systeminfo |Out-File $env:COMPUTERNAME-SystemInfo.txt -Append
write-host "System Info: Done"
echo "|----------Requirement 1----------|" >> $env:COMPUTERNAME-Requirement-1.txt
try {
$adserver1= (Get-ADComputer -Filter {OperatingSystem -Like "*server*"}).DNSHostName  -join ", "
}
catch {}
$admachines= ([adsisearcher]“objectcategory=computer”).findall()
if ($adserver1) {Add-Content -Path $env:COMPUTERNAME-Requirement-1.txt -value "Servers Listed in the domain= $adserver1 "}
    elseif ($admachines) {echo "List of Servers Connected to the Domain:" >> $env:COMPUTERNAME-Requirement-1.txt; $admachines |out-file $env:COMPUTERNAME-Requirement-1.txt -append}
    else {echo "Cannot get Server list from Domain." >> $env:COMPUTERNAME-Requirement-1.txt}
Echo "|-----Requirement 1.4-----| " >> $env:COMPUTERNAME-Requirement-1.txt
Echo "-Active Directory Status=" >> $env:COMPUTERNAME-Requirement-1.txt
(Get-WmiObject -class win32_computersystem).Domain |Out-File $env:COMPUTERNAME-Requirement-1.txt -append


echo "-Firewall Status=" >> $env:COMPUTERNAME-Requirement-1.txt
Get-Service -DisplayName "*firewall*" |Select DisplayName,Name,Status |out-file $env:COMPUTERNAME-Requirement-1.txt -Append


echo "-Firewall Configuration=" >> $env:COMPUTERNAME-Requirement-1.txt
Get-NetFirewallProfile -All | Out-File $env:COMPUTERNAME-Requirement-1.txt -Append
Get-NetFirewallSetting -All | Out-File $env:COMPUTERNAME-Requirement-1.txt -Append

echo "-Inbound Firewall Rules=" >> $env:COMPUTERNAME-Requirement-1.txt
Get-NetFirewallRule -All |Where-Object{$_.Direction -eq "Inbound"} |Out-File $env:COMPUTERNAME-Requirement-1.txt -Append
echo "-Outbound Firewall Rules=" >> $env:COMPUTERNAME-Requirement-1.txt
Get-NetFirewallRule -All |Where-Object{$_.Direction -eq "Inbound"} |Out-File $env:COMPUTERNAME-Requirement-1.txt -Append
write-host "Requirement 1: Done"

"|-----Requirement 2.1-----|" >> $env:COMPUTERNAME-Requirement-2.txt
echo "-User Accounts=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject -class win32_useraccount |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
#default users enabled?Disabled?

echo "-Default User accounts that are Enabled=" >> $env:COMPUTERNAME-Requirement-2.txt
$useraccount1= (Get-WmiObject -class win32_useraccount -filter "disabled='False'" | Where-Object {($_.name -eq "Guest") -or ($_.name -eq "Administrator")}).name
if (!$useraccount1) {echo "None" >> $env:COMPUTERNAME-Requirement-2.txt}
 else {$useraccount1 | Out-File $env:COMPUTERNAME-Requirement-2.txt -Append}
Echo ""  >> $env:COMPUTERNAME-Requirement-2.txt
echo "-Default User accounts that are Disabled=" >> $env:COMPUTERNAME-Requirement-2.txt
$useraccount2= (Get-WmiObject -class win32_useraccount -filter "disabled='True'" | Where-Object {($_.name -eq "Guest") -or ($_.name -eq "Administrator")}).name
if (!$useraccount2) {echo "None" >> $env:COMPUTERNAME-Requirement-2.txt}
 else {$useraccount2 | Out-File $env:COMPUTERNAME-Requirement-2.txt -Append}
Echo ""  >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|-----Requirement 2.2-----|" >> $env:COMPUTERNAME-Requirement-2.txt
echo "-Installed Software=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table –AutoSize |Out-File $env:COMPUTERNAME-Requirement-2.txt -append

Echo "-Running Services=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-Service |Where-Object {$_.Status -EQ "running"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -append

Echo "-Stopped Services=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-Service |Where-Object {$_.Status -EQ "Stopped"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append

echo "-Running Processes=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-Process |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append

Echo "-Network Connections=" >> $env:COMPUTERNAME-Requirement-2.txt
netstat -na |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append

echo "" >> $env:COMPUTERNAME-Requirement-2.txt
echo "-IPv6 Support=" >> $env:COMPUTERNAME-Requirement-2.txt
$IPV6 = $false
$arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress

foreach ($i in $arrInterfaces) {$IPV6 = $IPV6 -or $i.contains(":")} 

Echo "IPv6 Enabled=$IPV6" |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
# MISC Security Settings R2.2.4
Echo "-----Misc Security Settings-----" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "-Accounts: Administrator Account Status=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject -class win32_useraccount |select Name,Disabled,Status |Where-Object {$_.Name -eq "Administrator"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -append

Echo "-Accounts: Guest Account Status=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject -class win32_useraccount |select Name,Disabled,Status |Where-Object {$_.Name -eq "Guest"} |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
#-- List New Admin Names--

Echo "-Current Administrators=" >> $env:COMPUTERNAME-Requirement-2.txt
$group=Get-WmiObject win32_group -Filter "name='Administrators'"
$group.getrelated("win32_useraccount") |Out-File $env:COMPUTERNAME-Requirement-2.txt -append

Echo "-Current Guest Accounts=" >> $env:COMPUTERNAME-Requirement-2.txt
$group=Get-WmiObject win32_group -Filter "name='Guests'"
$group.getrelated("win32_useraccount") |Out-File $env:COMPUTERNAME-Requirement-2.txt -append

secedit /export /cfg sec.tmp /quiet
Echo "-Accounts: Limit local account use of blank passwords to console logon only=" >> $env:COMPUTERNAME-Requirement-2.txt
$LimitBlankPasswordUse= Get-Content sec.tmp |Select-String LimitBlankPasswordUse
if (!$LimitBlankPasswordUse) {echo "LimitBlankPasswordUse is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $LimitBlankPasswordUse}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Devices: Allowed to format and eject removable media=" >> $env:COMPUTERNAME-Requirement-2.txt
$AllocateDASD= Get-Content sec.tmp |Select-String AllocateDASD
if (!$AllocateDASD) {echo "AllocateDASD is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $AllocateDASD}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Devices: Prevent users from installing printer drivers=" >> $env:COMPUTERNAME-Requirement-2.txt
$AddPrinterDrivers= Get-Content sec.tmp |Select-String AddPrinterDrivers
if (!$AddPrinterDrivers) {echo "AddPrinterDrivers is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $AddPrinterDrivers}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Devices: Restrict CD-ROM access to locally logged-on user only==" >> $env:COMPUTERNAME-Requirement-2.txt
$AllocateCDRoms= Get-Content sec.tmp |Select-String AllocateCDRoms
if (!$AllocateCDRoms) {echo "AllocateCDRoms is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $AllocateCDRoms}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Devices: Restrict floppy access to locally logged-on user only=" >> $env:COMPUTERNAME-Requirement-2.txt
$AllocateFloppies= Get-Content sec.tmp |Select-String AllocateFloppies
if (!$AllocateFloppies) {echo "AllocateFloppiese is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $AllocateFloppies}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Domain member: Digitally encrypt or sign secure channel data (always)=" >> $env:COMPUTERNAME-Requirement-2.txt
$requiresignorseal= Get-Content sec.tmp |Select-String requiresignorseal
if (!$requiresignorseal) {echo "requiresignorseal is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $requiresignorseal}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Domain member: Digitally encrypt secure channel data (when possible)=" >> $env:COMPUTERNAME-Requirement-2.txt
$sealsecurechannel= Get-Content sec.tmp |Select-String sealsecurechannel
if (!$sealsecurechannel) {echo "sealsecurechannel is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $sealsecurechannel}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Domain member: Disable machine account password changes=" >> $env:COMPUTERNAME-Requirement-2.txt
$disablepasswordchange= Get-Content sec.tmp |Select-String disablepasswordchange
if (!$disablepasswordchange) {echo "disablepasswordchange is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $disablepasswordchange}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Domain member: Maximum machine account password age=" >> $env:COMPUTERNAME-Requirement-2.txt
$maximumpasswordage= Get-Content sec.tmp |Select-String -SimpleMatch Parameters\maximumpasswordage
if (!$maximumpasswordage) {echo "Parameters\maximumpasswordage is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $maximumpasswordage}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Domain member: Require strong (Windows 2000 or later) session key=" >> $env:COMPUTERNAME-Requirement-2.txt
$requirestrongkey= Get-Content sec.tmp |Select-String requirestrongkey
if (!$requirestrongkey) {echo "requirestrongkey is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $requirestrongkey}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

echo "-Interactive logon: Do not display last user name=" >> $env:COMPUTERNAME-Requirement-2.txt
$DontDisplayLastUserName= Get-Content sec.tmp |Select-String DontDisplayLastUserName
if (!$DontDisplayLastUserName) {echo "DontDisplayLastUserName is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $DontDisplayLastUserName}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Interactive logon: Number of previous logons to cache (in case domain controller is not available)=" >> $env:COMPUTERNAME-Requirement-2.txt
$cachedlogonscount= Get-Content sec.tmp |Select-String cachedlogonscount
if (!$cachedlogonscount) {echo "cachedlogonscount is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $cachedlogonscount}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Interactive logon: Prompt user to change password before expiration=" >> $env:COMPUTERNAME-Requirement-2.txt
$passwordexpirywarning= Get-Content sec.tmp |Select-String passwordexpirywarning
if (!$passwordexpirywarning) {echo "passwordexpirywarning is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $passwordexpirywarning}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Interactive logon: Require Domain Controller authentication to unlock workstation=" >> $env:COMPUTERNAME-Requirement-2.txt
$ForceUnlockLogon= Get-Content sec.tmp |Select-String ForceUnlockLogon
if (!$ForceUnlockLogon) {echo "ForceUnlockLogon is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $ForceUnlockLogon}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Interactive logon: Message title for users attempting to log on=" >> $env:COMPUTERNAME-Requirement-2.txt
$LegalNoticeCaption= Get-Content sec.tmp |Select-String LegalNoticeCaption
if (!$LegalNoticeCaption) {echo "LegalNoticeCaption is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $LegalNoticeCaption}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Interactive logon: Message text for users attempting to log on=" >> $env:COMPUTERNAME-Requirement-2.txt
$LegalNoticeText= Get-Content sec.tmp |Select-String LegalNoticeText
if (!$LegalNoticeText) {echo "LegalNoticeText is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $LegalNoticeText}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network client: Digitally sign communications (always)=" >> $env:COMPUTERNAME-Requirement-2.txt
$RequireSecuritySignature= Get-Content sec.tmp |Select-String -simplematch LanmanWorkstation\Parameters\RequireSecuritySignature
if (!$RequireSecuritySignature) {echo "LanmanWorkstation\Parameters\RequireSecuritySignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $RequireSecuritySignature}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network client: Digitally sign communications (if server agrees)=" >> $env:COMPUTERNAME-Requirement-2.txt
$EnableSecuritySignature= Get-Content sec.tmp |Select-String -SimpleMatch LanmanWorkstation\Parameters\EnableSecuritySignature
if (!$EnableSecuritySignature) {echo "LanmanWorkstation\Parameters\EnableSecuritySignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $EnableSecuritySignature}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network client: Send unencrypted password to third-party SMB servers=" >> $env:COMPUTERNAME-Requirement-2.txt
$EnablePlainTextPassword= Get-Content sec.tmp |Select-String -simplematch LanmanWorkstation\Parameters\EnablePlainTextPassword
if (!$EnablePlainTextPassword) {echo "LanmanWorkstation\Parameters\EnablePlainTextPassword is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $EnablePlainTextPassword}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network server: Amount of idle time required before suspending session=" >> $env:COMPUTERNAME-Requirement-2.txt
$autodisconnect= Get-Content sec.tmp |Select-String -simplematch LanManServer\Parameters\autodisconnect
if (!$autodisconnect) {echo "LanManServer\Parameters\autodisconnect is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $autodisconnect}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network server: Digitally sign communications (always)=" >> $env:COMPUTERNAME-Requirement-2.txt
$requiresecuritysignature= Get-Content sec.tmp |Select-String -simplematch LanManServer\Parameters\requiresecuritysignature
if (!$requiresecuritysignature) {echo "LanManServer\Parameters\requiresecuritysignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $requiresecuritysignature}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network server: Digitally sign communications (if client agrees)=" >> $env:COMPUTERNAME-Requirement-2.txt
$enablesecuritysignature= Get-Content sec.tmp |Select-String -SimpleMatch LanManServer\Parameters\enablesecuritysignature
if (!$enablesecuritysignature) {echo "LanManServer\Parameters\enablesecuritysignature is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $enablesecuritysignature}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Microsoft network server: Disconnect clients when logon hours expire=" >> $env:COMPUTERNAME-Requirement-2.txt
$enableforcedlogoff= Get-Content sec.tmp |Select-String -SimpleMatch LanManServer\Parameters\enableforcedlogoff
if (!$enableforcedlogoff) {echo "LanManServer\Parameters\enableforcedlogoff is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $enableforcedlogoff}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network Access: Allow Anonymous SID\Name Translation=" >> $env:COMPUTERNAME-Requirement-2.txt
$LSAAnonymousNameLookup= Get-Content sec.tmp |Select-String LSAAnonymousNameLookup
if (!$LSAAnonymousNameLookup) {echo "LSAAnonymousNameLookup is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $LSAAnonymousNameLookup}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network Access: Do not allow Anonymous Enumeration of SAM Accounts=" >> $env:COMPUTERNAME-Requirement-2.txt
$RestrictAnonymousSAM= Get-Content sec.tmp |Select-String RestrictAnonymousSAM
if (!$RestrictAnonymousSAM) {echo "RestrictAnonymousSAM is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $RestrictAnonymousSAM}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network Access: Do not allow Anonymous Enumeration of SAM Accounts and shares=" >> $env:COMPUTERNAME-Requirement-2.txt
$RestrictAnonymous= Get-Content sec.tmp |Select-String RestrictAnonymous
if (!$RestrictAnonymous) {echo "RestrictAnonymous is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $RestrictAnonymous}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network access: Let Everyone permissions apply to anonymous users=" >> $env:COMPUTERNAME-Requirement-2.txt
$EveryoneIncludesAnonymous= Get-Content sec.tmp |Select-String EveryoneIncludesAnonymous
if (!$EveryoneIncludesAnonymous) {echo "EveryoneIncludesAnonymous is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $EveryoneIncludesAnonymous}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network access: Named Pipes that can be accessed anonymously=" >> $env:COMPUTERNAME-Requirement-2.txt
$NullSessionPipes= Get-Content sec.tmp |Select-String NullSessionPipes
if (!$NullSessionPipes) {echo "NullSessionPipes is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $NullSessionPipes}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network access: Remotely accessible registry paths=" >> $env:COMPUTERNAME-Requirement-2.txt
$AllowedExactPaths= Get-Content sec.tmp |Select-String AllowedExactPaths
if (!$AllowedExactPaths) {echo "AllowedExactPaths is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $AllowedExactPaths}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network access: Restrict anonymous access to Named Pipes and Shares=" >> $env:COMPUTERNAME-Requirement-2.txt
$restrictnullsessaccess= Get-Content sec.tmp |Select-String restrictnullsessaccess
if (!$restrictnullsessaccess) {echo "restrictnullsessaccess is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $restrictnullsessaccess}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network access: Shares that can be accessed anonymously=" >> $env:COMPUTERNAME-Requirement-2.txt
$NullSessionShares= Get-Content sec.tmp |Select-String NullSessionShares
if (!$NullSessionShares) {echo "NullSessionShares is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $NullSessionShares}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network security: Do not store LAN Manager hash value on next password change=" >> $env:COMPUTERNAME-Requirement-2.txt
$NoLMHash= Get-Content sec.tmp |Select-String NoLMHash
if (!$NoLMHash) {echo "NoLMHash is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $NoLMHash}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network security: LAN Manager authentication level=" >> $env:COMPUTERNAME-Requirement-2.txt
$LmCompatibilityLevel= Get-Content sec.tmp |Select-String LmCompatibilityLevel
if (!$LmCompatibilityLevel) {echo "LmCompatibilityLevel is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $LmCompatibilityLevel}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network security: LDAP client signing requirements=" >> $env:COMPUTERNAME-Requirement-2.txt
$LDAPClientIntegrity= Get-Content sec.tmp |Select-String LDAPClientIntegrity
if (!$LDAPClientIntegrity) {echo "LDAPClientIntegrity is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $LDAPClientIntegrity}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Network security: Minimum session security for NTLM SSP based (including secure RPC) clients=" >> $env:COMPUTERNAME-Requirement-2.txt
$NTLMMinClientSec= Get-Content sec.tmp |Select-String NTLMMinClientSec
if (!$NTLMMinClientSec) {echo "NTLMMinClientSec is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $NTLMMinClientSec}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Recovery console: Allow automatic administrative logon=" >> $env:COMPUTERNAME-Requirement-2.txt
$securitylevel= Get-Content sec.tmp |Select-String securitylevel
if (!$securitylevel) {echo "securitylevel is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $securitylevel}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Recovery console: Allow floppy copy and access to all drives and all folders=" >> $env:COMPUTERNAME-Requirement-2.txt
$setcommand= Get-Content sec.tmp |Select-String setcommand
if (!$setcommand) {echo "setcommand is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $setcommand}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Shutdown: Allow system to be shut down without having to log on=" >> $env:COMPUTERNAME-Requirement-2.txt
$ShutdownWithoutLogon= Get-Content sec.tmp |Select-String ShutdownWithoutLogon
if (!$ShutdownWithoutLogon) {echo "ShutdownWithoutLogon is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $ShutdownWithoutLogon}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing=" >> $env:COMPUTERNAME-Requirement-2.txt
$FIPSAlgorithmPolicy= Get-Content sec.tmp |Select-String FIPSAlgorithmPolicy
if (!$FIPSAlgorithmPolicy) {echo "FIPSAlgorithmPolicy is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $FIPSAlgorithmPolicy}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-System cryptography: Force strong key protection for user keys stored on the computer=" >> $env:COMPUTERNAME-Requirement-2.txt
$ForceKeyProtection= Get-Content sec.tmp |Select-String ForceKeyProtection
if (!$ForceKeyProtection) {echo "ForceKeyProtection is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $ForceKeyProtection}
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt

Echo "-Interactive logon: Do not require CTRL+ALT+DEL=" >> $env:COMPUTERNAME-Requirement-2.txt
$DisableCAD= Get-Content sec.tmp |Select-String DisableCAD
if (!$DisableCAD) {echo "DisableCAD is not set" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -Value $DisableCAD}
echo ""  >> $env:COMPUTERNAME-Requirement-2.txt

# Local Drives R2.2.5
Echo "-Local Drives=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WmiObject win32_logicaldisk |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append

# Shared Folders R2.2.5
Echo "-Shared Folders=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-SmbShare |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Packages Installed R2.2.5
Echo "-Packages Installed=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-AppxPackage -AllUsers |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Features Installed R2.2.5
Echo "-Installed Features=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WindowsFeature |Where-Object {$_.Installstate -eq 'Installed'} |Out-File $env:COMPUTERNAME-Requirement-2.txt -Append
# Drivers Installed R2.2.5
Echo "-Drivers Installed=" >> $env:COMPUTERNAME-Requirement-2.txt
Get-WindowsDriver -online -all |Out-File $env:COMPUTERNAME-Requirement-2.txt -append
Echo "" >> $env:COMPUTERNAME-Requirement-2.txt
Echo "|----------Requirement 2.3-----------|" >> $env:COMPUTERNAME-Requirement-2.txt
# get information for Remote connection encryption ( RDP? )
# RDP Encryption setting
$RDPKey= 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$RDPEncryp=(Get-ItemProperty -path $RDPKey MinEncryptionLevel -EA SilentlyContinue).MinEncryptionLevel
if (!$RDPEncryp) {echo "Local Security Policy 'Set client Connection Encryption Level' is Disabled or Not Configured!" >> $env:COMPUTERNAME-Requirement-2.txt}
    elseif ($RDPEncryp -eq 1) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Encryption Level is set to LOW LEVEL, The Low setting encrypts only data sent from the client to the server by using 56-bit encryption"}
    elseif ($RDPEncryp -eq 2) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Encryption Level is set to CLIENT COMPATIBLE, The Client Compatible setting encrypts data sent between the client and the server at the maximum key strength supported by the client. Use this encryption level in environments that include clients that do not support 128-bit encryption"}
    elseif ($RDPEncryp -eq 3) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Encryption Level is set to HIGH LEVEL, The High setting encrypts data sent from the client to the server and from the server to the client by using strong 128-bit encryption"}
Echo ""  >> $env:COMPUTERNAME-Requirement-2.txt
# RDP Security Layer Settings
$key1= 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$Seclay1=(Get-ItemProperty -Path $key1 SecurityLayer).SecurityLayer
if ( $Seclay1 -eq "0" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Security Layer = $Seclay1 `r`nDescription: Specifies that the Microsoft Remote Desktop Protocol (RDP) is used by the server and the client for authentication before a remote desktop connection is established.`r`nRDP is a Microsoft protocol that supports terminal services across heterogeneous network environments."}
        elseif ( $Seclay1 -eq "1" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Security Layer = $Seclay1 `r`nDescription: Specifies that the server and the client negotiate the method for authentication before a remote desktop connection is established.`r`nThis is the default value." }
        elseif ( $Seclay1 -eq "2" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Security Layer = $Seclay1 `r`nDescription: Specifies that the Transport Layer Security (TLS) protocol is used by the server and the client for authentication before`r`n a remote desktop connection is established." }
        else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Security Layer has an Unknown Variable of = $Seclay1" }
echo "" >> $env:COMPUTERNAME-Requirement-2.txt
$MinEncryp1=(Get-ItemProperty -Path $key1 MinEncryptionLevel).MinEncryptionLevel
if ( $MinEncryp1 -eq "0" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Minimum Encryption Level = $MinEncryp1"}
        elseif ( $MinEncryp1 -eq "1" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Minimum Encryption Level = $MinEncryp1`r`nDescription: Security Layer 1 – With a low security level, communications sent from the client to the server are encrypted using 56-bit encryption.`r`nData sent from the server to the client is not encrypted." }
        elseif ( $MinEncryp1 -eq "2" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Minimum Encryption Level = $MinEncryp1`r`nDescription: Security Layer 2 – Having a client compatible security level, communications between the server and the client are encrypted at the maximum key strength supported by the client." }
        elseif ( $MinEncryp1 -eq "3" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Minimum Encryption Level = $MinEncryp1`r`nDescription: Security Layer 3 – With a high security level, communications between server and client are encrypted using 128-bit encryption.`r`nIf this option is set, clients that do not support 128-bit encryption will not be able to connect." }
        elseif ( $MinEncryp1 -eq "4" ) {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Minimum Encryption Level = $MinEncryp1`r`nDescription: Security Layer 4 – This security level is FIPS-Compliant, meaning that all communication between the server and client are encrypted and decrypted with the Federal Information Processing Standard (FIPS) encryption algorithms." }
        else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "Minimum Encryption Level has an Unknown Variable of = $MinEncryp1" }
echo "" >> $env:COMPUTERNAME-Requirement-2.txt
# RDP Port Number
$key1= 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
$portnum1=(Get-ItemProperty -Path $key1 PortNumber).PortNumber
if (!$portnum1) {echo "RDP Port Number = No Port Variable found/set!" >> $env:COMPUTERNAME-Requirement-2.txt}
else {add-content -path $env:COMPUTERNAME-Requirement-2.txt -value "RDP Port Number = $portnum1"}




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
if ([int]($OSVersion.BuildNumber) -ge 3790)
	{
	#Check to see if rule is applicable to this computer
	$InformationCollected = GetPKICipherReg
	}	
	

"SSL, TLS and Cipher Registry Values" | Out-File -Encoding UTF8 -FilePath $OutputFileName -Append
"***************************************" | Out-File -Encoding UTF8 -FilePath $OutputFileName -append
$InformationCollected | Out-File -Encoding UTF8 -FilePath $OutputFileName -append
write-host "Requirement 4: Done"

echo "|-----Requirement 6.1-----|" >> $env:COMPUTERNAME-Requirement-6.txt
echo "Operating System Version=" >> $env:COMPUTERNAME-Requirement-6.txt
Get-WmiObject -class win32_operatingsystem |select caption,OSArchitecture |Out-File $env:COMPUTERNAME-Requirement-6.txt -Append
echo "|-----Requirement 6.2-----|" >> $env:COMPUTERNAME-Requirement-6.txt
echo "OS Updates - Service Status=" >> $env:COMPUTERNAME-Requirement-6.txt
get-service -DisplayName "windows update" |select DisplayName,Name,Status | Out-File $env:COMPUTERNAME-Requirement-6.txt -Append
echo "OS Updates - Sources=" >> $env:COMPUTERNAME-Requirement-6.txt
if (get-childitem -ErrorAction 'silentlycontinue' 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU') {get-childitem "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate"|Out-File $env:COMPUTERNAME-Requirement-6.txt -append}
else {echo "No Windows Update Server Configured" >> $env:COMPUTERNAME-Requirement-6.txt}
echo "OS Updates - Patch Status=" >> $env:COMPUTERNAME-Requirement-6.txt
Get-WmiObject -Class win32_quickfixengineering |out-file $env:COMPUTERNAME-Requirement-6.txt -Append
echo "Last update Success=" >> $env:COMPUTERNAME-Requirement-6.txt
(New-Object -com "Microsoft.Update.AutoUpdate"). Results | fl |out-file $env:COMPUTERNAME-Requirement-6.txt -Append
write-host "Requirement 6: Done"

Echo "|----------Requirement 7.1----------|" >> $env:COMPUTERNAME-Requirement-7.txt
# Active Directory Roles Normal\Privileged
# With Role installed
$domain0=(Get-WmiObject -class win32_computersystem).Domain
#High-priviledged Administrators, Domain Admins, Enterprise Admins, Schema Admins ( Groups )
Echo "High Privileged Users"  >> $env:COMPUTERNAME-Requirement-7.txt
try{
$domainadmin=(Get-ADGroupMember -Identity 'Domain admins' -EA SilentlyContinue).name -join ", "
}
catch {}
try{
$entadmin=(Get-ADGroupMember -Identity 'Enterprise Admins'-EA SilentlyContinue).name -join ", "
}
catch {}
try{
$Scheadmin=(Get-ADGroupMember -Identity 'Schema Admins'-EA SilentlyContinue).name -join ", "
}
catch {}
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Domain Admins = $domainadmin"
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Enterprise Admins = $entadmin"
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Schema Admins = $Scheadmin"
#non-privileged domain user
Echo "Normal Privileged Users"  >> $env:COMPUTERNAME-Requirement-7.txt
try{
$DomUsers=(Get-ADGroupMember -Identity 'Domain Users' -EA SilentlyContinue).name  -join ", "
}
catch {}
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Domain Users = $Domusers"
echo "" >> $env:COMPUTERNAME-Requirement-7.txt
echo "---Domain Members universal command---" >> $env:COMPUTERNAME-Requirement-7.txt
# Universal command?
$dom1=net group "domain admins" /domain
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $dom1
echo "" >> $env:COMPUTERNAME-Requirement-7.txt
$dom2=net group "enterprise admins" /domain
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $dom2
echo "" >> $env:COMPUTERNAME-Requirement-7.txt
$dom3=net group "schema admins" /domain
add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $dom3
echo "" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Domain users" >> $env:COMPUTERNAME-Requirement-7.txt
net group "domain users" /domain >> $env:COMPUTERNAME-Requirement-7.txt
echo "" >> $env:COMPUTERNAME-Requirement-7.txt

# Current User Privilege Rights R7.1-7.2
Echo "|-----Requirement 7.1 & 7.2-----|" >> $env:COMPUTERNAME-Requirement-7.txt
echo "Current User Priviledge Rights=" >> $env:COMPUTERNAME-Requirement-7.txt
whoami /all /fo list | Out-File $env:COMPUTERNAME-Requirement-7.txt -append
echo "" >> $env:COMPUTERNAME-Requirement-7.txt
# Security Identifiers R7.1-7.2
echo "-Security Identifiers=" >> $env:COMPUTERNAME-Requirement-7.txt
Get-WmiObject -class win32_useraccount |select name,sid | Out-File $env:COMPUTERNAME-Requirement-7.txt -append
# Global Privilege Rights R7.1-7.2
echo "--Global Priviledge Rights--" >> $env:COMPUTERNAME-Requirement-7.txt
#SeBatchLogonRight
secedit /export /areas USER_RIGHTS /cfg OUTFILE.tmp
$SeBatchLogonRight = Get-Content OUTFILE.tmp |Select-String SeBatchLogonRight
if (!$SeBatchLogonRight) { echo "SeBatchLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeBatchLogonRight }
echo "Required for an account to log on using the batch logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeDenyBatchLogonRight
$SeDenyBatchLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyBatchLogonRight
if (!$SeDenyBatchLogonRight) { echo "SeDenyBatchLogonRight is not set`n" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeDenyBatchLogonRight}
echo "Explicitly denies an account the right to log on using the batch logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeDenyInteractiveLogonRight
$SeDenyInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyInteractiveLogonRight
if (!$SeDenyInteractiveLogonRight) { echo "SeDenyInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeDenyInteractiveLogonRight}
Echo "Explicitly denies an account the right to log on using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeDenyNetworkLogonRight
$SeDenyNetworkLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyNetworkLogonRight
if (!$SeDenyNetworkLogonRight) { echo "SeDenyNetworkLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeDenyNetworkLogonRight}
echo "Explicitly denies an account the right to log on using the network logon type" >> $env:COMPUTERNAME-Requirement-7.txt 
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeDenyRemoteInteractiveLogonRight
$SeDenyRemoteInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyRemoteInteractiveLogonRight
if (!$SeDenyRemoteInteractiveLogonRight) { echo "SeDenyRemoteInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeDenyRemoteInteractiveLogonRight}
Echo "Explicitly denies an account the right to log on remotely using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt 
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeDenyServiceLogonRight
$SeDenyServiceLogonRight = Get-Content OUTFILE.tmp |Select-String SeDenyServiceLogonRight
if (!$SeDenyServiceLogonRight) { echo "SeDenyServiceLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeDenyServiceLogonRight}
echo "Explicitly denies an account the right to log on using the service logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeInteractiveLogonRight
$SeInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeInteractiveLogonRight
if (!$SeInteractiveLogonRight) { echo "SeInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeInteractiveLogonRight}
echo "Required for an account to log on using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeNetworkLogonRight
$SeNetworkLogonRight = Get-Content OUTFILE.tmp |Select-String SeNetworkLogonRight
if (!$SeNetworkLogonRight) { echo "SeNetworkLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeNetworkLogonRight}
echo "Required for an account to log on using the network logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeRemoteInteractiveLogonRight
$SeRemoteInteractiveLogonRight = Get-Content OUTFILE.tmp |Select-String SeRemoteInteractiveLogonRight
if (!$SeRemoteInteractiveLogonRight) { echo "SeRemoteInteractiveLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeRemoteInteractiveLogonRight}
echo "Required for an account to log on remotely using the interactive logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#SeServiceLogonRight
$SeServiceLogonRight = Get-Content OUTFILE.tmp |Select-String SeServiceLogonRight
if (!$SeServiceLogonRight) { echo "SeServiceLogonRight is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value $SeServiceLogonRight}
echo "Required for an account to log on using the service logon type" >> $env:COMPUTERNAME-Requirement-7.txt
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#
ECHO "----------------------"  >> $env:COMPUTERNAME-Requirement-7.txt
ECHO "|= Privilege Constants"  >> $env:COMPUTERNAME-Requirement-7.txt
ECHO "----------------------"  >> $env:COMPUTERNAME-Requirement-7.txt
#Replace a process-level token
$SeAssignPrimaryTokenPrivilege = Get-Content OUTFILE.tmp |Select-String SeAssignPrimaryTokenPrivilege
if (!$SeAssignPrimaryTokenPrivilege) { echo "Replace a process-level token=SeAssignPrimaryTokenPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Replace a process-level token= $SeAssignPrimaryTokenPrivilege "}
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Generate security audits
$SeAuditPrivilege = Get-Content OUTFILE.tmp |Select-String SeAuditPrivilege
if (!$SeAuditPrivilege) { echo "Generate security audits=SeAuditPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Generate security audits= $SeAuditPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

#Back up files and directories
$SeBackupPrivilege = Get-Content OUTFILE.tmp |Select-String SeBackupPrivilege
if (!$SeBackupPrivilege) { echo "Back up files and directories=SeBackupPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Back up files and directories= $SeBackupPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Bypass traverse checking
$SeChangeNotifyPrivilege = Get-Content OUTFILE.tmp |Select-String SeChangeNotifyPrivilege
if (!$SeChangeNotifyPrivilege) { echo "Bypass traverse checking=SeChangeNotifyPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Bypass traverse checking= $SeChangeNotifyPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Create global objects
$SeCreateGlobalPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreateGlobalPrivilege
if (!$SeCreateGlobalPrivilege) { echo "Create global objects=SeCreateGlobalPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Create global objects= $SeCreateGlobalPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Create a pagefile
$SeCreatePagefilePrivilege = Get-Content OUTFILE.tmp |Select-String SeCreatePagefilePrivilege
if (!$SeCreatePagefilePrivilege) { echo "Create a pagefile=SeCreatePagefilePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Create a pagefile= $SeCreatePagefilePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Create permanent shared objects
$SeCreatePermanentPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreatePermanentPrivilege
if (!$SeCreatePermanentPrivilege) { echo "Create permanent shared objects=SeCreatePermanentPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Create permanent shared objects= $SeCreatePermanentPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Create symbolic links
$SeCreateSymbolicLinkPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreateSymbolicLinkPrivilege
if (!$SeCreateSymbolicLinkPrivilege) { echo "Create symbolic links=SeCreateSymbolicLinkPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Create symbolic links= $SeCreateSymbolicLinkPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Create a token object
$SeCreateTokenPrivilege = Get-Content OUTFILE.tmp |Select-String SeCreateTokenPrivilege
if (!$SeCreateTokenPrivilege) { echo "Create a token object=SeCreateTokenPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Create a token object= $SeCreateTokenPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Debug programs
$SeDebugPrivilege = Get-Content OUTFILE.tmp |Select-String SeDebugPrivilege
if (!$SeDebugPrivilege) { echo "Debug programs=SeDebugPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Debug programs= $SeDebugPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Enable computer and user accounts to be trusted for delegation
$SeEnableDelegationPrivilege = Get-Content OUTFILE.tmp |Select-String SeEnableDelegationPrivilege
if (!$SeEnableDelegationPrivilege) { echo "Enable computer and user accounts to be trusted for delegation=SeEnableDelegationPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Enable computer and user accounts to be trusted for delegation= $SeEnableDelegationPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Impersonate a client after authentication
$SeImpersonatePrivilege = Get-Content OUTFILE.tmp |Select-String SeImpersonatePrivilege
if (!$SeImpersonatePrivilege) { echo "Impersonate a client after authentication=SeImpersonatePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Impersonate a client after authentication= $SeImpersonatePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Increase scheduling priority
$SeIncreaseBasePriorityPrivilege = Get-Content OUTFILE.tmp |Select-String SeIncreaseBasePriorityPrivilege
if (!$SeIncreaseBasePriorityPrivilege) { echo "Increase scheduling priority=SeIncreaseBasePriorityPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Increase scheduling priority= $SeIncreaseBasePriorityPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Adjust memory quotas for a proces
$SeIncreaseQuotaPrivilege = Get-Content OUTFILE.tmp |Select-String SeIncreaseQuotaPrivilege
if (!$SeIncreaseQuotaPrivilege) { echo "Adjust memory quotas for a process=SeIncreaseQuotaPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Adjust memory quotas for a process= $SeIncreaseQuotaPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Increase a process working set
$SeIncreaseWorkingSetPrivilege = Get-Content OUTFILE.tmp |Select-String SeIncreaseWorkingSetPrivilege
if (!$SeIncreaseWorkingSetPrivilege) { echo "Increase a process working set=SeIncreaseWorkingSetPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Increase a process working set= $SeIncreaseWorkingSetPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Load and unload device driver
$SeLoadDriverPrivilege = Get-Content OUTFILE.tmp |Select-String SeLoadDriverPrivilege
if (!$SeLoadDriverPrivilege) { echo "Load and unload device drivers=SeLoadDriverPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Load and unload device drivers= $SeLoadDriverPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Lock pages in memory
$SeLockMemoryPrivilege = Get-Content OUTFILE.tmp |Select-String SeLockMemoryPrivilege
if (!$SeLockMemoryPrivilege) { echo "Lock pages in memory=SeLockMemoryPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Lock pages in memory= $SeLockMemoryPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Add workstations to domain
$SeMachineAccountPrivilege = Get-Content OUTFILE.tmp |Select-String SeMachineAccountPrivilege
if (!$SeMachineAccountPrivilege) { echo "Add workstations to domain=SeMachineAccountPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Add workstations to domain= $SeMachineAccountPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Manage the files on a volume
$SeManageVolumePrivilege = Get-Content OUTFILE.tmp |Select-String SeManageVolumePrivilege
if (!$SeManageVolumePrivilege) { echo "Manage the files on a volume=SeManageVolumePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Manage the files on a volume= $SeManageVolumePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Profile single process
$SeProfileSingleProcessPrivilege = Get-Content OUTFILE.tmp |Select-String SeProfileSingleProcessPrivilege
if (!$SeProfileSingleProcessPrivilege) { echo "Profile single process=SeProfileSingleProcessPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Profile single process= $SeProfileSingleProcessPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Modify an object label
$SeRelabelPrivilege = Get-Content OUTFILE.tmp |Select-String SeRelabelPrivilege
if (!$SeRelabelPrivilege) { echo "Modify an object label=SeRelabelPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Modify an object label= $SeRelabelPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Force shutdown from a remote system
$SeRemoteShutdownPrivilege = Get-Content OUTFILE.tmp |Select-String SeRemoteShutdownPrivilege
if (!$SeRemoteShutdownPrivilege) { echo "Force shutdown from a remote system=SeRemoteShutdownPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Force shutdown from a remote system= $SeRemoteShutdownPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Restore files and directories
$SeRestorePrivilege = Get-Content OUTFILE.tmp |Select-String SeRestorePrivilege
if (!$SeRestorePrivilege) { echo "Restore files and directories=SeRestorePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Restore files and directories= $SeRestorePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Manage auditing and security log
$SeSecurityPrivilege = Get-Content OUTFILE.tmp |Select-String SeSecurityPrivilege
if (!$SeSecurityPrivilege) { echo "Manage auditing and security log=SeSecurityPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Manage auditing and security log= $SeSecurityPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Shut down the system
$SeShutdownPrivilege = Get-Content OUTFILE.tmp |Select-String SeShutdownPrivilege
if (!$SeShutdownPrivilege) { echo "Shut down the system=SeShutdownPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Shut down the system= $SeShutdownPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Synchronize directory service data
$SeSyncAgentPrivilege = Get-Content OUTFILE.tmp |Select-String SeSyncAgentPrivilege
if (!$SeSyncAgentPrivilege) { echo "Synchronize directory service data=SeSyncAgentPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Synchronize directory service data= $SeSyncAgentPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Modify firmware environment values
$SeSystemEnvironmentPrivilege = Get-Content OUTFILE.tmp |Select-String SeSystemEnvironmentPrivilege
if (!$SeSystemEnvironmentPrivilege) { echo "Modify firmware environment valuesSeSystemEnvironmentPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Modify firmware environment values= $SeSystemEnvironmentPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Profile system performance
$SeSystemProfilePrivilege = Get-Content OUTFILE.tmp |Select-String SeSystemProfilePrivilege
if (!$SeSystemProfilePrivilege) { echo "Profile system performance=SeSystemProfilePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Profile system performance= $SeSystemProfilePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Change the system time
$SeSystemtimePrivilege = Get-Content OUTFILE.tmp |Select-String SeSystemtimePrivilege
if (!$SeSystemtimePrivilege) { echo "Change the system time=SeSystemtimePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Change the system time= $SeSystemtimePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Take ownership of files or other objects
$SeTakeOwnershipPrivilege = Get-Content OUTFILE.tmp |Select-String SeTakeOwnershipPrivilege
if (!$SeTakeOwnershipPrivilege) { echo "Take ownership of files or other objectsSeTakeOwnershipPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Take ownership of files or other objects= $SeTakeOwnershipPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Act as part of the operating system
$SeTcbPrivilege = Get-Content OUTFILE.tmp |Select-String SeTcbPrivilege
if (!$SeTcbPrivilege) { echo "Act as part of the operating system=SeTcbPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Act as part of the operating system= $SeTcbPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Change the time zone
$SeTimeZonePrivilege = Get-Content OUTFILE.tmp |Select-String SeTimeZonePrivilege
if (!$SeTimeZonePrivilege) { echo "Change the time zone=SeTimeZonePrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Change the time zone= $SeTimeZonePrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Access Credential Manager as a trusted caller
$SeTrustedCredManAccessPrivilege = Get-Content OUTFILE.tmp |Select-String SeTrustedCredManAccessPrivilege
if (!$SeTrustedCredManAccessPrivilege) { echo "Access Credential Manager as a trusted caller=SeTrustedCredManAccessPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Access Credential Manager as a trusted caller= $SeTrustedCredManAccessPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Remove computer from docking station
$SeUndockPrivilege = Get-Content OUTFILE.tmp |Select-String SeUndockPrivilege
if (!$SeUndockPrivilege) { echo "Remove computer from docking station=SeUndockPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Remove computer from docking station= $SeUndockPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt
#Required to read unsolicited input from a terminal device
$SeUnsolicitedInputPrivilege = Get-Content OUTFILE.tmp |Select-String SeUnsolicitedInputPrivilege
if (!$SeUnsolicitedInputPrivilege) { echo "Required to read unsolicited input from a terminal device=SeUnsolicitedInputPrivilege is not set" >> $env:COMPUTERNAME-Requirement-7.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-7.txt -value "Required to read unsolicited input from a terminal device= $SeUnsolicitedInputPrivilege " }
Echo "`n" >> $env:COMPUTERNAME-Requirement-7.txt

write-host "Requirement 7: Done"

echo "|----------Requirement 8.1----------|" >> $env:COMPUTERNAME-Requirement-8.txt
# Enabled Local Accounts
Echo "-Enabled Local Accounts" >> $env:COMPUTERNAME-Requirement-8.txt
Get-WmiObject -class win32_useraccount -filter "disabled='false'" |Select Name |Out-File $env:COMPUTERNAME-Requirement-8.txt -append
# Disabled Local accounts
Echo "-Disabled Local Accounts" >> $env:COMPUTERNAME-Requirement-8.txt
Get-WmiObject -class win32_useraccount -filter "disabled='True'" |Select Name |Out-File $env:COMPUTERNAME-Requirement-8.txt -append
echo "-Account Settings" >> $env:COMPUTERNAME-Requirement-8.txt
# Account Lockout Threshold
net accounts >>accounts.tmp
$Lockthresh1=Get-Content accounts.tmp |Select-String "lockout threshold=" 
if (!$Lockthresh1) {echo "Lockout Threshold not set!" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $Lockthresh1}
echo ""  >> $env:COMPUTERNAME-Requirement-8.txt
# Account Lockout Duration
$accdur1=Get-Content accounts.tmp |Select-String "lockout duration"
if (!$accdur1) {echo "Account Duration not set!"  >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $accdur1}
echo ""  >> $env:COMPUTERNAME-Requirement-8.txt
echo "-Session Settings" >> $env:COMPUTERNAME-Requirement-8.txt
# Session Timeout
REG export "HKCU\Control Panel\Desktop" screen.tmp
$Screensaveactive= Get-Content screen.tmp |Select-String ScreenSaveActive
if (!$Screensaveactive) {Echo "ScreenSaveActive is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $Screensaveactive}
echo ""  >> $env:COMPUTERNAME-Requirement-8.txt
#ScreenSaveTimeout Check
$screensavetimeout= Get-Content screen.tmp |Select-String screensavetimeout
if (!$screensavetimeout) {Echo "screensavetimeout is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $screensavetimeout}
echo ""  >> $env:COMPUTERNAME-Requirement-8.txt
#ScreenSaveSecure Check
$screensavesecure= Get-Content screen.tmp |Select-String screensavesecure
if (!$screensavesecure) {Echo "screensavesecure is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $screensavesecure}
Echo "" >> $env:COMPUTERNAME-Requirement-8.txt
Echo "|----------Requirement 8.2----------|" >> $env:COMPUTERNAME-Requirement-8.txt
secedit /export /mergedpolicy /cfg temp3.tmp /quiet
# Password Store Configuration
$ClearTextPassword= Get-Content temp3.tmp |Select-String ClearTextPassword
if (!$ClearTextPassword) {Echo "ClearTextPassword is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $ClearTextPassword}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Password Length
$MinimumPasswordLength= Get-Content temp3.tmp |Select-String MinimumPasswordLength
if (!$MinimumPasswordLength) {Echo "MinimumPasswordLength is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $MinimumPasswordLength}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Password Complexity
$PasswordComplexity= Get-Content temp3.tmp |Select-String PasswordComplexity
if (!$PasswordComplexity) {Echo "PasswordComplexity is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $PasswordComplexity}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Password Change Threshold
$MaximumPasswordAge= Get-Content temp3.tmp |Select-String MaximumPasswordAge
if (!$MaximumPasswordAge) {Echo "MaximumPasswordAge is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $MaximumPasswordAge}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Password History
$PasswordHistorySize= Get-Content temp3.tmp |Select-String PasswordHistorySize
if (!$PasswordHistorySize) {Echo "PasswordHistorySize is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else {add-content -path $env:COMPUTERNAME-Requirement-8.txt -value $PasswordHistorySize}
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
echo "|----------Requirement 8.5----------|" >> $env:COMPUTERNAME-Requirement-8.txt
# Local Accounts
echo "-Local Accounts" >> $env:COMPUTERNAME-Requirement-8.txt
(Get-wmiobject -Class win32_useraccount).name | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Local Administrators
echo "-Local Administrators" >> $env:COMPUTERNAME-Requirement-8.txt
$group=Get-WmiObject win32_group -Filter "name='Administrators'"
$group.getrelated("win32_useraccount") |select Name | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Local Administrator Status
echo "-Local Administrator Status" >> $env:COMPUTERNAME-Requirement-8.txt
$group=Get-WmiObject win32_group -Filter "name='Administrators'"
$group.getrelated("win32_useraccount") |select name,status | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
echo "" >> $env:COMPUTERNAME-Requirement-8.txt
# Local Groups R8.5
echo "-Local Groups" >> $env:COMPUTERNAME-Requirement-8.txt
(Get-WmiObject -Class win32_group).name | Out-File $env:COMPUTERNAME-Requirement-8.txt -Append
write-host "Requirement 8: Done"
echo "|----------Requirement 10.2 & 10.3----------|"  >> $env:COMPUTERNAME-Requirement-10.txt
Echo "-Event Log - Service Status" >> $env:COMPUTERNAME-Requirement-10.txt
Get-Service -Name EventLog |Out-File $env:COMPUTERNAME-Requirement-10.txt -append

Echo "-Log Configuration" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit System Events" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditSystemEvents= Get-Content sec.tmp |Select-String AuditSystemEvents
if (!$AuditSystemEvents) {Echo "AuditSystemEvents is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditSystemEvents -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditSystemEvents - Variable 'AuditSystemEvents' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditSystemEvents - Variable 'AuditSystemEvents' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Logon Events" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditLogonEvents= Get-Content sec.tmp |Select-String AuditLogonEvents
if (!$AuditLogonEvents) {Echo "AuditLogonEvents is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditLogonEvents -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditLogonEvents - Variable 'AuditLogonEvents' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditLogonEvents - Variable 'AuditLogonEvents' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Object Status" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditObjectAccess= Get-Content sec.tmp |Select-String AuditObjectAccess
if (!$AuditObjectAccess) {Echo "AuditObjectAccess is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditObjectAccess -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditObjectAccess - Variable 'AuditObjectAccess' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditObjectAccess - Variable 'AuditObjectAccess' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Priviledge use" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditPrivilegeUse= Get-Content sec.tmp |Select-String AuditPrivilegeUse
if (!$AuditPrivilegeUse) {Echo "AuditPrivilegeUse is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditPrivilegeUse -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditPrivilegeUse - Variable 'AuditPrivilegeUse' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditPrivilegeUse - Variable 'AuditPrivilegeUse' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Policy Change" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditPolicyChange= Get-Content sec.tmp |Select-String AuditPolicyChange
if (!$AuditPolicyChange) {Echo "AuditPolicyChange is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditPolicyChange -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditPolicyChange - Variable 'AuditPolicyChange' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditPolicyChange - Variable 'AuditPolicyChange' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Account Manage" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditAccountManage= Get-Content sec.tmp |Select-String AuditAccountManage
if (!$AuditAccountManage) {Echo "AuditAccountManages is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditAccountManage -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditAccountManage - Variable 'AuditAccountManage' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditAccountManage - Variable 'AuditAccountManage' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Process Tracking" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditProcessTracking= Get-Content sec.tmp |Select-String AuditProcessTracking
if (!$AuditProcessTracking) {Echo "AuditProcessTracking is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditProcessTracking -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditProcessTracking - Variable 'AuditProcessTracking' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditProcessTracking - Variable 'AuditProcessTracking' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit DS Access" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditDSAccess= Get-Content sec.tmp |Select-String AuditDSAccess
if (!$AuditDSAccess) {Echo "AuditDSAccess is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditDSAccess -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditDSAccess - Variable 'AuditDSAccess' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditDSAccess - Variable 'AuditDSAccess' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
#Echo "-Audit Account Logon" >> $env:COMPUTERNAME-Requirement-10.txt
$AuditAccountLogon= Get-Content sec.tmp |Select-String AuditAccountLogon
if (!$AuditAccountLogon) {Echo "AuditAccountLogon is not set" >> $env:COMPUTERNAME-Requirement-8.txt
} else { if ($AuditAccountLogon -ne 3) {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditAccountLogon - Variable 'AuditAccountLogon' does not meet with Req. 10.2 - 10.3"
        } else {add-content -path $env:COMPUTERNAME-Requirement-10.txt -value "$AuditAccountLogon - Variable 'AuditAccountLogon' complies with PCI DSS Req. 10.2 - 10.3"}
}
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "-Log Policies R10.2-10.3" >> $env:COMPUTERNAME-Requirement-10.txt
auditpol /get /category:* >> $env:COMPUTERNAME-Requirement-10.txt
echo "|----------Requirement 10.4-----------|" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "-NTP - Service Status" >> $env:COMPUTERNAME-Requirement-10.txt
Get-Service -name W32Time | Out-File $env:COMPUTERNAME-Requirement-10.txt -append

Echo "-NTP Configuration" >> $env:COMPUTERNAME-Requirement-10.txt
$timestatus=get-service -Name w32time 
if ($timestatus.status -eq "Stopped") {Echo "WARNING!: W32Time Service is Not running" >> $env:COMPUTERNAME-Requirement-10.txt
} else {echo "w32tm Status" >> $env:COMPUTERNAME-Requirement-10.txt; w32tm /query /status |Out-File $env:COMPUTERNAME-Requirement-10.txt -Append;echo "w32tm configuration" >> $env:COMPUTERNAME-Requirement-10.txt;w32tm /query /Configuration|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append }
echo "|----------Requirement 10.5----------|" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "-Log DACL Permissions" >> $env:COMPUTERNAME-Requirement-10.txt
Echo "-Application Event Log DACL:" >> $env:COMPUTERNAME-Requirement-10.txt
get-acl $env:systemroot\system32\winevt\logs\Application.evtx -EA SilentlyContinue|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
get-acl $env:systemroot\system32\winevt\logs\Application.evtx -EA SilentlyContinue|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
Echo "-Security Event Log DACL:" >> $env:COMPUTERNAME-Requirement-10.txt
get-acl $env:systemroot\System32\Config\SecEvent.Evt -EA SilentlyContinue|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
get-acl $env:systemroot\system32\winevt\logs\Security.evtx -EA SilentlyContinue|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
Echo "-System Event Log DACL:" >> $env:COMPUTERNAME-Requirement-10.txt
get-acl $env:systemroot\System32\Config\SysEvent.Evt -EA SilentlyContinue|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append
get-acl $env:systemroot\system32\winevt\logs\System.evtx -EA SilentlyContinue|Out-File $env:COMPUTERNAME-Requirement-10.txt -Append


del sec.tmp
del OUTFILE.tmp
del accounts.tmp
del screen.tmp
del temp3.tmp
write-host "Requirement 10: Done"
Write-Host "Finished"
