<#
.SYNOPSIS
Create three accounts (Victim, Helpdesk & Domain Admin) for the attack demo.

.DESCRIPTION

Based on the Tutorial: Setup a Microsoft Defender for Identity security alert lab


.NOTES

last update: 2022-10-25
File Name  : AS2Go-create-users.ps1
Author     : Holger Zimmermann | @HerrHozi


.PARAMETER Shortname

Define the name for the accounts. "y" is the default.
Y - yyyyMMdd
N - yyyyMMdd.hhmmss
<your name> 

.PARAMETER DomainAdmin
Create an DA-xxxxx Domain Admin account. "y" is the default.

.PARAMETER HelpDesk
Create an HD-xxxxx HelpDesk account. "y" is the default.

.PARAMETER Victim
Create an VI-xxxxx Victim account. "y" is the default.

.EXAMPLE
PS> cd C:\Temp\AS2Go
PS> .\AS2GO-create-users.ps1

.EXAMPLE
PS> .\AS2GO-create-users.ps1 -Shortname n

.EXAMPLE
PS> .\AS2GO-create-users.ps1 -Shortname HerrHoZi


.EXAMPLE
PS> .\AS2GO-create-users.ps1 -DomainAdmin y -HelpDesk y -Victim n -Shortname AS2Go
creates the only the domain admin & help desk account with an dedicated name, da-AS2Go & hd-AS2Go



.LINK
https://docs.microsoft.com/en-us/defender-for-identity/playbook-setup-lab
#>

#Check if the current Windows PowerShell session is running as Administrator. 
#If not Start Windows PowerShell by  using the Run as Administrator option, and then try running the script again.

#Requires -RunAsAdministrator

param([string] $DomainAdmin='y', [string] $HelpDesk='y', [string] $Victim='y', [string] $Shortname='y')

#get current Posh Name & path
$PoSHPath    = Get-Location
$scriptName  = $MyInvocation.MyCommand.Name
$logfile     = "$PoSHPath\$scriptName.log"
$NTDSDITFILE = "$PoSHPath\ntds.dit"


#get the Domain Roout OU
$ADRoot = Get-ADRootDSE
$Domain = Get-ADDomain
$RootOU = $ADRoot.defaultNamingContext


 $AS2GoUser = @(
       [pscustomobject]@{Path = "OU=Accounts,OU=Tier 0 Assets,OU=AS2Go,$RootOU"; ComputerPath = "OU=Tier 0 Servers,OU=Tier 0 Assets,OU=AS2Go,$RootOU"}
       [pscustomobject]@{Path = "OU=Accounts,OU=Tier 1 Assets,OU=AS2Go,$RootOU"; ComputerPath = "OU=Devices,OU=Tier 1 Assets,OU=AS2Go,$RootOU"}
       [pscustomobject]@{Path = "OU=Accounts,OU=Tier 2 Assets,OU=AS2Go,$RootOU"; ComputerPath = "OU=Devices,OU=Tier 2 Assets,OU=AS2Go,$RootOU"}
   )


# OU Path for new Users
$sUPNSuffix = "@HerrHozi.com"

# Store the user passwords as variables
$master = '1q2w3e$R'
$DASecurePass = ConvertTo-SecureString -String $master+'da' -AsPlainText -Force
$HDSecurePass = ConvertTo-SecureString -String $master+'hd' -AsPlainText -Force
$VISecurePass = ConvertTo-SecureString -String $master+'vi' -AsPlainText -Force

# Manager's must exist in the AD
$DAManager = (get-aduser -filter * | Get-Random).samaccountname # "Holger"
$HDManager = (get-aduser -filter * | Get-Random).samaccountname # "HoZi"
$VIManager = (get-aduser -filter * | Get-Random).samaccountname #"Zimbo"

# User thumbnail Photo
$DAPhoto = "$PoSHPath\mdi-admin.jpg"
$HDPhoto = "$PoSHPath\mdi-helpdesk.jpg"
$VIPhoto = "$PoSHPath\mdi-victim.jpg"

# Active Directory Security Groups
$VIGroup = "SG-AS2Go-Victims"            # member of local admins on VICTIM PC
$HDGroup = "SG-AS2Go-HelpDesk"           # member of local admins on ADMIN PC & VICTIM PC
$DAGroup = "SG-AS2Go-Admins"             # member of local admins on ADMIN PC

#define the user first & last name
$sFirstName = Get-Date -Format HHmmssff  # create the first name based on hours, minutes, seconds & milli seconds
$sLastname  = Get-Date -Format yyyyMMdd  # create the last name based on year, month, days

#Account expires after xx Days
$TimeSpan = New-TimeSpan -Days 7 -Hours 0 -Minutes 0

#Service to create SPN
$services = ("HTTPS","FTP","CIFS","kafka","MSSQL","POP3","HTTP")

Import-Module ActiveDirectory


Function NewMDIUser()

{

param([string] $sUserPrincipalName, 
      [string] $sName, 
      [string] $sSamaccountName,  
      [string] $sFirstName, 
      [string] $sLastname, 
      [string] $sDisplayName, 
      [string] $sPath, 
      [SecureString] $secure_string_pwd)


New-aduser -UserPrincipalName $sUserPrincipalName -Name $sName -SamAccountName $sSamaccountName -PasswordNeverExpires $false -Path $sPath -AccountPassword $secure_string_pwd -PassThru | Enable-ADAccount


#additional attributes same for all

  $UserProperties = @{
  "mobile"            = Get-Date -Format HHmmssffff
  "telephoneNumber"   = Get-Date -Format HHmmssffff
  "employeenumber"    = Get-Date -Format HHmmssffff
  "GivenName"         = $sFirstName
  "sn"                = $sLastname
  "DisplayName"       = $sDisplayName
  "Company"           = "Herr Hozi INC."
  "Description"       = "AS2Go Dummy User"
  "c"                 = "DE"
  "countryCode"       = 276
  "co"                = "Germany"
  "l"                 = "somewhere in Germany"
  "wWWHomePage"       = "https://HerrHozi.com"
  "physicalDeliveryOfficeName" = "AS2Go Lab"
  }

sleep -Milliseconds 1000
Set-ADUser -Identity $sSamaccountName  -Replace $UserProperties 
Set-ADAccountExpiration –Identity $sSamaccountName -TimeSpan $TimeSpan
}



If ($Shortname -eq 'y')
{
   $sNewName = ($sLastname)
  
}
elseif ($Shortname -eq 'n')
{
   $sNewName = ($sLastname + "." + $sFirstName)
}
else
{
   $sNewName = $Shortname
}



$sNewUserPrincipalName = ($sNewName + $sUPNSuffix)


Write-Host "`nStart creating 3 users for use case '$sNewName'. Accounts expire after $TimeSpan days`n" -ForegroundColo Yellow


if ($Victim -eq 'y')
  {
  # create Victim User (like VI-HerrHozi)
  # =========================================

  $sUserPrincipalName  = "VI-" + $sNewUserPrincipalName
  $sName               = $sNewName + "-VI"
  $sSamAccountName     = "VI-" + $sNewName
  $sDisplayName        = "Compromised Credentials ($sSamAccountName)"
  $bthumbnailPhoto     = $VIPhoto
  $sPath               = $AS2GoUser[2].Path

  NewMDIUser -sUserPrincipalName $sUserPrincipalName -sName $sName -sSamaccountName $sSamAccountName -sFirstName $sFirstName -sLastname $sLastname -sDisplayName $sDisplayName -sPath $sPath -secure_string_pwd $VISecurePass
  $sName = $sSamAccountName

  Add-ADGroupMember -Identity $VIGroup -Members $sName
  Set-ADUser $sName -Replace @{thumbnailPhoto=([byte[]](Get-Content $bthumbnailPhoto -Encoding byte))} -Manager $VIManager -Initials "VI" -Title "Normal User" -Department "Tier 2"
  Write-Host "... created new user - $sName | Compromised User account (Victim)"
  }

  
if ($HelpDesk -eq 'y')
  {
  # create Helpdesk User (like HD-HerrHozi)
  # =========================================

  $sUserPrincipalName  = "HD-" + $sNewUserPrincipalName
  $sName               = $sNewName + "-HD"
  $sSamAccountName     = "HD-" + $sNewName
  $sDisplayName        = "Helpdesk User ($sSamAccountName)"
  $bthumbnailPhoto     = $HDPhoto
  $sPath               = $AS2GoUser[1].Path

  
  NewMDIUser -sUserPrincipalName $sUserPrincipalName -sName $sName -sSamaccountName $sSamAccountName -sFirstName $sFirstName -sLastname $sLastname -sDisplayName $sDisplayName -sPath $sPath -secure_string_pwd $HDSecurePass
  $sName = $sSamAccountName
  Add-ADGroupMember -Identity $HDGroup  -Members $sName
  Set-ADUser $sName -Replace @{thumbnailPhoto=([byte[]](Get-Content $bthumbnailPhoto -Encoding byte))} -Manager $HDManager -Initials "HD" -Title "Helpdesk" -Department "Tier 1"
  Write-Host "... created new user - $sName | Helpdesk User"


  # additionally Helpdesk User (HD-HerrHoziP)
  # member of the protected users group
    
  $sUserPrincipalName  = "HD-" + $sNewName + "P" + $sUPNSuffix
  $sName               = $sNewName + "P-HD"
  $sSamAccountName     = "HD-" + $sNewName + "P"
  $sDisplayName        = "Helpdesk User ($sSamAccountName)"
  $bthumbnailPhoto     = $HDPhoto
  $sPath               = $AS2GoUser[1].Path

  NewMDIUser -sUserPrincipalName $sUserPrincipalName -sName $sName -sSamaccountName $sSamAccountName -sFirstName $sFirstName -sLastname $sLastname -sDisplayName $sDisplayName -sPath $sPath -secure_string_pwd $HDSecurePass
  $sName = $sSamAccountName
  $ProtectedUser =  (Get-ADGroup -Filter * -Properties * | where {($_.SID -like "*-525")}).name
  Add-ADGroupMember -Identity $ProtectedUser -Members $sName
  Add-ADGroupMember -Identity $HDGroup  -Members $sName
  Set-ADUser $sName -Replace @{thumbnailPhoto=([byte[]](Get-Content $bthumbnailPhoto -Encoding byte))} -Manager $HDManager -Initials "HD" -Title "Helpdesk" -Department "Tier 1"
  Write-Host "... created new user - $sName | Helpdesk User"
  
  #create new computer
  $NewComputer = "PAW-$sNewName"
  New-ADComputer -Name $NewComputer -Description "needed for Kerberoasting Attack" -Path $AS2GoUser[1].ComputerPath  -Location $sNewName -OperatingSystem "Windows 10 Enterprise"

  #set ServicePrincipalNames to a random service
  $service = $services | get-Random
  $NewSPN = "$service/$NewComputer"
  Set-ADUser -Identity $sName -ServicePrincipalNames @{Add=$NewSPN} 

  }

 
if ($DomainAdmin -eq 'y')
  {
  # create Domain Admin User (like DA-HerrHozi)
  # =============================================

  $sUserPrincipalName  = "DA-" + $sNewUserPrincipalName
  $sName               = $sNewName + "-DA"
  $sSamAccountName     = "DA-" + $sNewName
  $sDisplayName        = ("Domain Admin ($sSamAccountName)")
  $bthumbnailPhoto     = $DAPhoto
  $sPath               = $AS2GoUser[0].Path

  NewMDIUser -sUserPrincipalName $sUserPrincipalName -sName $sName -sSamaccountName $sSamAccountName -sFirstName $sFirstName -sLastname $sLastname -sDisplayName $sDisplayName -sPath $sPath -secure_string_pwd $DASecurePass

  $sName = $sSamAccountName
  $DomainAdmins =  (Get-ADGroup -Filter * -Properties * | where {($_.SID -like "*-512")}).name
  Add-ADGroupMember -Identity $DomainAdmins -Members $sName
  Add-ADGroupMember -Identity $DAGroup -Members $sName

  Set-ADUser $sName -Replace @{thumbnailPhoto=([byte[]](Get-Content $bthumbnailPhoto -Encoding byte))} -Manager $DAManager -Initials "DA" -Title "Domain Admin" -Department "Tier 0"
  Write-Host "... created new user - $sName | Domain Admin"

  #create new computer object
  $NewComputer = "SRV-$sNewName"
  New-ADComputer -Name $NewComputer -Description "needed for Kerberoasting Attack" -Path $AS2GoUser[0].ComputerPath  -Location $sNewName -OperatingSystem "Windows Server 2019"
  
  #set ServicePrincipalNames to a random service
  $service = $services | get-Random
  $NewSPN = "$service/$NewComputer"
  Set-ADUser -Identity $sName -ServicePrincipalNames @{Add=$NewSPN} 
  
  }



# SUMMMARY
# ========

$sNewName = "paul06"
$attributesU = @("Created","samaccountname","servicePrincipalName","canonicalName","name","department","memberof")
$attributesC = @("Created","samaccountname","servicePrincipalName","canonicalName","name","description")
 
Write-Host "`n`nSUMMARY for new User & Computer Objects:" -ForegroundColor Yellow
Write-Host     "========================================" -ForegroundColor Yellow

Get-ADUser     -LDAPFilter "(sAMAccountName=*$sNewName*)"   -Properties $attributesU | select $attributesU | ft
Get-ADComputer -LDAPFilter "(sAMAccountName=*-$sNewName*)" -Properties $attributesC | select $attributesC | ft


$MyScript = $MyInvocation.MyCommand.Definition
$OnServer = " on server [" + [Environment]::machinename + "]" 
$byUser   = " by user [" + [Environment]::UserName + "]"
$UseCase  = " Usecase [" + $sNewName + "]"


Write-Host "`n`nReminder:" -ForegroundColor Yellow
Write-Host "If you changed the default password, do NOT forget to update the XML file!!!!!!!" -ForegroundColor Yellow

# update the log file
# ===================
" " | Out-File -FilePath $logfile -Append -Encoding default 
(Get-Date).ToString() + " last run: " + $MyScript + $onserver + $byUser + $UseCase  | Out-File -FilePath $logfile -Append -Encoding default 
Get-ADUser -LDAPFilter "(sAMAccountName=*$sNewName)" -Properties canonicalName, Created  | select sAMAccountName, Created, userPrincipalName, name, canonicalName | ft | Out-File -FilePath $logfile -Append -Encoding default


# update the dummy NTDS.DIT file
# ==============================
$NTDSDITFILE = "$PoSHPath\ntds.dit"
Get-ChildItem -Path c:\windows | Out-File -FilePath $NTDSDITFILE -Append -Encoding default 
