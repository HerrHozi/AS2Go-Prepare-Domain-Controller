#last update: 2022-01-01
#File Name  : AS2Go-create-users.ps1
#Author     : Holger Zimmermann | hozimmer@microsoft.com

#assuming english OS



#define the AS2Go & Sensitive Account Organisation Unit
$AS2GoOU = "AS2Go"
$SenAcOU = "Sensitve Accounts"

# define the AS2Go Group Names
$VIGroup = "SG-AS2Go-Victims"            # member of local admins on VICTIM PC
$HDGroup = "SG-AS2Go-HelpDesk"           # member of local admins on ADMIN PC & VICTIM PC
$DAGroup = "SG-AS2Go-Admins"             # member of local admins on ADMIN PC


#get the Domain Roout OU
$ADRoot = Get-ADRootDSE
$RootOU = $ADRoot.defaultNamingContext


Write-Host "Creating AS2Go Groups & OUs ...." -ForegroundColor Yellow


# Create the AS2Go Groups
New-ADGroup -Name $VIGroup -GroupScope Global -GroupCategory Security -Description "AS2GO Group"
New-ADGroup -Name $HDGroup -GroupScope Global -GroupCategory Security -Description "AS2GO Group"
New-ADGroup -Name $DAGroup -GroupScope Global -GroupCategory Security -Description "AS2GO Group"

New-ADOrganizationalUnit -Name $AS2GoOU  -Path "$RootOU"             -Description "AS2Go Accounts" 
New-ADOrganizationalUnit -Name "Users"   -Path "OU=$AS2GoOU,$RootOU" -Description "AS2Go User Accounts" 
New-ADOrganizationalUnit -Name "Groups"  -Path "OU=$AS2GoOU,$RootOU" -Description "AS2Go Group Accounts"
New-ADOrganizationalUnit -Name "Demo Accounts"  -Path "OU=$AS2GoOU,$RootOU" -Description "Demo Accounts for User Manipulation"  

Write-Host "Moving AS2Go Groups to target OUs ...." -ForegroundColor Yellow

#Move the AS2Go groups to the target OU
get-adgroup -Filter {name -like 'sg-as2go*'} | Move-ADObject -TargetPath "OU=Groups,OU=$AS2GoOU,$RootOU"

#List new Gorups
Get-ADGroup -LDAPFilter "(sAMAccountName=SG-AS2Go*)" -Properties canonicalName, Created  | select sAMAccountName, Created,  name, canonicalName | ft

Write-Host "Creating OUs for Sensitive Accounts ...." -ForegroundColor Yellow


New-ADOrganizationalUnit -Name  $SenAcOU         -Path "$RootOU"             -Description "Sensitve Accounts" 
New-ADOrganizationalUnit -Name "Sensitve Users"  -Path "OU=$SenAcOU,$RootOU" -Description "Denied for $VIGroup" 
New-ADOrganizationalUnit -Name "Sensitve Groups" -Path "OU=$SenAcOU,$RootOU" -Description "Denied for $VIGroup" 


#List new Gorups
#Get-ADOrganizationalUnit -LDAPFilter "(Description=Denied for *)" -Properties canonicalName, Created  | select Name, Created, canonicalName | ft


Write-Host "Moving Sensitive Groups ...." -ForegroundColor Yellow

Get-ADGroup -LDAPFilter "(sAMAccountName=Domain Admins)" | Move-ADObject -TargetPath "OU=Sensitve Groups,OU=$SenAcOU,$RootOU"
Get-ADGroup -LDAPFilter "(sAMAccountName=Schema Admins)" | Move-ADObject -TargetPath "OU=Sensitve Groups,OU=$SenAcOU,$RootOU"
Get-ADGroup -LDAPFilter "(sAMAccountName=Enterprise Admins)" | Move-ADObject -TargetPath "OU=Sensitve Groups,OU=$SenAcOU,$RootOU"
Get-ADGroup -LDAPFilter "(sAMAccountName=Group Policy Creator Owners)" | Move-ADObject -TargetPath "OU=Sensitve Groups,OU=$SenAcOU,$RootOU"

#Get-adgroup -Filter {name -like 'sg-as2go*'} | Move-ADObject -TargetPath "OU=Groups,OU=$AS2GoOU,$RootOU"


#List new Gorups
Get-ADGroup -LDAPFilter "(Description=Designated administrators of the*)" -Properties canonicalName, Created  | select sAMAccountName, Created, name, canonicalName | ft


Write-Host "`n Done! Please do NOT forget to set the DENY right for group '$VIGroup' on Organization Unit:" -ForegroundColor Yellow
Write-Host "`n --> OU=Sensitve Groups,OU=$SenAcOU,$RootOU`n" -ForegroundColor Yellow

dsa.msc