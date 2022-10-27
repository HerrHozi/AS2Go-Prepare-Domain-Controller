# AS2Go-Setup-Domain-Controller
Files to prepare the AS2GO | Domain Controller Setup. AS2Go is an acronym for Attack Scenario To Go. 

Find more information here in my blog post [AS2Go | Lab Setup | Domain Controller](https://herrhozi.com/2022/01/04/as2go-lab-setup-domain-controller/). 

## Quick Start Guide
Open a Admin PowerShell terminal from the Windows command.

The following command will automatically create a set of users based on the current date.
```PowerShell
New-AS2GoUsers.ps1 
```

The following command will automatically create a set of users based on the current date and time 
```PowerShell
New-AS2GoUsers -Shortname n
```

The following command will automatically create a set of users based on an predefined name
```PowerShell
New-AS2GoUsers -Shortname HerrHozi
```
![image](https://user-images.githubusercontent.com/96825160/198322677-35487f01-ff48-46d1-a3c9-fe46bf297472.png)
